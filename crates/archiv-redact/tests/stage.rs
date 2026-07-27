//! End-to-end: synthetic record → guarded redact stage → spans verified by
//! simulating the exporter's vectored assembly (`core/02` §3.2). Ties to the
//! `core/04` §6 acceptance criterion: a log containing an email exits with
//! `[REDACTED:email]`; the original buffer is never mutated.
//!
//! Fixture data is synthetic only (docs/engineering/02 §6).
#![allow(clippy::expect_used, clippy::unwrap_used)] // test setup: panic on failure is intended

use archiv_pipeline::{Envelope, RecordView, StageOutcome, guarded};
use archiv_redact::{CompileLimits, FieldSelector, RedactEngine, RedactStage};
use bytes::Bytes;
use smallvec::SmallVec;
use std::ops::Range;

/// Test-only stand-in for the exporter: interleave `raw` slices and mask
/// bytes across a field range. (Allocation is fine here — this is the
/// verification harness, not the pipeline.)
fn assemble(env: &Envelope, engine: &RedactEngine, record: usize, field: Range<usize>) -> Vec<u8> {
    let mut spans: Vec<_> = env
        .decisions
        .redactions_for(record)
        .filter(|r| r.target.start >= field.start && r.target.end <= field.end)
        .collect();
    spans.sort_by_key(|r| r.target.start);

    let mut out = Vec::new();
    let mut cursor = field.start;
    for span in spans {
        out.extend_from_slice(&env.raw[cursor..span.target.start]);
        out.extend_from_slice(engine.mask_bytes(span.mask).expect("known mask"));
        cursor = span.target.end;
    }
    out.extend_from_slice(&env.raw[cursor..field.end]);
    out
}

/// Build one record whose body and attributes are ranges into a single buffer.
fn fixture() -> (Envelope, Range<usize>, Range<usize>, Range<usize>) {
    let mut buf: Vec<u8> = Vec::new();
    let mut push = |s: &str| -> Range<usize> {
        let start = buf.len();
        buf.extend_from_slice(s.as_bytes());
        start..buf.len()
    };

    let body = push("login ok for alice@example.com from 10.0.0.7");
    let k1 = push("user.email");
    let v1 = push("bob@example.com");
    let k2 = push("request.note");
    let v2 = push("contact carol@example.com later");

    let mut env = Envelope::new(Bytes::from(buf));
    env.records.push(RecordView {
        body: body.start..body.end,
        trace_id: None,
        attrs: SmallVec::from_vec(vec![
            archiv_pipeline::AttrView {
                key: k1,
                value: v1.start..v1.end,
            },
            archiv_pipeline::AttrView {
                key: k2,
                value: v2.start..v2.end,
            },
        ]),
        severity_number: None,
        namespace: None,
        service_name: None,
    });
    (env, body, v1, v2)
}

fn email_stage() -> RedactStage {
    let engine = RedactEngine::compile(
        vec![archiv_redact::RuleSpec {
            name: "email".to_string(),
            pattern: r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}".to_string(),
            mask: "[REDACTED:email]".to_string(),
            fields: vec![
                FieldSelector::Body,
                FieldSelector::Attrs("user.*".to_string()),
            ],
        }],
        CompileLimits::default(),
    )
    .expect("canonical rule compiles");
    RedactStage::new(engine)
}

#[test]
fn guarded_stage_redacts_body_and_selected_attrs_only() {
    let (mut env, body, v1, v2) = fixture();
    let original = env.raw.slice(..); // Bytes refcount, not a copy

    let stage = email_stage();
    let outcome = guarded(&stage, &mut env);
    assert!(matches!(outcome, StageOutcome::Applied));

    // Acceptance: the email exits masked, everything else byte-identical.
    assert_eq!(
        assemble(&env, stage.engine(), 0, body),
        b"login ok for [REDACTED:email] from 10.0.0.7".as_slice()
    );
    // Attr selected by `attributes.user.*` is masked in full.
    assert_eq!(
        assemble(&env, stage.engine(), 0, v1),
        b"[REDACTED:email]".as_slice()
    );
    // Attr NOT matching the selector passes through even though the pattern
    // would match — selectors are part of the rule contract.
    assert_eq!(
        assemble(&env, stage.engine(), 0, v2),
        b"contact carol@example.com later".as_slice()
    );

    // The original payload was never mutated (zero-copy law).
    assert_eq!(env.raw, original);

    // redaction_count per rule (core/04 §5): body + user.email = 2 matches.
    let counts: Vec<_> = stage.counts().collect();
    assert_eq!(counts, vec![("email", 2)]);
}

#[test]
fn clean_record_produces_no_spans() {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"healthy request completed status=200");
    let body = 0..buf.len();
    let mut env = Envelope::new(Bytes::from(buf));
    env.records.push(RecordView {
        body: body.start..body.end,
        trace_id: None,
        attrs: SmallVec::new(),
        severity_number: None,
        namespace: None,
        service_name: None,
    });

    let stage = email_stage();
    let outcome = guarded(&stage, &mut env);
    assert!(matches!(outcome, StageOutcome::Applied));
    assert_eq!(env.decisions.redactions_for(0).count(), 0);
    assert_eq!(
        assemble(&env, stage.engine(), 0, body),
        b"healthy request completed status=200".as_slice()
    );
}

#[test]
fn invalid_utf8_payload_is_handled_bytewise() {
    // regex::bytes works on raw bytes — invalid UTF-8 must not panic or skip
    // valid matches elsewhere in the field (`core/02` §3.5).
    let mut buf: Vec<u8> = vec![0xFF, 0xFE, b' '];
    buf.extend_from_slice(b"dave@example.com");
    buf.extend_from_slice(&[0x80, 0x81]);
    let body = 0..buf.len();
    let mut env = Envelope::new(Bytes::from(buf));
    env.records.push(RecordView {
        body: body.start..body.end,
        trace_id: None,
        attrs: SmallVec::new(),
        severity_number: None,
        namespace: None,
        service_name: None,
    });

    let stage = email_stage();
    assert!(matches!(guarded(&stage, &mut env), StageOutcome::Applied));
    let out = assemble(&env, stage.engine(), 0, body);
    assert_eq!(
        out,
        [
            &[0xFF, 0xFE, b' '][..],
            b"[REDACTED:email]",
            &[0x80, 0x81][..]
        ]
        .concat()
    );
}
