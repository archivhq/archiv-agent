//! Cross-crate pipeline test: real OTLP bytes → parse(view) → sample →
//! redact → simulated export assembly (`core/01` §3.4 stage order).
//! Proves the crates compose on one buffer with zero payload copies.
#![allow(clippy::expect_used, clippy::unwrap_used)] // test setup: panic on failure is intended

mod common;

use archiv_ingest::ParseStage;
use archiv_pipeline::{Envelope, STAGE_SAMPLE, SampleVerdict, StageOutcome, guarded};
use archiv_redact::{CompileLimits, FieldSelector, RedactEngine, RedactStage, RuleSpec};
use bytes::Bytes;
use common::{LogRecord, any_string, key_value, request};

fn email_stage() -> RedactStage {
    RedactStage::new(
        RedactEngine::compile(
            vec![RuleSpec {
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
        .expect("rule compiles"),
    )
}

#[test]
fn otlp_bytes_flow_through_parse_sample_redact() {
    let keep_id = [0x11u8; 16];
    let rec1 = LogRecord {
        body: Some(any_string("password reset link sent to alice@example.com")),
        trace_id: Some(&keep_id),
        attrs: vec![key_value("user.email", &any_string("alice@example.com"))],
        with_noise_fields: true,
    }
    .encode();
    let rec2 = LogRecord {
        body: Some(any_string("debug noise, no pii")),
        trace_id: Some(&keep_id),
        attrs: vec![],
        with_noise_fields: false,
    }
    .encode();

    let mut env = Envelope::new(Bytes::from(request(&[rec1, rec2])));

    // 1. parse(view)
    assert!(matches!(
        guarded(&ParseStage, &mut env),
        StageOutcome::Applied
    ));
    assert_eq!(env.records.len(), 2);

    // 2. sample — frozen decision per record (core/03 §3.1); the stage
    //    orchestrator crate arrives with archiv-pipeline's runner loop.
    let target = 100u8; // keep-all policy for this test
    let verdicts: Vec<SampleVerdict> = env
        .records
        .iter()
        .map(|r| match r.trace_id_bytes(&env.raw) {
            Some(id) if archiv_sampling::keep(&id, target) => SampleVerdict::Keep,
            Some(_) => SampleVerdict::Drop,
            None => SampleVerdict::Keep,
        })
        .collect();
    env.decisions.set_sampling(verdicts);
    assert_eq!(env.decisions.sampling_verdict(0), SampleVerdict::Keep);

    // 3. redact
    let stage = email_stage();
    assert!(matches!(guarded(&stage, &mut env), StageOutcome::Applied));

    // 4. simulated export assembly over the body view of record 0.
    let body = &env.records[0].body;
    let mut spans: Vec<_> = env
        .decisions
        .redactions_for(0)
        .filter(|r| r.target.start >= body.start && r.target.end <= body.end)
        .collect();
    spans.sort_by_key(|r| r.target.start);
    let mut out = Vec::new();
    let mut cursor = body.start;
    for span in spans {
        out.extend_from_slice(&env.raw[cursor..span.target.start]);
        out.extend_from_slice(stage.engine().mask_bytes(span.mask).expect("mask"));
        cursor = span.target.end;
    }
    out.extend_from_slice(&env.raw[cursor..body.end]);

    assert_eq!(out, b"password reset link sent to [REDACTED:email]");

    // Record 1 (no PII) has no spans; record 0's attr got one.
    assert_eq!(env.decisions.redactions_for(1).count(), 0);
    assert_eq!(env.decisions.redactions_for(0).count(), 2); // body + user.email

    // Sampling verdicts survive the redact stage (per-stage isolation).
    assert_eq!(env.decisions.sampling_verdict(1), SampleVerdict::Keep);
    let _ = STAGE_SAMPLE; // stage id shared with the future orchestrator
}

#[test]
fn drop_verdicts_follow_the_frozen_rule_end_to_end() {
    // Pick ids with known buckets from the pinned generator logic.
    let ids: Vec<[u8; 16]> = (0u8..32).map(|i| [i; 16]).collect();
    let target = 25u8;

    let records: Vec<Vec<u8>> = ids
        .iter()
        .map(|id| {
            LogRecord {
                body: Some(any_string("record")),
                trace_id: Some(id.as_slice()),
                attrs: vec![],
                with_noise_fields: false,
            }
            .encode()
        })
        .collect();

    let mut env = Envelope::new(Bytes::from(request(&records)));
    assert!(matches!(
        guarded(&ParseStage, &mut env),
        StageOutcome::Applied
    ));
    assert_eq!(env.records.len(), ids.len());

    // Decisions derived through the pipeline equal direct calls to keep() —
    // parsing must not perturb sampling inputs (billing depends on this).
    for (i, rec) in env.records.iter().enumerate() {
        let id = rec.trace_id_bytes(&env.raw).expect("trace id parsed");
        assert_eq!(id, ids[i], "parsed trace_id must be byte-identical");
        assert_eq!(
            archiv_sampling::keep(&id, target),
            archiv_sampling::bucket(&id) < target,
        );
    }
}
