//! Export re-encoder: byte-exact identity, drop, and redact round-trips
//! compared against independently encoded expected requests, plus the
//! zero-copy chunk guarantee (`core/02` §3.2).
#![allow(clippy::expect_used, clippy::unwrap_used)] // test setup: panic on failure is intended

mod common;

use archiv_export::{MaskTable, assemble};
use archiv_ingest::ParseStage;
use archiv_pipeline::{Envelope, SampleVerdict, Stage, StageOutcome, guarded};
use archiv_redact::{CompileLimits, FieldSelector, RedactEngine, RedactStage, RuleSpec};
use bytes::Bytes;
use common::{Rec, any_int, any_string, key_value, request};

const KEEP: [u8; 16] = [0x11; 16];
const DROP: [u8; 16] = [0x22; 16];

fn parsed_env(buf: Vec<u8>) -> Envelope {
    let mut env = Envelope::new(Bytes::from(buf));
    assert!(matches!(
        guarded(&ParseStage, &mut env),
        StageOutcome::Applied
    ));
    env
}

fn email_stage() -> (RedactStage, MaskTable) {
    let engine = RedactEngine::compile(
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
    .unwrap();
    let masks = MaskTable::new(engine.masks().map(str::to_string).collect::<Vec<_>>());
    (RedactStage::new(engine), masks)
}

#[test]
fn identity_when_no_decisions_reuses_raw_buffer() {
    let buf = request(&[Rec {
        body: Some(any_string("nothing to do here")),
        trace_id: Some(&KEEP),
        attrs: vec![key_value("k", &any_string("v"))],
        noise: true,
    }]);
    let env = parsed_env(buf.clone());
    let masks = MaskTable::new(Vec::<String>::new());

    let out = assemble(&env, &masks).unwrap();
    assert_eq!(out.contiguous(), buf);
    // Fast path: a single chunk that is a refcounted view of raw, not a copy.
    assert_eq!(out.chunks().len(), 1);
    assert_eq!(out.chunks()[0].as_ptr(), env.raw.as_ptr());
}

#[test]
fn dropping_a_record_matches_a_fresh_encode_without_it() {
    let kept = Rec {
        body: Some(any_string("keep me")),
        trace_id: Some(&KEEP),
        attrs: vec![],
        noise: true,
    };
    let dropped = Rec {
        body: Some(any_string("drop me")),
        trace_id: Some(&DROP),
        attrs: vec![key_value("user.email", &any_string("gone@example.com"))],
        noise: true,
    };

    let mut env = parsed_env(request(&[kept.clone(), dropped.clone()]));
    // Record 0 keep, record 1 drop.
    env.decisions
        .set_sampling([SampleVerdict::Keep, SampleVerdict::Drop]);

    let masks = MaskTable::new(Vec::<String>::new());
    let out = assemble(&env, &masks).unwrap();

    // Independently encode the request as if only the kept record existed.
    let expected = request(&[kept]);
    assert_eq!(out.contiguous(), expected);
}

#[test]
fn redaction_matches_a_fresh_encode_with_masked_text() {
    let (stage, masks) = email_stage();

    let original = Rec {
        body: Some(any_string("reset link for alice@example.com sent")),
        trace_id: Some(&KEEP),
        attrs: vec![
            key_value("user.email", &any_string("alice@example.com")),
            key_value("note", &any_string("cc bob@example.com")), // not selected
            key_value("count", &any_int(5)),                      // non-string
        ],
        noise: true,
    };
    let mut env = parsed_env(request(&[original]));
    assert!(matches!(stage.apply(&mut env), Ok(())));

    let out = assemble(&env, &masks).unwrap();

    // Expected: body + user.email masked; note + count untouched.
    let expected = request(&[Rec {
        body: Some(any_string("reset link for [REDACTED:email] sent")),
        trace_id: Some(&KEEP),
        attrs: vec![
            key_value("user.email", &any_string("[REDACTED:email]")),
            key_value("note", &any_string("cc bob@example.com")),
            key_value("count", &any_int(5)),
        ],
        noise: true,
    }]);
    assert_eq!(out.contiguous(), expected);
}

#[test]
fn drop_and_redact_together_across_multiple_records() {
    let (stage, masks) = email_stage();

    let r0 = Rec {
        body: Some(any_string("first, mail carol@corp.io ok")),
        trace_id: Some(&KEEP),
        attrs: vec![key_value("user.id", &any_string("dan@corp.io"))],
        noise: false,
    };
    let r1_dropped = Rec {
        body: Some(any_string("second dropped mail eve@corp.io")),
        trace_id: Some(&DROP),
        attrs: vec![],
        noise: true,
    };
    let r2 = Rec {
        body: Some(any_string("third clean")),
        trace_id: Some(&KEEP),
        attrs: vec![],
        noise: true,
    };

    let mut env = parsed_env(request(&[r0, r1_dropped, r2.clone()]));
    assert!(matches!(stage.apply(&mut env), Ok(())));
    env.decisions.set_sampling([
        SampleVerdict::Keep,
        SampleVerdict::Drop,
        SampleVerdict::Keep,
    ]);

    let out = assemble(&env, &masks).unwrap();

    let expected = request(&[
        Rec {
            body: Some(any_string("first, mail [REDACTED:email] ok")),
            trace_id: Some(&KEEP),
            attrs: vec![key_value("user.id", &any_string("[REDACTED:email]"))],
            noise: false,
        },
        r2,
    ]);
    assert_eq!(out.contiguous(), expected);
}

#[test]
fn payload_content_chunks_are_views_into_raw() {
    let (stage, masks) = email_stage();
    let mut env = parsed_env(request(&[Rec {
        body: Some(any_string("mail frank@corp.io now")),
        trace_id: Some(&KEEP),
        attrs: vec![],
        noise: false,
    }]));
    assert!(matches!(stage.apply(&mut env), Ok(())));

    let out = assemble(&env, &masks).unwrap();
    let raw_start = env.raw.as_ptr() as usize;
    let raw_end = raw_start + env.raw.len();

    // Every chunk is either a view into raw, or a small owned header/mask
    // buffer — never a contiguous copy of payload content.
    let mut viewed = 0usize;
    for chunk in out.chunks() {
        let p = chunk.as_ptr() as usize;
        if p >= raw_start && p < raw_end {
            viewed += chunk.len();
        }
    }
    // The verbatim "mail " / " now" runs around the mask must be raw views.
    assert!(viewed >= "mail ".len() + " now".len());
}

#[test]
fn unknown_mask_id_is_an_error_not_a_panic() {
    // Redact with a real engine, then assemble with an empty mask table.
    let (stage, _real) = email_stage();
    let mut env = parsed_env(request(&[Rec {
        body: Some(any_string("mail grace@corp.io")),
        trace_id: Some(&KEEP),
        attrs: vec![],
        noise: false,
    }]));
    assert!(matches!(stage.apply(&mut env), Ok(())));

    let empty = MaskTable::new(Vec::<String>::new());
    assert!(assemble(&env, &empty).is_err());
}
