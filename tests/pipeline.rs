//! End-to-end proof the assembled engine runs: raw OTLP bytes → the full
//! `Pipeline` (parse → sample → redact → assemble) → governed output bytes,
//! compared against an independently encoded expected request. Covers the
//! happy path, rule-based sampling, redaction, and the fail-open guarantee.
#![allow(clippy::expect_used, clippy::unwrap_used)] // test setup: panic on failure is intended

mod common;

use archiv_agent::pipeline::Pipeline;
use archiv_config::AgentConfig;
use bytes::Bytes;
use common::{Rec, any_string, key_value, request, request_ns};

const TRACE: [u8; 16] = [0x11; 16];

fn pipeline(yaml: &str) -> Pipeline {
    Pipeline::from_config(AgentConfig::from_yaml(yaml).expect("config valid"))
        .expect("pipeline builds")
}

fn rec(body: &str) -> Rec<'_> {
    Rec {
        body,
        trace_id: Some(&TRACE),
        attrs: vec![],
        severity: None,
    }
}

const EMAIL_RULE: &str = r#"
sampling:
  default_target: 100
redaction:
  regex_rules:
    - name: email
      pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
      mask: "[REDACTED:email]"
      fields: [body, "attributes.user.*"]
"#;

#[test]
fn keep_all_no_redaction_is_byte_identical_passthrough() {
    let pipe = pipeline("sampling:\n  default_target: 100\n");
    let input = request(&[rec("first record"), rec("second record")]);

    let out = pipe.process(Bytes::from(input.clone()));
    assert_eq!(
        out.output.contiguous(),
        input,
        "no policy → output equals input"
    );
    assert_eq!(out.stats.records_in, 2);
    assert_eq!(out.stats.kept, 2);
    assert_eq!(out.stats.dropped, 0);
    assert_eq!(out.stats.redactions, 0);
    assert_eq!(out.stats.bytes_out, out.stats.bytes_in);
    assert!(
        !out.stats.parse_bypassed && !out.stats.redact_bypassed && !out.stats.assemble_bypassed
    );
}

#[test]
fn redaction_matches_fresh_encode_with_masks() {
    let pipe = pipeline(EMAIL_RULE);
    let input = request(&[Rec {
        body: "reach alice@corp.io today",
        trace_id: Some(&TRACE),
        attrs: vec![
            key_value("user.email", &any_string("bob@corp.io")),
            key_value("note", &any_string("cc dave@corp.io")), // not selected
        ],
        severity: None,
    }]);

    let out = pipe.process(Bytes::from(input));

    let expected = request(&[Rec {
        body: "reach [REDACTED:email] today",
        trace_id: Some(&TRACE),
        attrs: vec![
            key_value("user.email", &any_string("[REDACTED:email]")),
            key_value("note", &any_string("cc dave@corp.io")),
        ],
        severity: None,
    }]);
    assert_eq!(out.output.contiguous(), expected);
    assert_eq!(out.stats.kept, 1);
    assert_eq!(out.stats.redactions, 2); // body + user.email
}

#[test]
fn zero_target_drops_every_record() {
    let pipe = pipeline("sampling:\n  default_target: 0\n");
    let input = request(&[rec("drop me"), rec("me too")]);

    let out = pipe.process(Bytes::from(input));

    // Every record omitted → the ResourceLogs/ScopeLogs wrapper survives empty.
    assert_eq!(out.output.contiguous(), request(&[]));
    assert_eq!(out.stats.records_in, 2);
    assert_eq!(out.stats.dropped, 2);
    assert_eq!(out.stats.kept, 0);
}

/// The headline of this loop: configured namespace / severity rules actually
/// steer keep/drop decisions, driven by fields the parser now extracts.
#[test]
fn rule_based_sampling_by_namespace_and_severity() {
    // payments → never sample (100); DEBUG (≤8) anywhere else → drop (0).
    let pipe = pipeline(
        "sampling:\n  default_target: 100\n  rules:\n    \
         - match: { namespace: payments }\n      target: 100\n    \
         - match: { severity_lte: DEBUG }\n      target: 0\n",
    );

    // DEBUG(5) in namespace "web" → severity rule → dropped.
    let debug_web = request_ns(
        Some("web"),
        &[Rec {
            body: "debug noise",
            trace_id: Some(&TRACE),
            attrs: vec![],
            severity: Some(5),
        }],
    );
    let out = pipe.process(Bytes::from(debug_web));
    assert_eq!(
        (out.stats.kept, out.stats.dropped),
        (0, 1),
        "debug in web dropped"
    );

    // DEBUG(5) in "payments" → payments rule wins first → kept.
    let debug_payments = request_ns(
        Some("payments"),
        &[Rec {
            body: "debug in payments",
            trace_id: Some(&TRACE),
            attrs: vec![],
            severity: Some(5),
        }],
    );
    let out = pipe.process(Bytes::from(debug_payments));
    assert_eq!(
        (out.stats.kept, out.stats.dropped),
        (1, 0),
        "payments never sampled"
    );

    // INFO(9) in "web" → no rule matches → default 100 → kept.
    let info_web = request_ns(
        Some("web"),
        &[Rec {
            body: "info",
            trace_id: Some(&TRACE),
            attrs: vec![],
            severity: Some(9),
        }],
    );
    let out = pipe.process(Bytes::from(info_web));
    assert_eq!(
        (out.stats.kept, out.stats.dropped),
        (1, 0),
        "info falls through to default"
    );
}

#[test]
fn garbage_input_fails_open_and_forwards_verbatim() {
    let pipe = pipeline(EMAIL_RULE);
    let garbage = Bytes::from_static(&[0xFF; 40]);

    let out = pipe.process(garbage.clone());

    assert!(
        out.stats.parse_bypassed,
        "unparseable payload must bypass parse"
    );
    assert_eq!(out.stats.records_in, 0);
    assert_eq!(out.output.contiguous(), garbage.as_ref());
    assert_eq!(out.stats.bytes_out, out.stats.bytes_in);
}

#[test]
fn default_pipeline_is_full_passthrough() {
    let pipe = Pipeline::from_config(AgentConfig::default()).expect("builds");
    let input = request(&[rec("anything at all with an email x@y.io")]);
    let out = pipe.process(Bytes::from(input.clone()));
    assert_eq!(out.output.contiguous(), input);
    assert_eq!(out.stats.kept, 1);
    assert_eq!(out.stats.redactions, 0);
}

#[test]
fn unknown_severity_name_fails_pipeline_build() {
    let err = AgentConfig::from_yaml(
        "sampling:\n  rules:\n    - match: { severity_lte: LOUD }\n      target: 10\n",
    )
    .map(Pipeline::from_config);
    // config parses (severity name is free text), pipeline build rejects it.
    assert!(
        matches!(err, Ok(Err(_))),
        "unknown severity must fail build"
    );
}
