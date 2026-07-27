//! Parser unit tests over hand-encoded OTLP bytes: view correctness,
//! non-string handling, noise-field skipping, malformed-input fail-open.
#![allow(clippy::expect_used, clippy::unwrap_used)] // test setup: panic on failure is intended

mod common;

use archiv_ingest::{ParseError, ParseStage, parse_export_logs_request};
use archiv_pipeline::{Envelope, StageOutcome, guarded};
use bytes::Bytes;
use common::{LogRecord, any_int, any_string, key_value, request};
use smallvec::SmallVec;

const TRACE_ID: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
];

#[test]
fn views_point_at_the_right_bytes() {
    let rec1 = LogRecord {
        body: Some(any_string("payment accepted for order 7781")),
        trace_id: Some(&TRACE_ID),
        attrs: vec![
            key_value("user.email", &any_string("alice@example.com")),
            key_value("retries", &any_int(3)), // non-string value → skipped
        ],
        with_noise_fields: true,
    }
    .encode();
    let rec2 = LogRecord {
        body: Some(any_string("second record")),
        trace_id: None,
        attrs: vec![],
        with_noise_fields: false,
    }
    .encode();

    let buf = request(&[rec1, rec2]);
    let mut records = SmallVec::new();
    parse_export_logs_request(&buf, &mut records).expect("valid request parses");

    assert_eq!(records.len(), 2);

    let r1 = &records[0];
    assert_eq!(
        &buf[r1.body.start..r1.body.end],
        b"payment accepted for order 7781"
    );
    assert_eq!(r1.attrs.len(), 1, "int-valued attr must be skipped");
    let a = &r1.attrs[0];
    assert_eq!(&buf[a.key.start..a.key.end], b"user.email");
    assert_eq!(&buf[a.value.start..a.value.end], b"alice@example.com");

    // trace_id extraction through the pipeline helper (16-byte binary form).
    let raw = Bytes::from(buf);
    assert_eq!(r1.trace_id_bytes(&raw), Some(TRACE_ID));

    let r2 = &records[1];
    assert_eq!(&raw[r2.body.start..r2.body.end], b"second record");
    assert_eq!(r2.trace_id, None);
}

#[test]
fn non_string_body_yields_empty_view() {
    let rec = LogRecord {
        body: Some(any_int(42)),
        trace_id: None,
        attrs: vec![],
        with_noise_fields: false,
    }
    .encode();
    let buf = request(&[rec]);

    let mut records = SmallVec::new();
    parse_export_logs_request(&buf, &mut records).expect("parses");
    assert_eq!(records.len(), 1);
    assert!(
        records[0].body.is_empty(),
        "int body must not become a text view"
    );
}

#[test]
fn malformed_trace_id_length_is_ignored() {
    let short_id = [0x01u8; 5];
    let rec = LogRecord {
        body: Some(any_string("x")),
        trace_id: Some(&short_id),
        attrs: vec![],
        with_noise_fields: false,
    }
    .encode();
    let buf = request(&[rec]);

    let mut records = SmallVec::new();
    parse_export_logs_request(&buf, &mut records).expect("parses");
    assert_eq!(records[0].trace_id, None);
}

#[test]
fn truncated_and_overrunning_buffers_error_without_panic() {
    let rec = LogRecord {
        body: Some(any_string("hello")),
        trace_id: Some(&TRACE_ID),
        attrs: vec![],
        with_noise_fields: true,
    }
    .encode();
    let full = request(&[rec]);

    // Every prefix of a valid request must error or parse cleanly — never panic.
    for cut in 0..full.len() {
        let mut records = SmallVec::new();
        let _ = parse_export_logs_request(&full[..cut], &mut records);
    }

    // A length that overruns its enclosing message is rejected.
    let mut evil = Vec::new();
    common::varint(1 << 3 | 2, &mut evil); // field 1, wire 2
    common::varint(1_000_000, &mut evil); // claims 1 MB payload
    evil.push(0x00); // ...delivers 1 byte
    let mut records = SmallVec::new();
    assert!(matches!(
        parse_export_logs_request(&evil, &mut records),
        Err(ParseError::LengthOverrun(_))
    ));
}

#[test]
fn extracts_severity_namespace_and_service_name() {
    // Resource carries k8s.namespace.name (matcher) and service.name (untraced
    // fallback key, core/03 §3.2); the record carries severity 9 (INFO) via the
    // noise fields. All must land on the RecordView, propagated from the resource.
    let lr = LogRecord {
        body: Some(any_string("hello")),
        trace_id: Some(&TRACE_ID),
        attrs: vec![],
        with_noise_fields: true, // emits severity_number = 9
    }
    .encode();

    let mut scope_logs = Vec::new();
    common::field_len(2, &lr, &mut scope_logs);
    let mut resource = Vec::new();
    common::field_len(
        1,
        &key_value("k8s.namespace.name", &any_string("payments")),
        &mut resource,
    );
    common::field_len(
        1,
        &key_value("service.name", &any_string("checkout")),
        &mut resource,
    );
    let mut rl = Vec::new();
    common::field_len(1, &resource, &mut rl);
    common::field_len(2, &scope_logs, &mut rl);
    let mut req = Vec::new();
    common::field_len(1, &rl, &mut req);

    let mut records = SmallVec::new();
    parse_export_logs_request(&req, &mut records).expect("parses");
    let raw = Bytes::from(req);

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].severity_number, Some(9));
    assert_eq!(
        records[0].namespace_bytes(&raw),
        Some(b"payments".as_slice())
    );
    assert_eq!(
        records[0].service_name_bytes(&raw),
        Some(b"checkout".as_slice())
    );
}

#[test]
fn parse_stage_fails_open_on_garbage() {
    // 0xFF runs decode as tags with wire type 7 → UnsupportedWire → bypass.
    let mut env = Envelope::new(Bytes::from_static(&[0xFF; 32]));
    let outcome = guarded(&ParseStage, &mut env);
    assert!(matches!(outcome, StageOutcome::Bypassed(_)));
    // No views: downstream stages no-op and the exporter forwards raw as-is.
    assert!(env.records.is_empty());
    assert_eq!(env.raw, Bytes::from_static(&[0xFF; 32]));
}
