//! Hand-rolled OTLP logs encoder for end-to-end pipeline fixtures
//! (synthetic data only, docs/engineering/02 §6). Mirrors the per-crate test
//! encoders so pipeline output can be byte-compared against a fresh encode of
//! the governed result.
#![allow(dead_code)] // shared encoder toolkit: not every test binary uses every builder

pub fn varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let b = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            break;
        }
        out.push(b | 0x80);
    }
}

pub fn field_len(field: u32, payload: &[u8], out: &mut Vec<u8>) {
    varint(u64::from(field) << 3 | 2, out);
    varint(payload.len() as u64, out);
    out.extend_from_slice(payload);
}

pub fn field_varint(field: u32, v: u64, out: &mut Vec<u8>) {
    varint(u64::from(field) << 3, out);
    varint(v, out);
}

pub fn any_string(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    field_len(1, s.as_bytes(), &mut out);
    out
}

pub fn key_value(key: &str, value_any: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    field_len(1, key.as_bytes(), &mut out);
    field_len(2, value_any, &mut out);
    out
}

#[derive(Clone)]
pub struct Rec<'a> {
    pub body: &'a str,
    pub trace_id: Option<&'a [u8]>,
    pub attrs: Vec<Vec<u8>>,
    /// OTLP SeverityNumber (LogRecord field 2), or `None` to omit.
    pub severity: Option<i32>,
}

impl Rec<'_> {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(sev) = self.severity {
            field_varint(2, sev as u64, &mut out); // severity_number
        }
        field_len(5, &any_string(self.body), &mut out); // body
        for attr in &self.attrs {
            field_len(6, attr, &mut out); // attributes
        }
        if let Some(tid) = self.trace_id {
            field_len(9, tid, &mut out); // trace_id
        }
        out
    }
}

/// ResourceLogs (Resource preserved verbatim) → ScopeLogs → records, with an
/// optional `k8s.namespace.name` resource attribute.
pub fn request_ns(namespace: Option<&str>, records: &[Rec]) -> Vec<u8> {
    let mut scope_logs = Vec::new();
    for r in records {
        field_len(2, &r.encode(), &mut scope_logs);
    }
    let mut resource = Vec::new();
    field_len(
        1,
        &key_value("service.name", &any_string("checkout")),
        &mut resource,
    );
    if let Some(ns) = namespace {
        field_len(
            1,
            &key_value("k8s.namespace.name", &any_string(ns)),
            &mut resource,
        );
    }

    let mut resource_logs = Vec::new();
    field_len(1, &resource, &mut resource_logs);
    field_len(2, &scope_logs, &mut resource_logs);

    let mut req = Vec::new();
    field_len(1, &resource_logs, &mut req);
    req
}

/// ResourceLogs with no namespace attribute.
pub fn request(records: &[Rec]) -> Vec<u8> {
    request_ns(None, records)
}
