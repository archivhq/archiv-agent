//! Hand-rolled OTLP logs encoder for export fixtures (synthetic only,
//! docs/engineering/02 §6). Mirrors the ingest test encoder so the export
//! output can be compared byte-for-byte against an independently built
//! "expected" request — the re-encoder must produce exactly what a fresh
//! encode of the governed data would.
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

pub fn field_fixed64(field: u32, v: u64, out: &mut Vec<u8>) {
    varint(u64::from(field) << 3 | 1, out);
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn any_string(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    field_len(1, s.as_bytes(), &mut out);
    out
}

pub fn any_int(v: i64) -> Vec<u8> {
    let mut out = Vec::new();
    field_varint(3, v as u64, &mut out);
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
    pub body: Option<Vec<u8>>,
    pub trace_id: Option<&'a [u8]>,
    pub attrs: Vec<Vec<u8>>,
    pub noise: bool,
}

impl Rec<'_> {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if self.noise {
            field_fixed64(1, 1_720_000_000_000_000_000, &mut out);
            field_varint(2, 9, &mut out);
            field_len(3, b"INFO", &mut out);
        }
        if let Some(body) = &self.body {
            field_len(5, body, &mut out);
        }
        for attr in &self.attrs {
            field_len(6, attr, &mut out);
        }
        if let Some(tid) = self.trace_id {
            field_len(9, tid, &mut out);
        }
        if self.noise {
            field_len(10, &[0xAA; 8], &mut out);
        }
        out
    }
}

/// ResourceLogs with a Resource (must be preserved verbatim) wrapping the
/// given records in one ScopeLogs.
pub fn request(records: &[Rec]) -> Vec<u8> {
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

    let mut resource_logs = Vec::new();
    field_len(1, &resource, &mut resource_logs);
    field_len(2, &scope_logs, &mut resource_logs);

    let mut req = Vec::new();
    field_len(1, &resource_logs, &mut req);
    req
}
