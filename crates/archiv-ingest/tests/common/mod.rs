//! Hand-rolled OTLP logs encoder for test fixtures — deterministic bytes with
//! no prost dependency (synthetic data only, docs/engineering/02 §6).
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

pub fn field_fixed32(field: u32, v: u32, out: &mut Vec<u8>) {
    varint(u64::from(field) << 3 | 5, out);
    out.extend_from_slice(&v.to_le_bytes());
}

/// AnyValue with string_value (field 1).
pub fn any_string(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    field_len(1, s.as_bytes(), &mut out);
    out
}

/// AnyValue with int_value (field 3).
pub fn any_int(v: i64) -> Vec<u8> {
    let mut out = Vec::new();
    field_varint(3, v as u64, &mut out);
    out
}

/// KeyValue { key = 1, value = 2 }.
pub fn key_value(key: &str, value_any: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    field_len(1, key.as_bytes(), &mut out);
    field_len(2, value_any, &mut out);
    out
}

pub struct LogRecord<'a> {
    pub body: Option<Vec<u8>>, // encoded AnyValue
    pub trace_id: Option<&'a [u8]>,
    pub attrs: Vec<Vec<u8>>, // encoded KeyValues
    pub with_noise_fields: bool,
}

impl LogRecord<'_> {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if self.with_noise_fields {
            field_fixed64(1, 1_720_000_000_000_000_000, &mut out); // time_unix_nano
            field_varint(2, 9, &mut out); // severity_number = INFO
            field_len(3, b"INFO", &mut out); // severity_text
        }
        if let Some(body) = &self.body {
            field_len(5, body, &mut out);
        }
        for attr in &self.attrs {
            field_len(6, attr, &mut out);
        }
        if self.with_noise_fields {
            field_varint(7, 0, &mut out); // dropped_attributes_count
            field_fixed32(8, 1, &mut out); // flags
        }
        if let Some(tid) = self.trace_id {
            field_len(9, tid, &mut out);
        }
        if self.with_noise_fields {
            field_len(10, &[0xAA; 8], &mut out); // span_id
            field_fixed64(11, 1_720_000_000_000_000_001, &mut out); // observed_time
            field_len(12, b"test.event", &mut out); // event_name
        }
        out
    }
}

/// Wrap records into ScopeLogs → ResourceLogs → ExportLogsServiceRequest.
pub fn request(records: &[Vec<u8>]) -> Vec<u8> {
    let mut scope_logs = Vec::new();
    for r in records {
        field_len(2, r, &mut scope_logs);
    }
    let mut resource_logs = Vec::new();
    // A Resource with one attribute — structurally present, must be skipped.
    let mut resource = Vec::new();
    field_len(
        1,
        &key_value("service.name", &any_string("checkout")),
        &mut resource,
    );
    field_len(1, &resource, &mut resource_logs);
    field_len(2, &scope_logs, &mut resource_logs);

    let mut req = Vec::new();
    field_len(1, &resource_logs, &mut req);
    req
}
