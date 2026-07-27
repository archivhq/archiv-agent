//! Zero-copy walker over the OTLP logs wire format.
//!
//! Message shape (opentelemetry-proto, logs v1):
//! ```text
//! ExportLogsServiceRequest { repeated ResourceLogs resource_logs = 1 }
//! ResourceLogs  { Resource resource = 1; repeated ScopeLogs scope_logs = 2 }
//! ScopeLogs     { InstrumentationScope scope = 1; repeated LogRecord log_records = 2 }
//! LogRecord     { fixed64 time_unix_nano = 1; SeverityNumber severity_number = 2;
//!                 string severity_text = 3; AnyValue body = 5;
//!                 repeated KeyValue attributes = 6; uint32 dropped_attributes_count = 7;
//!                 fixed32 flags = 8; bytes trace_id = 9; bytes span_id = 10;
//!                 fixed64 observed_time_unix_nano = 11; string event_name = 12 }
//! KeyValue      { string key = 1; AnyValue value = 2 }
//! AnyValue      { oneof: string_value = 1 | bool | int | double | array | kvlist | bytes }
//! ```
//! Only string bodies/values become views (redaction targets strings, v1);
//! everything else is skipped structurally. Nesting depth is fixed by the
//! schema walk — no recursion on attacker-controlled structure.
//!
//! All positions are absolute offsets into the request buffer, so emitted
//! ranges plug straight into `Envelope::raw`.

use std::ops::Range;

use archiv_pipeline::{AttrView, RecordView};
use smallvec::SmallVec;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("truncated buffer at offset {0}")]
    Truncated(usize),
    #[error("varint overflow at offset {0}")]
    VarintOverflow(usize),
    #[error("unsupported wire type {wire} at offset {offset}")]
    UnsupportedWire { wire: u8, offset: usize },
    #[error("length overruns enclosing message at offset {0}")]
    LengthOverrun(usize),
}

/// Bounds-checked cursor over one (sub-)message window of the buffer.
///
/// Public because the export re-encoder (`archiv-export`) walks the same wire
/// format to rebuild length prefixes; both sides must agree byte-for-byte on
/// traversal semantics, so there is exactly one cursor implementation.
pub struct WireCursor<'a> {
    buf: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> WireCursor<'a> {
    pub fn new(buf: &'a [u8], window: Range<usize>) -> Self {
        Self {
            buf,
            pos: window.start,
            end: window.end,
        }
    }

    pub fn done(&self) -> bool {
        self.pos >= self.end
    }

    fn byte(&mut self) -> Result<u8, ParseError> {
        if self.pos >= self.end {
            return Err(ParseError::Truncated(self.pos));
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(b)
    }

    pub fn varint(&mut self) -> Result<u64, ParseError> {
        let start = self.pos;
        let mut v = 0u64;
        let mut shift = 0u32;
        loop {
            let b = self.byte()?;
            if shift >= 64 {
                return Err(ParseError::VarintOverflow(start));
            }
            v |= u64::from(b & 0x7F) << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
            shift += 7;
        }
    }

    /// Absolute offset of the next unread byte.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Field tag: (field number, wire type).
    pub fn tag(&mut self) -> Result<(u32, u8), ParseError> {
        let t = self.varint()?;
        Ok(((t >> 3) as u32, (t & 0x7) as u8))
    }

    /// Length-delimited payload as an absolute range; cursor jumps past it.
    pub fn len_range(&mut self) -> Result<Range<usize>, ParseError> {
        let at = self.pos;
        let len = self.varint()?;
        let len = usize::try_from(len).map_err(|_| ParseError::LengthOverrun(at))?;
        let start = self.pos;
        let end = start
            .checked_add(len)
            .ok_or(ParseError::LengthOverrun(at))?;
        if end > self.end {
            return Err(ParseError::LengthOverrun(at));
        }
        self.pos = end;
        Ok(start..end)
    }

    fn advance(&mut self, n: usize) -> Result<(), ParseError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(ParseError::Truncated(self.pos))?;
        if end > self.end {
            return Err(ParseError::Truncated(self.pos));
        }
        self.pos = end;
        Ok(())
    }

    pub fn skip(&mut self, wire: u8) -> Result<(), ParseError> {
        match wire {
            0 => {
                self.varint()?;
            }
            1 => self.advance(8)?,
            2 => {
                self.len_range()?;
            }
            5 => self.advance(4)?,
            w => {
                return Err(ParseError::UnsupportedWire {
                    wire: w,
                    offset: self.pos,
                });
            }
        }
        Ok(())
    }
}

/// Parse a full `ExportLogsServiceRequest`, appending one `RecordView` per
/// `LogRecord`. On error the caller discards `out` and fails open.
pub fn parse_export_logs_request(
    buf: &[u8],
    out: &mut SmallVec<[RecordView; 8]>,
) -> Result<(), ParseError> {
    let mut cur = WireCursor::new(buf, 0..buf.len());
    while !cur.done() {
        let (field, wire) = cur.tag()?;
        if field == 1 && wire == 2 {
            let rl = cur.len_range()?;
            parse_resource_logs(buf, rl, out)?;
        } else {
            cur.skip(wire)?;
        }
    }
    Ok(())
}

fn parse_resource_logs(
    buf: &[u8],
    window: Range<usize>,
    out: &mut SmallVec<[RecordView; 8]>,
) -> Result<(), ParseError> {
    // Two-pass over the ResourceLogs so the resource attributes (field 1) are
    // known before records are built, regardless of field order on the wire.
    let mut namespace: Option<Range<usize>> = None;
    let mut service_name: Option<Range<usize>> = None;
    let mut scopes: SmallVec<[Range<usize>; 4]> = SmallVec::new();

    let mut cur = WireCursor::new(buf, window);
    while !cur.done() {
        let (field, wire) = cur.tag()?;
        match (field, wire) {
            (1, 2) => {
                let resource = cur.len_range()?;
                let attrs = parse_resource_attrs(buf, resource)?;
                namespace = attrs.namespace;
                service_name = attrs.service_name;
            }
            (2, 2) => scopes.push(cur.len_range()?),
            _ => cur.skip(wire)?,
        }
    }
    for sl in scopes {
        parse_scope_logs(buf, sl, namespace.as_ref(), service_name.as_ref(), out)?;
    }
    Ok(())
}

/// Resource-level views extracted once per `ResourceLogs` and propagated to
/// every record under it: `namespace` (sampling matcher) and `service.name`
/// (untraced fallback key, `core/03` §3.2).
#[derive(Default)]
struct ResourceAttrs {
    namespace: Option<Range<usize>>,
    service_name: Option<Range<usize>>,
}

/// Resource `{ repeated KeyValue attributes = 1 }` → the string values of the
/// `k8s.namespace.name` and `service.name` attributes, if present.
fn parse_resource_attrs(buf: &[u8], window: Range<usize>) -> Result<ResourceAttrs, ParseError> {
    let mut namespace = None;
    let mut service_name = None;
    let mut cur = WireCursor::new(buf, window);
    while !cur.done() {
        let (field, wire) = cur.tag()?;
        if field == 1 && wire == 2 {
            let kv = cur.len_range()?;
            if let Some(attr) = parse_key_value(buf, kv)? {
                match buf.get(attr.key.start..attr.key.end) {
                    Some(k) if k == b"k8s.namespace.name".as_slice() => {
                        namespace = Some(attr.value)
                    }
                    Some(k) if k == b"service.name".as_slice() => service_name = Some(attr.value),
                    _ => {}
                }
            }
        } else {
            cur.skip(wire)?;
        }
    }
    Ok(ResourceAttrs {
        namespace,
        service_name,
    })
}

fn parse_scope_logs(
    buf: &[u8],
    window: Range<usize>,
    namespace: Option<&Range<usize>>,
    service_name: Option<&Range<usize>>,
    out: &mut SmallVec<[RecordView; 8]>,
) -> Result<(), ParseError> {
    let mut cur = WireCursor::new(buf, window);
    while !cur.done() {
        let (field, wire) = cur.tag()?;
        if field == 2 && wire == 2 {
            let lr = cur.len_range()?;
            out.push(parse_log_record(buf, lr, namespace, service_name)?);
        } else {
            cur.skip(wire)?;
        }
    }
    Ok(())
}

fn parse_log_record(
    buf: &[u8],
    window: Range<usize>,
    namespace: Option<&Range<usize>>,
    service_name: Option<&Range<usize>>,
) -> Result<RecordView, ParseError> {
    let mut body = window.start..window.start; // empty = no string body
    let mut trace_id = None;
    let mut severity_number = None;
    let mut attrs: SmallVec<[AttrView; 16]> = SmallVec::new();

    let mut cur = WireCursor::new(buf, window);
    while !cur.done() {
        let (field, wire) = cur.tag()?;
        match (field, wire) {
            (2, 0) => {
                // severity_number: enum varint (a sampling matcher input).
                severity_number = Some(cur.varint()? as i32);
            }
            (5, 2) => {
                // body: AnyValue — only a string_value becomes a view.
                let av = cur.len_range()?;
                if let Some(s) = any_value_string(buf, av)? {
                    body = s;
                }
            }
            (6, 2) => {
                // attributes: KeyValue
                let kv = cur.len_range()?;
                if let Some(attr) = parse_key_value(buf, kv)? {
                    attrs.push(attr);
                }
            }
            (9, 2) => {
                // trace_id bytes: 16 binary (spec) or 32 hex (lenient
                // transports); RecordView::trace_id_bytes handles both.
                let r = cur.len_range()?;
                if r.len() == 16 || r.len() == 32 {
                    trace_id = Some(r);
                }
            }
            _ => cur.skip(wire)?,
        }
    }
    Ok(RecordView {
        body,
        trace_id,
        attrs,
        severity_number,
        namespace: namespace.map(|r| r.start..r.end),
        service_name: service_name.map(|r| r.start..r.end),
    })
}

/// `AnyValue.string_value` (field 1) as a view, if that's the variant set.
fn any_value_string(buf: &[u8], window: Range<usize>) -> Result<Option<Range<usize>>, ParseError> {
    let mut cur = WireCursor::new(buf, window);
    while !cur.done() {
        let (field, wire) = cur.tag()?;
        if field == 1 && wire == 2 {
            return Ok(Some(cur.len_range()?));
        }
        cur.skip(wire)?;
    }
    Ok(None)
}

/// `KeyValue` → `AttrView`, only when the value is a string (redaction scans
/// strings in v1; other types have no redactable text).
fn parse_key_value(buf: &[u8], window: Range<usize>) -> Result<Option<AttrView>, ParseError> {
    let mut key = None;
    let mut value = None;

    let mut cur = WireCursor::new(buf, window);
    while !cur.done() {
        let (field, wire) = cur.tag()?;
        match (field, wire) {
            (1, 2) => key = Some(cur.len_range()?),
            (2, 2) => {
                let av = cur.len_range()?;
                value = any_value_string(buf, av)?;
            }
            _ => cur.skip(wire)?,
        }
    }
    Ok(match (key, value) {
        (Some(key), Some(value)) => Some(AttrView { key, value }),
        _ => None,
    })
}
