//! Vectored export assembly (`docs/architecture/core/02` §3.2) [NORMATIVE].
//!
//! Turns an `Envelope` plus its `Decisions` into a valid OTLP
//! `ExportLogsServiceRequest` byte stream: sampled-out records are omitted,
//! redaction spans are replaced by mask bytes, everything else is preserved
//! verbatim. Because masks change field lengths, every enclosing protobuf
//! length prefix (string → AnyValue → KeyValue/LogRecord → ScopeLogs →
//! ResourceLogs) is recomputed bottom-up.
//!
//! The output is a chunk list: `Bytes::slice` views of `raw` for payload
//! content, plus small owned buffers for rewritten headers and mask bytes.
//! The full mutated payload never exists as a contiguous heap copy unless the
//! destination protocol strictly requires it ([`AssembledPayload::contiguous`],
//! the documented exception).
//!
//! Fail-open: any walk error returns `Err` and the caller forwards `raw`
//! unchanged — over-delivery, never loss (`core/05` §3.4). The destination
//! transport (OTLP forwarder) lands in the receivers loop.

#![forbid(unsafe_code)]

use std::ops::Range;

use archiv_ingest::ParseError;
use archiv_ingest::otlp::WireCursor;
use archiv_pipeline::{Envelope, MaskId, SampleVerdict};
use bytes::{BufMut, Bytes, BytesMut};
use smallvec::SmallVec;

#[derive(Debug, thiserror::Error)]
pub enum AssembleError {
    #[error("wire walk failed: {0}")]
    Wire(#[from] ParseError),
    #[error("record count mismatch: parsed {parsed}, walked {walked}")]
    RecordCountMismatch { parsed: usize, walked: usize },
    #[error("unknown mask id {0}")]
    UnknownMask(u32),
}

/// Mask bytes indexed by `MaskId`. Built once per policy swap from the
/// redaction engines' mask strings — config data, not payload.
#[derive(Debug)]
pub struct MaskTable {
    masks: Vec<Bytes>,
}

impl MaskTable {
    pub fn new<I, B>(masks: I) -> Self
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        Self {
            masks: masks
                .into_iter()
                .map(|m| Bytes::copy_from_slice(m.as_ref()))
                .collect(),
        }
    }

    pub fn bytes(&self, id: MaskId) -> Option<&Bytes> {
        self.masks.get(id.0 as usize)
    }
}

/// The assembled request: ordered chunks for `write_vectored`/`Buf` chaining.
#[derive(Debug)]
pub struct AssembledPayload {
    chunks: Vec<Bytes>,
    len: usize,
}

impl AssembledPayload {
    pub fn chunks(&self) -> &[Bytes] {
        &self.chunks
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Fail-open pass-through: forward the original buffer unchanged as one
    /// refcounted chunk. Used when assembly errors — over-deliver the original
    /// rather than lose data (`core/05` §3.4).
    pub fn passthrough(raw: Bytes) -> Self {
        let len = raw.len();
        Self {
            chunks: vec![raw],
            len,
        }
    }

    /// Contiguous copy — the documented exception of `core/02` §3.2, only for
    /// destinations that strictly require a single buffer (and for byte-exact
    /// comparisons in tests). Not the default path.
    pub fn contiguous(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.len);
        for c in &self.chunks {
            out.extend_from_slice(c);
        }
        out
    }
}

/// Assemble the governed request. Fast path: with no drops and no redactions
/// the output is `raw` itself (one refcounted chunk, zero work).
pub fn assemble(env: &Envelope, masks: &MaskTable) -> Result<AssembledPayload, AssembleError> {
    if !env.decisions.any_dropped() && env.decisions.redaction_total() == 0 {
        return Ok(AssembledPayload {
            chunks: vec![env.raw.slice(..)],
            len: env.raw.len(),
        });
    }

    let mut rec_idx = 0usize;
    let segs = build_request(&env.raw, env, masks, &mut rec_idx)?;
    if rec_idx != env.records.len() {
        return Err(AssembleError::RecordCountMismatch {
            parsed: env.records.len(),
            walked: rec_idx,
        });
    }

    let mut asm = Assembler::new(&env.raw);
    emit_segs(&mut asm, &segs, masks)?;
    Ok(asm.finish())
}

// ---------------------------------------------------------------------------
// Segment tree: sizes are computed at build time (bottom-up), emission then
// writes headers with the new lengths and splices raw slices with masks.

#[derive(Debug)]
enum Part {
    Raw(Range<usize>),
    Mask(MaskId),
}

#[derive(Debug)]
enum Seg {
    /// Bytes copied verbatim from `raw`, including their own field headers.
    Verbatim(Range<usize>),
    /// A message field whose payload changed → new length prefix.
    Nested {
        field: u32,
        size: usize,
        segs: Vec<Seg>,
    },
    /// A length-delimited scalar (string) with mask splices.
    Scalar {
        field: u32,
        size: usize,
        parts: Vec<Part>,
    },
}

fn varint_len(v: u64) -> usize {
    (64 - (v | 1).leading_zeros() as usize).div_ceil(7)
}

fn header_len(field: u32, size: usize) -> usize {
    varint_len(u64::from(field) << 3 | 2) + varint_len(size as u64)
}

fn seg_encoded_len(seg: &Seg) -> usize {
    match seg {
        Seg::Verbatim(r) => r.len(),
        Seg::Nested { field, size, .. } | Seg::Scalar { field, size, .. } => {
            header_len(*field, *size) + size
        }
    }
}

fn segs_encoded_len(segs: &[Seg]) -> usize {
    segs.iter().map(seg_encoded_len).sum()
}

/// What became of a child message during the walk.
enum Child {
    /// No change — leave it inside the parent's verbatim run.
    Unchanged,
    /// Sampled out — omit it entirely.
    Dropped,
    /// Content changed — re-emit with recomputed lengths.
    Rebuilt(Vec<Seg>),
}

/// Redaction spans inside `window`, sorted, overlap-resolved (first match
/// wins — deterministic across the fleet).
fn effective_spans(
    env: &Envelope,
    idx: usize,
    window: &Range<usize>,
) -> SmallVec<[(Range<usize>, MaskId); 4]> {
    let mut spans: SmallVec<[(Range<usize>, MaskId); 4]> = env
        .decisions
        .redactions_for(idx)
        .filter(|r| r.target.start >= window.start && r.target.end <= window.end)
        .map(|r| (r.target.start..r.target.end, r.mask))
        .collect();
    spans.sort_by_key(|(r, _)| (r.start, r.end));

    let mut out = SmallVec::new();
    let mut cursor = window.start;
    for (r, m) in spans {
        if r.start < cursor {
            continue; // overlaps an earlier span — first match wins
        }
        cursor = r.end;
        out.push((r, m));
    }
    out
}

/// Spliced scalar for a string window, or `None` when no spans touch it.
fn build_scalar(
    field: u32,
    window: &Range<usize>,
    idx: usize,
    env: &Envelope,
    masks: &MaskTable,
) -> Result<Option<Seg>, AssembleError> {
    let spans = effective_spans(env, idx, window);
    if spans.is_empty() {
        return Ok(None);
    }
    let mut parts = Vec::with_capacity(spans.len() * 2 + 1);
    let mut size = 0usize;
    let mut cursor = window.start;
    for (r, m) in spans {
        if r.start > cursor {
            size += r.start - cursor;
            parts.push(Part::Raw(cursor..r.start));
        }
        size += masks.bytes(m).ok_or(AssembleError::UnknownMask(m.0))?.len();
        parts.push(Part::Mask(m));
        cursor = r.end;
    }
    if cursor < window.end {
        size += window.end - cursor;
        parts.push(Part::Raw(cursor..window.end));
    }
    Ok(Some(Seg::Scalar { field, size, parts }))
}

/// AnyValue: rewrite its `string_value` (field 1) if spans touch it.
fn build_any_value(
    buf: &[u8],
    window: Range<usize>,
    idx: usize,
    env: &Envelope,
    masks: &MaskTable,
) -> Result<Child, AssembleError> {
    let mut cur = WireCursor::new(buf, window.start..window.end);
    let mut segs = Vec::new();
    let mut run = window.start;
    let mut changed = false;

    while !cur.done() {
        let tag_start = cur.pos();
        let (field, wire) = cur.tag()?;
        if field == 1 && wire == 2 {
            let s = cur.len_range()?;
            if let Some(scalar) = build_scalar(1, &s, idx, env, masks)? {
                if tag_start > run {
                    segs.push(Seg::Verbatim(run..tag_start));
                }
                segs.push(scalar);
                run = cur.pos();
                changed = true;
            }
        } else {
            cur.skip(wire)?;
        }
    }
    if !changed {
        return Ok(Child::Unchanged);
    }
    if run < window.end {
        segs.push(Seg::Verbatim(run..window.end));
    }
    Ok(Child::Rebuilt(segs))
}

/// KeyValue: key stays verbatim; the value AnyValue may be rewritten.
fn build_key_value(
    buf: &[u8],
    window: Range<usize>,
    idx: usize,
    env: &Envelope,
    masks: &MaskTable,
) -> Result<Child, AssembleError> {
    let mut cur = WireCursor::new(buf, window.start..window.end);
    let mut segs = Vec::new();
    let mut run = window.start;
    let mut changed = false;

    while !cur.done() {
        let tag_start = cur.pos();
        let (field, wire) = cur.tag()?;
        if field == 2 && wire == 2 {
            let av = cur.len_range()?;
            if let Child::Rebuilt(inner) = build_any_value(buf, av, idx, env, masks)? {
                if tag_start > run {
                    segs.push(Seg::Verbatim(run..tag_start));
                }
                let size = segs_encoded_len(&inner);
                segs.push(Seg::Nested {
                    field: 2,
                    size,
                    segs: inner,
                });
                run = cur.pos();
                changed = true;
            }
        } else {
            cur.skip(wire)?;
        }
    }
    if !changed {
        return Ok(Child::Unchanged);
    }
    if run < window.end {
        segs.push(Seg::Verbatim(run..window.end));
    }
    Ok(Child::Rebuilt(segs))
}

/// LogRecord: dropped entirely, or body (5) / attributes (6) rewritten.
fn build_record(
    buf: &[u8],
    window: Range<usize>,
    idx: usize,
    env: &Envelope,
    masks: &MaskTable,
) -> Result<Child, AssembleError> {
    if env.decisions.sampling_verdict(idx) == SampleVerdict::Drop {
        return Ok(Child::Dropped);
    }

    let mut cur = WireCursor::new(buf, window.start..window.end);
    let mut segs = Vec::new();
    let mut run = window.start;
    let mut changed = false;

    while !cur.done() {
        let tag_start = cur.pos();
        let (field, wire) = cur.tag()?;
        let child = match (field, wire) {
            (5, 2) | (6, 2) => {
                let w = cur.len_range()?;
                if field == 5 {
                    build_any_value(buf, w, idx, env, masks)?
                } else {
                    build_key_value(buf, w, idx, env, masks)?
                }
            }
            _ => {
                cur.skip(wire)?;
                Child::Unchanged
            }
        };
        if let Child::Rebuilt(inner) = child {
            if tag_start > run {
                segs.push(Seg::Verbatim(run..tag_start));
            }
            let size = segs_encoded_len(&inner);
            segs.push(Seg::Nested {
                field,
                size,
                segs: inner,
            });
            run = cur.pos();
            changed = true;
        }
    }
    if !changed {
        return Ok(Child::Unchanged);
    }
    if run < window.end {
        segs.push(Seg::Verbatim(run..window.end));
    }
    Ok(Child::Rebuilt(segs))
}

/// ScopeLogs / ResourceLogs / request: one generic walk — `field` selects the
/// repeated child, `build` produces it, record index advances per LogRecord.
fn build_container(
    buf: &[u8],
    window: Range<usize>,
    child_field: u32,
    env: &Envelope,
    masks: &MaskTable,
    rec_idx: &mut usize,
    level: Level,
) -> Result<Child, AssembleError> {
    let mut cur = WireCursor::new(buf, window.start..window.end);
    let mut segs = Vec::new();
    let mut run = window.start;
    let mut changed = false;

    while !cur.done() {
        let tag_start = cur.pos();
        let (field, wire) = cur.tag()?;
        if field == child_field && wire == 2 {
            let w = cur.len_range()?;
            let child = match level {
                Level::Scope => {
                    let idx = *rec_idx;
                    *rec_idx += 1;
                    build_record(buf, w, idx, env, masks)?
                }
                Level::Resource => build_container(buf, w, 2, env, masks, rec_idx, Level::Scope)?,
                Level::Request => build_container(buf, w, 2, env, masks, rec_idx, Level::Resource)?,
            };
            match child {
                Child::Unchanged => {}
                Child::Dropped => {
                    if tag_start > run {
                        segs.push(Seg::Verbatim(run..tag_start));
                    }
                    run = cur.pos();
                    changed = true;
                }
                Child::Rebuilt(inner) => {
                    if tag_start > run {
                        segs.push(Seg::Verbatim(run..tag_start));
                    }
                    let size = segs_encoded_len(&inner);
                    segs.push(Seg::Nested {
                        field: child_field,
                        size,
                        segs: inner,
                    });
                    run = cur.pos();
                    changed = true;
                }
            }
        } else {
            cur.skip(wire)?;
        }
    }
    if !changed {
        return Ok(Child::Unchanged);
    }
    if run < window.end {
        segs.push(Seg::Verbatim(run..window.end));
    }
    Ok(Child::Rebuilt(segs))
}

#[derive(Clone, Copy)]
enum Level {
    Request,
    Resource,
    Scope,
}

fn build_request(
    buf: &[u8],
    env: &Envelope,
    masks: &MaskTable,
    rec_idx: &mut usize,
) -> Result<Vec<Seg>, AssembleError> {
    // The request itself has no length prefix — its "window" is the buffer.
    match build_container(buf, 0..buf.len(), 1, env, masks, rec_idx, Level::Request)? {
        Child::Rebuilt(segs) => Ok(segs),
        // Unchanged despite decisions: all spans/drops resolved to nothing
        // visible (e.g. drops of records that no longer parse) — emit as-is.
        Child::Unchanged | Child::Dropped => Ok(vec![Seg::Verbatim(0..buf.len())]),
    }
}

// ---------------------------------------------------------------------------
// Emission

struct Assembler<'a> {
    raw: &'a Bytes,
    chunks: Vec<Bytes>,
    scratch: BytesMut,
    len: usize,
}

impl<'a> Assembler<'a> {
    fn new(raw: &'a Bytes) -> Self {
        Self {
            raw,
            chunks: Vec::new(),
            scratch: BytesMut::new(),
            len: 0,
        }
    }

    fn flush_scratch(&mut self) {
        if !self.scratch.is_empty() {
            self.chunks.push(self.scratch.split().freeze());
        }
    }

    /// Payload content: a refcounted view of `raw`, never a copy.
    fn push_raw(&mut self, r: Range<usize>) {
        if r.is_empty() {
            return;
        }
        self.len += r.len();
        self.flush_scratch();
        self.chunks.push(self.raw.slice(r));
    }

    /// Structural bytes (tags, recomputed length prefixes): tiny, coalesced.
    fn push_header(&mut self, field: u32, size: usize) {
        put_varint(u64::from(field) << 3 | 2, &mut self.scratch);
        put_varint(size as u64, &mut self.scratch);
        self.len += header_len(field, size);
    }

    fn push_mask(&mut self, mask: &Bytes) {
        self.len += mask.len();
        self.flush_scratch();
        self.chunks.push(Bytes::clone(mask));
    }

    fn finish(mut self) -> AssembledPayload {
        self.flush_scratch();
        AssembledPayload {
            chunks: self.chunks,
            len: self.len,
        }
    }
}

fn put_varint(mut v: u64, out: &mut BytesMut) {
    loop {
        let b = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.put_u8(b);
            break;
        }
        out.put_u8(b | 0x80);
    }
}

fn emit_segs(asm: &mut Assembler, segs: &[Seg], masks: &MaskTable) -> Result<(), AssembleError> {
    for seg in segs {
        match seg {
            Seg::Verbatim(r) => asm.push_raw(r.start..r.end),
            Seg::Nested { field, size, segs } => {
                asm.push_header(*field, *size);
                emit_segs(asm, segs, masks)?;
            }
            Seg::Scalar { field, size, parts } => {
                asm.push_header(*field, *size);
                for part in parts {
                    match part {
                        Part::Raw(r) => asm.push_raw(r.start..r.end),
                        Part::Mask(m) => {
                            let mask = masks.bytes(*m).ok_or(AssembleError::UnknownMask(m.0))?;
                            // SAFETY-PERF: Bytes::clone is a refcount bump
                            // (core/02 §3.3), not a payload copy.
                            asm.push_mask(mask);
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::varint_len;

    #[test]
    fn varint_len_matches_encoding() {
        for v in [
            0u64,
            1,
            127,
            128,
            16_383,
            16_384,
            u64::from(u32::MAX),
            u64::MAX,
        ] {
            let mut buf = bytes::BytesMut::new();
            super::put_varint(v, &mut buf);
            assert_eq!(varint_len(v), buf.len(), "v={v}");
        }
    }
}
