//! The unit of work (`docs/architecture/core/01` §3.3, `core/02` §3).
//!
//! `raw` is the single owned copy of the request body. Everything else is a
//! `Range<usize>` view into it. Redaction never rewrites `raw`; engines emit
//! replacement spans and the exporter performs vectored assembly.

use bytes::Bytes;
use smallvec::SmallVec;
use std::ops::Range;
use std::time::Instant;

use crate::guard::StageId;

/// One parsed log record: offsets into `Envelope::raw`, never owned bytes.
///
/// Introducing an owned `String`/`Vec<u8>` field here is a design change that
/// requires updating `core/02` §4 and a data-handling compliance entry.
#[derive(Debug, Clone)]
pub struct RecordView {
    /// Slice of `raw` holding the record body.
    pub body: Range<usize>,
    /// Slice of `raw` holding the trace id: 16 binary bytes or 32 hex chars.
    pub trace_id: Option<Range<usize>>,
    /// Attribute key/value ranges into `raw`.
    pub attrs: SmallVec<[AttrView; 16]>,
    /// OTLP `SeverityNumber` (LogRecord field 2), if present — a sampling
    /// matcher input (`core/03` §3.3), not payload content.
    pub severity_number: Option<i32>,
    /// Slice of `raw` holding the k8s namespace (Resource attribute
    /// `k8s.namespace.name`), propagated to every record under that resource —
    /// a sampling matcher input.
    pub namespace: Option<Range<usize>>,
    /// Slice of `raw` holding the `service.name` Resource attribute, propagated
    /// to every record under that resource — the untraced sampling fallback key
    /// input (`core/03` §3.2), not payload content.
    pub service_name: Option<Range<usize>>,
}

#[derive(Debug, Clone)]
pub struct AttrView {
    pub key: Range<usize>,
    pub value: Range<usize>,
}

impl RecordView {
    /// Extract the trace id as a fixed 16-byte stack array (the sanctioned
    /// small copy, `core/02` §3.3), decoding hex if the transport delivered
    /// hex (`core/03` §3.1). Returns `None` when absent or malformed.
    pub fn trace_id_bytes(&self, raw: &Bytes) -> Option<[u8; 16]> {
        let range = self.trace_id.as_ref()?;
        let src = raw.get(range.start..range.end)?;
        match src.len() {
            16 => {
                let mut id = [0u8; 16];
                id.copy_from_slice(src);
                Some(id)
            }
            32 => decode_hex_16(src),
            _ => None,
        }
    }

    /// Namespace bytes (view into `raw`), for the sampling matcher.
    pub fn namespace_bytes<'a>(&self, raw: &'a Bytes) -> Option<&'a [u8]> {
        let r = self.namespace.as_ref()?;
        raw.get(r.start..r.end)
    }

    /// `service.name` bytes (view into `raw`), for the untraced fallback key.
    pub fn service_name_bytes<'a>(&self, raw: &'a Bytes) -> Option<&'a [u8]> {
        let r = self.service_name.as_ref()?;
        raw.get(r.start..r.end)
    }
}

/// Decode 32 hex chars into 16 bytes on the stack — no allocation.
fn decode_hex_16(hex: &[u8]) -> Option<[u8; 16]> {
    fn nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, pair) in hex.chunks_exact(2).enumerate() {
        out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

/// Index into the policy's mask table (e.g. `"[REDACTED:email]"`). Masks carry
/// type, not value — redacted content is never reconstructable (`core/04` §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaskId(pub u32);

/// A replacement span: mask `target` bytes of `raw` at export time
/// (`core/02` §3.2). `raw` itself is never mutated.
#[derive(Debug, Clone)]
pub struct Redaction {
    pub target: Range<usize>,
    pub mask: MaskId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleVerdict {
    Keep,
    Drop,
}

/// Additive, per-stage decisions. Fail-open bypass is literally
/// `clear_stage(id)` — discard that stage's spans and continue (`core/05` §3.1).
#[derive(Debug, Default)]
pub struct Decisions {
    /// Per-record sampling verdicts; empty = keep everything.
    sampling: SmallVec<[SampleVerdict; 8]>,
    redactions: Vec<StageRedaction>,
}

#[derive(Debug)]
struct StageRedaction {
    stage: StageId,
    record: usize,
    redaction: Redaction,
}

/// Well-known stage id for the sampling stage (used by `clear_stage`).
pub const STAGE_SAMPLE: StageId = StageId("sample");

impl Decisions {
    pub fn set_sampling(&mut self, verdicts: impl IntoIterator<Item = SampleVerdict>) {
        self.sampling.clear();
        self.sampling.extend(verdicts);
    }

    /// Verdict for record `idx`; unset means Keep (the fail-open direction,
    /// `core/05` §3.4).
    pub fn sampling_verdict(&self, idx: usize) -> SampleVerdict {
        self.sampling
            .get(idx)
            .copied()
            .unwrap_or(SampleVerdict::Keep)
    }

    pub fn push_redaction(&mut self, stage: StageId, record: usize, redaction: Redaction) {
        self.redactions.push(StageRedaction {
            stage,
            record,
            redaction,
        });
    }

    pub fn redactions_for(&self, record: usize) -> impl Iterator<Item = &Redaction> {
        self.redactions
            .iter()
            .filter(move |r| r.record == record)
            .map(|r| &r.redaction)
    }

    /// True when any record carries a Drop verdict — the exporter's fast
    /// identity path checks this together with [`Self::redaction_total`].
    pub fn any_dropped(&self) -> bool {
        self.sampling.contains(&SampleVerdict::Drop)
    }

    /// Total redaction spans across all records and stages.
    pub fn redaction_total(&self) -> usize {
        self.redactions.len()
    }

    /// Fail-open bypass: drop everything the failing stage contributed.
    pub fn clear_stage(&mut self, id: StageId) {
        self.redactions.retain(|r| r.stage != id);
        if id == STAGE_SAMPLE {
            self.sampling.clear();
        }
    }
}

/// The unit of work flowing through the pipeline (`core/01` §3.3).
#[derive(Debug)]
pub struct Envelope {
    /// Original OTLP payload — never mutated after ingest.
    pub raw: Bytes,
    /// Parsed views: offsets into `raw`.
    pub records: SmallVec<[RecordView; 8]>,
    /// Sampling verdicts and redaction spans, additive per stage.
    pub decisions: Decisions,
    pub received_at: Instant,
}

impl Envelope {
    pub fn new(raw: Bytes) -> Self {
        Self {
            raw,
            records: SmallVec::new(),
            decisions: Decisions::default(),
            received_at: Instant::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_id_binary_and_hex_agree() {
        // "00112233445566778899aabbccddeeff" as hex chars, then raw binary.
        let hex = b"00112233445566778899aabbccddeeff";
        let bin: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let mut buf = Vec::with_capacity(48);
        buf.extend_from_slice(hex);
        buf.extend_from_slice(&bin);
        let raw = Bytes::from(buf);

        let hex_view = RecordView {
            body: 0..0,
            trace_id: Some(0..32),
            attrs: SmallVec::new(),
            severity_number: None,
            namespace: None,
            service_name: None,
        };
        let bin_view = RecordView {
            body: 0..0,
            trace_id: Some(32..48),
            attrs: SmallVec::new(),
            severity_number: None,
            namespace: None,
            service_name: None,
        };
        assert_eq!(hex_view.trace_id_bytes(&raw), Some(bin));
        assert_eq!(bin_view.trace_id_bytes(&raw), Some(bin));
    }

    #[test]
    fn malformed_trace_id_is_none() {
        let raw = Bytes::from_static(b"zz112233445566778899aabbccddeeffXX");
        let view = RecordView {
            body: 0..0,
            trace_id: Some(0..32), // invalid hex chars
            attrs: SmallVec::new(),
            severity_number: None,
            namespace: None,
            service_name: None,
        };
        assert_eq!(view.trace_id_bytes(&raw), None);
    }

    #[test]
    fn clear_stage_removes_only_that_stage() {
        let mut d = Decisions::default();
        let redact = StageId("redact-regex");
        let wasm = StageId("redact-wasm");
        d.push_redaction(
            redact,
            0,
            Redaction {
                target: 0..4,
                mask: MaskId(1),
            },
        );
        d.push_redaction(
            wasm,
            0,
            Redaction {
                target: 5..9,
                mask: MaskId(2),
            },
        );
        d.set_sampling([SampleVerdict::Drop]);

        d.clear_stage(wasm);
        assert_eq!(d.redactions_for(0).count(), 1);
        assert_eq!(d.sampling_verdict(0), SampleVerdict::Drop);

        d.clear_stage(STAGE_SAMPLE);
        assert_eq!(d.sampling_verdict(0), SampleVerdict::Keep);
    }
}
