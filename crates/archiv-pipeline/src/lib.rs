//! Zero-copy pipeline core for `archiv-agent`.
//!
//! Implements `docs/architecture/core/02-zero-copy-pipeline.md` (the memory
//! law: one `Bytes` buffer per request, all structure as range views) and
//! `docs/architecture/core/05-fail-open-resiliency.md` (the guard: a failing
//! stage is bypassed, never fatal — the original payload is always exportable).

#![forbid(unsafe_code)]

pub mod envelope;
pub mod guard;

pub use envelope::{
    AttrView, Decisions, Envelope, MaskId, RecordView, Redaction, STAGE_SAMPLE, SampleVerdict,
};
pub use guard::{BypassReason, Stage, StageError, StageId, StageOutcome, guarded};
