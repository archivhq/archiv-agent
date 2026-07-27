//! OTLP ingest for `archiv-agent` (`docs/architecture/core/01` §2, §3.4).
//!
//! This crate owns the `parse(view)` stage: turning a raw OTLP
//! `ExportLogsServiceRequest` buffer into `RecordView` offsets — **zero
//! payload copies** (`core/02` §3.1). A generated protobuf decoder (prost)
//! would materialize owned `String`/`Vec` values and violate the Memory Law,
//! so the walker here is hand-rolled and emits only `Range<usize>` views
//! into `Envelope::raw`.
//!
//! The parent `archiv-agent` crate's gRPC/HTTP receivers (`:4317`/`:4318`) read
//! each request body into one `Bytes` and hand it to `ParseStage` through the
//! bounded worker pool.
//!
//! Fail-open shape: a malformed payload yields a `Bypassed` stage outcome and
//! an envelope with **zero records** — downstream transforms no-op and the
//! exporter forwards `raw` untouched. Garbage in, same garbage out, nothing
//! lost (`core/05` §3.1).

#![forbid(unsafe_code)]

pub mod otlp;

use archiv_pipeline::{Envelope, Stage, StageError, StageId};
use smallvec::SmallVec;

pub use otlp::{ParseError, parse_export_logs_request};

/// Stage id for the view parser; bypass counter label (`core/05` §3.2).
pub const STAGE_PARSE: StageId = StageId("parse");

/// The `parse(view)` pipeline stage (`core/01` §3.4).
#[derive(Debug, Default)]
pub struct ParseStage;

impl Stage for ParseStage {
    fn id(&self) -> StageId {
        STAGE_PARSE
    }

    fn apply(&self, env: &mut Envelope) -> Result<(), StageError> {
        let mut records = SmallVec::new();
        match otlp::parse_export_logs_request(&env.raw, &mut records) {
            Ok(()) => {
                env.records = records;
                Ok(())
            }
            // Offset detail stays in tracing (later loop); errors never carry
            // payload bytes (docs/engineering/02 §7).
            Err(_) => Err(StageError::Internal("malformed OTLP logs payload")),
        }
    }
}
