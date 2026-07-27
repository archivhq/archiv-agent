//! `archiv-agent` library — the composition root.
//!
//! The stage crates (`archiv-ingest`, `archiv-sampling`, `archiv-redact`,
//! `archiv-export`) each own one job and depend only on `archiv-pipeline`'s
//! core types. This crate is the one place they are wired together into the
//! fixed pipeline (`docs/architecture/core/01` §3.4):
//!
//! ```text
//! ingest → parse(view) → sample → redact → export(assemble)
//! ```
//!
//! `main.rs` builds a [`pipeline::Pipeline`] from config and feeds it OTLP bytes
//! from the HTTP and gRPC receivers. Keeping the orchestrator in a library makes
//! the whole engine testable without network I/O.

#![forbid(unsafe_code)]

pub mod breaker;
pub mod forward;
pub mod grpc;
pub mod metrics;
pub mod pipeline;
pub mod server;
pub mod spool;
