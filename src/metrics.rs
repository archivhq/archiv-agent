//! The agent-side driver for `archiv-metrics` (`docs/architecture/core/06`).
//!
//! The `archiv-metrics` crate is pure and clock-free; this module supplies the
//! two things it deliberately does not: the tokio 10 s cadence and the wall
//! clock. Every [`FLUSH_INTERVAL`] it drains the window and hands the
//! numbers-only [`Aggregate`] to a [`Sink`].
//!
//! [`StdoutSink`] is the Community sink — it logs numbers to stdout via
//! `tracing` (`CLAUDE.md` §3 auditability). The Enterprise edition supplies its
//! own durable sink that ships aggregates to a Control Plane; this Community
//! agent links none of it.

use std::future::Future;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use archiv_metrics::{Aggregate, FLUSH_INTERVAL, Metrics, Sink, SinkError};

/// Milliseconds since the Unix epoch (0 if the clock is before the epoch).
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Community aggregate sink: one numbers-only `tracing` line per window on
/// `target: "archiv.metrics"`. No payload can appear — every field is a number.
pub struct StdoutSink;

impl Sink for StdoutSink {
    fn deliver(&self, agg: &Aggregate) -> Result<(), SinkError> {
        tracing::info!(
            target: "archiv.metrics",
            seq = agg.seq,
            window_start_ms = agg.window_start_ms,
            window_end_ms = agg.window_end_ms,
            policy_version = agg.policy_version,
            events_in = agg.events_in,
            events_sampled_out = agg.events_sampled_out,
            events_exported = agg.events_exported,
            bytes_in = agg.bytes_in,
            bytes_dropped = agg.bytes_dropped,
            bytes_exported = agg.bytes_exported,
            redaction_count = agg.redaction_count,
            failopen_count = agg.failopen_count,
            "aggregate window"
        );
        Ok(())
    }
}

/// Deliver one window through the sink; a failure is logged and swallowed —
/// metrics delivery must never disturb telemetry (`core/06` §3.3).
fn deliver<S: Sink>(sink: &S, agg: &Aggregate) {
    if let Err(err) = sink.deliver(agg) {
        tracing::warn!(target: "archiv.metrics", error = %err, seq = agg.seq, "aggregate delivery failed");
    }
}

/// Flush every [`FLUSH_INTERVAL`] until `shutdown` resolves, then flush one
/// final aggregate so the last partial window is not lost.
pub async fn run_flush_loop<S: Sink>(
    metrics: Arc<Metrics>,
    sink: S,
    shutdown: impl Future<Output = ()>,
) {
    let mut ticker = tokio::time::interval(FLUSH_INTERVAL);
    // `interval` fires immediately on the first tick — swallow it so the first
    // emitted window actually covers a full interval of traffic.
    ticker.tick().await;
    let mut window_start = now_ms();

    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let window_end = now_ms();
                deliver(&sink, &metrics.flush(window_start, window_end));
                window_start = window_end;
            }
            _ = &mut shutdown => {
                deliver(&sink, &metrics.flush(window_start, now_ms()));
                break;
            }
        }
    }
}
