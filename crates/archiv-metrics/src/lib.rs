//! `archiv-metrics` — the agent's numbers-only aggregation core
//! (`docs/architecture/core/06-agent-metrics.md`).
//!
//! Per-request [`Sample`]s are folded into lock-free [`WindowCounters`] on the
//! payload hot path (relaxed `AtomicU64` adds — no lock, no allocation). Every
//! 10 s ([`FLUSH_INTERVAL`]) the binary calls [`Metrics::flush`], which
//! atomically **drains** the window into an [`Aggregate`] snapshot — the exact
//! numeric surface PRD §6.2 allows off the node.
//!
//! # Privacy boundary (`core/06` §2, NORMATIVE)
//! Every field here is a number, timestamp, or id. Record bodies, attribute
//! values, and attribute keys are **categorically absent** — they cannot even
//! be represented. Adding a payload-derived string is a security-boundary
//! change requiring a compliance entry.
//!
//! This crate is edition-neutral and dependency-light (no tokio, no clock
//! reads): the caller supplies wall-clock timestamps at flush, keeping the core
//! deterministically testable. The Enterprise build (`enterprise/04`) reuses
//! these snapshots behind a durable journal + `PushAggregates` gRPC sink; the
//! Open_Source  build logs them to stdout.

#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::Serialize;

/// Fixed tumbling-window length. **A constant, never a per-policy knob**
/// (`core/06` §2 / `enterprise/04` §4 — billing math and UI cadence assume it).
pub const FLUSH_INTERVAL: Duration = Duration::from_secs(FLUSH_INTERVAL_SECS);

/// [`FLUSH_INTERVAL`] in whole seconds.
pub const FLUSH_INTERVAL_SECS: u64 = 10;

/// One request's numeric outcome, mapped from `pipeline::Stats` by the binary.
///
/// Numbers only — this type is the choke point that keeps payload content out
/// of aggregates by construction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Sample {
    /// Records parsed from the request (`Stats::records_in`).
    pub events_in: u64,
    /// Records dropped by sampling (`Stats::dropped`).
    pub events_sampled_out: u64,
    /// Records that survived sampling (`Stats::kept`).
    pub events_exported: u64,
    /// Received OTLP request size (`Stats::bytes_in`).
    pub bytes_in: u64,
    /// Governed output size (`Stats::bytes_out`).
    pub bytes_exported: u64,
    /// Redaction spans applied (`Stats::redactions`).
    pub redaction_count: u64,
    /// A **governance** stage (redact/assemble) bypassed via fail-open.
    /// Parse-bypass on malformed input is a client error, not counted here.
    pub failed_open: bool,
}

impl Sample {
    /// Wire-size saved on this request — the ROI/billing input
    /// (`bytes_in - bytes_exported`, saturating).
    #[must_use]
    pub fn bytes_dropped(&self) -> u64 {
        self.bytes_in.saturating_sub(self.bytes_exported)
    }
}

/// Lock-free, allocation-free accumulator for the in-flight window.
///
/// Safe to share across any number of request tasks; [`record`](Self::record)
/// never blocks and never allocates.
#[derive(Debug, Default)]
struct WindowCounters {
    events_in: AtomicU64,
    events_sampled_out: AtomicU64,
    events_exported: AtomicU64,
    bytes_in: AtomicU64,
    bytes_dropped: AtomicU64,
    bytes_exported: AtomicU64,
    redaction_count: AtomicU64,
    failopen_count: AtomicU64,
}

impl WindowCounters {
    #[inline]
    fn record(&self, s: &Sample) {
        self.events_in.fetch_add(s.events_in, Ordering::Relaxed);
        self.events_sampled_out
            .fetch_add(s.events_sampled_out, Ordering::Relaxed);
        self.events_exported
            .fetch_add(s.events_exported, Ordering::Relaxed);
        self.bytes_in.fetch_add(s.bytes_in, Ordering::Relaxed);
        self.bytes_dropped
            .fetch_add(s.bytes_dropped(), Ordering::Relaxed);
        self.bytes_exported
            .fetch_add(s.bytes_exported, Ordering::Relaxed);
        self.redaction_count
            .fetch_add(s.redaction_count, Ordering::Relaxed);
        self.failopen_count
            .fetch_add(u64::from(s.failed_open), Ordering::Relaxed);
    }

    /// Atomically read-and-reset every counter — makes windows tumbling.
    fn drain(&self) -> DrainedCounts {
        DrainedCounts {
            events_in: self.events_in.swap(0, Ordering::Relaxed),
            events_sampled_out: self.events_sampled_out.swap(0, Ordering::Relaxed),
            events_exported: self.events_exported.swap(0, Ordering::Relaxed),
            bytes_in: self.bytes_in.swap(0, Ordering::Relaxed),
            bytes_dropped: self.bytes_dropped.swap(0, Ordering::Relaxed),
            bytes_exported: self.bytes_exported.swap(0, Ordering::Relaxed),
            redaction_count: self.redaction_count.swap(0, Ordering::Relaxed),
            failopen_count: self.failopen_count.swap(0, Ordering::Relaxed),
        }
    }
}

struct DrainedCounts {
    events_in: u64,
    events_sampled_out: u64,
    events_exported: u64,
    bytes_in: u64,
    bytes_dropped: u64,
    bytes_exported: u64,
    redaction_count: u64,
    failopen_count: u64,
}

/// A drained 10 s window — the numbers-only snapshot emitted off the node.
///
/// Field names and meanings match `enterprise/04` §3.1 so the Enterprise flush
/// adopts them unchanged. Open_Source  v1 omits the per-namespace split.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Aggregate {
    /// Per-agent monotonic flush counter (0-based).
    pub seq: u64,
    /// Wall-clock window bounds (ms since epoch), supplied by the caller.
    pub window_start_ms: i64,
    pub window_end_ms: i64,
    /// Active governance-policy generation, supplied by the caller (Open_Source :
    /// the `AgentConfig::policy_fingerprint`, `core/06` §3.1).
    pub policy_version: u64,
    pub events_in: u64,
    pub events_sampled_out: u64,
    pub events_exported: u64,
    pub bytes_in: u64,
    pub bytes_dropped: u64,
    pub bytes_exported: u64,
    pub redaction_count: u64,
    pub failopen_count: u64,
}

impl std::fmt::Display for Aggregate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "seq={} window=[{},{}] policy_version={} events_in={} sampled_out={} \
             exported={} bytes_in={} bytes_dropped={} bytes_exported={} redactions={} \
             failopen={}",
            self.seq,
            self.window_start_ms,
            self.window_end_ms,
            self.policy_version,
            self.events_in,
            self.events_sampled_out,
            self.events_exported,
            self.bytes_in,
            self.bytes_dropped,
            self.bytes_exported,
            self.redaction_count,
            self.failopen_count,
        )
    }
}

/// The agent's live metrics register: shared (`Arc`) across all request tasks
/// and the flush task. Cheap and lock-free.
#[derive(Debug)]
pub struct Metrics {
    counters: WindowCounters,
    seq: AtomicU64,
    policy_version: u64,
}

impl Metrics {
    /// New register for the given policy generation (the Open_Source  binary passes
    /// `AgentConfig::policy_fingerprint`; tests may pass `0`).
    #[must_use]
    pub fn new(policy_version: u64) -> Self {
        Self {
            counters: WindowCounters::default(),
            seq: AtomicU64::new(0),
            policy_version,
        }
    }

    /// Fold one request outcome into the current window. Hot path: lock-free,
    /// allocation-free.
    #[inline]
    pub fn record(&self, sample: &Sample) {
        self.counters.record(sample);
    }

    /// Close the current window: atomically drain the counters into an
    /// [`Aggregate`] stamped with the caller's wall-clock bounds and the next
    /// `seq`. A window with no traffic still yields an all-zero aggregate, so
    /// the series has no gaps.
    pub fn flush(&self, window_start_ms: i64, window_end_ms: i64) -> Aggregate {
        let d = self.counters.drain();
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        Aggregate {
            seq,
            window_start_ms,
            window_end_ms,
            policy_version: self.policy_version,
            events_in: d.events_in,
            events_sampled_out: d.events_sampled_out,
            events_exported: d.events_exported,
            bytes_in: d.bytes_in,
            bytes_dropped: d.bytes_dropped,
            bytes_exported: d.bytes_exported,
            redaction_count: d.redaction_count,
            failopen_count: d.failopen_count,
        }
    }
}

/// A destination for drained [`Aggregate`]s. The flush driver delivers each
/// window through a `Sink`, decoupling *what was measured* from *where it goes*
/// — the seam the editions boundary runs along (`core/06` §3.3, `CLAUDE.md` §3):
///
/// - **Open_Source **: the binary's `StdoutSink` logs numbers to stdout.
/// - **Enterprise**: a durable sink records each window and ships it to a
///   Control Plane. This Open_Source  agent links none of it.
///
/// A delivery failure must never disturb telemetry — the driver logs it and
/// continues; metrics are not on the fail-open payload path.
pub trait Sink {
    fn deliver(&self, aggregate: &Aggregate) -> Result<(), SinkError>;
}

/// Why an [`Aggregate`] could not be delivered by a [`Sink`].
#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    /// The Enterprise flush path is not built in this edition/loop.
    #[error("aggregate sink not implemented in this build")]
    Unimplemented,
    /// A sink-specific delivery failure (network, journal I/O, …).
    #[error("aggregate delivery failed: {0}")]
    Delivery(String),
}

// This crate stays edition-neutral: it defines the `Sink` trait and the
// Open_Source  `StdoutSink` seam; it does not embed any Control-Plane sink.

#[cfg(test)]
mod tests {
    use super::*;

    /// A `Sink` that captures delivered aggregates — proves the trait is usable
    /// and exercises the delivery path the binary's `StdoutSink` follows.
    #[derive(Default)]
    struct CollectSink(std::sync::Mutex<Vec<Aggregate>>);

    impl Sink for CollectSink {
        fn deliver(&self, aggregate: &Aggregate) -> Result<(), SinkError> {
            self.0.lock().expect("lock").push(*aggregate);
            Ok(())
        }
    }

    #[test]
    fn sink_receives_flushed_aggregate() {
        let m = Metrics::new(0);
        m.record(&sample(4, 1, 40, 30));
        let sink = CollectSink::default();
        sink.deliver(&m.flush(0, 10_000)).expect("deliver");

        let got = sink.0.lock().expect("lock");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].events_in, 4);
        assert_eq!(got[0].bytes_dropped, 10);
    }

    fn sample(events_in: u64, dropped: u64, bytes_in: u64, bytes_out: u64) -> Sample {
        Sample {
            events_in,
            events_sampled_out: dropped,
            events_exported: events_in - dropped,
            bytes_in,
            bytes_exported: bytes_out,
            redaction_count: 0,
            failed_open: false,
        }
    }

    #[test]
    fn flush_sums_inputs_then_resets() {
        let m = Metrics::new(0);
        m.record(&sample(10, 4, 1000, 600));
        m.record(&sample(5, 1, 500, 500));

        let agg = m.flush(100, 10_100);
        assert_eq!(agg.seq, 0);
        assert_eq!(agg.window_start_ms, 100);
        assert_eq!(agg.window_end_ms, 10_100);
        assert_eq!(agg.events_in, 15);
        assert_eq!(agg.events_sampled_out, 5);
        assert_eq!(agg.events_exported, 10);
        assert_eq!(agg.bytes_in, 1500);
        assert_eq!(agg.bytes_exported, 1100);
        assert_eq!(agg.bytes_dropped, 400); // (1000-600) + (500-500)

        // Tumbling: an immediate second flush is all zeros, and seq advances.
        let empty = m.flush(10_100, 20_100);
        assert_eq!(empty.seq, 1);
        assert_eq!(empty.events_in, 0);
        assert_eq!(empty.bytes_dropped, 0);
    }

    #[test]
    fn failopen_counts_only_governance_bypass() {
        let m = Metrics::new(0);
        let mut s = sample(1, 0, 10, 10);
        s.failed_open = true;
        m.record(&s);
        m.record(&sample(1, 0, 10, 10)); // clean request
        assert_eq!(m.flush(0, 10_000).failopen_count, 1);
    }

    #[test]
    fn bytes_dropped_saturates_when_output_grew() {
        // Redaction masks can make output larger than input; savings floor at 0.
        let s = Sample {
            bytes_in: 100,
            bytes_exported: 130,
            ..Sample::default()
        };
        assert_eq!(s.bytes_dropped(), 0);
    }

    #[test]
    fn concurrent_records_lose_no_increment() {
        use std::sync::Arc;
        use std::thread;

        let m = Arc::new(Metrics::new(0));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let m = Arc::clone(&m);
                thread::spawn(move || {
                    for _ in 0..10_000 {
                        m.record(&sample(2, 1, 20, 12));
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().expect("thread panicked");
        }

        let agg = m.flush(0, 10_000);
        assert_eq!(agg.events_in, 8 * 10_000 * 2);
        assert_eq!(agg.events_sampled_out, 8 * 10_000);
        assert_eq!(agg.bytes_dropped, 8 * 10_000 * 8); // (20-12) per record
    }

    #[test]
    fn display_and_json_are_numbers_only() {
        let agg = Metrics::new(3).flush(1, 2);
        let line = agg.to_string();
        assert!(line.contains("policy_version=3"));
        assert!(line.contains("bytes_dropped=0"));

        let json = serde_json::to_string(&agg).expect("serialize");
        // Sanity: the serialized shape is flat numbers, no nested payload.
        assert!(json.contains("\"bytes_dropped\":0"));
        assert!(!json.contains("body"));
    }
}
