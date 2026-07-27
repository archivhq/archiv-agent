//! A minimal circuit breaker for the fail-open degradation ladder
//! (`docs/architecture/core/05` §3.2 row 2). After `threshold` faults within
//! `window`, it **opens** for `cooldown` — during which the guarded stage is
//! skipped (the fail-open direction: keep exporting) — then half-opens and
//! closes on the next allowed call.
//!
//! Time is injected (`*_at(now)`) so the policy is deterministically testable;
//! the pipeline passes `Instant::now()`. The lock is only ever held for the
//! short counter update — never across the guarded stage or a `catch_unwind`
//! (`core/05` §4), so it cannot poison from a stage panic.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A rolling-window fault breaker guarding one pipeline stage.
pub struct CircuitBreaker {
    threshold: u32,
    window: Duration,
    cooldown: Duration,
    inner: Mutex<Inner>,
}

struct Inner {
    window_start: Instant,
    faults: u32,
    opened_at: Option<Instant>,
}

impl CircuitBreaker {
    pub fn new(threshold: u32, window: Duration, cooldown: Duration) -> Self {
        Self {
            threshold: threshold.max(1),
            window,
            cooldown,
            inner: Mutex::new(Inner {
                window_start: Instant::now(),
                faults: 0,
                opened_at: None,
            }),
        }
    }

    /// `core/05` §3.2 defaults: 5 faults / 10 s, open for 30 s.
    pub fn with_defaults() -> Self {
        Self::new(5, Duration::from_secs(10), Duration::from_secs(30))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // The critical section is trivial counter math and cannot panic, so the
        // lock never actually poisons; recover defensively rather than unwrap.
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether the guarded stage should run at `now`. If the cooldown has
    /// elapsed while open, the breaker half-opens (state reset) and allows a
    /// trial run.
    pub fn allow_at(&self, now: Instant) -> bool {
        let mut g = self.lock();
        if let Some(opened) = g.opened_at {
            if now.saturating_duration_since(opened) < self.cooldown {
                return false;
            }
            g.opened_at = None;
            g.faults = 0;
            g.window_start = now;
        }
        true
    }

    /// Record one stage fault at `now`. Returns `true` iff this fault tripped
    /// the breaker open (so the caller can log the transition exactly once).
    pub fn record_fault_at(&self, now: Instant) -> bool {
        let mut g = self.lock();
        if now.saturating_duration_since(g.window_start) > self.window {
            g.window_start = now;
            g.faults = 0;
        }
        g.faults += 1;
        if g.faults >= self.threshold && g.opened_at.is_none() {
            g.opened_at = Some(now);
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trips_after_threshold_within_window() {
        let b = CircuitBreaker::new(3, Duration::from_secs(10), Duration::from_secs(30));
        let t0 = Instant::now();
        assert!(b.allow_at(t0));
        assert!(!b.record_fault_at(t0));
        assert!(!b.record_fault_at(t0));
        assert!(b.record_fault_at(t0), "3rd fault trips the breaker");
        assert!(!b.allow_at(t0), "open → stage is skipped");
    }

    #[test]
    fn faults_outside_window_do_not_accumulate() {
        let b = CircuitBreaker::new(3, Duration::from_secs(10), Duration::from_secs(30));
        let t0 = Instant::now();
        b.record_fault_at(t0);
        b.record_fault_at(t0);
        // 11 s later → a fresh window; the count resets, so one fault is benign.
        let t1 = t0 + Duration::from_secs(11);
        assert!(!b.record_fault_at(t1));
        assert!(b.allow_at(t1), "still closed");
    }

    #[test]
    fn closes_after_cooldown_and_can_retrip() {
        let b = CircuitBreaker::new(2, Duration::from_secs(10), Duration::from_secs(30));
        let t0 = Instant::now();
        b.record_fault_at(t0);
        assert!(b.record_fault_at(t0), "trips");
        assert!(!b.allow_at(t0), "open");

        let t1 = t0 + Duration::from_secs(31); // cooldown elapsed
        assert!(b.allow_at(t1), "half-open trial allowed");

        b.record_fault_at(t1);
        assert!(b.record_fault_at(t1), "re-trips after re-closing");
        assert!(!b.allow_at(t1));
    }
}
