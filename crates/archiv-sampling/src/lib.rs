//! Deterministic sampling engine (`docs/architecture/core/03`) [NORMATIVE].
//!
//! Every agent in the fleet reaches the same keep/drop decision for the same
//! `trace_id` with no coordination, so distributed traces are never broken.
//!
//! The function, seed, and modulus are **frozen** (`core/03` §3.1). Changing
//! any of them is a breaking fleet event requiring a new `algo_version`, a
//! migration plan in the doc, and a compliance entry (data-handling +
//! billing-metrics). The Go and TS reimplementations are pinned to this one
//! via `proto/testdata/sampling_vectors.json` (regenerate with the
//! `gen_vectors` example).

#![forbid(unsafe_code)]

pub mod policy;

use xxhash_rust::xxh64::{Xxh64, xxh64};

/// Frozen algorithm version; travels with policy and billing statements.
pub const ALGO_VERSION: u32 = 1;

/// Frozen seed. Never change (see module docs).
pub const SEED: u64 = 0;

/// The decision rule [NORMATIVE, `core/03` §3.1]: keep iff
/// `xxHash64(trace_id, 0) % 100 < target_pct`.
///
/// `trace_id` is the raw 16-byte binary id (decode hex at parse time,
/// `archiv-pipeline::RecordView::trace_id_bytes`). `target_pct` is percent
/// kept; 100 = sampling disabled, 0 = drop everything.
#[inline]
pub fn keep(trace_id: &[u8; 16], target_pct: u8) -> bool {
    xxh64(trace_id, SEED) % 100 < target_pct as u64
}

/// Raw hash bucket (0..=99) for a trace id — used by the dry-run simulator
/// output (`ui/03` §3.3: "kept|dropped (hash % 100 = N vs target)").
#[inline]
pub fn bucket(trace_id: &[u8; 16]) -> u8 {
    (xxh64(trace_id, SEED) % 100) as u8
}

/// Fallback key for records without a trace_id (`core/03` §3.2):
/// `xxh64(service.name ‖ 0x00 ‖ log body bytes)`. Streamed — no
/// concatenation buffer, no allocation.
#[inline]
pub fn fallback_key(service_name: &[u8], body: &[u8]) -> u64 {
    let mut h = Xxh64::new(SEED);
    h.update(service_name);
    h.update(&[0u8]);
    h.update(body);
    h.digest()
}

/// Decision for untraced records. Counted separately in aggregates
/// (`sampled_out_untraced`).
#[inline]
pub fn keep_untraced(service_name: &[u8], body: &[u8], target_pct: u8) -> bool {
    fallback_key(service_name, body) % 100 < target_pct as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic PRNG for test ids — sampling itself must never see
    /// randomness (`core/03` §4), but test inputs may.
    fn xorshift64(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    fn test_id(state: &mut u64) -> [u8; 16] {
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&xorshift64(state).to_be_bytes());
        id[8..].copy_from_slice(&xorshift64(state).to_be_bytes());
        id
    }

    #[test]
    fn target_0_drops_everything_target_100_keeps_everything() {
        let mut s = 0x243F_6A88_85A3_08D3u64;
        for _ in 0..10_000 {
            let id = test_id(&mut s);
            assert!(!keep(&id, 0));
            assert!(keep(&id, 100));
        }
    }

    #[test]
    fn decision_is_pure_and_stable() {
        let id = [1u8; 16];
        for target in [1u8, 25, 50, 99] {
            let first = keep(&id, target);
            for _ in 0..100 {
                assert_eq!(keep(&id, target), first);
            }
        }
    }

    #[test]
    fn bucket_and_keep_agree_at_every_target() {
        let mut s = 0x0123_4567_89AB_CDEFu64;
        for _ in 0..1_000 {
            let id = test_id(&mut s);
            let b = bucket(&id);
            for target in 0..=100u8 {
                assert_eq!(
                    keep(&id, target),
                    b < target,
                    "id bucket {b} target {target}"
                );
            }
        }
    }

    /// Acceptance criterion (`core/03` §5): measured keep-rate over 1M uniform
    /// random trace_ids within ±0.5pp of target.
    #[test]
    fn keep_rate_within_half_percentage_point() {
        let mut s = 0xDEAD_BEEF_CAFE_F00Du64;
        for target in [10u8, 25, 50, 75] {
            let mut kept = 0u32;
            const N: u32 = 1_000_000;
            for _ in 0..N {
                let id = test_id(&mut s);
                if keep(&id, target) {
                    kept += 1;
                }
            }
            let rate_pct = kept as f64 * 100.0 / N as f64;
            assert!(
                (rate_pct - target as f64).abs() <= 0.5,
                "target {target}%: measured {rate_pct:.3}%"
            );
        }
    }

    #[test]
    fn fallback_streaming_equals_concatenation() {
        // The separator byte must matter: ("ab","c") != ("a","bc").
        let k1 = fallback_key(b"ab", b"c");
        let k2 = fallback_key(b"a", b"bc");
        assert_ne!(k1, k2);

        // Streamed hash == one-shot over service ‖ 0x00 ‖ body.
        let mut concat = Vec::new();
        concat.extend_from_slice(b"checkout-service");
        concat.push(0);
        concat.extend_from_slice(b"user login succeeded");
        assert_eq!(
            fallback_key(b"checkout-service", b"user login succeeded"),
            xxh64(&concat, SEED)
        );
    }
}
