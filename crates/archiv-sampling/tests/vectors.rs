//! Pins the sampling implementation against the shared cross-language vector
//! file (`docs/architecture/core/03` §4) so a dependency upgrade cannot
//! silently change fleet decisions — that would break traces *and* billing.
#![allow(clippy::expect_used, clippy::unwrap_used)] // test setup: panic on failure is intended

use archiv_sampling::{ALGO_VERSION, SEED, bucket, fallback_key, keep};

const VECTORS_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/testdata/sampling_vectors.json"
);

fn decode_hex_16(s: &str) -> [u8; 16] {
    let bytes = s.as_bytes();
    assert_eq!(bytes.len(), 32, "trace_id must be 32 hex chars");
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("valid hex");
    }
    out
}

#[test]
fn pinned_vectors_match_implementation() {
    let data = std::fs::read_to_string(VECTORS_PATH).expect(
        "proto/testdata/sampling_vectors.json missing — generate it with \
         `cargo run -p archiv-sampling --example gen_vectors`",
    );
    let doc: serde_json::Value = serde_json::from_str(&data).expect("valid JSON");

    assert_eq!(doc["algo_version"], ALGO_VERSION as i64);
    assert_eq!(doc["seed"], SEED);
    assert_eq!(doc["modulus"], 100);

    let trace_vectors = doc["trace_vectors"]
        .as_array()
        .expect("trace_vectors array");
    assert!(
        trace_vectors.len() >= 64,
        "expected at least 64 trace vectors"
    );
    for v in trace_vectors {
        let id = decode_hex_16(v["trace_id"].as_str().expect("trace_id"));
        let expected_hash =
            u64::from_str_radix(v["xxh64_hex"].as_str().expect("xxh64_hex"), 16).expect("hex u64");
        let expected_mod = v["mod100"].as_u64().expect("mod100") as u8;

        assert_eq!(
            xxhash_rust::xxh64::xxh64(&id, SEED),
            expected_hash,
            "hash drift for trace_id {}",
            v["trace_id"]
        );
        assert_eq!(bucket(&id), expected_mod);
        // The decision rule holds at every target for every pinned vector.
        for target in 0..=100u8 {
            assert_eq!(keep(&id, target), expected_mod < target);
        }
    }

    let untraced = doc["untraced_vectors"]
        .as_array()
        .expect("untraced_vectors array");
    assert!(!untraced.is_empty());
    for v in untraced {
        let service = v["service_name"].as_str().expect("service_name");
        let body = v["body"].as_str().expect("body");
        let expected_key =
            u64::from_str_radix(v["xxh64_hex"].as_str().expect("xxh64_hex"), 16).expect("hex u64");
        assert_eq!(
            fallback_key(service.as_bytes(), body.as_bytes()),
            expected_key,
            "fallback key drift for ({service}, {body})"
        );
        assert_eq!(expected_key % 100, v["mod100"].as_u64().expect("mod100"));
    }
}
