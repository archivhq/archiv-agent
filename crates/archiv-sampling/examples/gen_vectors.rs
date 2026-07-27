//! Generates `proto/testdata/sampling_vectors.json` — the cross-language pin
//! (`docs/architecture/core/03` §4). The Go and TS reimplementations (Control
//! Plane dry-run simulator) must agree with these vectors bit-for-bit.
//!
//! Run from anywhere:
//!   cargo run -p archiv-sampling --example gen_vectors
//!
//! Hashes are emitted as hex strings so JSON consumers without native u64
//! (TypeScript) can verify via BigInt without precision loss.

use std::error::Error;
use std::fmt::Write as _;

fn xorshift64(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut trace_vectors = Vec::new();

    // Edge-case ids plus 61 deterministic pseudo-random ids.
    let mut ids: Vec<[u8; 16]> = vec![[0u8; 16], [0xffu8; 16], {
        let mut id = [0u8; 16];
        id[15] = 1;
        id
    }];
    let mut state = 0x243F_6A88_85A3_08D3u64; // deterministic: pi fractional bits
    for _ in 0..61 {
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&xorshift64(&mut state).to_be_bytes());
        id[8..].copy_from_slice(&xorshift64(&mut state).to_be_bytes());
        ids.push(id);
    }

    for id in &ids {
        let hash = xxhash_rust::xxh64::xxh64(id, archiv_sampling::SEED);
        trace_vectors.push(serde_json::json!({
            "trace_id": hex(id),
            "xxh64_hex": format!("{hash:016x}"),
            "mod100": archiv_sampling::bucket(id),
        }));
    }

    // Untraced fallback vectors: xxh64(service ‖ 0x00 ‖ body), seed 0.
    let untraced_inputs: &[(&str, &str)] = &[
        ("checkout-service", "user login succeeded"),
        ("checkout-service", ""),
        ("", "orphan record with empty service name"),
        ("payments", "request completed status=200 duration_ms=41"),
        ("batch-nightly", "job finished rows=100000"),
    ];
    let mut untraced_vectors = Vec::new();
    for (service, body) in untraced_inputs {
        let key = archiv_sampling::fallback_key(service.as_bytes(), body.as_bytes());
        untraced_vectors.push(serde_json::json!({
            "service_name": service,
            "body": body,
            "xxh64_hex": format!("{key:016x}"),
            "mod100": (key % 100) as u8,
        }));
    }

    let doc = serde_json::json!({
        "description": "Cross-language sampling pin: keep iff xxHash64(trace_id, seed 0) % 100 < target_pct. See docs/architecture/core/03-deterministic-sampling.md §3.1 (frozen).",
        "algo_version": archiv_sampling::ALGO_VERSION,
        "seed": archiv_sampling::SEED,
        "modulus": 100,
        "trace_vectors": trace_vectors,
        "untraced_vectors": untraced_vectors,
    });

    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/testdata/sampling_vectors.json"
    );
    std::fs::create_dir_all(std::path::Path::new(path).parent().ok_or("no parent dir")?)?;
    std::fs::write(path, serde_json::to_string_pretty(&doc)? + "\n")?;
    println!(
        "wrote {} trace + {} untraced vectors to {path}",
        ids.len(),
        untraced_inputs.len()
    );
    Ok(())
}
