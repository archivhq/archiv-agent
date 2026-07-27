//! Gate harness for **G1 (throughput)** and **G2 (latency)** —
//! `docs/engineering/05-quality-gates.md` §2, run against the real
//! [`Pipeline::process`] path (the `ingest→export` delta the gate measures).
//!
//! This is the CPU-bound core measurement: one thread, one core, a realistic
//! mixed policy (redaction rules + partial sampling) over a seeded synthetic
//! corpus. The networked full-G1 (`k6` over the wire, RSS ≤ 50 MB) lives in
//! `gates/g1-throughput/`; this example is what a developer runs locally and
//! what the per-PR *smoke* variant shells out to.
//!
//! Run (always `--release` — debug numbers are meaningless):
//! ```text
//! cargo run --release -p archiv-agent --example perf
//! ARCHIV_PERF_ITERS=200000 cargo run --release --example perf
//! ```
//! Synthetic data only (`docs/engineering/02` §6).
#![allow(clippy::expect_used, clippy::unwrap_used)] // harness: panic on setup failure is intended

use std::time::Instant;

use archiv_agent::pipeline::Pipeline;
use archiv_config::AgentConfig;
use bytes::Bytes;

// ---- minimal OTLP logs encoder (mirrors tests/common, self-contained) ------

fn varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let b = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            break;
        }
        out.push(b | 0x80);
    }
}
fn field_len(field: u32, payload: &[u8], out: &mut Vec<u8>) {
    varint(u64::from(field) << 3 | 2, out);
    varint(payload.len() as u64, out);
    out.extend_from_slice(payload);
}
fn field_varint(field: u32, v: u64, out: &mut Vec<u8>) {
    varint(u64::from(field) << 3, out);
    varint(v, out);
}
fn any_string(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    field_len(1, s.as_bytes(), &mut out);
    out
}
fn key_value(key: &str, value: &str) -> Vec<u8> {
    let mut out = Vec::new();
    field_len(1, key.as_bytes(), &mut out);
    field_len(2, &any_string(value), &mut out);
    out
}

/// One LogRecord: severity + body + a couple of attributes + trace id.
fn log_record(body: &str, trace_id: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::new();
    field_varint(2, 9, &mut out); // severity_number = INFO
    field_len(5, &any_string(body), &mut out); // body
    field_len(6, &key_value("http.method", "POST"), &mut out); // attr (noise)
    field_len(6, &key_value("user.email", "alice@corp.io"), &mut out); // attr w/ PII
    field_len(9, trace_id, &mut out); // trace_id
    out
}

/// A realistic request: `records` LogRecords under one ResourceLogs/ScopeLogs,
/// with a k8s namespace resource attribute so namespace sampling rules apply.
fn request(records: usize, seed: u64) -> Vec<u8> {
    let mut scope_logs = Vec::new();
    for i in 0..records {
        let mut tid = [0u8; 16];
        tid[..8].copy_from_slice(&seed.to_le_bytes());
        tid[8..].copy_from_slice(&(i as u64).to_le_bytes());
        // Every 3rd record carries an email in the body too (redaction work).
        let body = if i % 3 == 0 {
            "login for bob@corp.io from 10.0.0.1 succeeded in 42ms with token abc123"
        } else {
            "GET /api/v1/orders 200 in 12ms region=us-east-1 cache=hit bytes=2048"
        };
        field_len(2, &log_record(body, &tid), &mut scope_logs);
    }

    let mut resource = Vec::new();
    field_len(1, &key_value("service.name", "checkout"), &mut resource);
    field_len(
        1,
        &key_value("k8s.namespace.name", "payments"),
        &mut resource,
    );

    let mut resource_logs = Vec::new();
    field_len(1, &resource, &mut resource_logs);
    field_len(2, &scope_logs, &mut resource_logs);

    let mut req = Vec::new();
    field_len(1, &resource_logs, &mut req);
    req
}

// A realistic mixed policy: partial sampling + several redaction rules.
const POLICY: &str = r#"
sampling:
  default_target: 100
  rules:
    - match: { namespace: "payments" }
      target: 25
redaction:
  regex_rules:
    - { name: email, pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', mask: "[EMAIL]", fields: [body] }
    - { name: ipv4,  pattern: '\b\d{1,3}(\.\d{1,3}){3}\b', mask: "[IP]", fields: [body] }
    - { name: token, pattern: 'token [A-Za-z0-9]+', mask: "token [TOK]", fields: [body] }
    - { name: bearer, pattern: 'Bearer [A-Za-z0-9._-]+', mask: "Bearer [TOK]", fields: [body] }
    - { name: ccard, pattern: '\b(?:\d[ -]*?){13,16}\b', mask: "[CARD]", fields: [body] }
"#;

fn percentile(sorted_ns: &[u64], p: f64) -> u64 {
    if sorted_ns.is_empty() {
        return 0;
    }
    let idx = ((sorted_ns.len() as f64 - 1.0) * p).round() as usize;
    sorted_ns[idx]
}

fn main() {
    let records_per_req: usize = env_usize("ARCHIV_PERF_RECORDS", 10);
    let iters: usize = env_usize("ARCHIV_PERF_ITERS", 100_000);
    let corpus_size: usize = 64; // distinct requests cycled through

    // Dump mode: write one encoded OTLP request to disk for the k6 networked
    // G1 to POST, then exit. Keeps the wire corpus identical to this harness.
    if let Ok(path) = std::env::var("ARCHIV_PERF_DUMP") {
        let payload = request(records_per_req, 1);
        std::fs::write(&path, &payload).expect("write dump");
        println!(
            "wrote {} bytes ({records_per_req} records) to {path}",
            payload.len()
        );
        return;
    }

    let pipeline =
        Pipeline::from_config(AgentConfig::from_yaml(POLICY).expect("perf policy parses"))
            .expect("perf pipeline builds");

    // Pre-encode a seeded corpus of distinct requests (as Bytes, ready to run).
    let corpus: Vec<Bytes> = (0..corpus_size)
        .map(|s| Bytes::from(request(records_per_req, s as u64 + 1)))
        .collect();
    let req_bytes: usize = corpus.iter().map(bytes::Bytes::len).sum::<usize>() / corpus.len();

    // Warm up (page-in, branch predictor, regex DFA caches).
    for r in &corpus {
        std::hint::black_box(pipeline.process(r.clone()));
    }

    // Measure per-request latency of the full ingest→export pipeline.
    let mut samples = Vec::with_capacity(iters);
    let mut total_records: u64 = 0;
    let mut total_dropped: u64 = 0;
    let start = Instant::now();
    for i in 0..iters {
        let raw = corpus[i % corpus_size].clone(); // Bytes clone = refcount, not payload copy
        let t0 = Instant::now();
        let out = pipeline.process(raw);
        let dt = t0.elapsed().as_nanos() as u64;
        samples.push(dt);
        total_records += out.stats.records_in as u64;
        total_dropped += out.stats.dropped as u64;
        std::hint::black_box(&out.output);
    }
    let wall = start.elapsed();

    samples.sort_unstable();
    let p50 = percentile(&samples, 0.50);
    let p99 = percentile(&samples, 0.99);
    let p999 = percentile(&samples, 0.999);
    let per_req_eps = iters as f64 / wall.as_secs_f64();
    let eps = total_records as f64 / wall.as_secs_f64();

    println!("archiv-agent perf harness (G1/G2, single core, --release recommended)");
    println!(
        "  corpus:        {corpus_size} requests × {records_per_req} records, ~{req_bytes} B/req"
    );
    println!("  iterations:    {iters}");
    println!("  wall:          {:?}", wall);
    println!("  records:       {total_records} processed, {total_dropped} sampled out");
    println!("  --- G1 throughput ---");
    println!("  requests/s:    {per_req_eps:>12.0}");
    println!(
        "  events/s:      {eps:>12.0}   (SLA ≥ 10,000 EPS/core → {})",
        pass(eps >= 10_000.0)
    );
    println!("  --- G2 latency (per request, ingest→export) ---");
    println!("  p50:           {:>8.3} µs", p50 as f64 / 1000.0);
    println!(
        "  p99:           {:>8.3} µs   (SLA < 1 ms → {})",
        p99 as f64 / 1000.0,
        pass(p99 < 1_000_000)
    );
    println!("  p99.9:         {:>8.3} µs", p999 as f64 / 1000.0);
    println!("note: RSS ≤ 50 MB is asserted by gates/g1-throughput/run.sh via `/usr/bin/time`.");
}

fn pass(ok: bool) -> &'static str {
    if ok { "PASS" } else { "FAIL" }
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
