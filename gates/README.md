# Release Quality Gates — agent harness

Runnable harness for the release-blocking gates in
`docs/engineering/05-quality-gates.md`. Track A implements G1 and G2 fully and
provides the agent-side portions of G3. Cross-plane portions of G3–G5 remain
scaffolded with their blockers recorded, so the gates are visible rather than
silently absent.

| Gate | SLA | Status here | Blocked on |
|---|---|---|---|
| **G1** throughput | ≥ 10,000 EPS / core, RSS ≤ 50 MB | **Implemented** — `g1-throughput/` (k6 networked) + `examples/perf.rs` (core CPU) | — |
| **G2** latency | p99 < 1 ms ingest→export | **Implemented** — `examples/perf.rs` measures the real `Pipeline::process` delta | full OTel span export is a later self-telemetry loop |
| **G3** fail-open | 0% data loss | **Partial** — panic bypass and destination-outage spooling/backpressure are covered; the full chaos suite is not wired | Control Plane push (scn.1), WASM host (scn.2–3) |
| **G4** billing replay | 100% match | **Not startable** | Control Plane billing + ClickHouse (`enterprise/03`, `enterprise/02`) |
| **G5** audit tamper | 100% detection | **Partial** — hash-chain and Postgres tamper tests exist | Continuous verifier + UI lockout/banner (`trust/02`, `ui/04`) |

## G1 / G2 — how to run

Core CPU measurement (no network, deterministic, what the per-PR *smoke* uses):

```bash
cargo run --release -p archiv-agent --example perf          # prints G1 EPS + G2 p99, PASS/FAIL
ARCHIV_PERF_ITERS=500000 cargo run --release --example perf # longer sample
```

Networked full-G1 (`k6` over the wire + RSS budget):

```bash
gates/g1-throughput/run.sh          # needs `k6` on PATH; boots the agent validate-only
```

`run.sh` dumps a real OTLP payload via the harness's `ARCHIV_PERF_DUMP` mode, starts
`archiv-agent` on an ephemeral port under `/usr/bin/time` (to capture max RSS), warms up,
runs `load.js`, then asserts sustained EPS ≥ 10,000 and peak RSS ≤ 50 MB.

## Notes

- Always `--release`; debug throughput/latency numbers are meaningless.
- Fixtures are synthetic and seeded (`docs/engineering/02` §6) — no real payloads.
- Thresholds are the product contract: changing one requires editing
  `docs/engineering/05-quality-gates.md` in the same PR plus a compliance entry
  (`05` §4). Do not loosen a gate to make a build pass.
