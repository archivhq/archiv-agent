# Archiv

**Telemetry governance for OpenTelemetry.**

Reduce observability costs.
Prevent secret leaks.
Never lose telemetry.

---

`archiv-agent` is a single static Rust binary that sits between your workloads and your
observability vendor. It samples low-value telemetry before it reaches the vendor's meter,
redacts secrets before they leave the node, and fails open so that governance can never
become an outage.

Apache 2.0. No control plane, no account, no phone-home. Drop it into a live pipeline as a
transparent proxy and turn governance on when you're ready.

```sh
docker run -p 4317:4317 -p 4318:4318 ghcr.io/archiv/archiv-agent:latest
```

## Architecture

```
   your services
        │  OTLP  (gRPC :4317 / HTTP :4318)
        ▼
 ┌───────────────────────────────────────────────┐
 │  archiv-agent                     (DaemonSet)  │
 │                                                │
 │    ingest ──► sample ──► redact ──► export     │
 │       │          │          │          │       │
 │       └──────────┴──────────┴──────────┘       │
 │                fail-open bypass                │
 │                       │                        │
 │                  disk spool  ◄── vendor down   │
 └───────────────────────────────────────────────┘
        │  OTLP
        ▼
   Datadog · Splunk · New Relic · Grafana Cloud · Elastic · any OTLP endpoint
```

One hop. Your SDKs and collectors keep their existing OTLP configuration; only the endpoint
changes.

## Why not just use the OpenTelemetry Collector?

For a single pipeline you configure by hand, the Collector is a good answer, and Archiv
doesn't try to replace it — you can run `archiv-agent` in front of, behind, or instead of a
Collector, and most teams start by putting it in front.

Archiv exists for the case where telemetry has to be *governed* rather than merely
processed: where dropping the wrong log during an incident is a real cost, where a sampling
decision needs to be explainable to an auditor months later, and where the policy applies to
a fleet rather than a file.

Three commitments the agent makes:

**1. Fail-open is a guarantee, not a configuration.** Every governance stage can be bypassed
at runtime. A malformed rule, a panicking regex, a redaction plugin that misbehaves — the
event passes through ungoverned rather than being dropped. Losing a log is treated as a bug
in Archiv, not as an operator error.

**2. Sampling is deterministic and reproducible.** The keep/drop decision is a pure function
of the event and the policy, with no per-instance randomness. Every agent in a fleet makes
the same call for the same trace, so traces don't tear across nodes — and you can replay a
policy against historical data and get the identical answer, which is what makes a sampling
decision auditable.

**3. The resource budget is release-blocking.** 10,000 events/sec per core, p99 processing
latency under 1 ms, and ≤ 50 MB RSS at full load are gates in CI, not aspirations. On a
DaemonSet across a large fleet, agent overhead is itself an infrastructure cost.

> Running both? A common layout is `SDK → archiv-agent (node) → Collector (gateway) → vendor`,
> so cost and secret controls apply at the edge and the Collector keeps doing enrichment and
> routing.

## Quick start

With no configuration the agent forwards everything untouched — safe to insert into a live
pipeline first and enable governance second.

```sh
# Run it
docker run -p 4317:4317 -p 4318:4318 ghcr.io/archiv/archiv-agent:latest

# Or build from source (stable Rust)
cargo build --release && ./target/release/archiv-agent
```

| Port   | Protocol         |
| ------ | ---------------- |
| `4317` | OTLP/gRPC ingest |
| `4318` | OTLP/HTTP ingest |

Point your existing exporter at it:

```yaml
# OpenTelemetry SDK / Collector exporter
exporters:
  otlp:
    endpoint: archiv-agent.observability.svc:4317
```

## Configuration

Set `ARCHIV_CONFIG` to a YAML file. Every key is optional; omitted sections are off.
Full annotated example: [`config/agent.example.yaml`](config/agent.example.yaml).

```yaml
sampling:                                  # first matching rule wins
  default_target: 100                      # percent kept; 100 = sampling off
  rules:
    - match: { namespace: "security-audit" }   # never sample audit trails
      target: 100
    - match: { namespace: "payments" }         # never sample payments
      target: 100
    - match: { severity_lte: "DEBUG" }         # keep 10% of debug logs
      target: 10

redaction:
  regex_rules:
    - name: email
      pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
      mask: "[REDACTED:email]"
      fields: [body, "attributes.*"]

export:
  otlp_endpoint: "https://otlp.your-vendor.com:4318"
  spool_dir: "/var/lib/archiv/spool"       # survives vendor outages
```

```sh
ARCHIV_CONFIG=/etc/archiv/agent.yaml archiv-agent
```

### What that config does to your bill

Sampling savings are a direct function of your own severity mix, not a property of Archiv.
For a workload that is 70% `DEBUG`, the rule above keeps 10% of that 70% and all of the
remaining 30%, so ingestion drops to 37% of baseline. Substitute your own distribution — the
agent reports observed keep/drop counters at `/metrics` so you can measure the real number
before committing to a policy.

> Run the agent in `dry_run: true` to emit those counters while forwarding everything, and
> see the savings a policy *would* produce before it drops anything.

### Sampling determinism

The decision is `xxHash64(trace_id, seed 0) % 100 < target`. Because it is seeded identically
everywhere, every agent in a fleet reaches the same verdict for the same trace: no torn
traces, and a policy can be replayed against past data for audit.

<!-- TODO(before publishing): document the fallback for logs with no trace_id. This is the
     first thing a reviewer will ask. Candidates: hash(service.name ‖ body), or always-keep. -->

## Design guarantees

- **Fail-open, always.** Governance failures degrade to pass-through; exporter failures
  degrade to a bounded on-disk spool with oldest-first eviction.
- **Nothing leaves the node that you didn't send.** No telemetry, no config, and no usage
  data is transmitted anywhere except your configured OTLP endpoint.
- **Zero-copy pipeline.** Payloads are reference-counted (`bytes::Bytes`), never cloned.

## Benchmarks

<!-- TODO(before Show HN): this section is the launch. Numbers without a reproduction
     command will be dismissed, and the strategy's whole GitHub motion rests on them.
     Required: hardware spec, payload shape/size, generator, config used, and a single
     command a reader can run on their own machine. -->

| Metric                  | Result | Conditions |
| ----------------------- | ------ | ---------- |
| Throughput (per core)   | _TBD_  | _TBD_      |
| p99 processing latency  | _TBD_  | _TBD_      |
| RSS at sustained load   | _TBD_  | _TBD_      |
| Overhead vs. direct OTLP| _TBD_  | _TBD_      |

Reproduce on your own hardware:

```sh
cargo bench                 # microbenchmarks
./bench/run.sh              # end-to-end load test, prints the table above
```

Full methodology and raw results: [`bench/README.md`](bench/README.md).

## Deploying

### Kubernetes (Helm)

```sh
helm repo add archiv https://charts.archiv.dev
helm install archiv-agent archiv/archiv-agent \
  -n observability --create-namespace \
  --set config.export.otlpEndpoint=https://otlp.your-vendor.com:4318
```

Runs as a DaemonSet, one agent per node. Chart reference: [`deploy/helm/`](deploy/helm/).

### Other examples

- [`examples/kubernetes/`](examples/kubernetes/) — raw DaemonSet manifests
- [`examples/docker-compose/`](examples/docker-compose/) — local development
- [`examples/terraform/`](examples/terraform/) — ECS and EC2 modules
- [`examples/collector/`](examples/collector/) — running alongside an OTel Collector gateway

## Community and Enterprise

This repository is the complete Community Edition — full sampling and redaction, fail-open
resiliency, local YAML config. It runs forever, free, with no control plane and no
limitations bolted on to push you to upgrade.

The Enterprise Edition adds the fleet layer on top of this same agent: a central console that
pushes policy to thousands of agents live, SSO/RBAC, a tamper-evident audit ledger, and
verified savings reporting. Agents still fail open if the control plane is unreachable, and
log contents never reach it — only aggregate counters.

[Enterprise documentation →](docs/enterprise/getting-started.md)

## Contributing

Issues and PRs welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the development setup
and the performance gates a PR has to clear.

## License

Apache License 2.0.
