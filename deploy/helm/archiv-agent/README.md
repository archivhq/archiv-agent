# archiv-agent Helm chart (Open_Source Edition)

Deploys the open-source [`archiv-agent`](https://github.com/archivhq/archiv-agent) as a per-node
DaemonSet: a fail-open OTLP governance proxy with deterministic sampling, regex PII redaction
(CWE-532), and a durable disk spool. Apache-2.0 — no control plane, no account, no phone-home.

> For the **Enterprise** bundle (agent + control-plane + web + Sigstore admission), use the umbrella
> chart shipped with the Enterprise distribution, not this one.

## Install

From a checkout of the repo (works today, no chart repo needed):

```sh
helm install archiv-agent ./deploy/helm/archiv-agent \
  -n observability --create-namespace \
  --set config.export.otlp_endpoint=https://otlp.your-vendor.com:4318
```

Point your existing OTLP exporters at the node-local Service:

```yaml
exporters:
  otlp:
    endpoint: archiv-agent.observability.svc:4317 # OTLP/gRPC (4318 for HTTP)
```

## Configuration

The whole agent config lives under `config:` and is rendered into a ConfigMap mounted at
`/etc/archiv/agent.yaml`. The schema is [`config/agent.example.yaml`](../../../config/agent.example.yaml).
An empty `config: {}` runs a pure pass-through agent — safe to insert into a live pipeline first,
then turn governance on.

| Key                             | Default                   | Notes                                            |
| ------------------------------- | ------------------------- | ------------------------------------------------ |
| `image.repository`              | `archivhq/archiv-agent`   |                                                  |
| `image.tag`                     | `""` → chart `appVersion` | never `latest` (rejected at render)              |
| `image.digest`                  | `""`                      | `sha256:…`; **wins over tag** — pin this in prod |
| `config`                        | pass-through              | agent config, ConfigMap-mounted                  |
| `spool.type`                    | `emptyDir`                | `hostPath` for node-durable spool                |
| `resources.limits.memory`       | `64Mi`                    | budget is ≤ 50 MB RSS at 10k EPS                 |
| `hostPort.enabled`              | `false`                   | expose 4317/4318 on the node                     |
| `service.internalTrafficPolicy` | `Cluster`                 | `Local` = node-local delivery                    |
| `tolerations`                   | `[]`                      | add the control-plane taint for full coverage    |

## Supply chain (trust/03)

The agent image is **cosign keyless-signed** by the release workflow. Pin by digest and verify:

```sh
cosign verify ghcr.io/archivhq/archiv-agent@<digest> \
  --certificate-identity-regexp \
    '^https://github.com/archivhq/archiv-agent/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The chart **refuses to render** an image referenced by the mutable tag `latest` (trust/03 §4).
