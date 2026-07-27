# Raw Kubernetes manifests

Plain `kubectl apply` deployment of `archiv-agent` for people who don't use Helm. For anything
beyond a quick try, prefer the chart at [`deploy/helm/archiv-agent`](../../deploy/helm/archiv-agent)
— it wires config, probes, security context, and image-digest pinning for you.

```sh
kubectl apply -f examples/kubernetes/daemonset.yaml
```

This creates the `observability` namespace, a pass-through `archiv-agent` DaemonSet (one per node),
a ConfigMap, and a ClusterIP Service on 4317 (OTLP/gRPC) and 4318 (OTLP/HTTP). Edit the ConfigMap
to enable sampling, redaction, and forwarding (schema: [`config/agent.example.yaml`](../../config/agent.example.yaml)).

**Production:** replace the `:0.1.0` tag with a pinned `@sha256:` digest and verify its cosign
signature (see the repo README / Security page).
