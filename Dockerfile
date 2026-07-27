# archiv-agent (Track A data plane) container image (trust/03 §3.1).
#
# Reproducibility: build args pin the toolchain and SOURCE_DATE_EPOCH; the runtime is distroless
# (no shell, non-root). The image is signed + SBOM-attested in the release workflow, never here.
#
# Bases pinned to immutable @sha256: digests (trust/03 §4) — a mutable tag is prohibited in a
# released artifact. The human-readable tag is retained before the digest for auditability; to
# repin, resolve the tag's current digest from the registry and update both the tag and digest.
ARG RUST_IMAGE=rust:1.96-slim-bookworm@sha256:e18a79fc84dfcfc3ab5ba72290398a644c135c97eaa881447fddc354ee4701a3
# distroless/cc carries glibc + libgcc for the dynamically-linked Rust binary (ring links libgcc).
ARG RUNTIME_IMAGE=gcr.io/distroless/cc-debian12:nonroot@sha256:fccdbb0a547c14e23fcf4ce8ad62ca5d43b4faae8d22cd292f490fef9946c96e

FROM ${RUST_IMAGE} AS build
WORKDIR /src
# Reproducible builds: fixed timestamp for anything that embeds one.
ARG SOURCE_DATE_EPOCH=0
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
# Cache dependencies separately from source for faster rebuilds.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY src ./src
COPY scripts ./scripts
COPY deny.toml ./deny.toml
RUN cargo build --release && cp target/release/archiv-agent /archiv-agent

FROM ${RUNTIME_IMAGE}
# OTLP ingest ports (CLAUDE.md §6): 4317 gRPC, 4318 HTTP.
EXPOSE 4317 4318
COPY --from=build /archiv-agent /usr/local/bin/archiv-agent
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/archiv-agent"]
