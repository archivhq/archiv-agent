//! `archiv-agent` — Data Plane binary.
//!
//! Wiring only (docs/architecture/core/01 §3.1): config → pipeline → server.
//! Runs OTLP/HTTP on `ingest.http_endpoint` (4318) and OTLP/gRPC on
//! `ingest.grpc_endpoint` (4317), feeding both transports through the shared
//! worker pool, pipeline, and destination forwarder. No payload content appears
//! in these logs.

use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;

use archiv_agent::forward;
use archiv_agent::grpc;
use archiv_agent::metrics;
use archiv_agent::pipeline::Pipeline;
use archiv_agent::server::{self, AppState};
use archiv_agent::spool::{self, Spool};

#[tokio::main]
async fn main() -> ExitCode {
    // Verbosity from RUST_LOG (e.g. `archiv_agent=debug`), default info.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    // rustls 0.23 needs a process-level crypto provider before any TLS config.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut config = match std::env::var("ARCHIV_CONFIG") {
        // A set-but-blank var (common in Docker/systemd/k8s) means "no config",
        // not "load the file named ''" — fall through to defaults.
        Ok(path) if !path.trim().is_empty() => {
            match archiv_config::AgentConfig::load(path.trim()) {
                Ok(cfg) => cfg,
                Err(err) => {
                    tracing::error!(%path, error = %err, "failed to load config");
                    return ExitCode::FAILURE;
                }
            }
        }
        _ => {
            tracing::info!("ARCHIV_CONFIG unset — using default pass-through config");
            archiv_config::AgentConfig::default()
        }
    };

    // Move the transport settings out before the pipeline consumes the config
    // (no clones — the builder ignores these fields).
    let http_endpoint = std::mem::take(&mut config.ingest.http_endpoint);
    let grpc_endpoint = std::mem::take(&mut config.ingest.grpc_endpoint);
    let forward_endpoint = std::mem::take(&mut config.export.otlp_endpoint);
    let spool_dir = std::mem::take(&mut config.export.spool_dir);
    let spool_max_bytes = config.export.spool_max_bytes;
    let channel_capacity = config.ingest.channel_capacity;
    // Tag 10s aggregates with the governance-policy generation (`core/06` §3.1).
    let policy_version = config.policy_fingerprint();

    tracing::info!(
        http_endpoint = %http_endpoint,
        grpc_endpoint = %grpc_endpoint,
        default_sampling_target = config.sampling.default_target,
        sampling_rules = config.sampling.rules.len(),
        redaction_rules = config.redaction.regex_rules.len(),
        max_body_bytes = config.limits.max_body_bytes,
        forwarding = forward_endpoint.is_some(),
        "archiv-agent configuration loaded"
    );

    let pipeline = match Pipeline::from_config(config) {
        Ok(p) => p,
        Err(err) => {
            tracing::error!(error = %err, "failed to build pipeline");
            return ExitCode::FAILURE;
        }
    };

    let http_addr: SocketAddr = match http_endpoint.parse() {
        Ok(addr) => addr,
        Err(err) => {
            tracing::error!(endpoint = %http_endpoint, error = %err, "invalid ingest.http_endpoint");
            return ExitCode::FAILURE;
        }
    };
    let grpc_addr: SocketAddr = match grpc_endpoint.parse() {
        Ok(addr) => addr,
        Err(err) => {
            tracing::error!(endpoint = %grpc_endpoint, error = %err, "invalid ingest.grpc_endpoint");
            return ExitCode::FAILURE;
        }
    };

    let http_listener = match server::bind(http_addr).await {
        Ok(l) => l,
        Err(err) => {
            tracing::error!(%http_addr, error = %err, "failed to bind OTLP/HTTP port");
            return ExitCode::FAILURE;
        }
    };
    let grpc_listener = match server::bind(grpc_addr).await {
        Ok(l) => l,
        Err(err) => {
            tracing::error!(%grpc_addr, error = %err, "failed to bind OTLP/gRPC port");
            return ExitCode::FAILURE;
        }
    };

    // 10 s aggregation register (`core/06`), shared by request tasks + flusher.
    let metrics = Arc::new(archiv_metrics::Metrics::new(policy_version));

    // Durable destination spool (`core/07`) — only meaningful when forwarding is
    // configured. Best-effort: if the dir can't be opened, run without it and let
    // forward failures backpressure (availability over durability, §4).
    let spool = if forward_endpoint.is_some() {
        match Spool::open(&spool_dir, spool_max_bytes).await {
            Ok(s) => Some(Arc::new(s)),
            Err(err) => {
                tracing::error!(dir = %spool_dir, error = %err, "failed to open spool — forward failures will backpressure");
                None
            }
        }
    } else {
        None
    };

    // The drain task needs the endpoint too; clone it (config string, not payload)
    // before the state takes ownership.
    let drain_endpoint = forward_endpoint.clone();

    let state = Arc::new(AppState {
        pipeline: arc_swap::ArcSwap::from_pointee(pipeline),
        forward_endpoint,
        client: forward::build_client(),
        metrics: metrics.clone(),
        spool: spool.clone(),
        channel_capacity,
    });

    tracing::info!(
        %http_addr,
        %grpc_addr,
        version = env!("CARGO_PKG_VERSION"),
        sampling_algo = archiv_sampling::ALGO_VERSION,
        "archiv-agent listening (OTLP/HTTP + OTLP/gRPC)"
    );

    // One shutdown signal fans out to both receivers via a watch channel.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });

    let http = server::serve(
        http_listener,
        state.clone(),
        wait_for_shutdown(shutdown_rx.clone()),
    );
    // Aggregates are logged as numbers-only lines to stdout (CLAUDE.md §3 auditability).
    let sink = metrics::StdoutSink;
    let flusher = metrics::run_flush_loop(metrics, sink, wait_for_shutdown(shutdown_rx.clone()));
    // Drain the spool to the destination in the background (`core/07`); a no-op
    // wait when there is nothing to drain, so the join shape stays fixed.
    let drain_rx = shutdown_rx.clone();
    let drainer = async move {
        match (spool, drain_endpoint) {
            (Some(sp), Some(ep)) => {
                spool::run_drain_loop(sp, forward::build_client(), ep, wait_for_shutdown(drain_rx))
                    .await;
            }
            _ => wait_for_shutdown(drain_rx).await,
        }
    };
    let grpc = grpc::serve(grpc_listener, state, wait_for_shutdown(shutdown_rx));
    let (http_result, grpc_result, (), ()) = tokio::join!(http, grpc, flusher, drainer);

    match http_result.and(grpc_result) {
        Ok(()) => {
            tracing::info!("shutdown complete");
            ExitCode::SUCCESS
        }
        Err(err) => {
            tracing::error!(error = %err, "server error");
            ExitCode::FAILURE
        }
    }
}

/// Resolve once the shutdown watch flips to `true`.
async fn wait_for_shutdown(mut rx: tokio::sync::watch::Receiver<bool>) {
    let _ = rx.wait_for(|flagged| *flagged).await;
}

/// Resolve on Ctrl-C (SIGINT) or SIGTERM — the graceful-drain trigger.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}
