//! OTLP/HTTP receiver (`docs/architecture/core/01` §3.2): accepts
//! `POST /v1/logs`, runs the body through the [`Pipeline`], and forwards the
//! governed output to the destination (or validate-only when none configured).
//!
//! Response semantics:
//! - unparseable OTLP → `400` (client error — not a governance failure, so the
//!   fail-open guarantee does not apply to malformed input);
//! - processed + forwarded OK, or validate-only → `200` with an empty
//!   `ExportLogsServiceResponse` (zero bytes is a valid serialization);
//! - forward failed → `503` so the client SDK retries — the data is held
//!   upstream, never dropped (`core/05` §3.2 backpressure, simplest form).
//!
//! Body size is bounded to `limits.max_body_bytes` during read (`core/02`
//! §3.4). A bounded channel hands accepted bodies to a shared worker pool;
//! awaiting queue capacity applies backpressure without dropping a request.

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use archiv_metrics::{Metrics, Sample};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, header::CONTENT_TYPE, header::HeaderValue};
use hyper_util::rt::TokioIo;
use hyper_util::server::graceful::GracefulShutdown;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use crate::forward::{HttpClient, forward};
use crate::pipeline::Pipeline;
use crate::spool::Spool;

/// Shared server state (cheap to clone via `Arc`). The pipeline sits behind an
/// `ArcSwap` so the Enterprise policy applier can atomically install a rebuilt
/// pipeline (new WASM modules from a pushed bundle) without dropping in-flight
/// events (`core/01` §3). Open_Source  builds swap it exactly once at startup.
pub struct AppState {
    pub pipeline: arc_swap::ArcSwap<Pipeline>,
    /// Destination endpoint, or `None` for validate-only (no forwarding).
    pub forward_endpoint: Option<String>,
    pub client: HttpClient,
    /// 10 s aggregation register, shared with the flush task (`core/06`).
    pub metrics: Arc<Metrics>,
    /// Durable destination spool, or `None` when disabled (`core/07`).
    pub spool: Option<Arc<Spool>>,
    /// Bound of the ingest→worker queue (`core/01` §3.2, `ingest.channel_capacity`).
    pub channel_capacity: usize,
}

fn response(status: StatusCode, body: Bytes) -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(body));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-protobuf"),
    );
    resp
}

/// Empty `ExportLogsServiceResponse` (no fields set → zero bytes).
fn otlp_ok() -> Response<Full<Bytes>> {
    response(StatusCode::OK, Bytes::new())
}

/// Transport-agnostic result of running one payload through the pipeline and
/// (optionally) forwarding it. Each transport maps this to its own status
/// codes (HTTP here, gRPC in `grpc`).
pub(crate) enum Verdict {
    /// Processed and forwarded (or validate-only) successfully.
    Accepted,
    /// Unparseable OTLP — a client error, not a governance failure.
    Malformed,
    /// Forward to the destination failed — the client should retry.
    ForwardFailed,
}

/// One unit of work handed from a receiver to a pipeline worker: the raw OTLP
/// bytes plus a one-shot channel to return the verdict. The receiver awaits the
/// verdict before responding, so an ack still follows processing (`core/05` §4).
pub(crate) struct Job {
    pub raw: Bytes,
    pub respond: oneshot::Sender<Verdict>,
}

/// Ingress side of the bounded ingest→worker queue (`core/01` §3.2). Cloning is
/// cheap (a channel handle); a bounded `send().await` is the backpressure.
pub(crate) type Ingress = async_channel::Sender<Job>;

/// Default pipeline-worker count: the machine's parallelism (min 1).
pub(crate) fn worker_count() -> usize {
    std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(4)
}

/// Build the bounded work queue and spawn `workers` pipeline tasks that consume
/// it, decoupling accept from process (`core/01` §3.2). Workers run the shared
/// [`run`] per job and exit when every [`Ingress`] is dropped (the queue closes).
pub(crate) fn spawn_pool(state: Arc<AppState>, capacity: usize, workers: usize) -> Ingress {
    let (tx, rx) = async_channel::bounded::<Job>(capacity.max(1));
    for _ in 0..workers.max(1) {
        let state = state.clone();
        let rx = rx.clone();
        tokio::spawn(async move {
            while let Ok(job) = rx.recv().await {
                let verdict = run(&state, job.raw).await;
                let _ = job.respond.send(verdict); // receiver may have hung up
            }
        });
    }
    tx
}

/// Submit one payload to the worker pool and await its verdict. A full queue
/// applies backpressure (the `send` awaits); a closed queue or a dropped worker
/// maps to `ForwardFailed` — a retryable non-ack, never a false accept.
pub(crate) async fn submit(ingress: &Ingress, raw: Bytes) -> Verdict {
    let (respond, rx) = oneshot::channel();
    if ingress.send(Job { raw, respond }).await.is_err() {
        return Verdict::ForwardFailed;
    }
    rx.await.unwrap_or(Verdict::ForwardFailed)
}

/// Shared processing path: run the pipeline, then forward if configured.
/// Callers enforce the body-size limit before calling (transport-specific).
pub(crate) async fn run(state: &AppState, raw: Bytes) -> Verdict {
    // Load the current pipeline (lock-free); a concurrent atomic swap only affects
    // subsequent requests, never this in-flight one.
    let processed = state.pipeline.load().process(raw);

    if processed.stats.parse_bypassed {
        return Verdict::Malformed;
    }

    // Fold this request's numbers into the current 10 s window (`core/06`).
    // Lock-free, allocation-free — numbers only, never payload content.
    let stats = &processed.stats;
    state.metrics.record(&Sample {
        events_in: stats.records_in as u64,
        events_sampled_out: stats.dropped as u64,
        events_exported: stats.kept as u64,
        bytes_in: stats.bytes_in as u64,
        bytes_exported: stats.bytes_out as u64,
        redaction_count: stats.redactions as u64,
        failed_open: stats.redact_bypassed || stats.assemble_bypassed,
    });

    tracing::debug!(
        records_in = processed.stats.records_in,
        kept = processed.stats.kept,
        dropped = processed.stats.dropped,
        redactions = processed.stats.redactions,
        bytes_in = processed.stats.bytes_in,
        bytes_out = processed.stats.bytes_out,
        "processed request"
    );

    let Some(endpoint) = &state.forward_endpoint else {
        return Verdict::Accepted; // validate-only
    };
    match forward(&state.client, endpoint, &processed.output).await {
        Ok(()) => Verdict::Accepted,
        // Destination down. Durably spool so we can still honestly accept
        // (`core/07` §3.5); only ask the client to retry if we cannot hold it.
        Err(err) => match &state.spool {
            Some(spool) => {
                let bytes = Bytes::from(processed.output.contiguous());
                match spool.push(&bytes).await {
                    Ok(seq) => {
                        tracing::warn!(error = %err, seq, "forward failed — payload spooled for retry");
                        Verdict::Accepted
                    }
                    Err(spool_err) => {
                        tracing::error!(error = %err, spool = %spool_err, "forward failed and spool full/unavailable — backpressure");
                        Verdict::ForwardFailed
                    }
                }
            }
            None => {
                tracing::warn!(error = %err, "forward failed — asking client to retry");
                Verdict::ForwardFailed
            }
        },
    }
}

async fn handle(
    state: Arc<AppState>,
    ingress: Ingress,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    if req.method() != Method::POST || req.uri().path() != "/v1/logs" {
        return response(StatusCode::NOT_FOUND, Bytes::from_static(b"not found\n"));
    }

    // Bound the read to the configured max body size (`core/02` §3.4).
    let max = state.pipeline.load().max_body_bytes();
    let raw = match Limited::new(req.into_body(), max).collect().await {
        Ok(body) => body.to_bytes(),
        Err(_) => {
            return response(
                StatusCode::PAYLOAD_TOO_LARGE,
                Bytes::from_static(b"too large\n"),
            );
        }
    };

    // Hand off to a pipeline worker and await the verdict (`core/01` §3.2).
    match submit(&ingress, raw).await {
        Verdict::Accepted => otlp_ok(),
        Verdict::Malformed => response(
            StatusCode::BAD_REQUEST,
            Bytes::from_static(b"unparseable OTLP\n"),
        ),
        Verdict::ForwardFailed => response(
            StatusCode::SERVICE_UNAVAILABLE,
            Bytes::from_static(b"forward failed\n"),
        ),
    }
}

/// Bind the listener up front so callers (and tests) can learn the actual
/// local address before serving.
pub async fn bind(addr: SocketAddr) -> std::io::Result<TcpListener> {
    TcpListener::bind(addr).await
}

/// Serve until `shutdown` resolves, then drain in-flight requests.
pub async fn serve(
    listener: TcpListener,
    state: Arc<AppState>,
    shutdown: impl Future<Output = ()>,
) -> std::io::Result<()> {
    let graceful = GracefulShutdown::new();
    let mut shutdown = std::pin::pin!(shutdown);
    // Bounded ingest→worker queue: accept is decoupled from process (`core/01` §3.2).
    let ingress = spawn_pool(state.clone(), state.channel_capacity, worker_count());

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let stream = match accepted {
                    Ok((stream, _peer)) => stream,
                    Err(err) => {
                        tracing::warn!(error = %err, "accept failed");
                        continue;
                    }
                };
                let io = TokioIo::new(stream);
                let state = state.clone();
                let ingress = ingress.clone();
                let svc = service_fn(move |req| {
                    let state = state.clone();
                    let ingress = ingress.clone();
                    async move { Ok::<_, Infallible>(handle(state, ingress, req).await) }
                });
                let conn = http1::Builder::new().serve_connection(io, svc);
                let watched = graceful.watch(conn);
                tokio::spawn(async move {
                    if let Err(err) = watched.await {
                        tracing::debug!(error = %err, "connection closed with error");
                    }
                });
            }
            _ = &mut shutdown => {
                tracing::info!("shutdown signal received — draining in-flight requests");
                break;
            }
        }
    }

    graceful.shutdown().await;
    Ok(())
}
