//! OTLP/gRPC receiver (`docs/architecture/core/01` §3.2) on `:4317`.
//!
//! gRPC is HTTP/2 + a 5-byte length-prefixed message frame. This module speaks
//! it directly over hyper (no tonic/prost), so the `ExportLogsServiceRequest`
//! bytes reach the pipeline **without a decode/re-encode** — the zero-copy law
//! holds (the message is a `Bytes::slice` of the request body).
//!
//! Status mapping (gRPC status in the response trailers, HTTP always 200):
//! `OK=0` accepted/validate-only · `INVALID_ARGUMENT=3` malformed · `UNIMPLEMENTED=12`
//! wrong path or compressed frame · `RESOURCE_EXHAUSTED=8` over `max_body_bytes` ·
//! `UNAVAILABLE=14` forward failed (client retries).

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::{BodyExt, Limited};
use hyper::body::{Body, Frame, Incoming};
use hyper::header::{CONTENT_TYPE, HeaderValue};
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper::{HeaderMap, Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::graceful::GracefulShutdown;
use tokio::net::TcpListener;

use crate::server::{AppState, Ingress, Verdict, spawn_pool, submit, worker_count};

const LOGS_EXPORT_PATH: &str = "/opentelemetry.proto.collector.logs.v1.LogsService/Export";

/// A minimal gRPC response body: an optional framed message, then trailers.
struct GrpcBody {
    data: Option<Bytes>,
    trailers: Option<HeaderMap>,
}

impl Body for GrpcBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let this = self.get_mut();
        if let Some(data) = this.data.take() {
            return Poll::Ready(Some(Ok(Frame::data(data))));
        }
        if let Some(trailers) = this.trailers.take() {
            return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
        }
        Poll::Ready(None)
    }
}

/// Canonical grpc-status trailer value (avoids fallible construction).
fn status_value(code: u8) -> HeaderValue {
    match code {
        0 => HeaderValue::from_static("0"),
        3 => HeaderValue::from_static("3"),
        8 => HeaderValue::from_static("8"),
        12 => HeaderValue::from_static("12"),
        14 => HeaderValue::from_static("14"),
        _ => HeaderValue::from_static("2"), // UNKNOWN
    }
}

/// HTTP 200 + `content-type: application/grpc`; body carries the grpc-status.
fn grpc_response(status_code: u8, with_message: bool) -> Response<GrpcBody> {
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", status_value(status_code));
    // Empty `ExportLogsServiceResponse` framed: flag=0, length=0.
    let data = with_message.then(|| Bytes::from_static(&[0, 0, 0, 0, 0]));
    let mut resp = Response::new(GrpcBody {
        data,
        trailers: Some(trailers),
    });
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/grpc"));
    resp
}

async fn handle_grpc(
    state: Arc<AppState>,
    ingress: Ingress,
    req: Request<Incoming>,
) -> Response<GrpcBody> {
    if req.method() != Method::POST || req.uri().path() != LOGS_EXPORT_PATH {
        return grpc_response(12, false); // UNIMPLEMENTED
    }
    let content_type_ok = req
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.starts_with("application/grpc"));
    if !content_type_ok {
        return grpc_response(3, false); // INVALID_ARGUMENT
    }

    // Bound the read (+5 for the frame header) to the configured max body size.
    let max = state.pipeline.load().max_body_bytes();
    let framed = match Limited::new(req.into_body(), max + 5).collect().await {
        Ok(body) => body.to_bytes(),
        Err(_) => return grpc_response(8, false), // RESOURCE_EXHAUSTED
    };

    // gRPC frame: [compression flag: 1][length: 4 BE][message].
    if framed.len() < 5 {
        return grpc_response(3, false);
    }
    if framed[0] != 0 {
        return grpc_response(12, false); // compressed — UNIMPLEMENTED
    }
    let len = u32::from_be_bytes([framed[1], framed[2], framed[3], framed[4]]) as usize;
    if framed.len() < 5 + len {
        return grpc_response(3, false);
    }
    let message = framed.slice(5..5 + len); // zero-copy view of the request body

    // Hand off to a pipeline worker and await the verdict (`core/01` §3.2).
    match submit(&ingress, message).await {
        Verdict::Accepted => grpc_response(0, true),
        Verdict::Malformed => grpc_response(3, false), // INVALID_ARGUMENT
        Verdict::ForwardFailed => grpc_response(14, false), // UNAVAILABLE
    }
}

/// Serve gRPC (HTTP/2) until `shutdown` resolves, then drain in-flight requests.
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
                        tracing::warn!(error = %err, "gRPC accept failed");
                        continue;
                    }
                };
                let io = TokioIo::new(stream);
                let state = state.clone();
                let ingress = ingress.clone();
                let svc = service_fn(move |req| {
                    let state = state.clone();
                    let ingress = ingress.clone();
                    async move { Ok::<_, Infallible>(handle_grpc(state, ingress, req).await) }
                });
                let conn = http2::Builder::new(TokioExecutor::new()).serve_connection(io, svc);
                let watched = graceful.watch(conn);
                tokio::spawn(async move {
                    if let Err(err) = watched.await {
                        tracing::debug!(error = %err, "gRPC connection closed with error");
                    }
                });
            }
            _ = &mut shutdown => {
                tracing::info!("shutdown signal received — draining in-flight gRPC requests");
                break;
            }
        }
    }

    graceful.shutdown().await;
    Ok(())
}
