//! Live OTLP/gRPC end-to-end: send a real gRPC `LogsService/Export` over HTTP/2
//! to the agent's :4317 receiver and assert the governed output reaches a mock
//! destination with `grpc-status: 0`.
#![allow(clippy::expect_used, clippy::unwrap_used)] // test setup: panic on failure is intended

mod common;

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use archiv_agent::pipeline::Pipeline;
use archiv_agent::server::{self, AppState};
use archiv_agent::{forward, grpc};
use archiv_config::AgentConfig;
use bytes::Bytes;
use common::{Rec, request};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::CONTENT_TYPE;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

const TRACE: [u8; 16] = [0x11; 16];
const EXPORT_PATH: &str = "/opentelemetry.proto.collector.logs.v1.LogsService/Export";

const EMAIL_KEEP_ALL: &str = r#"
sampling:
  default_target: 100
redaction:
  regex_rules:
    - name: email
      pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
      mask: "[REDACTED:email]"
      fields: [body]
"#;

/// Plain-HTTP destination that records received bodies (the forward leg).
async fn start_mock_destination() -> (String, mpsc::UnboundedReceiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let io = TokioIo::new(stream);
            let tx = tx.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let tx = tx.clone();
                    async move {
                        let body = req.into_body().collect().await.unwrap().to_bytes();
                        let _ = tx.send(body.to_vec());
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::new())))
                    }
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });
    (format!("http://{addr}"), rx)
}

async fn start_grpc_agent(config_yaml: &str, forward_endpoint: Option<String>) -> String {
    let pipeline = Pipeline::from_config(AgentConfig::from_yaml(config_yaml).unwrap()).unwrap();
    let listener = server::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(AppState {
        pipeline: arc_swap::ArcSwap::from_pointee(pipeline),
        forward_endpoint,
        client: forward::build_client(),
        metrics: Arc::new(archiv_metrics::Metrics::new(0)),
        spool: None,
        channel_capacity: 8192,
    });
    tokio::spawn(async move {
        let _ = grpc::serve(listener, state, std::future::pending::<()>()).await;
    });
    format!("http://{addr}")
}

/// Wrap a message in a gRPC length-prefixed frame: [flag=0][len: u32 BE][msg].
fn grpc_frame(msg: Vec<u8>) -> Vec<u8> {
    let mut out = vec![0u8];
    out.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    out.extend_from_slice(&msg);
    out
}

fn h2_client() -> Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>> {
    Client::builder(TokioExecutor::new())
        .http2_only(true)
        .build_http()
}

#[tokio::test]
async fn grpc_export_forwards_redacted_output() {
    let (dest, mut received) = start_mock_destination().await;
    let agent = start_grpc_agent(EMAIL_KEEP_ALL, Some(dest)).await;

    let otlp = request(&[Rec {
        body: "mail alice@corp.io now",
        trace_id: Some(&TRACE),
        attrs: vec![],
        severity: None,
    }]);
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("{agent}{EXPORT_PATH}"))
        .header(CONTENT_TYPE, "application/grpc")
        .header("te", "trailers")
        .body(Full::new(Bytes::from(grpc_frame(otlp))))
        .unwrap();

    let resp = h2_client().request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let collected = resp.into_body().collect().await.unwrap();
    let trailers = collected.trailers().expect("gRPC trailers present");
    assert_eq!(trailers.get("grpc-status").unwrap(), "0", "OK status");

    let got = tokio::time::timeout(Duration::from_secs(5), received.recv())
        .await
        .expect("destination received a request")
        .expect("channel open");
    let expected = request(&[Rec {
        body: "mail [REDACTED:email] now",
        trace_id: Some(&TRACE),
        attrs: vec![],
        severity: None,
    }]);
    assert_eq!(got, expected);
}

#[tokio::test]
async fn grpc_wrong_path_is_unimplemented() {
    let agent = start_grpc_agent("sampling:\n  default_target: 100\n", None).await;
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("{agent}/wrong/Method"))
        .header(CONTENT_TYPE, "application/grpc")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = h2_client().request(req).await.unwrap();
    let collected = resp.into_body().collect().await.unwrap();
    assert_eq!(
        collected.trailers().unwrap().get("grpc-status").unwrap(),
        "12"
    );
}

#[tokio::test]
async fn grpc_malformed_message_is_invalid_argument() {
    let agent = start_grpc_agent(EMAIL_KEEP_ALL, None).await;
    // Well-framed, but the message bytes are garbage OTLP.
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("{agent}{EXPORT_PATH}"))
        .header(CONTENT_TYPE, "application/grpc")
        .body(Full::new(Bytes::from(grpc_frame(vec![0xFF; 20]))))
        .unwrap();
    let resp = h2_client().request(req).await.unwrap();
    let collected = resp.into_body().collect().await.unwrap();
    assert_eq!(
        collected.trailers().unwrap().get("grpc-status").unwrap(),
        "3"
    );
}
