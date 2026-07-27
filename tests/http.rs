//! Live network end-to-end: start the agent's OTLP/HTTP receiver on an
//! ephemeral port, POST a real OTLP request over HTTP, and assert the governed
//! output reaches a mock destination — proving Archiv works as a proxy.
#![allow(clippy::expect_used, clippy::unwrap_used)] // test setup: panic on failure is intended

mod common;

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use archiv_agent::forward;
use archiv_agent::pipeline::Pipeline;
use archiv_agent::server::{self, AppState};
use archiv_config::AgentConfig;
use bytes::Bytes;
use common::{Rec, request};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

const TRACE: [u8; 16] = [0x11; 16];

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

/// A destination that records every request body it receives.
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

/// Start the agent's receiver on an ephemeral port; returns its base URL.
async fn start_agent(config_yaml: &str, forward_endpoint: Option<String>) -> String {
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
        let _ = server::serve(listener, state, std::future::pending::<()>()).await;
    });
    format!("http://{addr}")
}

async fn post(base_url: &str, body: Vec<u8>) -> StatusCode {
    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("{base_url}/v1/logs"))
        .body(Full::new(Bytes::from(body)))
        .unwrap();
    client.request(req).await.unwrap().status()
}

#[tokio::test]
async fn forwards_governed_output_to_destination() {
    let (dest_url, mut received) = start_mock_destination().await;
    let agent_url = start_agent(EMAIL_KEEP_ALL, Some(dest_url)).await;

    let input = request(&[Rec {
        body: "mail alice@corp.io now",
        trace_id: Some(&TRACE),
        attrs: vec![],
        severity: None,
    }]);
    let status = post(&agent_url, input).await;
    assert_eq!(status, StatusCode::OK);

    // The destination must receive the *redacted* request, byte-for-byte.
    let got = tokio::time::timeout(Duration::from_secs(5), received.recv())
        .await
        .expect("destination received a request within 5s")
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
async fn validate_only_mode_accepts_without_forwarding() {
    let agent_url = start_agent(EMAIL_KEEP_ALL, None).await;
    let input = request(&[Rec {
        body: "no destination configured",
        trace_id: Some(&TRACE),
        attrs: vec![],
        severity: None,
    }]);
    assert_eq!(post(&agent_url, input).await, StatusCode::OK);
}

#[tokio::test]
async fn malformed_body_returns_400() {
    let agent_url = start_agent("sampling:\n  default_target: 100\n", None).await;
    assert_eq!(
        post(&agent_url, vec![0xFF; 40]).await,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn oversized_body_returns_413() {
    let agent_url = start_agent("limits:\n  max_body_bytes: 8\n", None).await;
    assert_eq!(
        post(&agent_url, vec![0u8; 64]).await,
        StatusCode::PAYLOAD_TOO_LARGE
    );
}

#[tokio::test]
async fn wrong_path_returns_404() {
    let agent_url = start_agent("sampling:\n  default_target: 100\n", None).await;
    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("{agent_url}/wrong"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    assert_eq!(
        client.request(req).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
}
