//! End-to-end wiring of `archiv-metrics` (`core/06`): drive real OTLP requests
//! through the live HTTP receiver, then drain the shared register and assert the
//! aggregate matches — proving the `Stats → Sample → Aggregate` mapping in
//! `server::run` is correct. Validate-only mode (no destination) keeps the test
//! focused on the metrics path.
#![allow(clippy::expect_used, clippy::unwrap_used)] // test setup: panic on failure is intended

mod common;

use std::sync::Arc;

use archiv_agent::forward;
use archiv_agent::pipeline::Pipeline;
use archiv_agent::server::{self, AppState};
use archiv_config::AgentConfig;
use archiv_metrics::Metrics;
use bytes::Bytes;
use common::{Rec, request};
use http_body_util::Full;
use hyper::{Method, Request, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

const TRACE: [u8; 16] = [0x22; 16];

/// Start the receiver on an ephemeral port; return its URL and the metrics
/// register the server records into (so the test can drain it).
async fn start_agent(config_yaml: &str) -> (String, Arc<Metrics>) {
    let pipeline = Pipeline::from_config(AgentConfig::from_yaml(config_yaml).unwrap()).unwrap();
    let listener = server::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let metrics = Arc::new(Metrics::new(0));
    let state = Arc::new(AppState {
        pipeline: arc_swap::ArcSwap::from_pointee(pipeline),
        forward_endpoint: None, // validate-only: isolate the metrics path
        client: forward::build_client(),
        metrics: metrics.clone(),
        spool: None,
        channel_capacity: 8192,
    });
    tokio::spawn(async move {
        let _ = server::serve(listener, state, std::future::pending::<()>()).await;
    });
    (format!("http://{addr}"), metrics)
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

const KEEP_ALL_REDACT_EMAIL: &str = r#"
sampling:
  default_target: 100
redaction:
  regex_rules:
    - name: email
      pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
      mask: "[REDACTED:email]"
      fields: [body]
"#;

#[tokio::test]
async fn aggregate_counts_kept_and_redacted_records() {
    let (url, metrics) = start_agent(KEEP_ALL_REDACT_EMAIL).await;

    // Two requests, one record each, each carrying one email.
    for _ in 0..2 {
        let body = request(&[Rec {
            body: "ping alice@corp.io ok",
            trace_id: Some(&TRACE),
            attrs: vec![],
            severity: None,
        }]);
        assert_eq!(post(&url, body).await, StatusCode::OK);
    }

    let agg = metrics.flush(0, archiv_metrics::FLUSH_INTERVAL_SECS as i64 * 1000);
    assert_eq!(agg.seq, 0);
    assert_eq!(agg.events_in, 2, "two records ingested");
    assert_eq!(agg.events_exported, 2, "target 100 keeps all");
    assert_eq!(agg.events_sampled_out, 0);
    assert_eq!(agg.redaction_count, 2, "one email redacted per record");
    assert_eq!(agg.failopen_count, 0, "no governance stage bypassed");
    assert!(agg.bytes_in > 0);

    // Tumbling: the next window starts empty.
    assert_eq!(metrics.flush(0, 1).events_in, 0);
}

#[tokio::test]
async fn aggregate_counts_sampled_out_and_bytes_saved() {
    let (url, metrics) = start_agent("sampling:\n  default_target: 0\n").await;

    let body = request(&[Rec {
        body: "this record is dropped by sampling",
        trace_id: Some(&TRACE),
        attrs: vec![],
        severity: None,
    }]);
    assert_eq!(post(&url, body).await, StatusCode::OK);

    let agg = metrics.flush(0, 10_000);
    assert_eq!(agg.events_in, 1);
    assert_eq!(agg.events_sampled_out, 1, "target 0 drops all");
    assert_eq!(agg.events_exported, 0);
    assert!(
        agg.bytes_dropped > 0,
        "dropping the record shrinks the output → real savings"
    );
    assert!(agg.bytes_exported < agg.bytes_in);
}
