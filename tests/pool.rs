//! Ingest decoupling (`core/01` §3.2): with a deliberately tiny work queue,
//! many concurrent requests must all still succeed — the bounded queue applies
//! backpressure (senders await a free slot) and **never drops**. Synthetic data
//! only (`docs/engineering/02` §6).
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

#[tokio::test]
async fn tiny_queue_backpressures_never_drops_under_concurrency() {
    // Capacity 2, validate-only (fast processing) — force the queue to fill.
    let pipeline = Pipeline::from_config(
        AgentConfig::from_yaml("sampling:\n  default_target: 100\n").unwrap(),
    )
    .unwrap();
    let state = Arc::new(AppState {
        pipeline: arc_swap::ArcSwap::from_pointee(pipeline),
        forward_endpoint: None,
        client: forward::build_client(),
        metrics: Arc::new(Metrics::new(0)),
        spool: None,
        channel_capacity: 2,
    });
    let listener = server::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = server::serve(listener, state, std::future::pending::<()>()).await;
    });

    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let payload = request(&[Rec {
        body: "concurrent record",
        trace_id: Some(&[0x44; 16]),
        attrs: vec![],
        severity: None,
    }]);

    // Fire 64 requests at once against a 2-deep queue.
    let mut handles = Vec::new();
    for _ in 0..64 {
        let client = client.clone();
        let base = base.clone();
        let payload = payload.clone();
        handles.push(tokio::spawn(async move {
            let req = Request::builder()
                .method(Method::POST)
                .uri(format!("{base}/v1/logs"))
                .body(Full::new(Bytes::from(payload)))
                .unwrap();
            client.request(req).await.unwrap().status()
        }));
    }

    // Every request completes with 200 — the tight queue delayed, never dropped.
    for h in handles {
        assert_eq!(h.await.unwrap(), StatusCode::OK);
    }
}
