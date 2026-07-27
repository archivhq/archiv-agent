//! Disk spool (`core/07`): durability, FIFO drain, backpressure-when-full,
//! crash recovery, and the end-to-end "destination down → 200 + spooled" path
//! through the live HTTP receiver. Synthetic data only (`docs/engineering/02` §6).
#![allow(clippy::expect_used, clippy::unwrap_used)] // test setup: panic on failure is intended

mod common;

use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use archiv_agent::forward;
use archiv_agent::pipeline::Pipeline;
use archiv_agent::server::{self, AppState};
use archiv_agent::spool::{DrainOutcome, Spool};
use archiv_config::AgentConfig;
use archiv_metrics::Metrics;
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

static UNIQ: AtomicU64 = AtomicU64::new(0);

/// A fresh, unique temp directory for one test's spool.
fn temp_dir(tag: &str) -> PathBuf {
    let n = UNIQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("archiv-spool-{tag}-{}-{n}", std::process::id()))
}

/// A destination that records every request body it receives.
async fn mock_destination() -> (String, mpsc::UnboundedReceiver<Vec<u8>>) {
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

/// A URL whose port is guaranteed closed → connections are refused.
async fn dead_endpoint() -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    format!("http://{addr}")
}

#[tokio::test]
async fn push_then_drain_delivers_fifo_and_empties() {
    let dir = temp_dir("drain");
    let spool = Spool::open(&dir, 1 << 20).await.unwrap();
    let (dest, mut rx) = mock_destination().await;
    let client = forward::build_client();

    for i in 0u8..3 {
        spool.push(&Bytes::from(vec![i; 8])).await.unwrap();
    }
    assert_eq!(spool.stats().await, (3, 24));

    // Drain to the live destination until empty.
    let mut delivered = 0;
    loop {
        match spool.drain_once(&client, &dest).await {
            DrainOutcome::Delivered => delivered += 1,
            DrainOutcome::Idle => break,
            DrainOutcome::Retry => panic!("live destination should not retry"),
        }
    }
    assert_eq!(delivered, 3);
    assert_eq!(spool.stats().await, (0, 0));

    // FIFO order preserved: payloads arrive 0,1,2.
    for i in 0u8..3 {
        let got = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("received")
            .expect("open");
        assert_eq!(got, vec![i; 8]);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn full_spool_backpressures_without_eviction() {
    let dir = temp_dir("full");
    let spool = Spool::open(&dir, 16).await.unwrap(); // tiny cap
    spool.push(&Bytes::from(vec![1u8; 10])).await.unwrap(); // fits (10/16)

    // 10 more would exceed 16 → Full, and nothing is evicted.
    let err = spool.push(&Bytes::from(vec![2u8; 10])).await.unwrap_err();
    assert!(matches!(err, archiv_agent::spool::SpoolError::Full { .. }));
    assert_eq!(
        spool.stats().await,
        (1, 10),
        "the first payload is untouched"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn recovery_recounts_and_resumes_sequence() {
    let dir = temp_dir("recover");
    {
        let spool = Spool::open(&dir, 1 << 20).await.unwrap();
        spool.push(&Bytes::from(vec![9u8; 5])).await.unwrap();
        spool.push(&Bytes::from(vec![9u8; 7])).await.unwrap();
    } // drop — simulate restart

    let spool = Spool::open(&dir, 1 << 20).await.unwrap();
    assert_eq!(spool.stats().await, (2, 12), "backlog recovered");

    // A stray .tmp is swept, not counted.
    std::fs::write(dir.join("00000000000000000099.otlp.tmp"), b"partial").unwrap();
    let spool2 = Spool::open(&dir, 1 << 20).await.unwrap();
    assert_eq!(spool2.stats().await, (2, 12));

    // New push resumes the sequence without colliding, and all drain out.
    spool2.push(&Bytes::from(vec![9u8; 3])).await.unwrap();
    let (dest, _rx) = mock_destination().await;
    let client = forward::build_client();
    let mut delivered = 0;
    while spool2.drain_once(&client, &dest).await == DrainOutcome::Delivered {
        delivered += 1;
    }
    assert_eq!(delivered, 3);
    assert_eq!(spool2.stats().await, (0, 0));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn drain_leaves_payload_when_destination_down() {
    let dir = temp_dir("down");
    let spool = Spool::open(&dir, 1 << 20).await.unwrap();
    spool.push(&Bytes::from(vec![7u8; 12])).await.unwrap();

    let dead = dead_endpoint().await;
    let client = forward::build_client();
    assert_eq!(
        spool.drain_once(&client, &dead).await,
        DrainOutcome::Retry,
        "down destination → Retry, payload kept"
    );
    assert_eq!(spool.stats().await, (1, 12));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn unreadable_payload_remains_queued_until_restored() {
    let dir = temp_dir("unreadable");
    let spool = Spool::open(&dir, 1 << 20).await.unwrap();
    let payload = Bytes::from_static(b"held payload");
    let seq = spool.push(&payload).await.unwrap();
    let path = dir.join(format!("{seq:020}.otlp"));
    let held = dir.join(format!("{seq:020}.otlp.held"));
    std::fs::rename(&path, &held).unwrap();

    let (dest, mut received) = mock_destination().await;
    let client = forward::build_client();
    assert_eq!(spool.drain_once(&client, &dest).await, DrainOutcome::Retry);
    assert_eq!(spool.stats().await, (1, payload.len() as u64));

    std::fs::rename(&held, &path).unwrap();
    assert_eq!(
        spool.drain_once(&client, &dest).await,
        DrainOutcome::Delivered
    );
    assert_eq!(received.recv().await.unwrap(), payload.as_ref());
    assert_eq!(spool.stats().await, (0, 0));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn server_spools_on_forward_failure_and_returns_200() {
    let dir = temp_dir("server");
    let spool = Arc::new(Spool::open(&dir, 1 << 20).await.unwrap());
    let pipeline = Pipeline::from_config(
        AgentConfig::from_yaml("sampling:\n  default_target: 100\n").unwrap(),
    )
    .unwrap();
    let state = Arc::new(AppState {
        pipeline: arc_swap::ArcSwap::from_pointee(pipeline),
        forward_endpoint: Some(dead_endpoint().await), // destination down
        client: forward::build_client(),
        metrics: Arc::new(Metrics::new(0)),
        spool: Some(spool.clone()),
        channel_capacity: 8192,
    });

    let listener = server::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = server::serve(listener, state, std::future::pending::<()>()).await;
    });

    let body = request(&[Rec {
        body: "held for retry",
        trace_id: Some(&[0x33; 16]),
        attrs: vec![],
        severity: None,
    }]);
    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("{base}/v1/logs"))
        .body(Full::new(Bytes::from(body)))
        .unwrap();
    // Destination is down, but the agent durably spooled → it honestly accepts.
    assert_eq!(client.request(req).await.unwrap().status(), StatusCode::OK);

    // The governed payload is on disk awaiting retry.
    let (files, bytes) = spool.stats().await;
    assert_eq!(files, 1);
    assert!(bytes > 0);
    let _ = std::fs::remove_dir_all(&dir);
}
