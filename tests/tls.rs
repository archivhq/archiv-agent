//! HTTPS forwarding end-to-end: a self-signed HTTPS destination, and the agent
//! forwarding governed output to it over TLS (rustls). Proves Archiv can talk
//! to real (HTTPS) telemetry vendors.
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
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;

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

fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// HTTPS destination presenting `cert`/`key`; records each received body.
async fn start_https_destination(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> (u16, mpsc::UnboundedReceiver<Vec<u8>>) {
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let io = TokioIo::new(tls);
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
    (port, rx)
}

#[tokio::test]
async fn forwards_over_tls_to_https_destination() {
    ensure_crypto_provider();

    // Self-signed cert valid for "localhost" — used by the destination and
    // trusted by the agent's forward client.
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = certified.cert.der().clone();
    let key_der =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));

    let (dest_port, mut received) = start_https_destination(cert_der.clone(), key_der).await;
    let dest_url = format!("https://localhost:{dest_port}");

    // Agent forward client trusts the self-signed cert.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let client = forward::build_client_with_tls(client_config);

    // Start the agent forwarding to the HTTPS destination.
    let pipeline = Pipeline::from_config(AgentConfig::from_yaml(EMAIL_KEEP_ALL).unwrap()).unwrap();
    let listener = server::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let agent_addr = listener.local_addr().unwrap();
    let state = Arc::new(AppState {
        pipeline: arc_swap::ArcSwap::from_pointee(pipeline),
        forward_endpoint: Some(dest_url),
        client,
        metrics: Arc::new(archiv_metrics::Metrics::new(0)),
        spool: None,
        channel_capacity: 8192,
    });
    tokio::spawn(async move {
        let _ = server::serve(listener, state, std::future::pending::<()>()).await;
    });

    // POST an email log to the agent (plain HTTP); the HTTPS leg is the forward.
    let input = request(&[Rec {
        body: "mail alice@corp.io now",
        trace_id: Some(&TRACE),
        attrs: vec![],
        severity: None,
    }]);
    let poster = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{agent_addr}/v1/logs"))
        .body(Full::new(Bytes::from(input)))
        .unwrap();
    assert_eq!(poster.request(req).await.unwrap().status(), StatusCode::OK);

    // The HTTPS destination received the redacted request, byte-for-byte.
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
