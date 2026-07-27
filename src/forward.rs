//! Destination forwarder: POST the governed OTLP payload to the configured
//! upstream (`export.otlp_endpoint`) over OTLP/HTTP, on `http://` or `https://`.
//!
//! TLS uses rustls (ring) with the OS trust store, falling back to the bundled
//! webpki roots — so real vendor endpoints (Datadog / Splunk / New Relic, all
//! HTTPS) work out of the box, and enterprise custom CAs are honored via the OS
//! store.
//!
//! The single contiguous copy here ([`AssembledPayload::contiguous`]) is the
//! documented transport-edge exception to the zero-copy law (`core/02` §3.2):
//! the HTTP body must be one buffer.

use archiv_export::AssembledPayload;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Method, Request};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;

/// Pooled OTLP/HTTP(S) client shared across requests (cheap to clone).
pub type HttpClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// Production client: OS trust store, falling back to bundled webpki roots.
pub fn build_client() -> HttpClient {
    let connector = match HttpsConnectorBuilder::new().with_native_roots() {
        Ok(builder) => builder.https_or_http().enable_http1().build(),
        Err(err) => {
            tracing::warn!(error = %err, "OS trust store unavailable — using bundled webpki roots");
            HttpsConnectorBuilder::new()
                .with_webpki_roots()
                .https_or_http()
                .enable_http1()
                .build()
        }
    };
    Client::builder(TokioExecutor::new()).build(connector)
}

/// Build a client from an explicit rustls config (tests: trust a private CA).
pub fn build_client_with_tls(config: rustls::ClientConfig) -> HttpClient {
    let connector = HttpsConnectorBuilder::new()
        .with_tls_config(config)
        .https_or_http()
        .enable_http1()
        .build();
    Client::builder(TokioExecutor::new()).build(connector)
}

#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    #[error("unsupported destination scheme in `{0}` (expected http:// or https://)")]
    UnsupportedScheme(String),
    #[error("building forward request: {0}")]
    Request(String),
    #[error("sending to destination: {0}")]
    Send(String),
    #[error("destination returned HTTP {0}")]
    Status(u16),
}

/// Forward one assembled payload to `{endpoint}/v1/logs`.
pub async fn forward(
    client: &HttpClient,
    endpoint: &str,
    payload: &AssembledPayload,
) -> Result<(), ForwardError> {
    if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
        return Err(ForwardError::UnsupportedScheme(endpoint.to_string()));
    }

    let url = format!("{}/v1/logs", endpoint.trim_end_matches('/'));
    let body = Bytes::from(payload.contiguous()); // documented transport-edge copy
    let req = Request::builder()
        .method(Method::POST)
        .uri(url)
        .header(hyper::header::CONTENT_TYPE, "application/x-protobuf")
        .body(Full::new(body))
        .map_err(|e| ForwardError::Request(e.to_string()))?;

    let resp = client
        .request(req)
        .await
        .map_err(|e| ForwardError::Send(e.to_string()))?;
    let status = resp.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(ForwardError::Status(status.as_u16()))
    }
}
