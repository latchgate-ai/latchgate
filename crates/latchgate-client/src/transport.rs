//! Shared HTTP/UDS transport layer for LatchGate gate communication.
//!
//! Provides a [`Transport`] enum that abstracts over Unix domain socket
//! and TCP/HTTP transports. Used by both the CLI [`super::GateClient`]
//! and the MCP adapter's gate client.
//!
//! # Security
//!
//! - UDS transport is the default and preferred mode. Only processes with
//!   filesystem access to the socket can reach the gate.
//! - TCP/HTTP requires `unsafe_expose_http = true` in latchgate.toml.

use std::time::Duration;

#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::sync::Arc;

#[cfg(unix)]
use bytes::Bytes;
#[cfg(unix)]
use http_body_util::{BodyExt, Full};
#[cfg(unix)]
use hyper_util::client::legacy::Client as HyperClient;
#[cfg(unix)]
use hyper_util::rt::TokioExecutor;
#[cfg(unix)]
use tower::Service;

use latchgate_config::Config;

use super::ClientError;

/// Timeout for UDS requests. The HTTP transport uses reqwest's built-in
/// 30s timeout; the UDS path (hyper) has no equivalent, so we enforce it
/// explicitly via `tokio::time::timeout`.
///
/// 5 seconds is generous for a local-socket round-trip while still failing
/// fast enough to keep the TUI responsive when a gate process has hung.
#[cfg(unix)]
const UDS_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// hyper connector that routes all requests to a fixed Unix domain socket,
/// ignoring the URI host. Connection-pooled via `hyper_util::client::legacy`.
#[cfg(unix)]
#[derive(Clone)]
struct UdsConnector {
    path: Arc<PathBuf>,
}

#[cfg(unix)]
impl Service<hyper::Uri> for UdsConnector {
    type Response = hyper_util::rt::TokioIo<tokio::net::UnixStream>;
    type Error = std::io::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: hyper::Uri) -> Self::Future {
        let path = Arc::clone(&self.path);
        Box::pin(async move {
            let stream = tokio::net::UnixStream::connect(path.as_path()).await?;
            Ok(hyper_util::rt::TokioIo::new(stream))
        })
    }
}

#[derive(Clone)]
enum TransportInner {
    /// Unix domain socket with connection pooling.
    #[cfg(unix)]
    Uds(Box<HyperClient<UdsConnector, Full<Bytes>>>),
    /// Standard TCP/HTTP via reqwest.
    Http(reqwest::Client),
}

/// Shared transport for gate communication. Supports Unix domain socket
/// (default, secure) and TCP/HTTP (dev only).
///
#[derive(Clone)]
pub struct Transport {
    inner: TransportInner,
    /// Base URL for DPoP `htu` signing and URI construction. Must match
    base_url: String,
    /// When set, HTTP requests are sent to this address instead of
    /// `base_url`. Used when the admin listener is on a different port
    connect_base: Option<String>,
}

impl Transport {
    /// Build a transport from the gate config, connecting to the **admin**
    /// socket (`listen_admin_uds_path`).
    ///
    /// Operator tools (CLI, TUI) use admin endpoints (`/v1/admin/*`,
    /// `/v1/audit/*`, `/v1/approvals/*`) which are served only on the admin
    /// socket. The admin router also serves client-visible routes (action
    /// list, schemas) so operator tools don't need a separate connection.
    pub fn from_config(config: &Config) -> Result<Self, ClientError> {
        let public_base = if config.listener.public_base_url.is_empty() {
            "http://localhost".to_string()
        } else {
            config
                .listener
                .public_base_url
                .trim_end_matches('/')
                .to_string()
        };

        if config.listener.unsafe_expose_http {
            if let Some(addr) = config.listener.listen_admin_http_addr {
                return Self::http_with_signing_base(format!("http://{addr}"), public_base);
            }
            if let Some(addr) = config.listener.listen_http_addr {
                return Self::http_with_signing_base(format!("http://{addr}"), public_base);
            }
        }
        Ok(Self::uds(
            config.listener.listen_admin_uds_path.clone(),
            public_base,
        ))
    }

    /// Create a UDS transport.
    ///
    /// `socket_path` is the filesystem path to the gate's Unix socket.
    /// `public_base_url` is used for URI construction in HTTP headers and
    /// DPoP `htu` binding — must match the server's `public_base_url`.
    #[cfg(unix)]
    pub fn uds(socket_path: String, public_base_url: String) -> Self {
        let connector = UdsConnector {
            path: Arc::new(PathBuf::from(socket_path)),
        };
        let hyper_client = HyperClient::builder(TokioExecutor::new()).build(connector);
        Self {
            inner: TransportInner::Uds(Box::new(hyper_client)),
            base_url: public_base_url.trim_end_matches('/').to_string(),
            connect_base: None,
        }
    }

    /// Stub for non-Unix: UDS is not available.
    #[cfg(not(unix))]
    pub fn uds(_socket_path: String, _public_base_url: String) -> Self {
        panic!("UDS transport is not available on this platform")
    }

    /// Create a TCP/HTTP transport.
    pub fn http(base_url: String) -> Result<Self, ClientError> {
        Self::http_with_signing_base(base_url.clone(), base_url)
    }

    /// HTTP transport where the connection target differs from the DPoP
    /// signing base.
    ///
    /// `connect_base` is the actual HTTP address to send requests to (e.g.
    /// the admin listener on port 3001). `signing_base` is the
    /// `public_base_url` used to construct DPoP `htu` claims — it must
    /// match what the server validates against.
    pub fn http_with_signing_base(
        connect_base: String,
        signing_base: String,
    ) -> Result<Self, ClientError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| {
                ClientError::Transport(format!("TLS backend initialization failed: {e}"))
            })?;
        Ok(Self {
            inner: TransportInner::Http(client),
            base_url: signing_base.trim_end_matches('/').to_string(),
            connect_base: Some(connect_base.trim_end_matches('/').to_string()),
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn full_url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }

    /// Send an HTTP request and return `(status_code, response_body)`.
    ///
    /// `path` is an absolute path (e.g. `/v1/actions`). For UDS, the path
    /// is combined with `base_url` for the HTTP request line; the actual
    /// connection goes to the socket. For HTTP, it's appended to `base_url`.
    ///
    /// `headers` are additional request headers as `(name, value)` pairs.
    pub async fn request(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        headers: &[(&str, &str)],
    ) -> Result<(u16, String), ClientError> {
        match &self.inner {
            #[cfg(unix)]
            TransportInner::Uds(client) => {
                self.uds_request(client, method, path, body, headers).await
            }
            TransportInner::Http(client) => {
                self.http_request(client, method, path, body, headers).await
            }
        }
    }

    #[cfg(unix)]
    async fn uds_request(
        &self,
        client: &HyperClient<UdsConnector, Full<Bytes>>,
        method: &str,
        path: &str,
        body: &[u8],
        headers: &[(&str, &str)],
    ) -> Result<(u16, String), ClientError> {
        let uri = self
            .full_url(path)
            .parse::<hyper::Uri>()
            .map_err(|e| ClientError::Transport(e.to_string()))?;

        let mut builder = hyper::Request::builder().method(method).uri(uri);
        if !body.is_empty() {
            builder = builder.header("content-type", "application/json");
        }
        for &(name, value) in headers {
            builder = builder.header(name, value);
        }
        let req = builder
            .body(Full::new(Bytes::copy_from_slice(body)))
            .map_err(|e| ClientError::Transport(e.to_string()))?;

        // Wrap both the request send and the body read in a single timeout.
        // hyper (unlike reqwest) has no built-in request timeout, so without
        // this a dead or half-open socket blocks the caller indefinitely.
        let (status, text) = tokio::time::timeout(UDS_REQUEST_TIMEOUT, async {
            let resp = client
                .request(req)
                .await
                .map_err(|e| ClientError::Transport(diagnose_transport(e.to_string())))?;

            let status = resp.status().as_u16();
            let bytes = resp
                .into_body()
                .collect()
                .await
                .map_err(|e| ClientError::Transport(e.to_string()))?
                .to_bytes();
            let text = String::from_utf8_lossy(&bytes).into_owned();

            Ok::<(u16, String), ClientError>((status, text))
        })
        .await
        .map_err(|_| {
            ClientError::NotReachable(
                "UDS request timed out — gate may be unresponsive. \
                 Check gate logs or restart with `latchgate up`."
                    .into(),
            )
        })??;

        if status >= 400 {
            return Err(ClientError::Http { status, body: text });
        }
        Ok((status, text))
    }

    async fn http_request(
        &self,
        client: &reqwest::Client,
        method: &str,
        path: &str,
        body: &[u8],
        headers: &[(&str, &str)],
    ) -> Result<(u16, String), ClientError> {
        let url = match &self.connect_base {
            Some(base) => format!("{base}{path}"),
            None => self.full_url(path),
        };
        let mut builder = match method {
            "POST" => client.post(&url),
            "PUT" => client.put(&url),
            "DELETE" => client.delete(&url),
            _ => client.get(&url),
        };
        if !body.is_empty() {
            builder = builder
                .header("content-type", "application/json")
                .body(body.to_vec());
        }
        for &(name, value) in headers {
            builder = builder.header(name, value);
        }
        let resp = builder
            .send()
            .await
            .map_err(|e| ClientError::NotReachable(diagnose_transport(e.to_string())))?;

        let status = resp.status().as_u16();
        let text = resp
            .text()
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;

        if status >= 400 {
            return Err(ClientError::Http { status, body: text });
        }
        Ok((status, text))
    }
}

/// Enrich raw transport errors with human-readable diagnostics for common
/// failure modes.
pub fn diagnose_transport(raw: String) -> String {
    let lower = raw.to_lowercase();

    if lower.contains("no such file or directory") || lower.contains("not found") {
        format!(
            "{raw} — hint: gate socket not found. Is `latchgate serve` running? \
             Check gate_socket path or use --gate-url for HTTP."
        )
    } else if lower.contains("connection refused") {
        format!(
            "{raw} — hint: connection refused. Is the LatchGate gate running? \
             Start with: latchgate up"
        )
    } else if lower.contains("permission denied") {
        format!(
            "{raw} — hint: permission denied on gate socket. Check file permissions \
             (socket mode should be 0660) and group membership."
        )
    } else if lower.contains("broken pipe") || lower.contains("connection reset") {
        format!(
            "{raw} — hint: gate closed the connection. It may have restarted or \
             shut down. Check gate logs."
        )
    } else {
        raw
    }
}
