//! Transport layer: UDS (default) and optional TCP.
//!
//! Gate is UDS-first. TCP exposure is an explicit opt-in via `unsafe_expose_http`.
//!
//! # UDS peer credential wiring
//!
//! On UDS connections, the kernel provides the peer process's effective UID,
//! GID, and PID via `SO_PEERCRED` (Linux) / `getpeereid` (macOS). This module
//! extracts these credentials at connection accept time and injects them into
//! every HTTP request as a [`ConnectionContext`] extension.
//!
//! The flow:
//!
//! ```text
//! UnixListener::accept()
//!   => extract_peer_cred(&UnixStream)      // kernel-guaranteed identity
//!   => UdsConnectInfo { peer_cred }        // carried via axum's ConnectInfo
//!   => inject_connection_context middleware // maps to Extension<ConnectionContext>
//!   => lease handler reads ConnectionContext
//!   => IdentityProvider.authenticate(ctx)  // PeerCredProvider uses peer_cred
//! ```
//!
//! SECURITY: `SO_PEERCRED` is kernel-enforced — the peer process cannot forge
//! it. This is the trust anchor for single-host identity bootstrapping.

use std::path::Path;
use std::sync::Arc;

use axum::Router;
use tokio::net::TcpListener;
use tower::ServiceExt;

/// Serve the application over TCP.
///
/// Only called when `unsafe_expose_http = true` is explicitly configured.
/// SECURITY: TCP expands the attack surface beyond UDS-local processes.
///
/// The server drains in-flight connections when `shutdown` resolves, ensuring
/// that mid-execution WASM dispatches produce receipts and audit events before
/// the process exits.
pub async fn serve_http(
    listener: TcpListener,
    app: Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
}

/// Load admin mTLS configuration from PEM files on disk.
///
/// Reads the server certificate chain, private key, and CA certificate from
/// the paths in [`ListenerConfig`]. Returns a [`rustls::ServerConfig`] that:
///   - presents the server certificate chain to connecting clients
///   - requires clients to present a certificate signed by the CA
///   - enforces TLS 1.2+ with safe cipher suite defaults
///
/// SECURITY: the returned config enforces mutual authentication. A client
/// without a valid certificate signed by `admin_tls_ca` is rejected during
/// the TLS handshake — before any HTTP request is parsed. This is the
/// transport-level trust anchor for cross-host admin communication.
///
/// Called once at startup. Cert rotation requires a process restart
/// (acceptable for managed-mode instances with a 1-year cert validity).
pub fn load_admin_tls_config(
    listener: &latchgate_config::ListenerConfig,
) -> std::io::Result<std::sync::Arc<rustls::ServerConfig>> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};
    use std::io;
    use std::sync::Arc;

    let cert_path = listener.admin_tls_cert.as_deref().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "admin_tls_cert not configured")
    })?;
    let key_path = listener.admin_tls_key.as_deref().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "admin_tls_key not configured")
    })?;
    let ca_path = listener.admin_tls_ca.as_deref().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "admin_tls_ca not configured")
    })?;

    // -- Server certificate chain --

    let cert_pem = std::fs::read(cert_path)
        .map_err(|e| io::Error::new(e.kind(), format!("admin_tls_cert ({cert_path}): {e}")))?;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("admin_tls_cert ({cert_path}): {e}"),
            )
        })?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("admin_tls_cert ({cert_path}): no certificates found in PEM"),
        ));
    }

    // -- Server private key --

    let key_pem = std::fs::read(key_path)
        .map_err(|e| io::Error::new(e.kind(), format!("admin_tls_key ({key_path}): {e}")))?;
    let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_slice(&key_pem).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("admin_tls_key ({key_path}): {e}"),
        )
    })?;

    // -- CA certificate for client verification --

    let ca_pem = std::fs::read(ca_path)
        .map_err(|e| io::Error::new(e.kind(), format!("admin_tls_ca ({ca_path}): {e}")))?;
    let ca_certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&ca_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("admin_tls_ca ({ca_path}): {e}"),
            )
        })?;
    if ca_certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("admin_tls_ca ({ca_path}): no certificates found in PEM"),
        ));
    }

    let mut root_store = rustls::RootCertStore::empty();
    for cert in ca_certs {
        root_store.add(cert).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("admin_tls_ca ({ca_path}): invalid certificate: {e}"),
            )
        })?;
    }

    // SECURITY: explicit crypto provider selection avoids ambiguity when
    // multiple providers (ring, aws-lc-rs) are compiled in via transitive deps.
    let crypto_provider = Arc::new(rustls::crypto::ring::default_provider());

    // SECURITY: WebPkiClientVerifier requires every connecting client to
    // present a valid certificate chain rooted in our CA. No anonymous or
    // self-signed client connections are accepted.
    let client_verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(root_store),
        crypto_provider.clone(),
    )
    .build()
    .map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("admin TLS client verifier: {e}"),
        )
    })?;

    let tls_config = rustls::ServerConfig::builder_with_provider(crypto_provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("admin TLS protocol config: {e}"),
            )
        })?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certs, key)
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("admin TLS server config: {e}"),
            )
        })?;

    Ok(Arc::new(tls_config))
}

/// Serve the admin API over TCP with mutual TLS.
///
/// Accepts TCP connections, performs the TLS handshake (rejecting clients
/// without a valid certificate), then serves HTTP/1.1 over the encrypted
/// channel. Each connection is spawned as a separate task.
///
/// SECURITY: mutual TLS is enforced at the transport layer — the `rustls`
/// `ServerConfig` built by [`load_admin_tls_config`] requires client
/// certificates. A client without a valid cert is rejected during the TLS
/// handshake before any HTTP bytes are exchanged.
///
/// When `shutdown` resolves, the listener stops accepting new connections
/// and all active connections are drained gracefully (in-flight requests
/// complete before the function returns).
pub async fn serve_admin_tls(
    listener: TcpListener,
    app: Router,
    tls_acceptor: tokio_rustls::TlsAcceptor,
    allowed_fingerprints: Option<Arc<Vec<String>>>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let (close_tx, close_rx) = tokio::sync::watch::channel(());
    let mut join_set = tokio::task::JoinSet::new();

    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            biased;

            _ = &mut shutdown => break,

            result = listener.accept() => {
                let (tcp_stream, peer_addr) = result?;
                let acceptor = tls_acceptor.clone();
                let app = app.clone();
                let mut close_rx = close_rx.clone();
                let allowed_fps = allowed_fingerprints.clone();

                join_set.spawn(async move {
                    // Phase 1: TLS handshake — rejects invalid/missing client certs.
                    let tls_stream = match acceptor.accept(tcp_stream).await {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::debug!(
                                peer = %peer_addr,
                                error = %e,
                                "admin mTLS handshake rejected",
                            );
                            return;
                        }
                    };

                    // Phase 2: extract client certificate fingerprint.
                    //
                    // SECURITY: the TLS handshake already verified the client cert
                    // chain against our CA. This fingerprint is for audit attribution,
                    // not authentication — authentication happened in Phase 1.
                    let client_cert_fingerprint: Option<std::sync::Arc<str>> = tls_stream
                        .get_ref()
                        .1
                        .peer_certificates()
                        .and_then(|certs| certs.first())
                        .map(|cert| {
                            use sha2::Digest;
                            let digest = sha2::Sha256::digest(cert.as_ref());
                            std::sync::Arc::from(hex::encode(digest))
                        });

                    // Phase 2b: enforce fingerprint allowlist.
                    //
                    // SECURITY: when an allowlist is configured, reject
                    // connections whose client cert fingerprint is not in the
                    // list. This provides per-certificate revocation without
                    // rotating the CA — omitting a fingerprint from the list
                    // is equivalent to revoking the certificate.
                    if let Some(ref allowed) = allowed_fps {
                        let fp_str = client_cert_fingerprint.as_deref().unwrap_or("");
                        if !allowed.iter().any(|a| a == fp_str) {
                            tracing::warn!(
                                peer = %peer_addr,
                                client_cert_sha256 = %fp_str,
                                "admin mTLS connection rejected: fingerprint not in allowlist",
                            );
                            return;
                        }
                    }

                    if let Some(ref fp) = client_cert_fingerprint {
                        tracing::debug!(
                            peer = %peer_addr,
                            client_cert_sha256 = %fp,
                            "admin mTLS connection established",
                        );
                    }

                    // Phase 3: serve HTTP/1.1 over the TLS channel.
                    //
                    // Inject ConnectionContext with the client cert fingerprint
                    // into every request so handlers and identity providers can
                    // read it from request extensions.
                    let io = hyper_util::rt::TokioIo::new(tls_stream);
                    let hyper_service = hyper::service::service_fn(
                        move |req: hyper::Request<hyper::body::Incoming>| {
                            let app = app.clone();
                            let fingerprint = client_cert_fingerprint.clone();
                            async move {
                                let mut req = req.map(axum::body::Body::new);
                                req.extensions_mut().insert(
                                    latchgate_auth::ConnectionContext {
                                        #[cfg(unix)]
                                        peer_cred: None,
                                        bearer_token: None,
                                        client_cert_fingerprint: fingerprint,
                                    },
                                );
                                app.oneshot(req).await
                            }
                        },
                    );

                    let conn = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, hyper_service);
                    tokio::pin!(conn);

                    // Drive the connection, respecting graceful shutdown.
                    loop {
                        tokio::select! {
                            result = conn.as_mut() => {
                                if let Err(e) = result {
                                    tracing::debug!(
                                        peer = %peer_addr,
                                        error = %e,
                                        "admin mTLS connection error",
                                    );
                                }
                                break;
                            }
                            _ = close_rx.changed() => {
                                // Shutdown signal: drain in-flight request,
                                // then let the outer loop break naturally.
                                conn.as_mut().graceful_shutdown();
                            }
                        }
                    }
                });
            }
        }
    }

    // Signal all active connections to begin draining.
    drop(close_tx);

    // Wait for in-flight requests to complete.
    while join_set.join_next().await.is_some() {}

    Ok(())
}

/// Serve the application over a Unix Domain Socket with peer credential
/// extraction.
///
/// Creates the socket parent directory (permissions 0o700) if it does not exist,
/// removes a stale socket from a previous run, binds, then sets socket permissions
/// to 0o600.
///
/// When `shutdown` resolves, the server drains in-flight connections and removes
/// the socket file. This prevents stale sockets from accumulating and ensures
/// mid-execution WASM dispatches complete with full receipt and audit trails.
///
/// SECURITY: every UDS connection's `SO_PEERCRED` is extracted at accept time
/// and injected into request extensions as [`ConnectionContext`]. This is the
/// transport-level trust anchor for [`PeerCredProvider`] identity verification.
/// Without this wiring, `PeerCredProvider` would never receive peer credentials
/// and lease issuance would fail-closed (correct, but non-functional).
#[cfg(unix)]
pub async fn serve_uds(
    path: &Path,
    app: Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::UnixListener;

    if let Some(parent) = path.parent() {
        // SECURITY: create the socket directory with restricted permissions.
        // Only set permissions if we created the directory — we may not own
        // a pre-existing parent (e.g. /tmp) and set_permissions would fail.
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }

    // Remove stale socket — UnixListener::bind returns AddrInUse if path exists.
    // SECURITY: we recreate it with the correct permissions below.
    if path.exists() {
        std::fs::remove_file(path)?;
    }

    let listener = UnixListener::bind(path)?;

    // SECURITY: restrict socket to the owning user only. Group and world
    // access would allow other local users to reach Gate, bypassing the
    // agent sandbox boundary.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;

    // SECURITY: layer the peercred injection middleware onto the router.
    // This middleware runs for every request and converts the transport-level
    // ConnectInfo<UdsConnectInfo> (populated by axum's connect_info mechanism)
    // into an Extension<ConnectionContext> that handlers can extract.
    let app = app.layer(axum::middleware::from_fn(inject_connection_context));

    // Keep a copy of the path for post-shutdown cleanup.
    let socket_path = path.to_path_buf();

    // SECURITY: `into_make_service_with_connect_info` tells axum to call
    // `Connected::connect_info` for every new connection. Our `UdsConnectInfo`
    // impl extracts `SO_PEERCRED` from the raw `UnixStream` at accept time —
    // the only moment the stream is accessible before hyper consumes it.
    let result = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<UdsConnectInfo>(),
    )
    .with_graceful_shutdown(shutdown)
    .await;

    // Clean up the socket file after shutdown. The listener is closed at this
    // point — remove the filesystem entry so the next startup does not need
    // to handle a stale socket race.
    if socket_path.exists() {
        let _ = std::fs::remove_file(&socket_path);
    }

    result
}

/// Transport-level metadata extracted from each UDS connection.
///
/// Populated by axum's `ConnectInfo` mechanism at connection accept time,
/// before the stream is handed to hyper for HTTP parsing. This is the only
/// point where we have access to the raw `UnixStream`.
///
/// SECURITY: `peer_cred` is `None` only when `SO_PEERCRED` extraction fails
/// (e.g. platform limitation). The `PeerCredProvider` treats `None` as
/// unauthenticated and denies the request (fail-closed).
#[cfg(unix)]
#[derive(Clone, Debug)]
pub struct UdsConnectInfo {
    /// Peer credentials from `SO_PEERCRED` / `getpeereid`.
    /// Kernel-guaranteed — cannot be forged by the peer process.
    pub peer_cred: Option<latchgate_auth::identity::PeerCred>,
}

/// Extract `SO_PEERCRED` from the `UnixStream` at connection accept time.
///
/// This is called by axum's serve infrastructure for every new UDS connection.
/// The `IncomingStream::io()` method gives us a reference to the raw stream
/// before hyper consumes it for HTTP parsing.
#[cfg(unix)]
impl
    axum::extract::connect_info::Connected<
        axum::serve::IncomingStream<'_, tokio::net::UnixListener>,
    > for UdsConnectInfo
{
    fn connect_info(target: axum::serve::IncomingStream<'_, tokio::net::UnixListener>) -> Self {
        let peer_cred = latchgate_auth::identity::peercred::extract_peer_cred(target.io());
        Self { peer_cred }
    }
}

/// Middleware that maps transport-level `ConnectInfo<UdsConnectInfo>` into
/// an `Extension<ConnectionContext>` on every request.
///
/// This decouples the transport layer from handlers: request handlers see a
/// uniform `ConnectionContext` regardless of whether identity came from UDS
/// peercred, TLS client certs, or OIDC tokens.
///
/// Reads `ConnectInfo<UdsConnectInfo>` directly from request extensions
/// (inserted by axum's `into_make_service_with_connect_info` before the
/// router's layers run) and transforms it into `Extension<ConnectionContext>`.
#[cfg(unix)]
async fn inject_connection_context(
    mut request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    // Read ConnectInfo directly from request extensions. axum's
    // `into_make_service_with_connect_info` inserts it before the router's
    // layers run, so it is available here.
    let connect_info = request
        .extensions()
        .get::<axum::extract::ConnectInfo<UdsConnectInfo>>()
        .cloned();

    let ctx = match connect_info {
        Some(axum::extract::ConnectInfo(info)) => latchgate_auth::ConnectionContext {
            peer_cred: info.peer_cred,
            bearer_token: None,
            client_cert_fingerprint: None,
        },
        None => {
            // SECURITY: if ConnectInfo is missing (should not happen on UDS
            // with correct wiring), construct an empty context. The
            // PeerCredProvider will see peer_cred=None and deny the request.
            tracing::warn!(
                "UDS request missing ConnectInfo<UdsConnectInfo> — \
                 PeerCredProvider will deny this request"
            );
            latchgate_auth::ConnectionContext::default()
        }
    };
    request.extensions_mut().insert(ctx);
    next.run(request).await
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn temp_socket_path() -> std::path::PathBuf {
        // SECURITY: use full nanoseconds since epoch for uniqueness.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("latchgate-test-{nanos}.sock"))
    }

    fn test_router() -> Router {
        let config = latchgate_config::Config::default();
        let state = crate::test_support::build_app_state(config);
        crate::router(state)
    }

    /// Wait until the socket file exists and a connection succeeds.
    async fn wait_for_uds(path: &std::path::Path) -> tokio::net::UnixStream {
        // Phase 1: wait for socket file to appear.
        for _ in 0..100 {
            if path.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            path.exists(),
            "socket file never appeared at {}",
            path.display()
        );

        // Phase 2: wait until the listener is accepting connections.
        for _ in 0..50 {
            match tokio::net::UnixStream::connect(path).await {
                Ok(s) => return s,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
        panic!("could not connect to UDS at {}", path.display());
    }

    #[tokio::test]
    async fn uds_healthz_returns_200() {
        let path = temp_socket_path();
        let app = test_router();

        let server_path = path.clone();
        tokio::spawn(async move {
            serve_uds(&server_path, app, std::future::pending())
                .await
                .ok();
        });

        let stream = wait_for_uds(&path).await;
        let (mut reader, mut writer) = stream.into_split();
        writer
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();

        let mut response = Vec::new();
        reader.read_to_end(&mut response).await.unwrap();
        let response_str = String::from_utf8_lossy(&response);

        assert!(
            response_str.starts_with("HTTP/1.1 200"),
            "expected HTTP 200, got: {:?}",
            &response_str[..response_str.len().min(80)]
        );
        assert!(
            response_str.contains("\"ok\""),
            "expected status ok in body"
        );

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn uds_stale_socket_removed_on_startup() {
        let path = temp_socket_path();

        std::fs::write(&path, b"stale").unwrap();
        assert!(path.exists());

        let app = test_router();
        let server_path = path.clone();
        tokio::spawn(async move {
            serve_uds(&server_path, app, std::future::pending())
                .await
                .ok();
        });

        let _stream = wait_for_uds(&path).await;

        std::fs::remove_file(&path).ok();
    }

    /// SECURITY regression: Gate UDS socket must not be world-readable.
    ///
    /// A world-readable socket (0o666) would allow any process on the host to
    /// reach Gate, defeating the isolation that UDS-first transport provides.
    /// Correct permissions are 0o600: owner rw only, no group or world access.
    #[tokio::test]
    async fn uds_socket_has_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let path = temp_socket_path();
        let app = test_router();

        let server_path = path.clone();
        tokio::spawn(async move {
            serve_uds(&server_path, app, std::future::pending())
                .await
                .ok();
        });

        wait_for_uds(&path).await;

        let meta = std::fs::metadata(&path).expect("socket must exist after serve_uds");
        let mode = meta.permissions().mode();
        // SECURITY: 0o600 — owner rw only, no group or world access.
        // Removing this assertion = removing a containment boundary.
        assert_eq!(
            mode & 0o777,
            0o600,
            "UDS socket must be 0o600 (owner rw only). \
             Got {:#o}. A more permissive socket exposes Gate to all host processes.",
            mode & 0o777,
        );

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn uds_socket_dir_created_if_missing() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("latchgate-newdir-{nanos}"));
        let path = dir.join("gate.sock");
        assert!(!dir.exists(), "test dir should not exist before test");

        let app = test_router();
        let server_path = path.clone();
        tokio::spawn(async move {
            serve_uds(&server_path, app, std::future::pending())
                .await
                .ok();
        });

        wait_for_uds(&path).await;
        assert!(dir.exists(), "socket directory should have been created");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o700,
                "socket directory must be 0o700 (owner only). Got {:#o}.",
                mode & 0o777,
            );
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    /// SECURITY: verify that lease issuance succeeds over UDS with the
    /// peercred middleware active. Uses NoneProvider (accepts all callers)
    /// to confirm the middleware doesn't break normal request flow.
    #[tokio::test]
    async fn lease_issuance_over_uds_succeeds_with_peercred_context() {
        let path = temp_socket_path();
        let app = test_router();

        let server_path = path.clone();
        tokio::spawn(async move {
            serve_uds(&server_path, app, std::future::pending())
                .await
                .ok();
        });

        let stream = wait_for_uds(&path).await;

        let (_, pk) = latchgate_auth::dpop::generate_dpop_keypair().unwrap();
        let body = serde_json::json!({
            "scopes": ["tools:call"],
            "dpop_jwk": {
                "kty": "EC", "crv": "P-256", "x": pk.x, "y": pk.y,
            }
        });
        let body_bytes = serde_json::to_vec(&body).unwrap();

        let request = format!(
            "POST /v1/leases HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            body_bytes.len()
        );

        let (mut reader, mut writer) = stream.into_split();
        writer.write_all(request.as_bytes()).await.unwrap();
        writer.write_all(&body_bytes).await.unwrap();

        let mut response = Vec::new();
        reader.read_to_end(&mut response).await.unwrap();
        let response_str = String::from_utf8_lossy(&response);

        assert!(
            response_str.starts_with("HTTP/1.1 200"),
            "lease issuance over UDS must succeed (NoneProvider). Got: {:?}",
            &response_str[..response_str.len().min(120)]
        );

        if let Some(body_start) = response_str.find("\r\n\r\n") {
            let body_str = &response_str[body_start + 4..];
            let json: serde_json::Value =
                serde_json::from_str(body_str).expect("response body must be valid JSON");
            assert!(json["lease_jwt"].is_string(), "must contain lease_jwt");
            assert!(json["session_id"].is_string(), "must contain session_id");
        } else {
            panic!("response must have a body");
        }

        std::fs::remove_file(&path).ok();
    }

    /// SECURITY: verify that `extract_peer_cred` returns the correct UID
    /// for the current process on a real UDS connection.
    #[tokio::test]
    #[allow(unsafe_code)] // libc::getuid() in test assertion
    async fn uds_connect_info_extracts_real_peer_cred() {
        use latchgate_auth::identity::peercred::extract_peer_cred;

        let dir = std::env::temp_dir().join(format!(
            "latchgate-ci-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let sock_path = dir.join("test.sock");

        let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();

        let path_clone = sock_path.clone();
        let client_handle = tokio::spawn(async move {
            let _stream = tokio::net::UnixStream::connect(&path_clone).await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        });

        let (stream, _addr) = listener.accept().await.unwrap();
        let cred = extract_peer_cred(&stream);
        assert!(cred.is_some(), "must extract peer creds from real UDS");

        let cred = cred.unwrap();
        // SAFETY: getuid() is always safe to call; it reads the calling
        // process's real UID from the kernel without any side effects.
        let current_uid = unsafe { libc::getuid() };
        assert_eq!(
            cred.uid, current_uid,
            "peer UID must match the current process UID"
        );

        client_handle.await.unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    /// SECURITY: end-to-end test — PeerCredProvider over real UDS.
    ///
    /// Configures PeerCredProvider with the current UID mapped to a principal,
    /// issues a lease over UDS, and verifies success. This proves the full
    /// chain: accept => peercred => ConnectInfo => middleware => handler =>
    /// PeerCredProvider.authenticate() => lease.
    #[tokio::test]
    #[allow(unsafe_code)] // libc::getuid() in test setup
    async fn peercred_provider_end_to_end_over_uds() {
        use latchgate_auth::identity::{
            peercred::PeerCredProvider, PeercredConfig, PeercredPrincipal,
        };
        use std::collections::HashMap;

        // SAFETY: getuid() is always safe — reads real UID with no side effects.
        let current_uid = unsafe { libc::getuid() };

        let peercred_config = PeercredConfig {
            principals: HashMap::from([(
                current_uid.to_string(),
                PeercredPrincipal {
                    principal: "test-agent".to_string(),
                    scopes: vec!["tools:call".into()],
                    owner: None,
                },
            )]),
            allow_unmapped: false,
        };

        let config = latchgate_config::Config::default();
        let state = crate::test_support::build_app_state_with_identity(
            config,
            Box::new(PeerCredProvider::new(peercred_config)),
        );
        let app = crate::router(state);

        let path = temp_socket_path();
        let server_path = path.clone();
        tokio::spawn(async move {
            serve_uds(&server_path, app, std::future::pending())
                .await
                .ok();
        });

        let stream = wait_for_uds(&path).await;

        let (_, pk) = latchgate_auth::dpop::generate_dpop_keypair().unwrap();
        let body = serde_json::json!({
            "scopes": ["tools:call"],
            "dpop_jwk": {
                "kty": "EC", "crv": "P-256", "x": pk.x, "y": pk.y,
            }
        });
        let body_bytes = serde_json::to_vec(&body).unwrap();

        let request = format!(
            "POST /v1/leases HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            body_bytes.len()
        );

        let (mut reader, mut writer) = stream.into_split();
        writer.write_all(request.as_bytes()).await.unwrap();
        writer.write_all(&body_bytes).await.unwrap();

        let mut response = Vec::new();
        reader.read_to_end(&mut response).await.unwrap();
        let response_str = String::from_utf8_lossy(&response);

        assert!(
            response_str.starts_with("HTTP/1.1 200"),
            "PeerCredProvider e2e: lease must succeed when UID is mapped. Got: {:?}",
            &response_str[..response_str.len().min(120)]
        );

        std::fs::remove_file(&path).ok();
    }

    /// SECURITY: unmapped UID is denied by PeerCredProvider over real UDS.
    #[tokio::test]
    async fn unmapped_uid_denied_over_uds_when_allow_unmapped_false() {
        use latchgate_auth::identity::{
            peercred::PeerCredProvider, PeercredConfig, PeercredPrincipal,
        };
        use std::collections::HashMap;

        // Map only UID 99999 — the current process UID will NOT match.
        let peercred_config = PeercredConfig {
            principals: HashMap::from([(
                "99999".to_string(),
                PeercredPrincipal {
                    principal: "other-agent".to_string(),
                    scopes: vec!["tools:call".into()],
                    owner: None,
                },
            )]),
            allow_unmapped: false,
        };

        let config = latchgate_config::Config::default();
        let state = crate::test_support::build_app_state_with_identity(
            config,
            Box::new(PeerCredProvider::new(peercred_config)),
        );
        let app = crate::router(state);

        let path = temp_socket_path();
        let server_path = path.clone();
        tokio::spawn(async move {
            serve_uds(&server_path, app, std::future::pending())
                .await
                .ok();
        });

        let stream = wait_for_uds(&path).await;

        let (_, pk) = latchgate_auth::dpop::generate_dpop_keypair().unwrap();
        let body = serde_json::json!({
            "scopes": ["tools:call"],
            "dpop_jwk": {
                "kty": "EC", "crv": "P-256", "x": pk.x, "y": pk.y,
            }
        });
        let body_bytes = serde_json::to_vec(&body).unwrap();

        let request = format!(
            "POST /v1/leases HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            body_bytes.len()
        );

        let (mut reader, mut writer) = stream.into_split();
        writer.write_all(request.as_bytes()).await.unwrap();
        writer.write_all(&body_bytes).await.unwrap();

        let mut response = Vec::new();
        reader.read_to_end(&mut response).await.unwrap();
        let response_str = String::from_utf8_lossy(&response);

        assert!(
            response_str.starts_with("HTTP/1.1 403"),
            "unmapped UID must be rejected with 403. Got: {:?}",
            &response_str[..response_str.len().min(120)]
        );

        if let Some(body_start) = response_str.find("\r\n\r\n") {
            let body_str = &response_str[body_start + 4..];
            let json: serde_json::Value =
                serde_json::from_str(body_str).expect("error body must be valid JSON");
            assert_eq!(
                json["error"], "identity_forbidden",
                "error code must be identity_forbidden for unmapped UID"
            );
        }

        std::fs::remove_file(&path).ok();
    }

    /// SECURITY regression: PeerCredProvider rejects TCP requests (no peercred).
    ///
    /// Validates: enabling PeerCredProvider on a TCP path (no peercred
    /// middleware) correctly denies requests because ConnectionContext is empty.
    #[tokio::test]
    async fn tcp_without_transport_identity_rejected_when_peercred_provider_enabled() {
        use latchgate_auth::identity::{
            peercred::PeerCredProvider, PeercredConfig, PeercredPrincipal,
        };
        use std::collections::HashMap;

        let peercred_config = PeercredConfig {
            principals: HashMap::from([(
                "1001".to_string(),
                PeercredPrincipal {
                    principal: "agent".to_string(),
                    scopes: vec!["tools:call".into()],
                    owner: None,
                },
            )]),
            allow_unmapped: false,
        };

        let config = latchgate_config::Config::default();
        let state = crate::test_support::build_app_state_with_identity(
            config,
            Box::new(PeerCredProvider::new(peercred_config)),
        );

        // Use the combined router WITHOUT UDS peercred middleware (simulates TCP).
        let app = crate::router(state);

        let (_, pk) = latchgate_auth::dpop::generate_dpop_keypair().unwrap();
        let body = serde_json::json!({
            "scopes": ["tools:call"],
            "dpop_jwk": { "kty": "EC", "crv": "P-256", "x": pk.x, "y": pk.y }
        });

        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/leases")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // SECURITY: PeerCredProvider requires SO_PEERCRED. Without transport
        // metadata, ConnectionContext.peer_cred is None => 401.
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::UNAUTHORIZED,
            "PeerCredProvider must reject TCP requests (no peercred). Got {}",
            resp.status()
        );
    }

    /// Helper: generate a CA keypair + self-signed CA cert, then a server
    /// cert signed by that CA. Writes PEM files into `dir` and returns
    /// a `ListenerConfig` pointing at them.
    fn generate_test_certs(dir: &std::path::Path) -> latchgate_config::ListenerConfig {
        use rcgen::{
            BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
            KeyUsagePurpose,
        };

        // CA keypair + self-signed cert.
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = CertificateParams::new(vec!["LatchGate Test CA".into()]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        // Server keypair + cert signed by CA.
        let server_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut server_params = CertificateParams::new(vec!["latchgate-test".into()]).unwrap();
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        server_params.is_ca = IsCa::NoCa;
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .unwrap();

        // Write PEM files.
        let cert_path = dir.join("server.crt");
        let key_path = dir.join("server.key");
        let ca_path = dir.join("ca.crt");

        std::fs::write(&cert_path, server_cert.pem()).unwrap();
        std::fs::write(&key_path, server_key.serialize_pem()).unwrap();
        std::fs::write(&ca_path, ca_cert.pem()).unwrap();

        latchgate_config::ListenerConfig {
            admin_tls_cert: Some(cert_path.to_string_lossy().into_owned()),
            admin_tls_key: Some(key_path.to_string_lossy().into_owned()),
            admin_tls_ca: Some(ca_path.to_string_lossy().into_owned()),
            ..latchgate_config::ListenerConfig::default()
        }
    }

    /// Valid CA + server cert + key => successfully loads TLS config.
    #[test]
    fn load_admin_tls_config_valid_certs() {
        let dir = tempfile::tempdir().unwrap();
        let listener = generate_test_certs(dir.path());

        let tls_config = super::load_admin_tls_config(&listener);
        assert!(
            tls_config.is_ok(),
            "valid certs must load: {:?}",
            tls_config.err()
        );
    }

    /// Missing cert file => io error with path in message.
    #[test]
    fn load_admin_tls_config_missing_cert_file() {
        let listener = latchgate_config::ListenerConfig {
            admin_tls_cert: Some("/nonexistent/server.crt".into()),
            admin_tls_key: Some("/nonexistent/server.key".into()),
            admin_tls_ca: Some("/nonexistent/ca.crt".into()),
            ..latchgate_config::ListenerConfig::default()
        };
        let err = super::load_admin_tls_config(&listener).unwrap_err();
        assert!(
            err.to_string().contains("/nonexistent/server.crt"),
            "error must include the path: {err}",
        );
    }

    /// Empty PEM file (valid file, zero certificates) => descriptive error.
    #[test]
    fn load_admin_tls_config_empty_pem() {
        let dir = tempfile::tempdir().unwrap();
        let listener = generate_test_certs(dir.path());

        // Overwrite the cert with an empty file.
        std::fs::write(listener.admin_tls_cert.as_ref().unwrap(), b"").unwrap();

        let err = super::load_admin_tls_config(&listener).unwrap_err();
        assert!(
            err.to_string().contains("no certificates found"),
            "must report empty PEM: {err}",
        );
    }

    /// None fields => immediate error (not configured).
    #[test]
    fn load_admin_tls_config_none_fields() {
        let listener = latchgate_config::ListenerConfig::default();
        assert!(listener.admin_tls_cert.is_none());

        let err = super::load_admin_tls_config(&listener).unwrap_err();
        assert!(
            err.to_string().contains("not configured"),
            "must report not configured: {err}",
        );
    }

    /// Key that does not match the cert => rustls rejects the config.
    #[test]
    fn load_admin_tls_config_mismatched_key() {
        let dir = tempfile::tempdir().unwrap();
        let listener = generate_test_certs(dir.path());

        // Generate a different key and overwrite the key file.
        let wrong_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        std::fs::write(
            listener.admin_tls_key.as_ref().unwrap(),
            wrong_key.serialize_pem(),
        )
        .unwrap();

        let err = super::load_admin_tls_config(&listener).unwrap_err();
        assert!(
            err.kind() == std::io::ErrorKind::InvalidData,
            "mismatched key must be InvalidData: {err}",
        );
    }

    /// Helper: generate CA, server cert, and client cert. Returns
    /// (ListenerConfig, client_cert_pem, client_key_pem, ca_cert_pem).
    fn generate_full_mtls_certs(
        dir: &std::path::Path,
    ) -> (latchgate_config::ListenerConfig, Vec<u8>, Vec<u8>, Vec<u8>) {
        use rcgen::{
            BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
            KeyUsagePurpose,
        };

        // CA
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = CertificateParams::new(vec!["Test CA".into()]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        // Server cert
        let server_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut server_params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        server_params.is_ca = IsCa::NoCa;
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .unwrap();

        // Client cert
        let client_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut client_params = CertificateParams::new(vec!["test-client".into()]).unwrap();
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        client_params.is_ca = IsCa::NoCa;
        let client_cert = client_params
            .signed_by(&client_key, &ca_cert, &ca_key)
            .unwrap();

        // Write server files
        let cert_path = dir.join("server.crt");
        let key_path = dir.join("server.key");
        let ca_path = dir.join("ca.crt");
        std::fs::write(&cert_path, server_cert.pem()).unwrap();
        std::fs::write(&key_path, server_key.serialize_pem()).unwrap();
        std::fs::write(&ca_path, ca_cert.pem()).unwrap();

        let listener_config = latchgate_config::ListenerConfig {
            admin_tls_cert: Some(cert_path.to_string_lossy().into_owned()),
            admin_tls_key: Some(key_path.to_string_lossy().into_owned()),
            admin_tls_ca: Some(ca_path.to_string_lossy().into_owned()),
            ..latchgate_config::ListenerConfig::default()
        };

        (
            listener_config,
            client_cert.pem().into_bytes(),
            client_key.serialize_pem().into_bytes(),
            ca_cert.pem().into_bytes(),
        )
    }

    /// Build a tokio-rustls client connector with mTLS client cert.
    fn build_tls_client_config(
        ca_pem: &[u8],
        client_cert_pem: &[u8],
        client_key_pem: &[u8],
    ) -> rustls::ClientConfig {
        use rustls_pki_types::pem::PemObject;
        use rustls_pki_types::{CertificateDer, PrivateKeyDer};
        use std::sync::Arc;

        let ca_certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(ca_pem)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let mut root_store = rustls::RootCertStore::empty();
        for cert in ca_certs {
            root_store.add(cert).unwrap();
        }

        let client_certs: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(client_cert_pem)
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        let client_key: PrivateKeyDer<'static> =
            PrivateKeyDer::from_pem_slice(client_key_pem).unwrap();

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_client_auth_cert(client_certs, client_key)
            .unwrap()
    }

    /// SECURITY e2e: valid client cert => HTTP request succeeds.
    #[tokio::test]
    async fn admin_tls_accepts_valid_client_cert() {
        let dir = tempfile::tempdir().unwrap();
        let (listener_config, client_cert, client_key, ca_cert) =
            generate_full_mtls_certs(dir.path());

        let tls_config = super::load_admin_tls_config(&listener_config).unwrap();
        let tls_acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();

        let app = axum::Router::new().route("/healthz", axum::routing::get(|| async { "ok" }));

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            super::serve_admin_tls(tcp_listener, app, tls_acceptor, None, async move {
                let _ = shutdown_rx.wait_for(|&v| v).await;
            })
            .await
            .ok();
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let client_config = build_tls_client_config(&ca_cert, &client_cert, &client_key);
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_config));
        let server_name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let tls = connector.connect(server_name, tcp).await.unwrap();

        let (mut reader, mut writer) = tokio::io::split(tls);
        let request = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        tokio::io::AsyncWriteExt::write_all(&mut writer, request)
            .await
            .unwrap();

        // hyper closes the TCP after Connection: close without sending TLS
        // close_notify, which rustls reports as UnexpectedEof. The response
        // bytes are valid regardless — read whatever arrived.
        let mut response = Vec::new();
        let _ = tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut response).await;
        let response_str = String::from_utf8_lossy(&response);

        assert!(
            response_str.starts_with("HTTP/1.1 200"),
            "valid client cert must get 200, got: {:?}",
            &response_str[..response_str.len().min(80)],
        );

        let _ = shutdown_tx.send(true);
    }

    /// SECURITY e2e: no client cert => connection rejected.
    ///
    /// In TLS 1.3, the client-side handshake may appear to succeed before the
    /// server processes the (empty) client certificate. The server then resets
    /// the connection, which manifests as a read/write error on the client.
    #[tokio::test]
    async fn admin_tls_rejects_missing_client_cert() {
        let dir = tempfile::tempdir().unwrap();
        let (listener_config, _client_cert, _client_key, ca_cert) =
            generate_full_mtls_certs(dir.path());

        let tls_config = super::load_admin_tls_config(&listener_config).unwrap();
        let tls_acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();

        let app = axum::Router::new().route("/healthz", axum::routing::get(|| async { "ok" }));

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            super::serve_admin_tls(tcp_listener, app, tls_acceptor, None, async move {
                let _ = shutdown_rx.wait_for(|&v| v).await;
            })
            .await
            .ok();
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Client config without any client certificate.
        use rustls_pki_types::pem::PemObject;
        let ca_certs: Vec<rustls_pki_types::CertificateDer<'static>> =
            rustls_pki_types::CertificateDer::pem_slice_iter(&ca_cert)
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        let mut root_store = rustls::RootCertStore::empty();
        for cert in ca_certs {
            root_store.add(cert).unwrap();
        }
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let no_cert_config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(no_cert_config));
        let server_name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();

        // TLS 1.2: handshake fails immediately.
        // TLS 1.3: handshake may appear to succeed, but the connection will
        // fail on the first read or write after the server processes the empty
        // client Certificate message.
        let rejected = match connector.connect(server_name, tcp).await {
            Err(_) => true,
            Ok(tls) => {
                let (mut reader, mut writer) = tokio::io::split(tls);
                let request =
                    b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
                let write_ok = tokio::io::AsyncWriteExt::write_all(&mut writer, request)
                    .await
                    .is_ok();
                let mut buf = Vec::new();
                let read_ok = tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut buf)
                    .await
                    .is_ok();
                // Rejected if write/read failed or we got no valid HTTP response.
                !write_ok
                    || !read_ok
                    || buf.is_empty()
                    || !String::from_utf8_lossy(&buf).starts_with("HTTP/1.1 200")
            }
        };

        assert!(
            rejected,
            "connection without client cert must be rejected (handshake or I/O)",
        );

        let _ = shutdown_tx.send(true);
    }

    /// SECURITY e2e: client cert fingerprint is populated in ConnectionContext.
    #[tokio::test]
    async fn admin_tls_populates_client_cert_fingerprint() {
        use std::sync::Arc;
        use tokio::sync::Mutex;

        let dir = tempfile::tempdir().unwrap();
        let (listener_config, client_cert, client_key, ca_cert) =
            generate_full_mtls_certs(dir.path());

        let tls_config = super::load_admin_tls_config(&listener_config).unwrap();
        let tls_acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();

        let captured: Arc<Mutex<Option<std::sync::Arc<str>>>> = Arc::new(Mutex::new(None));
        let captured_clone = captured.clone();
        let app = axum::Router::new().route(
            "/fingerprint",
            axum::routing::get(
                move |ctx: Option<axum::Extension<latchgate_auth::ConnectionContext>>| {
                    let captured = captured_clone.clone();
                    async move {
                        if let Some(axum::Extension(ctx)) = ctx {
                            *captured.lock().await = ctx.client_cert_fingerprint.clone();
                        }
                        "ok"
                    }
                },
            ),
        );

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            super::serve_admin_tls(tcp_listener, app, tls_acceptor, None, async move {
                let _ = shutdown_rx.wait_for(|&v| v).await;
            })
            .await
            .ok();
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let client_config = build_tls_client_config(&ca_cert, &client_cert, &client_key);
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let server_name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let tls = connector.connect(server_name, tcp).await.unwrap();

        let (mut reader, mut writer) = tokio::io::split(tls);
        let request = b"GET /fingerprint HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        tokio::io::AsyncWriteExt::write_all(&mut writer, request)
            .await
            .unwrap();

        let mut response = Vec::new();
        let _ = tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut response).await;
        let response_str = String::from_utf8_lossy(&response);
        assert!(
            response_str.starts_with("HTTP/1.1 200"),
            "expected 200, got: {:?}",
            &response_str[..response_str.len().min(80)],
        );

        let _ = shutdown_tx.send(true);

        // Verify the fingerprint was captured — it must be a 64-char hex SHA-256.
        let fingerprint = captured.lock().await;
        let fp = fingerprint
            .as_ref()
            .expect("client_cert_fingerprint must be populated");
        assert_eq!(fp.len(), 64, "SHA-256 hex must be 64 chars: {fp}");
        assert!(
            fp.chars().all(|c| c.is_ascii_hexdigit()),
            "fingerprint must be hex: {fp}",
        );
    }
}
