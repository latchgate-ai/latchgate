//! HTTPS egress proxy with CONNECT tunnel and credential-injecting reverse proxy.
//!
//! Listens on a Unix domain socket. Handles two request types:
//!
//! 1. **CONNECT tunnel** — existing passthrough mode. The agent sends
//!    `CONNECT host:443 HTTP/1.1`. If the hostname is in the allowlist,
//!    the proxy opens a TCP connection and relays encrypted bytes
//!    bidirectionally. TLS is end-to-end between agent and destination.
//!
//! 2. **Reverse proxy** — credential injection mode. The agent sends a
//!    normal HTTP request (POST, GET, etc.) with an `X-Gate-Token` header.
//!    The proxy validates the session token, strips any existing auth
//!    headers, injects the real credential, and forwards over TLS to the
//!    configured upstream. The agent never sees the API key.
//!
//! # Security properties
//!
//! - Only CONNECT or token-authenticated reverse proxy requests accepted.
//! - CONNECT: only hostnames in the allowlist, only port 443.
//! - Reverse proxy: session token (256-bit, constant-time comparison),
//!   credential stored as `Zeroizing<String>`, auth headers stripped
//!   before injection, upstream must be in allow_hosts.
//! - Resolved IPs validated: private, loopback, link-local, and metadata
//!   addresses are rejected (DNS rebinding defense).
//! - Connection count limited (prevent resource exhaustion).
//! - True idle timeout on tunnel connections.
//! - All denied attempts logged with hostname for audit.
//! - Credential values are never logged.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixListener, UnixStream};
use tokio::sync::{oneshot, Semaphore};
use zeroize::Zeroizing;

use crate::SandboxError;

/// Maximum concurrent connections (tunnel + reverse proxy combined).
const MAX_CONNECTIONS: usize = 64;

/// Idle timeout — connections with no data in either direction for this
/// duration are closed. Active streams are never interrupted.
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum HTTP header size for incoming requests.
const MAX_HEADER_SIZE: usize = 8192;

/// Maximum number of HTTP headers accepted per request.
///
/// Defense-in-depth cap. The 8 KiB header-size limit already constrains
/// header count implicitly (~250 minimal headers), but an explicit count
/// guard prevents pathological cases with many tiny headers.
const MAX_HEADER_COUNT: usize = 128;

/// Connection timeout for outbound TCP to target hosts.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Buffer size for each direction of relay.
const RELAY_BUF_SIZE: usize = 16 * 1024;

/// Headers stripped from agent requests before credential injection.
/// Both are removed regardless of which header the route injects into,
/// preventing the agent from overriding injected credentials.
const STRIPPED_AUTH_HEADERS: &[&str] = &["authorization", "x-api-key"];

/// The header carrying the per-session proxy authentication token.
const SESSION_TOKEN_HEADER: &str = "x-gate-token";

// Resolved credential route (ready-to-use, holds secret material)

/// A fully resolved credential route with the secret value in memory.
///
/// Constructed from [`latchgate_config::CredentialRouteConfig`] by reading
/// the credential from the host environment before fork. The `inject_value`
/// field is `Zeroizing` — its memory is overwritten on drop.
///
/// This type intentionally does NOT implement `Debug` or `Display` to
/// prevent accidental credential logging.
pub(crate) struct ResolvedCredentialRoute {
    /// Route name — matches the first path component (e.g. "openai").
    pub name: String,
    /// Upstream host (e.g. "api.openai.com").
    pub host: String,
    /// Upstream port (typically 443).
    pub port: u16,
    /// Upstream base path (e.g. "/v1"). May be empty.
    pub base_path: String,
    /// Header name to inject (e.g. "Authorization").
    pub inject_header: String,
    /// Formatted header value (e.g. "Bearer sk-..."). Zeroed on drop.
    pub inject_value: Zeroizing<String>,
}

// Handle returned to caller for shutdown

pub(crate) struct ProxyHandle {
    shutdown_tx: oneshot::Sender<()>,
}

impl ProxyHandle {
    /// Signal the proxy to stop accepting new connections and shut down.
    pub fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
    }
}

// Shared state

struct ProxyState {
    allow_hosts: HashSet<String>,
    semaphore: Semaphore,
    /// Per-session authentication token for reverse proxy requests.
    /// `None` when no credential routes are configured.
    session_token: Option<[u8; 32]>,
    /// Resolved credential routes for the reverse proxy.
    credential_routes: Vec<ResolvedCredentialRoute>,
    /// TLS connector for outbound upstream connections.
    /// `None` when no credential routes are configured.
    tls_connector: Option<tokio_rustls::TlsConnector>,
}

// Start / accept loop

/// Start the egress proxy on a Unix domain socket.
///
/// Returns a handle that can be used to shut down the proxy. The proxy
/// runs as a background tokio task.
///
/// `session_token` and `credential_routes` enable the reverse proxy mode.
/// When both are empty/None, only the CONNECT tunnel is available.
pub(crate) async fn start(
    socket_path: PathBuf,
    allow_hosts: Vec<String>,
    credential_routes: Vec<ResolvedCredentialRoute>,
    session_token: Option<[u8; 32]>,
) -> Result<ProxyHandle, SandboxError> {
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path)
        .map_err(|e| SandboxError::ProxySetup(format!("bind {}: {e}", socket_path.display())))?;

    // The sandbox agent may run as a different uid (e.g. nobody/65534 in
    // the root-assisted path). connect() on a Unix socket requires write
    // permission on the socket file. The default umask (typically 022)
    // creates mode 0755, blocking non-owner connect. Set 0o666 so any
    // uid inside the sandbox can reach the proxy. Access control is
    // enforced by the proxy itself (host allowlist, session tokens), not
    // by file permissions.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o666)).map_err(
            |e| SandboxError::ProxySetup(format!("chmod {}: {e}", socket_path.display())),
        )?;
    }

    let route_count = credential_routes.len();

    tracing::info!(
        path = %socket_path.display(),
        credential_routes = route_count,
        "egress proxy listening"
    );

    let tls_connector = if credential_routes.is_empty() {
        None
    } else {
        Some(build_tls_connector()?)
    };

    let state = Arc::new(ProxyState {
        allow_hosts: allow_hosts.into_iter().map(|h| h.to_lowercase()).collect(),
        semaphore: Semaphore::new(MAX_CONNECTIONS),
        session_token,
        credential_routes,
        tls_connector,
    });

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    tokio::spawn(accept_loop(listener, state, shutdown_rx));

    Ok(ProxyHandle { shutdown_tx })
}

/// Build a TLS connector using Mozilla CA roots.
///
/// Uses the `webpki-roots` bundle — no filesystem reads, no runtime
/// failures from missing system CA stores.
fn build_tls_connector() -> Result<tokio_rustls::TlsConnector, SandboxError> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Explicitly select ring as the crypto provider. The workspace enables
    // the "ring" feature on rustls, but rustls 0.23 requires an explicit
    // provider selection when no process-level default has been installed.
    let provider = rustls::crypto::ring::default_provider();
    let config = rustls::ClientConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()
        .map_err(|e| SandboxError::ProxySetup(format!("TLS config: {e}")))?
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

async fn accept_loop(
    listener: UnixListener,
    state: Arc<ProxyState>,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, _)) => {
                        let state = state.clone();
                        tokio::spawn(handle_connection(stream, state));
                    }
                    Err(e) => {
                        tracing::warn!("proxy accept error: {e}");
                    }
                }
            }
            _ = &mut shutdown_rx => {
                tracing::debug!("proxy shutting down");
                return;
            }
        }
    }
}

// Connection handler — dispatch to CONNECT or reverse proxy

async fn handle_connection(mut stream: UnixStream, state: Arc<ProxyState>) {
    let _permit = match state.semaphore.try_acquire() {
        Ok(p) => p,
        Err(_) => {
            tracing::warn!("proxy: max connections reached, rejecting");
            let _ = stream
                .write_all(b"HTTP/1.1 503 Too Many Connections\r\n\r\n")
                .await;
            return;
        }
    };

    let (request, body_start) = match read_http_request(&mut stream).await {
        Ok(r) => r,
        Err(msg) => {
            tracing::debug!("proxy: bad request: {msg}");
            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            return;
        }
    };

    if request.method == "CONNECT" {
        handle_connect(stream, &state, &request).await;
    } else {
        handle_reverse_proxy(stream, &state, &request, body_start).await;
    }
}

// CONNECT tunnel (existing logic, refactored to use ParsedRequest)

async fn handle_connect(mut stream: UnixStream, state: &ProxyState, request: &ParsedRequest) {
    let (host, port) = match parse_authority(&request.target) {
        Some(hp) => hp,
        None => {
            tracing::debug!("proxy: bad CONNECT target: {}", request.target);
            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
            return;
        }
    };

    if port != 443 {
        tracing::warn!(host = %host, port, "proxy denied: port is not 443");
        let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await;
        return;
    }

    if !state.allow_hosts.contains(&host) {
        tracing::warn!(host = %host, "proxy denied: host not in allowlist");
        let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await;
        return;
    }

    let safe_addrs = match resolve_and_validate(&host, port).await {
        Ok(addrs) => addrs,
        Err(response) => {
            let _ = stream.write_all(response.as_bytes()).await;
            return;
        }
    };

    let remote = match tokio::time::timeout(CONNECT_TIMEOUT, connect_to_first(&safe_addrs)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::warn!(host = %host, "proxy: connect failed: {e}");
            let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            return;
        }
        Err(_) => {
            tracing::warn!(host = %host, "proxy: connect timeout");
            let _ = stream
                .write_all(b"HTTP/1.1 504 Gateway Timeout\r\n\r\n")
                .await;
            return;
        }
    };

    tracing::debug!(
        host = %host,
        ip = %remote.peer_addr().map_or_else(|_| "unknown".to_string(), |a| a.ip().to_string()),
        "proxy: tunnel established"
    );

    if stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .is_err()
    {
        return;
    }

    let result = relay_bidirectional(stream, remote).await;
    match result {
        RelayResult::Finished => {}
        RelayResult::IoError(e) => tracing::debug!(host = %host, "tunnel I/O: {e}"),
        RelayResult::IdleTimeout => tracing::debug!(host = %host, "tunnel idle timeout"),
    }
}

// Reverse proxy (credential injection)

async fn handle_reverse_proxy(
    mut stream: UnixStream,
    state: &ProxyState,
    request: &ParsedRequest,
    body_start: Vec<u8>,
) {
    // 1. Session token required.
    let token = match state.session_token.as_ref() {
        Some(t) => t,
        None => {
            tracing::warn!("proxy: reverse proxy request but no credential routes configured");
            send_error(&mut stream, 404, "no credential routes configured").await;
            return;
        }
    };

    // 2. Validate X-Gate-Token (constant-time).
    let received_token = match request.find_header(SESSION_TOKEN_HEADER) {
        Some(val) => val,
        None => {
            tracing::debug!("proxy: reverse proxy request missing X-Gate-Token");
            send_error(&mut stream, 401, "missing X-Gate-Token").await;
            return;
        }
    };

    let received_bytes = match hex::decode(received_token) {
        Ok(b) => b,
        Err(_) => {
            tracing::debug!("proxy: invalid X-Gate-Token encoding");
            send_error(&mut stream, 401, "invalid token").await;
            return;
        }
    };

    if received_bytes.len() != 32 || !constant_time_eq(&received_bytes, token) {
        tracing::warn!("proxy: invalid session token");
        send_error(&mut stream, 401, "invalid token").await;
        return;
    }

    // 3. Parse route from path: /<route_name>/<rest>
    let (route_name, rest_path) = match parse_route_path(&request.target) {
        Some(r) => r,
        None => {
            tracing::debug!("proxy: bad route path: {}", request.target);
            send_error(&mut stream, 404, "invalid route path").await;
            return;
        }
    };

    // 4. Look up credential route.
    let route = match state
        .credential_routes
        .iter()
        .find(|r| r.name == route_name)
    {
        Some(r) => r,
        None => {
            tracing::debug!(route = %route_name, "proxy: unknown credential route");
            send_error(&mut stream, 404, "unknown credential route").await;
            return;
        }
    };

    // 5. Defense-in-depth: verify upstream host is in allowlist.
    let host_lower = route.host.to_lowercase();
    if !state.allow_hosts.contains(&host_lower) {
        tracing::warn!(
            host = %route.host,
            route = %route_name,
            "proxy: credential route host not in allowlist"
        );
        send_error(&mut stream, 403, "upstream not in allowlist").await;
        return;
    }

    // 6. DNS resolution + IP validation.
    let safe_addrs = match resolve_and_validate(&route.host, route.port).await {
        Ok(addrs) => addrs,
        Err(response) => {
            let _ = stream.write_all(response.as_bytes()).await;
            return;
        }
    };

    // 7. TCP connect.
    let tcp = match tokio::time::timeout(CONNECT_TIMEOUT, connect_to_first(&safe_addrs)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::warn!(host = %route.host, "proxy: upstream connect failed: {e}");
            send_error(&mut stream, 502, "upstream unreachable").await;
            return;
        }
        Err(_) => {
            tracing::warn!(host = %route.host, "proxy: upstream connect timeout");
            send_error(&mut stream, 504, "upstream timeout").await;
            return;
        }
    };

    // 8. TLS handshake.
    let connector = match state.tls_connector.as_ref() {
        Some(c) => c,
        None => {
            send_error(&mut stream, 500, "TLS not configured").await;
            return;
        }
    };

    let server_name = match rustls_pki_types::ServerName::try_from(route.host.clone()) {
        Ok(sn) => sn,
        Err(e) => {
            tracing::warn!(host = %route.host, "proxy: invalid server name: {e}");
            send_error(&mut stream, 502, "invalid upstream hostname").await;
            return;
        }
    };

    let mut tls_stream =
        match tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(server_name, tcp)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                tracing::warn!(host = %route.host, "proxy: TLS handshake failed: {e}");
                send_error(&mut stream, 502, "TLS handshake failed").await;
                return;
            }
            Err(_) => {
                tracing::warn!(host = %route.host, "proxy: TLS handshake timeout");
                send_error(&mut stream, 504, "TLS timeout").await;
                return;
            }
        };

    tracing::debug!(
        host = %route.host,
        route = %route_name,
        method = %request.method,
        "proxy: reverse proxy forwarding"
    );

    // 9. Build and send outbound request.
    let upstream_path = if route.base_path.is_empty() {
        rest_path.to_string()
    } else {
        format!("{}{rest_path}", route.base_path)
    };

    // Request line.
    let request_line = format!("{} {} HTTP/1.1\r\n", request.method, upstream_path);
    if tls_stream.write_all(request_line.as_bytes()).await.is_err() {
        send_error(&mut stream, 502, "upstream write failed").await;
        return;
    }

    // Mandatory headers.
    let host_header = format!("Host: {}\r\n", route.host);
    if tls_stream.write_all(host_header.as_bytes()).await.is_err() {
        send_error(&mut stream, 502, "upstream write failed").await;
        return;
    }

    // Injected credential header.
    let auth_header = format!(
        "{}: {}\r\n",
        route.inject_header,
        route.inject_value.as_str()
    );
    if tls_stream.write_all(auth_header.as_bytes()).await.is_err() {
        send_error(&mut stream, 502, "upstream write failed").await;
        return;
    }

    // Connection: close — simplifies response framing.
    if tls_stream
        .write_all(b"Connection: close\r\n")
        .await
        .is_err()
    {
        send_error(&mut stream, 502, "upstream write failed").await;
        return;
    }

    // Forward agent headers, stripping auth and session token headers.
    for (name, value) in &request.headers {
        if name == "host"
            || name == "connection"
            || name == SESSION_TOKEN_HEADER
            || STRIPPED_AUTH_HEADERS.contains(&name.as_str())
        {
            continue;
        }
        let header_line = format!("{name}: {value}\r\n");
        if tls_stream.write_all(header_line.as_bytes()).await.is_err() {
            send_error(&mut stream, 502, "upstream write failed").await;
            return;
        }
    }

    // End of headers.
    if tls_stream.write_all(b"\r\n").await.is_err() {
        send_error(&mut stream, 502, "upstream write failed").await;
        return;
    }

    // 10. Relay request body (if Content-Length present).
    let content_length = request.content_length();
    if let Some(cl) = content_length {
        if cl > 0 {
            // Write any bytes already read past the header boundary.
            let already_read = body_start.len().min(cl);
            if already_read > 0
                && tls_stream
                    .write_all(&body_start[..already_read])
                    .await
                    .is_err()
            {
                send_error(&mut stream, 502, "upstream write failed").await;
                return;
            }

            // Relay remaining body bytes from agent to upstream.
            let remaining = cl - already_read;
            if remaining > 0
                && relay_exact(&mut stream, &mut tls_stream, remaining)
                    .await
                    .is_err()
            {
                send_error(&mut stream, 502, "body relay failed").await;
                return;
            }
        }
    }

    // 11. Read upstream response and relay to agent.
    //     Since we sent Connection: close, the response ends at EOF.
    let mut buf = vec![0u8; RELAY_BUF_SIZE];
    loop {
        let n = match tokio::time::timeout(IDLE_TIMEOUT, tls_stream.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                tracing::debug!(host = %route.host, "proxy: upstream read error: {e}");
                break;
            }
            Err(_) => {
                tracing::debug!(host = %route.host, "proxy: upstream read timeout");
                break;
            }
        };
        if stream.write_all(&buf[..n]).await.is_err() {
            break;
        }
    }
}

/// Parse a route path: `/<route_name>/<rest>` or `/<route_name>`.
///
/// Returns `(route_name, rest)` where `rest` includes the leading `/`
/// or is `/` if no sub-path is present.
fn parse_route_path(path: &str) -> Option<(&str, &str)> {
    let path = path.strip_prefix('/')?;
    if path.is_empty() {
        return None;
    }
    match path.find('/') {
        Some(pos) => {
            let name = &path[..pos];
            let rest = &path[pos..];
            if name.is_empty() {
                None
            } else {
                Some((name, rest))
            }
        }
        None => Some((path, "/")),
    }
}

/// Relay exactly `count` bytes from `src` to `dst`.
async fn relay_exact<R, W>(src: &mut R, dst: &mut W, mut count: usize) -> std::io::Result<()>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut buf = vec![0u8; RELAY_BUF_SIZE.min(count)];
    while count > 0 {
        let to_read = buf.len().min(count);
        let n = src.read(&mut buf[..to_read]).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed during body relay",
            ));
        }
        dst.write_all(&buf[..n]).await?;
        count -= n;
    }
    Ok(())
}

/// Send an HTTP error response to the agent.
async fn send_error(stream: &mut UnixStream, status: u16, reason: &str) {
    let response = format!("HTTP/1.1 {status} {reason}\r\nConnection: close\r\n\r\n");
    let _ = stream.write_all(response.as_bytes()).await;
}

// Constant-time token comparison — delegates to `latchgate_core`.

use latchgate_core::constant_time_eq;

// DNS resolution + IP validation (shared by CONNECT and reverse proxy)

/// Resolve a hostname and validate all returned IPs are globally routable.
///
/// Returns the safe addresses or an HTTP error response string.
async fn resolve_and_validate(host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
    let target = format!("{host}:{port}");
    let addrs: Vec<SocketAddr> = match tokio::net::lookup_host(&target).await {
        Ok(iter) => iter.collect(),
        Err(e) => {
            tracing::warn!(host = %host, "proxy: DNS resolution failed: {e}");
            return Err("HTTP/1.1 502 Bad Gateway\r\n\r\n".to_string());
        }
    };

    if addrs.is_empty() {
        tracing::warn!(host = %host, "proxy: DNS returned no addresses");
        return Err("HTTP/1.1 502 Bad Gateway\r\n\r\n".to_string());
    }

    let safe_addrs: Vec<SocketAddr> = addrs
        .iter()
        .copied()
        .filter(|a| is_globally_routable(a.ip()))
        .collect();

    if safe_addrs.is_empty() {
        tracing::warn!(
            host = %host,
            resolved = ?addrs.iter().map(|a| a.ip()).collect::<Vec<_>>(),
            "proxy denied: all resolved addresses are private/loopback"
        );
        return Err("HTTP/1.1 403 Forbidden\r\n\r\n".to_string());
    }

    Ok(safe_addrs)
}

/// Returns `true` if the IP address is globally routable (safe to connect to).
///
/// Delegates to [`latchgate_core::is_private_ip`] — the single source of
/// truth for IP classification across the entire codebase.
fn is_globally_routable(ip: IpAddr) -> bool {
    !latchgate_core::is_private_ip(ip)
}

/// Connect to the first reachable address in the list.
async fn connect_to_first(addrs: &[SocketAddr]) -> std::io::Result<TcpStream> {
    let mut last_err = std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "no addresses");
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(s) => return Ok(s),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

// Bidirectional relay with idle timeout (CONNECT tunnel)

enum RelayResult {
    Finished,
    IoError(std::io::Error),
    IdleTimeout,
}

async fn relay_bidirectional(client: UnixStream, remote: TcpStream) -> RelayResult {
    let (mut client_r, mut client_w) = tokio::io::split(client);
    let (mut remote_r, mut remote_w) = tokio::io::split(remote);

    let mut c2r_buf = vec![0u8; RELAY_BUF_SIZE];
    let mut r2c_buf = vec![0u8; RELAY_BUF_SIZE];

    let idle_deadline = tokio::time::sleep(IDLE_TIMEOUT);
    tokio::pin!(idle_deadline);

    let mut c2r_done = false;
    let mut r2c_done = false;

    loop {
        if c2r_done && r2c_done {
            return RelayResult::Finished;
        }

        tokio::select! {
            result = client_r.read(&mut c2r_buf), if !c2r_done => {
                match result {
                    Ok(0) => {
                        c2r_done = true;
                        let _ = remote_w.shutdown().await;
                    }
                    Ok(n) => {
                        idle_deadline.as_mut().reset(tokio::time::Instant::now() + IDLE_TIMEOUT);
                        if remote_w.write_all(&c2r_buf[..n]).await.is_err() {
                            return RelayResult::Finished;
                        }
                    }
                    Err(e) => return RelayResult::IoError(e),
                }
            }

            result = remote_r.read(&mut r2c_buf), if !r2c_done => {
                match result {
                    Ok(0) => {
                        r2c_done = true;
                        let _ = client_w.shutdown().await;
                    }
                    Ok(n) => {
                        idle_deadline.as_mut().reset(tokio::time::Instant::now() + IDLE_TIMEOUT);
                        if client_w.write_all(&r2c_buf[..n]).await.is_err() {
                            return RelayResult::Finished;
                        }
                    }
                    Err(e) => return RelayResult::IoError(e),
                }
            }

            () = &mut idle_deadline => {
                return RelayResult::IdleTimeout;
            }
        }
    }
}

// HTTP request parsing

/// Parsed HTTP request line + headers from the agent.
#[derive(Debug)]
struct ParsedRequest {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
}

impl ParsedRequest {
    /// Find a header value by name.
    ///
    /// Header names are lowered at parse time, so `name` must be lowercase.
    fn find_header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// Extract Content-Length from headers, if present and valid.
    fn content_length(&self) -> Option<usize> {
        self.find_header("content-length")
            .and_then(|v| v.trim().parse().ok())
    }
}

/// Read and parse an HTTP request (any method) from the stream.
///
/// Returns the parsed request and any body bytes read past the header
/// boundary. The caller is responsible for relaying the body.
async fn read_http_request(stream: &mut UnixStream) -> Result<(ParsedRequest, Vec<u8>), String> {
    let mut buf = vec![0u8; MAX_HEADER_SIZE];
    let mut filled = 0;

    loop {
        if filled >= buf.len() {
            return Err("headers exceed 8 KiB".to_string());
        }
        let n = stream
            .read(&mut buf[filled..])
            .await
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("connection closed before headers complete".to_string());
        }
        filled += n;

        if let Some(pos) = find_header_end(&buf[..filled]) {
            let header_end = pos + 4;
            let header_str = String::from_utf8_lossy(&buf[..header_end]);
            let request = parse_request_headers(&header_str)?;
            let body_start = buf[header_end..filled].to_vec();
            return Ok((request, body_start));
        }
    }
}

/// Find the `\r\n\r\n` header terminator in a byte slice.
/// Returns the position of the first `\r` in the terminator.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Parse a raw HTTP request header block into a [`ParsedRequest`].
///
/// Header names are lowered to ASCII lowercase at parse time so all
/// subsequent lookups are direct `==` comparisons with no allocation.
fn parse_request_headers(raw: &str) -> Result<ParsedRequest, String> {
    let mut lines = raw.lines();

    let first_line = lines.next().ok_or_else(|| "empty request".to_string())?;

    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(format!("malformed request line: {first_line}"));
    }

    let method = parts[0].to_string();
    let target = parts[1].to_string();

    let mut headers = Vec::new();
    for line in lines {
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if headers.len() >= MAX_HEADER_COUNT {
            return Err("too many headers".to_string());
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }

    // Lowercase the target for CONNECT authority parsing.
    let target = if method == "CONNECT" {
        target.to_lowercase()
    } else {
        target
    };

    Ok(ParsedRequest {
        method,
        target,
        headers,
    })
}

/// Parse a `host:port` authority string.
fn parse_authority(authority: &str) -> Option<(String, u16)> {
    let (host, port_str) = authority.rsplit_once(':')?;
    let port: u16 = port_str.parse().ok()?;
    if host.is_empty() {
        return None;
    }
    Some((host.to_lowercase(), port))
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    /// Running proxy instance for tests.
    struct TestProxy {
        handle: ProxyHandle,
        sock: std::path::PathBuf,
        _dir: tempfile::TempDir,
    }

    impl TestProxy {
        async fn start(hosts: &[&str]) -> Self {
            Self::start_with_creds(hosts, vec![], None).await
        }

        async fn start_with_creds(
            hosts: &[&str],
            creds: Vec<ResolvedCredentialRoute>,
            token: Option<[u8; 32]>,
        ) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let sock = dir.path().join("proxy.sock");
            let allow: Vec<String> = hosts.iter().map(|s| s.to_string()).collect();
            let handle = start(sock.clone(), allow, creds, token).await.unwrap();
            Self {
                handle,
                sock,
                _dir: dir,
            }
        }

        fn shutdown(self) {
            self.handle.shutdown();
        }
    }

    async fn proxy_request(sock: &std::path::Path, request: &str) -> String {
        let mut stream = UnixStream::connect(sock).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf[..n]).to_string()
    }

    // CONNECT tunnel tests (existing behavior preserved)

    #[tokio::test]
    async fn denies_unlisted_host() {
        let tp = TestProxy::start(&["api.anthropic.com"]).await;
        let resp = proxy_request(
            &tp.sock,
            "CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com:443\r\n\r\n",
        )
        .await;
        assert!(
            resp.contains("403"),
            "expected 403 for unlisted host, got: {resp}"
        );
        tp.shutdown();
    }

    #[tokio::test]
    async fn denies_wrong_port() {
        let tp = TestProxy::start(&["api.anthropic.com"]).await;
        let resp = proxy_request(
            &tp.sock,
            "CONNECT api.anthropic.com:80 HTTP/1.1\r\nHost: api.anthropic.com:80\r\n\r\n",
        )
        .await;
        assert!(
            resp.contains("403"),
            "expected 403 for port 80, got: {resp}"
        );
        tp.shutdown();
    }

    #[tokio::test]
    async fn denies_non_connect_without_token() {
        let tp = TestProxy::start(&["api.anthropic.com"]).await;
        let resp = proxy_request(
            &tp.sock,
            "GET / HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n",
        )
        .await;
        // Without credential routes, non-CONNECT returns 404.
        assert!(
            resp.contains("404"),
            "expected 404 for GET without routes, got: {resp}"
        );
        tp.shutdown();
    }

    #[tokio::test]
    async fn allows_listed_host() {
        let tp = TestProxy::start(&["api.anthropic.com"]).await;
        let resp = proxy_request(
            &tp.sock,
            "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n",
        )
        .await;
        assert!(
            resp.contains("200") || resp.contains("502") || resp.contains("504"),
            "expected 200/502/504 for allowed host, got: {resp}"
        );
        tp.shutdown();
    }

    #[tokio::test]
    async fn host_matching_is_case_insensitive() {
        let tp = TestProxy::start(&["api.anthropic.com"]).await;
        let resp = proxy_request(&tp.sock, "CONNECT API.ANTHROPIC.COM:443 HTTP/1.1\r\n\r\n").await;
        assert!(
            resp.contains("200") || resp.contains("502") || resp.contains("504"),
            "case-insensitive match should allow, got: {resp}"
        );
        tp.shutdown();
    }

    #[tokio::test]
    async fn allowlist_with_uppercase_config() {
        let tp = TestProxy::start(&["API.ANTHROPIC.COM"]).await;
        let resp = proxy_request(&tp.sock, "CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n").await;
        assert!(
            resp.contains("200") || resp.contains("502") || resp.contains("504"),
            "uppercase config host should match lowercase target, got: {resp}"
        );
        tp.shutdown();
    }

    #[tokio::test]
    async fn rejects_oversized_headers() {
        let tp = TestProxy::start(&["api.anthropic.com"]).await;
        let huge_header = format!(
            "CONNECT api.anthropic.com:443 HTTP/1.1\r\nX-Junk: {}\r\n\r\n",
            "A".repeat(9000)
        );
        let resp = proxy_request(&tp.sock, &huge_header).await;
        assert!(
            resp.contains("400"),
            "expected 400 for huge headers, got: {resp}"
        );
        tp.shutdown();
    }

    #[tokio::test]
    async fn concurrent_denied_requests() {
        let tp = TestProxy::start(&["api.anthropic.com"]).await;
        let mut tasks = Vec::new();
        for _ in 0..50 {
            let sock = tp.sock.clone();
            tasks.push(tokio::spawn(async move {
                let resp = proxy_request(
                    &sock,
                    "CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com\r\n\r\n",
                )
                .await;
                assert!(resp.contains("403"), "expected 403, got: {resp}");
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        tp.shutdown();
    }

    // Reverse proxy tests

    fn test_token() -> [u8; 32] {
        let mut token = [0u8; 32];
        for (i, b) in token.iter_mut().enumerate() {
            *b = i as u8;
        }
        token
    }

    fn test_token_hex() -> String {
        hex::encode(test_token())
    }

    fn test_credential_route() -> ResolvedCredentialRoute {
        ResolvedCredentialRoute {
            name: "testapi".to_string(),
            host: "api.test.example.com".to_string(),
            port: 443,
            base_path: "/v1".to_string(),
            inject_header: "Authorization".to_string(),
            inject_value: Zeroizing::new("Bearer sk-test-secret".to_string()),
        }
    }

    #[tokio::test]
    async fn reverse_proxy_missing_token_returns_401() {
        let tp = TestProxy::start_with_creds(
            &["api.test.example.com"],
            vec![test_credential_route()],
            Some(test_token()),
        )
        .await;
        let resp = proxy_request(
            &tp.sock,
            "POST /testapi/v1/messages HTTP/1.1\r\nHost: proxy\r\n\r\n",
        )
        .await;
        assert!(
            resp.contains("401"),
            "expected 401 for missing token, got: {resp}"
        );
        tp.shutdown();
    }

    #[tokio::test]
    async fn reverse_proxy_wrong_token_returns_401() {
        let tp = TestProxy::start_with_creds(
            &["api.test.example.com"],
            vec![test_credential_route()],
            Some(test_token()),
        )
        .await;
        let bad_token = "ff".repeat(32);
        let resp = proxy_request(
            &tp.sock,
            &format!("POST /testapi/v1/messages HTTP/1.1\r\nX-Gate-Token: {bad_token}\r\n\r\n"),
        )
        .await;
        assert!(
            resp.contains("401"),
            "expected 401 for wrong token, got: {resp}"
        );
        tp.shutdown();
    }

    #[tokio::test]
    async fn reverse_proxy_unknown_route_returns_404() {
        let tp = TestProxy::start_with_creds(
            &["api.test.example.com"],
            vec![test_credential_route()],
            Some(test_token()),
        )
        .await;
        let token = test_token_hex();
        let resp = proxy_request(
            &tp.sock,
            &format!("POST /nonexistent/v1/messages HTTP/1.1\r\nX-Gate-Token: {token}\r\n\r\n"),
        )
        .await;
        assert!(
            resp.contains("404"),
            "expected 404 for unknown route, got: {resp}"
        );
        tp.shutdown();
    }

    #[tokio::test]
    async fn reverse_proxy_host_not_in_allowlist_returns_403() {
        // Credential route points to host NOT in allow_hosts.
        let tp = TestProxy::start_with_creds(
            &["other.example.com"], // not api.test.example.com
            vec![test_credential_route()],
            Some(test_token()),
        )
        .await;
        let token = test_token_hex();
        let resp = proxy_request(
            &tp.sock,
            &format!("POST /testapi/v1/messages HTTP/1.1\r\nX-Gate-Token: {token}\r\n\r\n"),
        )
        .await;
        assert!(
            resp.contains("403"),
            "expected 403 for host not in allowlist, got: {resp}"
        );
        tp.shutdown();
    }

    #[tokio::test]
    async fn reverse_proxy_valid_token_reaches_dns() {
        // Valid token + valid route → should attempt DNS/connect.
        // api.test.example.com won't resolve in CI → 502.
        let tp = TestProxy::start_with_creds(
            &["api.test.example.com"],
            vec![test_credential_route()],
            Some(test_token()),
        )
        .await;
        let token = test_token_hex();
        let resp = proxy_request(
            &tp.sock,
            &format!(
                "POST /testapi/v1/messages HTTP/1.1\r\nX-Gate-Token: {token}\r\nContent-Length: 0\r\n\r\n"
            ),
        )
        .await;
        // 502 = DNS/connect failure (expected in CI with no internet).
        // If it reaches DNS, it means auth passed.
        assert!(
            resp.contains("502") || resp.contains("504") || resp.contains("403"),
            "expected 502/504/403 (auth passed, DNS/connect failed), got: {resp}"
        );
        tp.shutdown();
    }

    // Route path parsing

    #[test]
    fn parse_route_path_normal() {
        assert_eq!(
            parse_route_path("/openai/v1/chat/completions"),
            Some(("openai", "/v1/chat/completions"))
        );
    }

    #[test]
    fn parse_route_path_no_subpath() {
        assert_eq!(parse_route_path("/anthropic"), Some(("anthropic", "/")));
    }

    #[test]
    fn parse_route_path_empty() {
        assert_eq!(parse_route_path("/"), None);
    }

    #[test]
    fn parse_route_path_no_slash() {
        assert_eq!(parse_route_path("noslash"), None);
    }

    // Header parsing

    #[test]
    fn headers_lowercased_at_parse_time() {
        let raw = "GET /path HTTP/1.1\r\nContent-Type: application/json\r\nX-Custom-Header: value\r\n\r\n";
        let req = parse_request_headers(raw).unwrap();
        assert_eq!(req.find_header("content-type"), Some("application/json"));
        assert_eq!(req.find_header("x-custom-header"), Some("value"));
        // Original case no longer matches — names are stored lowercase.
        assert_eq!(req.find_header("Content-Type"), None);
    }

    #[test]
    fn header_count_cap_rejects_excessive_headers() {
        let mut raw = String::from("GET /path HTTP/1.1\r\n");
        for i in 0..MAX_HEADER_COUNT + 1 {
            raw.push_str(&format!("x-h{i}: v\r\n"));
        }
        raw.push_str("\r\n");
        let result = parse_request_headers(&raw);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too many headers"));
    }

    #[test]
    fn header_count_at_limit_accepted() {
        let mut raw = String::from("GET /path HTTP/1.1\r\n");
        for i in 0..MAX_HEADER_COUNT {
            raw.push_str(&format!("x-h{i}: v\r\n"));
        }
        raw.push_str("\r\n");
        let result = parse_request_headers(&raw);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().headers.len(), MAX_HEADER_COUNT);
    }

    // Constant-time comparison

    #[test]
    fn constant_time_eq_identical() {
        let a = [1u8, 2, 3, 4];
        assert!(constant_time_eq(&a, &a));
    }

    #[test]
    fn constant_time_eq_different() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 5];
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        let a = [1u8, 2, 3];
        let b = [1u8, 2, 3, 4];
        assert!(!constant_time_eq(&a, &b));
    }

    // Resolved-IP validation (DNS rebinding defense)

    #[test]
    fn loopback_ipv4_rejected() {
        assert!(!is_globally_routable(IpAddr::V4(
            std::net::Ipv4Addr::LOCALHOST
        )));
    }

    #[test]
    fn loopback_ipv6_rejected() {
        assert!(!is_globally_routable(IpAddr::V6(
            std::net::Ipv6Addr::LOCALHOST
        )));
    }

    #[test]
    fn private_10_rejected() {
        assert!(!is_globally_routable("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn private_172_rejected() {
        assert!(!is_globally_routable("172.16.0.1".parse().unwrap()));
    }

    #[test]
    fn private_192_168_rejected() {
        assert!(!is_globally_routable("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn link_local_rejected() {
        assert!(!is_globally_routable("169.254.169.254".parse().unwrap()));
    }

    #[test]
    fn shared_address_space_rejected() {
        assert!(!is_globally_routable("100.64.0.1".parse().unwrap()));
        assert!(!is_globally_routable("100.127.255.255".parse().unwrap()));
        assert!(is_globally_routable("100.128.0.1".parse().unwrap()));
    }

    #[test]
    fn ipv4_mapped_ipv6_private_rejected() {
        let addr: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(!is_globally_routable(addr));
    }

    #[test]
    fn ipv6_link_local_rejected() {
        assert!(!is_globally_routable("fe80::1".parse().unwrap()));
    }

    #[test]
    fn ipv6_ula_rejected() {
        assert!(!is_globally_routable("fd00::1".parse().unwrap()));
    }

    #[test]
    fn public_ipv4_allowed() {
        assert!(is_globally_routable("1.1.1.1".parse().unwrap()));
        assert!(is_globally_routable("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn public_ipv6_allowed() {
        assert!(is_globally_routable("2606:4700::1111".parse().unwrap()));
    }

    #[test]
    fn unspecified_rejected() {
        assert!(!is_globally_routable(IpAddr::V4(
            std::net::Ipv4Addr::UNSPECIFIED
        )));
        assert!(!is_globally_routable(IpAddr::V6(
            std::net::Ipv6Addr::UNSPECIFIED
        )));
    }

    #[test]
    fn multicast_ipv4_rejected() {
        assert!(!is_globally_routable("224.0.0.1".parse().unwrap()));
        assert!(!is_globally_routable("239.255.255.255".parse().unwrap()));
    }

    #[test]
    fn reserved_ipv4_rejected() {
        assert!(!is_globally_routable("240.0.0.1".parse().unwrap()));
    }

    #[test]
    fn ietf_protocol_assignments_rejected() {
        assert!(!is_globally_routable("192.0.0.1".parse().unwrap()));
    }

    #[test]
    fn multicast_ipv6_rejected() {
        assert!(!is_globally_routable("ff02::1".parse().unwrap()));
        assert!(!is_globally_routable("ff05::2".parse().unwrap()));
    }
}
