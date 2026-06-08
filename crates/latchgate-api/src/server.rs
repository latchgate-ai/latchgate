//! Gate server lifecycle: startup, subsystem initialisation, and shutdown.
//!
//! All production-critical startup logic lives here so that both
//! `latchgate serve` (production) and `latchgate up` (dev/eval) share a
//! single, auditable code path. No server behaviour is duplicated elsewhere.

use std::path::Path;

use tracing::{info, warn};

use latchgate_config::{Config, LogFormat};

/// Emit a structured JSON error to stderr and exit with code 1.
///
/// Orchestrators (LatchGate Platform provisioner) parse these to determine
/// why a tenant instance failed to start and surface actionable errors in
/// the management UI. The JSON line is always on a single line for reliable
/// parsing even when mixed with tracing output.
///
/// Format: `{"startup_error": "<code>", "detail": "<message>"}`
fn startup_error(code: &str, detail: &str) -> ! {
    let json = serde_json::json!({
        "startup_error": code,
        "detail": detail,
    });
    eprintln!("{json}");
    std::process::exit(1);
}

/// Load `data.json` for the embedded policy evaluator.
///
/// Searches `policies/data.json` (init-output layout) then
/// `policies/opa/data.json` (repo-root layout). Returns `None` if
/// neither exists — the policy will run without external data, which
/// means the ACL will be empty and all requests denied.
fn load_policy_data(config: &Config) -> Option<String> {
    let candidates = [
        std::path::Path::new(".latchgate/policies/data.json"),
        std::path::Path::new("policies/data.json"),
        std::path::Path::new("policies/opa/data.json"),
    ];

    for path in &candidates {
        if path.exists() {
            match std::fs::read_to_string(path) {
                Ok(contents) => {
                    info!(path = %path.display(), "loaded policy data for embedded evaluator");
                    return Some(contents);
                }
                Err(e) => {
                    warn!(
                        path = %path.display(),
                        error = %e,
                        "policy data.json exists but cannot be read"
                    );
                }
            }
        }
    }

    // Also check config-relative path if manifests_dir is set.
    let config_relative = std::path::Path::new(&config.manifests_dir)
        .parent()
        .map(|p| p.join("data.json"));
    if let Some(ref path) = config_relative {
        if path.exists() {
            match std::fs::read_to_string(path) {
                Ok(contents) => {
                    info!(path = %path.display(), "loaded policy data for embedded evaluator");
                    return Some(contents);
                }
                Err(e) => {
                    warn!(
                        path = %path.display(),
                        error = %e,
                        "policy data.json exists but cannot be read"
                    );
                }
            }
        }
    }

    warn!("no policy data.json found — embedded evaluator will run without ACL data");
    None
}

/// All subsystem state needed by the listener phase.
///
/// Produced by [`init_subsystems`], consumed by [`serve`]. Intermediate
/// struct avoids a 10-parameter return from the init function.
struct ServerContext {
    state: latchgate_kernel::AppState,
    startup_info: latchgate_kernel::init::StartupInfo,
    webhook_dispatcher: Option<latchgate_webhooks::WebhookDispatcher>,
    webhook_outbox: std::sync::Arc<latchgate_webhooks::WebhookOutbox>,
    parsed_webhook_configs: Vec<latchgate_webhooks::WebhookEndpointConfig>,
}

/// Initialise all subsystems: policy, webhooks, kernel state, egress, sweeps.
///
/// Fails fast via [`startup_error`] for any fatal misconfiguration. Returns
/// a fully-constructed [`ServerContext`] ready for listener binding.
async fn init_subsystems(config: &Config) -> ServerContext {
    // SECURITY: always validate.  Each sub-validator checks its own
    // `SecurityPosture` flag and skips itself only when that specific
    // protection is explicitly relaxed.  Non-relaxed validators still
    // enforce — there is no global bypass.
    config.validate_production_security().unwrap_or_else(|e| {
        startup_error("production_security_validation_failed", &e.to_string());
    });

    if config.dev_mode() {
        warn!(
            "RELAXED POSTURE — one or more production security protections \
             are disabled. Do not deploy this configuration."
        );
    }

    // ── Load policy data ─────────────────────────────────────────────
    let data_json = load_policy_data(config);

    // ── Webhook dispatcher ─────────────────────────────────────────────
    let parsed_webhook_configs: Vec<latchgate_webhooks::WebhookEndpointConfig> =
        if config.webhooks.is_empty() {
            vec![]
        } else {
            config
                .webhooks
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    v.clone().try_into().unwrap_or_else(|e: toml::de::Error| {
                        startup_error("webhook_config_invalid", &format!("webhooks[{i}]: {e}"));
                    })
                })
                .collect()
        };

    let webhook_dispatcher = if parsed_webhook_configs.is_empty() {
        info!("no [[webhooks]] configured — webhook notifications disabled");
        None
    } else {
        let dispatcher = latchgate_webhooks::WebhookDispatcher::start(
            parsed_webhook_configs.clone(),
            env!("CARGO_PKG_VERSION"),
            config.dev_mode(),
        )
        .unwrap_or_else(|e| {
            startup_error("webhook_dispatcher_failed", &e.to_string());
        });
        Some(dispatcher)
    };

    let event_sink: Option<std::sync::Arc<dyn latchgate_core::EventSink>> = webhook_dispatcher
        .as_ref()
        .map(|d| std::sync::Arc::new(d.clone()) as std::sync::Arc<dyn latchgate_core::EventSink>);

    // ── Build kernel state ─────────────────────────────────────────────
    let (state, startup_info) =
        latchgate_kernel::init::build_state(latchgate_kernel::init::BuildParams {
            config: config.clone(),
            embedded_manifests: latchgate_embed::embedded_manifests::iter_yaml().collect(),
            embedded_providers: latchgate_embed::embedded_providers::PROVIDERS,
            embedded_policy_rego: latchgate_embed::embedded_policies::POLICY_REGO,
            policy_data_json: data_json,
            event_sink,
        })
        .await
        .unwrap_or_else(|e| {
            startup_error(e.code(), &e.to_string());
        });

    // ── Webhook outbox ─────────────────────────────────────────────────
    let webhook_outbox = {
        let outbox_path = std::path::Path::new(&config.storage.ledger_db_path)
            .with_file_name("webhook_outbox.db");
        latchgate_webhooks::WebhookOutbox::open(&outbox_path).unwrap_or_else(|e| {
            startup_error("webhook_outbox_open_failed", &e.to_string());
        })
    };
    let webhook_outbox = std::sync::Arc::new(webhook_outbox);

    // ── Initial egress allowlist sync ──────────────────────────────────
    let registry_guard = state.registry.load();
    match latchgate_embed::egress_sync::sync(config, &registry_guard, &state.ledger) {
        Ok(latchgate_embed::egress_sync::SyncOutcome::Written { domain_count, path }) => {
            info!(
                path = %path,
                domain_count = domain_count,
                "initial egress allowlist sync complete"
            );
        }
        Ok(latchgate_embed::egress_sync::SyncOutcome::Disabled) => {}
        Err(e) => {
            startup_error(
                "egress_sync_failed",
                &format!("failed to write initial egress allowlist: {e}"),
            );
        }
    }

    // ── Approval expiry scanner ────────────────────────────────────────
    if state.lifecycle.event_sink.is_some() {
        crate::expiry::spawn_expiry_scanner(state.clone());
        info!("approval expiry scanner started (30s interval)");
    }

    // ── Background sweeps ──────────────────────────────────────────────
    spawn_background_sweeps(&state);

    ServerContext {
        state,
        startup_info,
        webhook_dispatcher,
        webhook_outbox,
        parsed_webhook_configs,
    }
}

/// Initialise all subsystems and run the gate until a shutdown signal arrives.
///
/// This is the single entry point for the running gate — called by both
/// `serve` (production, externally managed deps) and `up` (dev, managed
/// Docker deps). The function does not return until SIGINT/SIGTERM.
///
/// # Security
///
/// Central production startup gate. Refuses to start if the trust model is
/// not closed: identity provider, operator auth, signing material, transport,
/// and response schema enforcement are all validated here. In unsafe dev mode
/// (requires `unsafe-dev` Cargo feature + `LATCHGATE_UNSAFE_DEV=1`) all checks
/// are bypassed.
pub async fn serve(config: Config) {
    let ctx = init_subsystems(&config).await;

    let ServerContext {
        state,
        startup_info,
        webhook_dispatcher,
        webhook_outbox,
        parsed_webhook_configs,
    } = ctx;

    let outbox_handle = spawn_outbox_poller(&config, &webhook_outbox, parsed_webhook_configs);

    print_startup_banner(&config, &state, &startup_info);

    // Capture webhook dispatcher handle for graceful shutdown. Must be done
    // before state is moved into routers.
    let webhook_dispatcher_for_shutdown = webhook_dispatcher.clone();

    // SECURITY: client and admin surfaces are served on separate sockets.
    // Agent processes need filesystem access only to `listen_uds_path`.
    // Operator tooling needs access only to `listen_admin_uds_path`.
    // A process with agent-level access cannot reach kill-switch, audit trail,
    // receipts, approvals, or metrics regardless of application-level auth.
    let client_app = crate::client_router(state.clone());
    let admin_app = crate::admin_router(state.clone());

    // Graceful shutdown: broadcast signal to all listeners so in-flight
    // requests (especially mid-WASM-dispatch executions) drain completely.
    // Without this, Ctrl+C / SIGTERM kills immediately, leaving executions
    // without matching receipts — an evidence gap in the audit trail.
    let (shutdown_tx, _) = tokio::sync::watch::channel(false);

    spawn_tcp_listeners(&config, &client_app, &admin_app, &shutdown_tx).await;
    spawn_mtls_listener(&config, &admin_app, &shutdown_tx).await;

    #[cfg(unix)]
    {
        let client_uds = Path::new(&config.listener.listen_uds_path).to_path_buf();
        let admin_uds = Path::new(&config.listener.listen_admin_uds_path).to_path_buf();

        info!(
            client_uds = %client_uds.display(),
            admin_uds  = %admin_uds.display(),
            "listeners bound"
        );

        // Spawn admin socket on a background task.
        let mut admin_rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            crate::listen::serve_uds(&admin_uds, admin_app, async move {
                let _ = admin_rx.wait_for(|&v| v).await;
            })
            .await
            .unwrap_or_else(|e| {
                startup_error("admin_uds_failed", &format!("admin UDS server: {e}"));
            });
        });

        // Client socket: blocks main task until shutdown completes.
        let mut client_rx = shutdown_tx.subscribe();
        let client_shutdown = async move {
            let _ = client_rx.wait_for(|&v| v).await;
        };

        // Spawn the shutdown signal listener. When SIGINT or SIGTERM arrives,
        // it broadcasts to all listeners via the watch channel.
        tokio::spawn(async move {
            shutdown_signal().await;
            info!("shutdown signal received, draining in-flight requests...");
            let _ = shutdown_tx.send(true);
        });

        crate::listen::serve_uds(&client_uds, client_app, client_shutdown)
            .await
            .unwrap_or_else(|e| {
                startup_error("client_uds_failed", &format!("client UDS server: {e}"));
            });

        drain_subsystems(webhook_dispatcher_for_shutdown, outbox_handle).await;
        info!("shutdown complete");
    }

    #[cfg(not(unix))]
    {
        if config.listener.listen_http_addr.is_none() || !config.listener.unsafe_expose_http {
            startup_error(
                "uds_unavailable",
                "UDS transport is not available on this platform. \
                 Set listen_http_addr and unsafe_expose_http = true in latchgate.toml.",
            );
        }

        // On non-unix, only TCP is available. Block until shutdown.
        tokio::spawn(async move {
            shutdown_signal().await;
            info!("shutdown signal received");
            let _ = shutdown_tx.send(true);
        });

        std::future::pending::<()>().await;
    }
}

/// Start the webhook outbox poller if outbox mode is active and endpoints
/// are configured.
///
/// Returns `(task_handle, shutdown_sender)` for graceful drain at shutdown.
fn spawn_outbox_poller(
    config: &Config,
    webhook_outbox: &std::sync::Arc<latchgate_webhooks::WebhookOutbox>,
    configs: Vec<latchgate_webhooks::WebhookEndpointConfig>,
) -> Option<(
    tokio::task::JoinHandle<()>,
    tokio::sync::watch::Sender<bool>,
)> {
    if config.webhook_mode != latchgate_config::WebhookMode::Outbox || configs.is_empty() {
        if config.webhook_mode == latchgate_config::WebhookMode::Outbox {
            info!("webhook_mode=outbox but no endpoints configured — poller skipped");
        }
        return None;
    }

    let (outbox_shutdown_tx, outbox_shutdown_rx) = tokio::sync::watch::channel(false);
    let active_configs: Vec<_> = configs.into_iter().filter(|c| !c.disable).collect();
    let handle = crate::outbox::start(
        std::sync::Arc::clone(webhook_outbox),
        active_configs,
        crate::outbox::OutboxPollerConfig {
            dev_mode: config.dev_mode(),
            ..Default::default()
        },
        outbox_shutdown_rx,
    );
    info!("webhook outbox poller started (mode=outbox)");
    Some((handle, outbox_shutdown_tx))
}

/// Spawn optional plaintext TCP listeners (dev / testing only).
///
/// SECURITY: client and admin routers bind to separate ports even in TCP
/// mode, mirroring the UDS separation. Operators can firewall the admin
/// port independently. Production deployments MUST NOT set
/// `unsafe_expose_http = true`.
async fn spawn_tcp_listeners(
    config: &Config,
    client_app: &axum::Router,
    admin_app: &axum::Router,
    shutdown_tx: &tokio::sync::watch::Sender<bool>,
) {
    if !config.listener.unsafe_expose_http {
        return;
    }
    let client_addr = match config.listener.listen_http_addr {
        Some(addr) => addr,
        None => return,
    };

    if config.listener.admin_tls_configured() {
        // Admin uses mTLS — only start the client TCP listener.
        warn!(
            client_addr = %client_addr,
            unsafe_http_exposed = true,
            "client HTTP/TCP listener enabled (unsafe_expose_http=true); \
             admin uses mTLS instead of plain HTTP."
        );
    } else {
        // Default admin addr to 127.0.0.1:3001 when not explicitly set.
        let admin_addr = config.listener.listen_admin_http_addr.unwrap_or_else(|| {
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 3001)
        });
        warn!(
            client_addr = %client_addr,
            admin_addr = %admin_addr,
            unsafe_http_exposed = true,
            "HTTP/TCP listeners enabled (unsafe_expose_http=true); not for production. \
             Client on {client_addr}, admin on {admin_addr}."
        );

        // Admin TCP listener — separate port.
        let admin_tcp_app = admin_app.clone();
        let admin_listener = tokio::net::TcpListener::bind(admin_addr)
            .await
            .unwrap_or_else(|e| {
                startup_error(
                    "tcp_bind_failed",
                    &format!("failed to bind admin TCP listener {admin_addr}: {e}"),
                );
            });
        let mut rx = shutdown_tx.subscribe();
        let admin_shutdown_tx = shutdown_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::listen::serve_http(admin_listener, admin_tcp_app, async move {
                let _ = rx.wait_for(|&v| v).await;
            })
            .await
            {
                tracing::error!(error = %e, "admin HTTP listener failed — triggering shutdown");
                let _ = admin_shutdown_tx.send(true);
            }
        });
    }

    // Client TCP listener.
    let client_tcp_app = client_app.clone();
    let client_listener = tokio::net::TcpListener::bind(client_addr)
        .await
        .unwrap_or_else(|e| {
            startup_error(
                "tcp_bind_failed",
                &format!("failed to bind client TCP listener {client_addr}: {e}"),
            );
        });
    let mut rx = shutdown_tx.subscribe();
    let client_shutdown_tx = shutdown_tx.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::listen::serve_http(client_listener, client_tcp_app, async move {
            let _ = rx.wait_for(|&v| v).await;
        })
        .await
        {
            tracing::error!(error = %e, "client HTTP listener failed — triggering shutdown");
            let _ = client_shutdown_tx.send(true);
        }
    });
}

/// Spawn the admin mutual-TLS listener if configured.
///
/// SECURITY: the TLS handshake rejects clients without a valid certificate
/// signed by the configured CA. Independent of `unsafe_expose_http` — mTLS
/// is a production transport, not a dev convenience.
async fn spawn_mtls_listener(
    config: &Config,
    admin_app: &axum::Router,
    shutdown_tx: &tokio::sync::watch::Sender<bool>,
) {
    if !config.listener.admin_tls_configured() {
        return;
    }
    let admin_addr = match config.listener.listen_admin_http_addr {
        Some(addr) => addr,
        None => return,
    };

    let tls_config = crate::listen::load_admin_tls_config(&config.listener).unwrap_or_else(|e| {
        startup_error(
            "admin_tls_config_failed",
            &format!("failed to load admin TLS configuration: {e}"),
        );
    });

    let tls_acceptor = tokio_rustls::TlsAcceptor::from(tls_config);

    let admin_tls_app = admin_app.clone();
    let admin_listener = tokio::net::TcpListener::bind(admin_addr)
        .await
        .unwrap_or_else(|e| {
            startup_error(
                "tcp_bind_failed",
                &format!("failed to bind admin TLS listener {admin_addr}: {e}"),
            );
        });

    info!(
        addr = %admin_addr,
        cert = config.listener.admin_tls_cert.as_deref().unwrap_or(""),
        ca = config.listener.admin_tls_ca.as_deref().unwrap_or(""),
        "admin mTLS listener enabled",
    );

    let mut rx = shutdown_tx.subscribe();
    let admin_shutdown_tx = shutdown_tx.clone();
    let allowed_fps = config
        .listener
        .admin_tls_allowed_fingerprints
        .as_ref()
        .map(|v| std::sync::Arc::new(v.clone()));
    tokio::spawn(async move {
        if let Err(e) = crate::listen::serve_admin_tls(
            admin_listener,
            admin_tls_app,
            tls_acceptor,
            allowed_fps,
            async move {
                let _ = rx.wait_for(|&v| v).await;
            },
        )
        .await
        {
            tracing::error!(error = %e, "admin mTLS listener failed — triggering shutdown");
            let _ = admin_shutdown_tx.send(true);
        }
    });
}

/// Drain webhook deliveries and stop the outbox poller after HTTP servers
/// have stopped accepting new requests.
///
/// Events queued during request drain are still delivered; the webhook
/// dispatcher waits up to 10 s for in-flight POSTs before aborting.
async fn drain_subsystems(
    webhook_dispatcher: Option<latchgate_webhooks::WebhookDispatcher>,
    outbox_handle: Option<(
        tokio::task::JoinHandle<()>,
        tokio::sync::watch::Sender<bool>,
    )>,
) {
    if let Some(ref dispatcher) = webhook_dispatcher {
        info!("draining webhook deliveries...");
        dispatcher.shutdown().await;
    }

    if let Some((handle, shutdown_tx)) = outbox_handle {
        let _ = shutdown_tx.send(true);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
    }
}

/// Spawn periodic rate-limiter eviction and replay cache sweeps.
///
/// Without this the `DashMap` / `HashMap` grow without bound as sessions
/// arrive and depart. The sweep runs every 60 seconds and evicts entries
/// idle for more than 5 minutes.
fn spawn_background_sweeps(state: &latchgate_kernel::AppState) {
    // Start the 1 Hz coarse clock used by the rate limiter. Replaces
    // per-request SystemTime::now() syscalls with a single atomic read.
    // The clock publishes a liveness gauge so a stalled ticker is observable.
    state.lifecycle.clock.start(state.metrics.clone());

    let execute_limiters = state.lifecycle.execute_rate_limiters.clone();
    let replay = state.auth.replay_cache.clone();
    tokio::spawn(async move {
        const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
        const IDLE_TTL_SECS: u64 = 300; // 5 minutes
        let mut interval = tokio::time::interval(SWEEP_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let removed = execute_limiters.sweep_stale(IDLE_TTL_SECS);
            if removed > 0 {
                tracing::debug!(
                    removed,
                    remaining = execute_limiters.len(),
                    "execute rate limiter sweep"
                );
            }
            let replay_evicted = replay.evict_expired().await;
            if replay_evicted > 0 {
                tracing::debug!(evicted = replay_evicted, "replay cache sweep");
            }
        }
    });
    info!("background sweeps started (60s interval)");
}

/// Print the structured startup banner to stderr.
fn print_startup_banner(
    config: &latchgate_config::Config,
    state: &latchgate_kernel::AppState,
    startup_info: &latchgate_kernel::init::StartupInfo,
) {
    let actions_count = startup_info.actions_total;
    let actions_embedded = startup_info.actions_embedded;
    let actions_from_dir = startup_info.actions_from_dir;
    let actions_overrides = startup_info.actions_overrides;
    let mode_str = if config.dev_mode() {
        "DEV"
    } else {
        "production"
    };
    let identity_str = format!("{:?}", config.identity.provider);

    let state_str = match &startup_info.state_backend {
        latchgate_kernel::init::StateBackendInfo::Redis { url } => format!("Redis ({url})"),
        latchgate_kernel::init::StateBackendInfo::Sqlite {
            state_db_path,
            max_replay_entries,
        } => format!("SQLite ({state_db_path}) + in-memory replay ({max_replay_entries} entries)"),
    };

    let policy_str = match &startup_info.policy_backend {
        latchgate_kernel::init::PolicyBackendInfo::Http { opa_url } => {
            format!("OPA ({opa_url})")
        }
        latchgate_kernel::init::PolicyBackendInfo::Embedded => "embedded regorus".to_string(),
    };

    let egress_str = if config.egress.egress_proxy_url.is_some() {
        format!(
            "proxy ({})",
            config.egress.egress_proxy_url.as_deref().unwrap_or("?")
        )
    } else {
        "kernel-validated (Layer 1 only)".to_string()
    };

    eprintln!();
    eprintln!("  ──────────────────────────────────────────────");
    eprintln!("  LatchGate {}", env!("CARGO_PKG_VERSION"));
    eprintln!();
    eprintln!("  Client:    {}", config.listener.listen_uds_path);
    eprintln!("  Admin:     {}", config.listener.listen_admin_uds_path);
    if let Some(addr) = config.listener.listen_http_addr {
        if config.listener.unsafe_expose_http {
            eprintln!("  HTTP:      http://{addr} (dev only)");
            if !config.listener.admin_tls_configured() {
                let admin_addr = config.listener.listen_admin_http_addr.unwrap_or_else(|| {
                    std::net::SocketAddr::new(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                        3001,
                    )
                });
                eprintln!("  Admin HTTP: http://{admin_addr} (dev only)");
            }
        }
    }
    if config.listener.admin_tls_configured() {
        if let Some(addr) = config.listener.listen_admin_http_addr {
            eprintln!("  Admin TLS: https://{addr} (mTLS)");
        }
    }
    eprintln!(
        "  Actions:   {actions_count} ({actions_embedded} embedded, {actions_from_dir} user, {actions_overrides} overrides)"
    );
    eprintln!(
        "  Providers: {} WASM module(s) ({} embedded, {} from dir)",
        startup_info.wasm_embedded + startup_info.wasm_from_dir,
        startup_info.wasm_embedded,
        startup_info.wasm_from_dir
    );
    eprintln!("  State:     {state_str}");
    eprintln!("  Policy:    {policy_str}");
    eprintln!("  Egress:    {egress_str}");
    eprintln!(
        "  Webhooks:  {}",
        if state.lifecycle.event_sink.is_some() {
            "active"
        } else {
            "disabled"
        }
    );
    eprintln!("  Identity:  {identity_str}");
    eprintln!("  Mode:      {mode_str}");

    if config.egress.egress_proxy_url.is_none() && !config.posture.egress_insecure {
        eprintln!();
        eprintln!("  \u{26a0} No egress proxy. Outbound domain enforcement uses");
        eprintln!("    manifest allowlists only (Layer 1). For defense-in-depth");
        eprintln!("    proxy enforcement (Layer 2), use --infra or configure");
        eprintln!("    egress_proxy_url.");
    }

    eprintln!("  ──────────────────────────────────────────────");
    eprintln!();
}

/// Wait for a shutdown signal (SIGINT or SIGTERM).
///
/// On Unix, listens for both signals. On other platforms, listens for Ctrl+C
/// only. Returns once the first signal is received.
#[allow(clippy::expect_used)] // Startup: process cannot run without signal handlers.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigint = signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");
        let mut sigterm =
            signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");

        tokio::select! {
            _ = sigint.recv() => {
                info!("received SIGINT");
            }
            _ = sigterm.recv() => {
                info!("received SIGTERM");
            }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
        info!("received Ctrl+C");
    }
}

/// Initialise structured logging from config (level + format).
///
/// Called once before `serve()`. Sets the global tracing subscriber — must
/// not be called more than once per process.
///
/// Returns an optional `WorkerGuard` that MUST be held alive for the
/// lifetime of the process. Dropping it stops the non-blocking file writer
/// and flushes pending events. The caller stores it alongside the
/// subscriber to prevent silent log loss.
///
/// Format resolution:
///
/// * `LogFormat::Auto` — Pretty when stderr is a terminal **and**
///   `dev_mode = true`; otherwise Json.
/// * `LogFormat::Json` — always JSON.
/// * `LogFormat::Pretty` — always compact pretty with ANSI when stderr is a TTY.
pub fn init_logging(config: &Config) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    use std::io::IsTerminal as _;
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.logging.level));

    let stderr_is_tty = std::io::stderr().is_terminal();

    let effective = match config.logging.format {
        LogFormat::Json => LogFormat::Json,
        LogFormat::Pretty => LogFormat::Pretty,
        LogFormat::Auto => {
            if stderr_is_tty && config.dev_mode() {
                LogFormat::Pretty
            } else {
                LogFormat::Json
            }
        }
    };

    // Build the rolling file writer if log_file is configured.
    let (file_writer, guard) = match config.logging.file.as_ref() {
        Some(path) => {
            let log_path = std::path::Path::new(path);
            if let Some(parent) = log_path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent).ok();
                }
            }

            let file_name = log_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("gate.log");
            let dir = log_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."));

            let appender = match config.logging.rotation {
                latchgate_config::LogRotation::Daily => {
                    tracing_appender::rolling::daily(dir, file_name)
                }
                latchgate_config::LogRotation::Hourly => {
                    tracing_appender::rolling::hourly(dir, file_name)
                }
                latchgate_config::LogRotation::Never => {
                    tracing_appender::rolling::never(dir, file_name)
                }
            };

            let (writer, guard) = tracing_appender::non_blocking(appender);
            (Some(writer), Some(guard))
        }
        None => (None, None),
    };

    // Build the subscriber with stderr layer + optional rolling file layer.
    match effective {
        LogFormat::Json => {
            let file_layer = file_writer.map(|w| fmt::layer().json().with_writer(w));
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().json().with_writer(std::io::stderr))
                .with(file_layer)
                .init();
        }
        LogFormat::Pretty => {
            let file_layer = file_writer.map(|w| fmt::layer().json().with_writer(w));
            tracing_subscriber::registry()
                .with(filter)
                .with(
                    fmt::layer()
                        .with_writer(std::io::stderr)
                        .with_ansi(stderr_is_tty)
                        .with_target(false)
                        .compact(),
                )
                .with(file_layer)
                .init();
        }
        LogFormat::Auto => unreachable!("LogFormat::Auto must be resolved before subscriber init"),
    }

    guard
}

/// Quiet logging for diagnostic commands — only warnings and above to stderr.
/// These commands print their own structured output; log noise pollutes it.
pub fn init_logging_quiet() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    fmt::Subscriber::builder()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .without_time()
        .init();
}
