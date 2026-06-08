//! `WasmRuntime` — module cache, precompilation, and per-call execution.
//!
//! Constructed once at server startup. The wasmtime `Engine` is shared
//! across all executions. Modules are precompiled into `Component`s and
//! cached as pre-linked `ProviderPre` handles. Each `execute` call
//! creates a fresh `Store` + `Instance` from the cached `ProviderPre`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use lettre::{AsyncSmtpTransport, Tokio1Executor};
use object_store::ObjectStore;
use tracing::{debug, info, instrument, warn};
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store};

use super::{HostResources, Provider, ProviderPre, WasmHostAccess, WasmHostState};
use crate::host_io::HostState;
use crate::task::{RunOutput, RunTask};
use crate::ProviderError;

type WasmCallResult = Result<
    Result<Result<Result<String, String>, wasmtime::Error>, ProviderError>,
    tokio::time::error::Elapsed,
>;

// Epoch ticker configuration

/// Interval between engine epoch ticks (milliseconds).
///
/// SECURITY: this determines the maximum overshoot of wall-clock timeouts
/// for pure-computation WASM modules (no host I/O calls). With 250ms ticks,
/// a module in an infinite loop will be interrupted within ~250ms of its
/// deadline.
const EPOCH_TICK_INTERVAL_MS: u64 = 250;

// ComponentEntry — cached pre-linked component

/// Cached pre-compiled and pre-linked WASM component.
///
/// After compilation and import resolution/typechecking, `ProviderPre` holds
/// everything needed to instantiate a fresh sandbox — no re-linking or
/// re-typechecking on the request path.
struct ComponentEntry {
    /// Pre-instantiated handle: compiled component + resolved imports.
    /// Calling `instantiate_async` on this is O(alloc) — all linking and
    /// typechecking was done once at precompile time.
    provider_pre: ProviderPre<WasmHostState>,
}

/// Drop guard that signals the epoch ticker OS thread to stop when
/// `WasmRuntime` is dropped.
///
/// The ticker runs on a dedicated OS thread rather than a tokio task.
/// This is intentional: a tight WASM compute loop has no `.await` points,
/// so a tokio task on a single-threaded runtime would never get scheduled
/// and the epoch would never increment. An OS thread runs independently of
/// the tokio executor and correctly interrupts any WASM execution.
struct EpochTickerGuard(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl Drop for EpochTickerGuard {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// WASM provider runtime.
///
/// Constructed once at server startup. The `Engine` is shared across all
/// executions. Modules are precompiled into `Component`s and cached as
/// pre-linked `ProviderPre` handles. Each `execute` call creates a fresh
/// `Store` + `Instance` from the cached `ProviderPre`.
pub struct WasmRuntime {
    /// wasmtime engine (shared, thread-safe, expensive to create).
    engine: Engine,
    /// Pre-built linker with host function implementations.
    linker: Linker<WasmHostState>,
    /// Pre-linked component cache, keyed by SHA-256 digest.
    /// Each entry holds a `ProviderPre` — instantiation skips linking.
    module_cache: dashmap::DashMap<String, Arc<ComponentEntry>>,
    /// Background task that increments the engine epoch at regular intervals.
    _epoch_ticker: EpochTickerGuard,
    /// Concurrency limiter for WASM executions.
    ///
    /// SECURITY: without this, an attacker can exhaust CPU/memory by
    /// triggering many concurrent WASM executions. The semaphore bounds
    /// parallelism to `max_concurrent` permits.
    execution_semaphore: tokio::sync::Semaphore,
    /// Maximum number of concurrent WASM executions. Stored for introspection
    /// by the drain endpoint (in_flight_count = max_concurrent - available_permits).
    max_concurrent: usize,
    /// PostgreSQL connection pool. Set once at startup via `init_database()`.
    db_pool: tokio::sync::OnceCell<sqlx::PgPool>,
    /// AMQP connection pool. Set once at startup via `init_queue()`.
    amqp_pool: tokio::sync::OnceCell<super::amqp_pool::Pool>,
    /// Object storage client. Set once at startup via `init_storage()`.
    object_store: tokio::sync::OnceCell<Arc<dyn ObjectStore + Send + Sync>>,
    /// SMTP transport. Set once at startup via `init_smtp()`.
    smtp_transport: tokio::sync::OnceCell<Arc<AsyncSmtpTransport<Tokio1Executor>>>,
    /// Pre-built HTTP client for egress proxy. Set once at startup via
    /// `init_http_proxy()`. Shared across all WASM executions — the proxy
    /// URL is server-wide config, so one client (with its connection pool
    /// and TLS session cache) serves every outbound HTTP call in proxy mode.
    http_proxy_client: tokio::sync::OnceCell<reqwest::Client>,
    /// Mapping from WASM filename stems (e.g. `"http_api"`) to their SHA-256
    /// digests. Populated by `load_modules_from_dir`. Used to resolve
    /// `builtin:<name>` provider_module_digest references to actual cached digests.
    builtin_digests: dashmap::DashMap<String, String>,
}

/// Behaviour of [`WasmRuntime::load_modules_from_dir`] when a `.wasm`
/// file fails to precompile.
///
/// The right mode depends on who owns the directory.
///
/// - [`Strict`](LoadMode::Strict): used for operator-deployed module
///   directories. A corrupted or unsupported file at startup is a
///   misconfiguration that must surface immediately — never as a
///   request-time `ModuleNotFound` after the gate has been accepting
///   traffic. Fail-closed at boot.
///
/// - [`Lenient`](LoadMode::Lenient): reserved for user-managed module
///   directories where one bad file from a third party shouldn't take
///   the gate down. Logs the failure and continues.
///
/// The gate currently calls `Strict` from `init`. `Lenient` is exposed
/// for future use and to keep the two modes symmetric and testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadMode {
    /// Fail the whole load if any `.wasm` file rejects precompilation.
    Strict,
    /// Log and skip files that fail to precompile.
    Lenient,
}

impl WasmRuntime {
    /// Create a new WasmRuntime with a configured wasmtime Engine.
    ///
    /// Engine configuration:
    /// - Component model enabled (WIT-based provider interface).
    /// - Fuel consumption enabled (CPU metering per execution).
    /// - Epoch interruption enabled (wall-clock timeout enforcement).
    /// - Cranelift compiler (optimised native code generation).
    pub fn new(max_concurrent: usize) -> Result<Self, ProviderError> {
        let mut config = Config::new();
        config.wasm_component_model(true);
        config.consume_fuel(true);
        config.epoch_interruption(true);

        let engine = Engine::new(&config).map_err(|e| ProviderError::ExecutionFailed {
            reason: format!("wasmtime engine init: {e}"),
        })?;

        // Build the linker with host function implementations.
        // The linker is shared across executions; host state is per-Store.
        let mut linker: Linker<WasmHostState> = Linker::new(&engine);

        // Register WASI imports (required for wasm32-wasip2 target components).
        wasmtime_wasi::p2::add_to_linker_async(&mut linker).map_err(|e| {
            ProviderError::ExecutionFailed {
                reason: format!("WASI linker setup: {e}"),
            }
        })?;

        // Register LatchGate host I/O imports from WIT definitions.
        Provider::add_to_linker::<_, WasmHostAccess>(&mut linker, |state| state).map_err(|e| {
            ProviderError::ExecutionFailed {
                reason: format!("linker setup: {e}"),
            }
        })?;

        info!("WASM runtime initialised (wasmtime, component model, fuel metering)");

        // Spawn background epoch ticker on a dedicated OS thread.
        //
        // IMPORTANT: must NOT use tokio::spawn here. A tight WASM compute
        // loop has no .await points, so a tokio task on a single-threaded
        // runtime (e.g. #[tokio::test]) would never be scheduled while WASM
        // is executing. An OS thread runs independently of the tokio executor
        // and correctly interrupts pure-compute WASM via epoch interruption.
        let ticker_engine = engine.clone();
        let stop_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ticker_stop = stop_flag.clone();
        std::thread::Builder::new()
            .name("latchgate-epoch-ticker".into())
            .spawn(move || {
                while !ticker_stop.load(std::sync::atomic::Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(EPOCH_TICK_INTERVAL_MS));
                    ticker_engine.increment_epoch();
                }
            })
            .expect("failed to spawn epoch ticker thread");
        let epoch_ticker = EpochTickerGuard(stop_flag);

        info!(
            tick_interval_ms = EPOCH_TICK_INTERVAL_MS,
            "epoch ticker started (wall-clock enforcement for pure-computation WASM)"
        );

        Ok(Self {
            engine,
            linker,
            module_cache: dashmap::DashMap::new(),
            _epoch_ticker: epoch_ticker,
            execution_semaphore: tokio::sync::Semaphore::new(max_concurrent),
            max_concurrent,
            db_pool: tokio::sync::OnceCell::new(),
            amqp_pool: tokio::sync::OnceCell::new(),
            object_store: tokio::sync::OnceCell::new(),
            smtp_transport: tokio::sync::OnceCell::new(),
            http_proxy_client: tokio::sync::OnceCell::new(),
            builtin_digests: dashmap::DashMap::new(),
        })
    }

    /// Initialise the PostgreSQL connection pool for `latchgate:io/database`.
    ///
    /// Called once at server startup when `database_url` is configured.
    /// The pool is shared across all WASM executions — providers cannot
    /// influence which database they connect to (pool is pre-configured).
    ///
    /// SECURITY: the connection URL (including credentials) is provided by
    /// the operator via latchgate.toml, not by the provider. This ensures
    /// the host controls which database is targeted for every query.
    ///
    /// Calling this more than once returns an error (idempotency guard).
    pub async fn init_database(&self, database_url: &str) -> Result<(), ProviderError> {
        let pool = sqlx::PgPool::connect(database_url).await.map_err(|e| {
            ProviderError::ExecutionFailed {
                reason: format!("database pool init failed: {e}"),
            }
        })?;

        self.db_pool
            .set(pool)
            .map_err(|_| ProviderError::ExecutionFailed {
                reason: "database pool already initialised (init_database called twice)".into(),
            })?;

        info!("database connection pool initialised (latchgate:io/database host import ready)");
        Ok(())
    }

    /// Initialise the AMQP connection pool for `latchgate:io/queue`.
    ///
    /// Uses deadpool with a direct lapin Manager so connections are reused
    /// across executions. Pool size defaults to 4 (matching max_concurrent_executions).
    /// Called once at startup when `amqp_url` is configured.
    pub async fn init_queue(&self, amqp_url: &str) -> Result<(), ProviderError> {
        let manager = super::amqp_pool::Manager::new(amqp_url);
        let pool = super::amqp_pool::Pool::builder(manager)
            .runtime(deadpool::Runtime::Tokio1)
            .build()
            .map_err(|e| ProviderError::ExecutionFailed {
                reason: format!("AMQP pool config failed: {e}"),
            })?;

        // Eagerly test the connection so startup fails fast if the broker is
        // unreachable, rather than deferring the error to the first execution.
        let _ = pool
            .get()
            .await
            .map_err(|e| ProviderError::ExecutionFailed {
                reason: format!("AMQP pool connect test failed: {e}"),
            })?;

        self.amqp_pool
            .set(pool)
            .map_err(|_| ProviderError::ExecutionFailed {
                reason: "AMQP pool already initialised (init_queue called twice)".into(),
            })?;

        info!("AMQP connection pool initialised (latchgate:io/queue host import ready)");
        Ok(())
    }

    /// Initialise the object storage client for `latchgate:io/storage`.
    ///
    /// `storage_url` is parsed by `object_store::parse_url`:
    ///   `s3://bucket`       — AWS S3 (AWS_* env vars / IAM)
    ///   `gs://bucket`       — Google Cloud Storage
    ///   `az://container`    — Azure Blob Storage
    ///   `file:///path`      — Local filesystem (dev only)
    ///
    /// For S3-compatible endpoints set `AWS_ENDPOINT_URL` in the environment.
    /// The store is scoped to the URL's bucket/container — providers cannot
    /// redirect writes to a different storage target.
    pub fn init_storage(&self, storage_url: &str) -> Result<(), ProviderError> {
        // Belt-and-suspenders: reject unexpected schemes at the point of use,
        // independent of any upstream validation. Restricts object store
        // backends to the four supported cloud/local schemes.
        const ALLOWED_SCHEMES: &[&str] = &["s3://", "gs://", "az://", "file://"];
        if !ALLOWED_SCHEMES.iter().any(|s| storage_url.starts_with(s)) {
            return Err(ProviderError::ExecutionFailed {
                reason: format!(
                    "storage_url must use one of {ALLOWED_SCHEMES:?}, got: {storage_url}"
                ),
            });
        }

        let parsed = url::Url::parse(storage_url).map_err(|e| ProviderError::ExecutionFailed {
            reason: format!("storage_url parse failed: {e}"),
        })?;

        let (store, _path) =
            object_store::parse_url(&parsed).map_err(|e| ProviderError::ExecutionFailed {
                reason: format!("object_store::parse_url failed for '{storage_url}': {e}"),
            })?;

        let store: Arc<dyn ObjectStore + Send + Sync> =
            Arc::from(store as Box<dyn ObjectStore + Send + Sync>);

        self.object_store
            .set(store)
            .map_err(|_| ProviderError::ExecutionFailed {
                reason: "object store already initialised (init_storage called twice)".into(),
            })?;

        info!(
            storage_url,
            "object store initialised (latchgate:io/storage host import ready)"
        );
        Ok(())
    }

    /// Initialise the SMTP transport for `latchgate:io/smtp`.
    ///
    /// `smtp_url` format:
    ///   `smtp://user:pass@host:587`   — STARTTLS (recommended)
    ///   `smtps://user:pass@host:465`  — Implicit TLS
    ///
    /// The transport is pooled internally by lettre and shared across
    /// executions. Providers cannot change which relay is used — only
    /// recipients (validated against allowed_sinks) are provider-controlled.
    pub fn init_smtp(&self, smtp_url: &str) -> Result<(), ProviderError> {
        let parsed = url::Url::parse(smtp_url).map_err(|e| ProviderError::ExecutionFailed {
            reason: format!("smtp_url parse failed: {e}"),
        })?;

        let host = parsed
            .host_str()
            .ok_or_else(|| ProviderError::ExecutionFailed {
                reason: format!("smtp_url '{smtp_url}' has no host"),
            })?;
        let port = parsed.port().unwrap_or(match parsed.scheme() {
            "smtps" => 465,
            _ => 587,
        });
        let user = parsed.username().to_string();
        let pass = parsed.password().unwrap_or("").to_string();

        let creds = lettre::transport::smtp::authentication::Credentials::new(user, pass);

        let transport: AsyncSmtpTransport<Tokio1Executor> = match parsed.scheme() {
            "smtps" => AsyncSmtpTransport::<Tokio1Executor>::relay(host)
                .map_err(|e| ProviderError::ExecutionFailed {
                    reason: format!("SMTP (smtps) relay init failed: {e}"),
                })?
                .port(port)
                .credentials(creds)
                .build(),
            _ => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
                .map_err(|e| ProviderError::ExecutionFailed {
                    reason: format!("SMTP (STARTTLS) relay init failed: {e}"),
                })?
                .port(port)
                .credentials(creds)
                .build(),
        };

        self.smtp_transport.set(Arc::new(transport)).map_err(|_| {
            ProviderError::ExecutionFailed {
                reason: "SMTP transport already initialised (init_smtp called twice)".into(),
            }
        })?;

        info!(
            smtp_host = host,
            smtp_port = port,
            smtp_scheme = parsed.scheme(),
            "SMTP transport initialised (latchgate:io/smtp host import ready)"
        );
        Ok(())
    }

    /// Build and cache a `reqwest::Client` pre-configured for the egress proxy.
    ///
    /// Called once at server startup when `config.egress.egress_proxy_url` is
    /// set. The client is shared across all WASM executions — `reqwest::Client`
    /// is internally `Arc`-backed, so cloning into each `HostResources` is O(1).
    ///
    /// The cached client has:
    /// - `user_agent("latchgate/0.1")`
    /// - Redirect following disabled (provider must handle redirects).
    /// - Proxy configured for all schemes.
    ///
    /// SECURITY: the kernel's SSRF check (`resolve_and_check_ssrf`) still runs
    /// on every request before the proxy client is used. The proxy provides an
    /// independent allowlist enforcement layer (defense-in-depth).
    pub fn init_http_proxy(&self, proxy_url: &str) -> Result<(), ProviderError> {
        let proxy = reqwest::Proxy::all(proxy_url).map_err(|e| ProviderError::ExecutionFailed {
            reason: format!("invalid egress proxy URL '{proxy_url}': {e}"),
        })?;

        let client = reqwest::Client::builder()
            .user_agent("latchgate/0.1")
            .redirect(reqwest::redirect::Policy::none())
            .proxy(proxy)
            .build()
            .map_err(|e| ProviderError::ExecutionFailed {
                reason: format!("egress proxy HTTP client build failed: {e}"),
            })?;

        self.http_proxy_client
            .set(client)
            .map_err(|_| ProviderError::ExecutionFailed {
                reason: "HTTP proxy client already initialised (init_http_proxy called twice)"
                    .into(),
            })?;

        info!(proxy_url, "egress proxy HTTP client initialised");
        Ok(())
    }

    /// Precompile a WASM component and cache it by digest.
    ///
    /// SECURITY: the SHA-256 digest of the raw bytes is computed and
    /// compared against `expected_digest`. Mismatch = reject.
    ///
    /// The `Component::new` call validates the WASM binary and compiles
    /// it to native code via Cranelift. This is the expensive step
    /// (~50-200ms) that we do once at startup.
    #[instrument(name = "wasm.precompile", skip(self, wasm_bytes), fields(%expected_digest, size_bytes = wasm_bytes.len()))]
    pub fn precompile(
        &self,
        wasm_bytes: &[u8],
        expected_digest: &str,
    ) -> Result<(), ProviderError> {
        // Step 1: verify digest.
        let actual_digest = latchgate_core::sha256_digest(wasm_bytes);
        if actual_digest != expected_digest {
            return Err(ProviderError::DigestMismatch {
                expected: expected_digest.to_string(),
                actual: actual_digest,
            });
        }

        // Step 2: compile to native code.
        let component = Component::new(&self.engine, wasm_bytes).map_err(|e| {
            ProviderError::ExecutionFailed {
                reason: format!("WASM compilation failed: {e}"),
            }
        })?;

        // Step 3: pre-instantiate (resolve imports + typecheck once).
        //
        // ProviderPre holds everything needed to instantiate a fresh
        // sandbox — import resolution and typechecking happen here,
        // not on the request path.
        let instance_pre = self.linker.instantiate_pre(&component).map_err(|e| {
            ProviderError::ExecutionFailed {
                reason: format!("instantiate_pre failed: {e}"),
            }
        })?;
        let provider_pre =
            ProviderPre::new(instance_pre).map_err(|e| ProviderError::ExecutionFailed {
                reason: format!("ProviderPre::new failed: {e}"),
            })?;

        let entry = Arc::new(ComponentEntry { provider_pre });

        // Step 4: cache by digest.
        info!(
            digest = %actual_digest,
            size_bytes = wasm_bytes.len(),
            "WASM component precompiled, pre-linked, and cached"
        );

        self.module_cache.insert(actual_digest.clone(), entry);
        Ok(())
    }

    /// Execute a WASM provider module in a fresh sandbox.
    ///
    /// # Per-call lifecycle
    ///
    /// 1. Look up pre-linked `ProviderPre` by digest (no linking work).
    /// 2. Create fresh `Store<WasmHostState>` with fuel + memory limits.
    /// 3. Instantiate from `ProviderPre` (skips import resolution/typechecking).
    /// 4. Call `execute(task_json)` export.
    /// 5. Parse result, collect metrics, drop instance.
    ///
    /// SECURITY: every call is a fresh sandbox. No state persists
    /// between calls. Credentials are injected at the host layer.
    #[instrument(
        name = "wasm.execute",
        skip(self, task),
        fields(
            trace_id = %task.trace_id,
            module_digest = %task.module_digest,
            fuel = task.resource_limits.fuel,
            timeout_seconds = task.resource_limits.timeout_seconds,
        )
    )]
    pub async fn execute(&self, task: RunTask) -> Result<RunOutput, ProviderError> {
        // SECURITY: bound concurrent WASM executions to prevent resource
        // exhaustion. The semaphore is sized from latchgate_core::security_constants::MAX_CONCURRENT_EXECUTIONS.
        let _permit = self.execution_semaphore.acquire().await.map_err(|_| {
            ProviderError::ExecutionFailed {
                reason: "execution semaphore closed".into(),
            }
        })?;

        let start = Instant::now();

        // Step 1: look up pre-linked component entry.
        let entry = self
            .module_cache
            .get(&*task.module_digest)
            .map(|r| Arc::clone(&*r))
            .ok_or_else(|| ProviderError::ModuleNotFound {
                digest: task.module_digest.to_string(),
            })?;

        // Step 2: create fresh Store with resource limits and host I/O bindings.
        debug!(
            allowed_imports = ?task.allowed_imports,
            memory_mb = task.resource_limits.memory_mb,
            max_io_calls = task.resource_limits.max_io_calls,
            "instantiating WASM sandbox"
        );
        let host_config = crate::host_io::HostStateConfig {
            allowed_sinks: task.allowed_sinks,
            approved_secrets: task.approved_secrets,
            decrypted_secrets: task.decrypted_secrets,
            trace_id: Arc::clone(&task.trace_id),
            max_io_calls: task.resource_limits.max_io_calls,
            max_host_response_bytes: task.resource_limits.max_host_response_bytes,
            allowed_imports: task.allowed_imports,
            database_config: task.database_config,
            egress_proxy_url: task.egress_proxy_url,
            max_log_calls: None,
            max_log_message_bytes: None,
            fs_config: task.fs_config,
        };
        let mut store = self.prepare_store(host_config, &task.resource_limits)?;

        // Steps 3+4: instantiate and execute under a single wall-clock timeout.
        let timeout = Duration::from_secs(task.resource_limits.timeout_seconds as u64);
        let call_result = tokio::time::timeout(timeout, async {
            let provider = entry
                .provider_pre
                .instantiate_async(&mut store)
                .await
                .map_err(|e| {
                    let reason = format!("{e}");
                    // SECURITY: check remaining fuel first. If fuel is 0 and we
                    // got a trap, fuel exhaustion is the root cause regardless of
                    // the error message (e.g. OOM in cabi_realloc with no fuel).
                    let fuel_left = store.get_fuel().unwrap_or_else(|e| {
                        warn!(error = %e, "SECURITY: store.get_fuel() failed — assuming 0");
                        0
                    });
                    if fuel_left == 0 || reason.contains("fuel") {
                        return ProviderError::FuelExhausted;
                    }
                    if reason.contains("import") {
                        ProviderError::ImportNotDeclared { import: reason }
                    } else {
                        ProviderError::ExecutionFailed { reason }
                    }
                })?;

            Ok::<_, ProviderError>(provider.call_execute(&mut store, &task.args_json).await)
        })
        .await;

        // Step 5: collect metrics and interpret the result.
        let duration = start.elapsed();
        let fuel_remaining = store.get_fuel().unwrap_or_else(|e| {
            warn!(error = %e, "SECURITY: store.get_fuel() failed post-execution — assuming 0");
            0
        });
        let fuel_consumed = task.resource_limits.fuel.saturating_sub(fuel_remaining);
        let io_calls_made = store.data().host_io.io_calls_count();
        let host_observed = store.data().host_io.take_observed_effects();

        collect_execution_result(
            call_result,
            &task.module_digest,
            &task.resource_limits,
            fuel_remaining,
            fuel_consumed,
            io_calls_made,
            host_observed,
            duration,
        )
    }

    /// Build a configured [`Store`] with host I/O bindings and resource limits.
    ///
    /// The returned store has fuel metering and epoch-based wall-clock
    /// enforcement configured. It is ready for `instantiate_async`.
    fn prepare_store(
        &self,
        host_config: crate::host_io::HostStateConfig,
        resource_limits: &latchgate_core::ResourceLimits,
    ) -> Result<Store<WasmHostState>, ProviderError> {
        let host_io = HostState::new(host_config);
        let host_state = WasmHostState::new(
            host_io,
            HostResources {
                db_pool: self.db_pool.get().cloned(),
                amqp_pool: self.amqp_pool.get().cloned(),
                object_store: self.object_store.get().cloned(),
                smtp_transport: self.smtp_transport.get().cloned(),
                http_proxy_client: self.http_proxy_client.get().cloned(),
            },
            resource_limits.memory_mb,
        );

        let mut store = Store::new(&self.engine, host_state);
        store.limiter(|state| state);

        // Fuel metering: set initial fuel budget.
        store
            .set_fuel(resource_limits.fuel)
            .map_err(|e| ProviderError::ExecutionFailed {
                reason: format!("set fuel: {e}"),
            })?;

        // Epoch-based wall-clock enforcement: set a deadline on this Store so
        // wasmtime traps the execution after approximately `timeout_seconds`.
        // The background epoch ticker increments the engine epoch every
        // EPOCH_TICK_INTERVAL_MS; we compute the number of ticks that
        // correspond to the configured timeout.
        //
        // SECURITY: this catches pure-computation infinite loops where
        // tokio::time::timeout would never fire (no await points in WASM).
        // Worst-case overshoot: one tick interval (250ms).
        {
            let ticks_per_second = 1_000 / EPOCH_TICK_INTERVAL_MS;
            let deadline_ticks = resource_limits.timeout_seconds as u64 * ticks_per_second;
            // Minimum 1 tick to avoid immediate trap.
            store.set_epoch_deadline(deadline_ticks.max(1));
            // REQUIRED for async stores: without this, wasmtime yields
            // at the epoch boundary instead of trapping.
            store.epoch_deadline_trap();
        }

        Ok(store)
    }

    /// Number of cached modules.
    pub fn cached_module_count(&self) -> usize {
        self.module_cache.len()
    }

    /// Number of WASM executions currently in flight.
    ///
    /// Computed from the execution semaphore: in_flight = max - available.
    /// Used by the drain endpoint to wait for all executions to complete.
    pub fn in_flight_count(&self) -> usize {
        self.max_concurrent - self.execution_semaphore.available_permits()
    }

    /// Maximum concurrent WASM executions (semaphore capacity).
    pub fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }

    /// Load and precompile all .wasm files from a directory.
    ///
    /// Each file is hashed (SHA-256) and cached by digest. The expected
    /// digest is computed from the file contents — the file name is
    /// informational only.
    ///
    /// Behaviour on a bad `.wasm` is controlled by `mode`; see
    /// [`LoadMode`] for the trade-off. Files whose extension is not
    /// `.wasm` are always skipped silently — they are not actionable
    /// regardless of mode.
    ///
    /// Returns the number of modules successfully loaded.
    pub fn load_modules_from_dir(
        &self,
        dir: &std::path::Path,
        mode: LoadMode,
    ) -> Result<usize, ProviderError> {
        if !dir.exists() {
            info!(path = %dir.display(), "WASM providers directory does not exist, skipping");
            return Ok(0);
        }

        let mut count = 0;
        let entries = std::fs::read_dir(dir).map_err(|e| ProviderError::ExecutionFailed {
            reason: format!("read providers dir {}: {e}", dir.display()),
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| ProviderError::ExecutionFailed {
                reason: format!("read dir entry: {e}"),
            })?;

            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("wasm") {
                continue;
            }

            latchgate_core::paths::ensure_contained(dir, &path).map_err(|_| {
                ProviderError::PathTraversal {
                    path: path.display().to_string(),
                    root: dir.display().to_string(),
                }
            })?;

            let wasm_bytes = std::fs::read(&path).map_err(|e| ProviderError::ExecutionFailed {
                reason: format!("read {}: {e}", path.display()),
            })?;

            let digest = latchgate_core::sha256_digest(&wasm_bytes);

            match self.precompile(&wasm_bytes, &digest) {
                Ok(()) => {
                    // Record file_stem => digest for builtin: resolution.
                    // e.g. "http_api.wasm" => file_stem "http_api" => digest "sha256:..."
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                        self.builtin_digests
                            .insert(stem.to_string(), digest.clone());
                    }

                    info!(
                        file = %path.display(),
                        digest = %digest,
                        "loaded WASM provider module"
                    );
                    count += 1;
                }
                Err(e) => match mode {
                    LoadMode::Strict => {
                        // SECURITY: fail-closed at startup. A corrupted
                        // builtin must not be silently absent — at request
                        // time it would surface as ModuleNotFound, after
                        // the gate has been accepting traffic with a
                        // broken capability surface. Surface the failure
                        // at boot so the operator sees it before serving.
                        return Err(ProviderError::ExecutionFailed {
                            reason: format!(
                                "precompile {} failed (strict mode): {e}",
                                path.display()
                            ),
                        });
                    }
                    LoadMode::Lenient => {
                        warn!(
                            file = %path.display(),
                            error = %e,
                            "failed to precompile WASM provider module, skipping (lenient mode)"
                        );
                    }
                },
            }
        }

        info!(count, "WASM provider modules loaded");
        Ok(count)
    }

    /// Load precompiled WASM provider modules from in-memory byte slices.
    ///
    /// Used for built-in providers embedded in the binary via `include_bytes!`.
    /// Each module's digest is computed from its bytes and registered in the
    /// builtin digest map for `builtin:<name>` manifest resolution.
    ///
    /// Embedded modules are trusted: the digest is self-computed (the bytes
    /// are part of the binary itself — tampering with them implies tampering
    /// with the entire binary).
    pub fn load_embedded_modules(&self, modules: &[(&str, &[u8])]) -> Result<usize, ProviderError> {
        let mut count = 0;

        for &(name, bytes) in modules {
            let digest = latchgate_core::sha256_digest(bytes);

            self.precompile(bytes, &digest)?;

            self.builtin_digests
                .insert(name.to_string(), digest.clone());

            info!(
                name = %name,
                digest = %digest,
                size_bytes = bytes.len(),
                "loaded embedded WASM provider module"
            );
            count += 1;
        }

        info!(count, "embedded WASM provider modules loaded");
        Ok(count)
    }

    /// Resolve a `builtin:<name>` provider module to its SHA-256 digest.
    ///
    /// Returns the cached digest for the named provider's `.wasm` file,
    /// or `None` if no file with that stem was loaded.
    ///
    /// Used by the pipeline to translate `builtin:http_api` =>
    /// `sha256:<actual_digest>` before constructing `RunTask`.
    pub fn resolve_builtin_digest(&self, builtin_name: &str) -> Option<String> {
        self.builtin_digests.get(builtin_name).map(|r| r.clone())
    }

    /// Resolve a manifest `provider_module_digest` to a concrete, cache-keyed
    /// digest. `builtin:<name>` references are mapped to the actual content
    /// SHA registered at startup; concrete digests pass through unchanged.
    ///
    /// SECURITY: this is the single source of truth for digest resolution.
    /// Both the direct pipeline and the approved-execution path MUST resolve
    /// through here before calling `execute`, otherwise an unresolved
    /// `builtin:` label is looked up in the (sha-keyed) module cache, misses,
    /// and surfaces as a spurious `ModuleNotFound`/provider failure.
    pub fn resolve_module_digest(
        &self,
        provider_module_digest: &str,
    ) -> Result<String, ProviderError> {
        match provider_module_digest.strip_prefix("builtin:") {
            Some(name) => {
                self.resolve_builtin_digest(name)
                    .ok_or_else(|| ProviderError::ModuleNotFound {
                        digest: format!("builtin:{name}"),
                    })
            }
            None => Ok(provider_module_digest.to_string()),
        }
    }

    /// Reference to the wasmtime Engine.
    ///
    /// The epoch ticker is managed internally; this accessor exists for
    /// diagnostics and testing.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }
}

// Trap classification

/// Interpret the nested result from wasmtime execution into a [`RunOutput`].
///
/// Handles four outcome layers:
///
/// 1. `Err(Elapsed)` — wall-clock timeout
/// 2. `Ok(Err(ProviderError))` — instantiation failure (already classified)
/// 3. `Ok(Ok(Err(wasmtime::Error)))` — WASM trap (fuel, memory, epoch)
/// 4. `Ok(Ok(Ok(Result<String, String>)))` — provider-level Ok/Err
#[allow(clippy::too_many_arguments)]
fn collect_execution_result(
    call_result: WasmCallResult,
    module_digest: &str,
    resource_limits: &latchgate_core::ResourceLimits,
    fuel_remaining: u64,
    fuel_consumed: u64,
    io_calls_made: u32,
    host_observed: Vec<crate::host_io::HostObservedEffect>,
    duration: Duration,
) -> Result<RunOutput, ProviderError> {
    match call_result {
        // Wall-clock timeout (covers both instantiation and execution).
        Err(_elapsed) => {
            warn!(
                module_digest = %module_digest,
                timeout_seconds = resource_limits.timeout_seconds,
                fuel_consumed,
                "WASM execution timed out"
            );
            Err(ProviderError::WasmTimeout)
        }
        // Instantiation failed (pre-linked handle error, fuel exhaustion
        // during start function, missing import). Already classified into
        // a ProviderError by the map_err in the instantiation step.
        Ok(Err(provider_err)) => Err(provider_err),
        // wasmtime execution error (trap).
        Ok(Ok(Err(e))) => Err(classify_wasm_trap(
            e,
            fuel_remaining,
            module_digest,
            resource_limits.timeout_seconds,
            fuel_consumed,
        )),
        // Provider returned result<string, string>.
        Ok(Ok(Ok(wasm_result))) => match wasm_result {
            // Provider Ok: parse JSON response.
            Ok(ref ok_json) => {
                let stdout: serde_json::Value =
                    serde_json::from_str(ok_json).map_err(|e| ProviderError::ExecutionFailed {
                        reason: format!("provider returned invalid JSON: {e}"),
                    })?;

                info!(
                    module_digest = %module_digest,
                    duration_ms = duration.as_millis(),
                    fuel_consumed,
                    io_calls_made,
                    "WASM execution succeeded"
                );

                Ok(RunOutput {
                    stdout: Arc::new(stdout),
                    exit_code: 0,
                    duration,
                    io_calls_made,
                    fuel_consumed,
                    host_observed,
                })
            }
            // Provider Err: business-level failure.
            Err(ref err_msg) => {
                info!(
                    module_digest = %module_digest,
                    duration_ms = duration.as_millis(),
                    fuel_consumed,
                    io_calls_made,
                    error = %err_msg,
                    "WASM execution returned provider error"
                );

                Ok(RunOutput {
                    stdout: Arc::new(serde_json::json!({ "error": err_msg })),
                    exit_code: 1,
                    duration,
                    io_calls_made,
                    fuel_consumed,
                    host_observed,
                })
            }
        },
    }
}

/// Classify a wasmtime execution trap into the appropriate [`ProviderError`].
///
/// SECURITY: fuel exhaustion takes priority over all other error signals.
/// When fuel reaches 0, wasmtime may report various trap types (OOM in
/// `cabi_realloc`, stack overflow, etc.) depending on where the fuel ran out.
/// Checking `fuel_remaining == 0` catches these regardless of the trap message.
///
/// Classification order (first match wins):
///
///   1. Fuel exhaustion  => `FuelExhausted`
///   2. Memory violation  => `MemoryLimitExceeded`
///   3. wasmtime::Trap    => `WasmTimeout` (epoch deadline)
///   4. Anything else     => `ExecutionFailed`
fn classify_wasm_trap(
    error: wasmtime::Error,
    fuel_remaining: u64,
    module_digest: &str,
    timeout_seconds: u32,
    fuel_consumed: u64,
) -> ProviderError {
    let reason = format!("{error}");

    // 1. Fuel exhaustion — highest priority.
    if reason.contains("fuel") || fuel_remaining == 0 {
        return ProviderError::FuelExhausted;
    }

    // 2. Memory limit.
    if reason.contains("memory") {
        return ProviderError::MemoryLimitExceeded;
    }

    // 3. wasmtime::Trap — epoch deadline (wall-clock timeout).
    // After excluding fuel and memory, any remaining Trap is the epoch
    // deadline. Stack overflow, unreachable, and divide-by-zero are mapped
    // to ExecutionFailed by the provider ABI before they reach here.
    if error.downcast_ref::<wasmtime::Trap>().is_some() {
        warn!(
            module_digest = %module_digest,
            timeout_seconds,
            fuel_consumed,
            trap = %reason,
            "WASM execution hit epoch deadline (wall-clock timeout)"
        );
        return ProviderError::WasmTimeout;
    }

    // 4. Unclassified execution failure.
    ProviderError::ExecutionFailed { reason }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    // Construction and configuration

    #[tokio::test]
    async fn engine_created_successfully() {
        let rt = WasmRuntime::new(4).unwrap();
        assert_eq!(rt.cached_module_count(), 0);
    }

    #[tokio::test]
    async fn max_concurrent_returns_configured_value() {
        let rt = WasmRuntime::new(8).unwrap();
        assert_eq!(rt.max_concurrent(), 8);
    }

    #[tokio::test]
    async fn in_flight_starts_at_zero() {
        let rt = WasmRuntime::new(4).unwrap();
        assert_eq!(rt.in_flight_count(), 0);
    }

    #[tokio::test]
    async fn single_concurrency_succeeds() {
        let rt = WasmRuntime::new(1).unwrap();
        assert_eq!(rt.max_concurrent(), 1);
    }

    #[tokio::test]
    async fn multiple_runtimes_are_independent() {
        let rt1 = WasmRuntime::new(2).unwrap();
        let rt2 = WasmRuntime::new(4).unwrap();

        assert_eq!(rt1.max_concurrent(), 2);
        assert_eq!(rt2.max_concurrent(), 4);
        assert_eq!(rt1.cached_module_count(), 0);
        assert_eq!(rt2.cached_module_count(), 0);
    }

    // Module digest resolution (shared by direct + approved-execution paths)

    #[tokio::test]
    async fn resolve_module_digest_maps_registered_builtin_to_sha() {
        let rt = WasmRuntime::new(2).unwrap();
        rt.builtin_digests
            .insert("http_api".into(), "sha256:abc123".into());

        // The bug: an unresolved `builtin:` label was passed to the sha-keyed
        // module cache. Resolution must yield the concrete sha.
        let resolved = rt.resolve_module_digest("builtin:http_api").unwrap();
        assert_eq!(resolved, "sha256:abc123");
    }

    #[tokio::test]
    async fn resolve_module_digest_passes_through_concrete_sha() {
        let rt = WasmRuntime::new(2).unwrap();
        let sha = "sha256:4579ece6038c6f949920b4972eba4dd6";
        assert_eq!(rt.resolve_module_digest(sha).unwrap(), sha);
    }

    #[tokio::test]
    async fn resolve_module_digest_errors_on_unregistered_builtin() {
        let rt = WasmRuntime::new(2).unwrap();
        let err = rt.resolve_module_digest("builtin:nonexistent").unwrap_err();
        assert!(
            matches!(err, ProviderError::ModuleNotFound { ref digest } if digest == "builtin:nonexistent"),
            "got: {err:?}"
        );
    }

    // Precompile

    #[tokio::test]
    async fn precompile_verifies_digest() {
        let rt = WasmRuntime::new(4).unwrap();
        let data = b"test module bytes";
        let correct = latchgate_core::sha256_digest(data);

        // Wrong digest: rejected before compilation.
        let err = rt.precompile(data, "sha256:0000").unwrap_err();
        assert!(matches!(err, ProviderError::DigestMismatch { .. }));

        // Correct digest but invalid WASM: compilation fails.
        let err = rt.precompile(data, &correct).unwrap_err();
        assert!(matches!(err, ProviderError::ExecutionFailed { .. }));
    }

    #[tokio::test]
    async fn precompile_empty_bytes_rejected() {
        let rt = WasmRuntime::new(4).unwrap();
        let data: &[u8] = b"";
        let digest = latchgate_core::sha256_digest(data);

        let err = rt.precompile(data, &digest).unwrap_err();
        assert!(
            matches!(err, ProviderError::ExecutionFailed { .. }),
            "empty bytes must fail WASM compilation: {err:?}"
        );
        assert_eq!(
            rt.cached_module_count(),
            0,
            "failed precompile must not cache"
        );
    }

    #[tokio::test]
    async fn precompile_wrong_digest_does_not_cache() {
        let rt = WasmRuntime::new(4).unwrap();
        let _ = rt.precompile(b"garbage", "sha256:wrong");
        assert_eq!(rt.cached_module_count(), 0);
    }

    // Execute

    #[tokio::test]
    async fn execute_not_found_without_precompile() {
        let rt = WasmRuntime::new(4).unwrap();
        let task = RunTask {
            module_digest: "sha256:deadbeef".into(),
            args_json: "{}".into(),
            allowed_imports: vec![],
            resource_limits: latchgate_core::ResourceLimits::default(),
            allowed_sinks: vec![],
            approved_secrets: vec![],
            decrypted_secrets: std::collections::HashMap::new(),
            trace_id: "test".into(),
            database_config: None,
            egress_proxy_url: None,
            fs_config: None,
        };
        let err = rt.execute(task).await.unwrap_err();
        assert!(matches!(err, ProviderError::ModuleNotFound { .. }));
    }

    // Stateless execution across calls is tested in
    // tests/standalone/isolation.rs::execute_is_stateless_across_calls.

    // Builtin digest resolution

    #[tokio::test]
    async fn resolve_builtin_unknown_returns_none() {
        let rt = WasmRuntime::new(1).unwrap();
        assert!(rt.resolve_builtin_digest("nonexistent_provider").is_none());
    }

    // Init guard tests (invalid URL, double-init) are in
    // tests/standalone/isolation.rs — they exercise the public API.

    // Load modules from dir

    #[tokio::test]
    async fn load_modules_from_empty_dir_strict() {
        let rt = WasmRuntime::new(1).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let count = rt
            .load_modules_from_dir(dir.path(), LoadMode::Strict)
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn load_modules_from_empty_dir_lenient() {
        let rt = WasmRuntime::new(1).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let count = rt
            .load_modules_from_dir(dir.path(), LoadMode::Lenient)
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn load_modules_from_nonexistent_dir_returns_zero_in_both_modes() {
        let rt = WasmRuntime::new(1).unwrap();
        for mode in [LoadMode::Strict, LoadMode::Lenient] {
            let count = rt
                .load_modules_from_dir(std::path::Path::new("/nonexistent/wasm/dir"), mode)
                .unwrap();
            assert_eq!(
                count, 0,
                "nonexistent dir must be gracefully skipped in {mode:?}"
            );
        }
    }

    #[tokio::test]
    async fn load_modules_skips_non_wasm_files() {
        // Non-.wasm extensions are not actionable as modules and must be
        // skipped silently regardless of mode.
        let rt = WasmRuntime::new(1).unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("readme.txt"), "not wasm").unwrap();
        std::fs::write(dir.path().join("config.json"), "{}").unwrap();
        let count_strict = rt
            .load_modules_from_dir(dir.path(), LoadMode::Strict)
            .unwrap();
        assert_eq!(count_strict, 0);
        let count_lenient = rt
            .load_modules_from_dir(dir.path(), LoadMode::Lenient)
            .unwrap();
        assert_eq!(count_lenient, 0);
    }

    #[tokio::test]
    async fn load_modules_strict_rejects_invalid_wasm_file() {
        // SECURITY regression: a corrupted `.wasm` in an operator-deployed
        // directory must fail the load — never silently skip. The gate
        // would otherwise come up with a missing builtin and surface the
        // problem at request time as ModuleNotFound.
        let rt = WasmRuntime::new(1).unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("bad.wasm"), "not valid wasm bytes").unwrap();
        let err = rt
            .load_modules_from_dir(dir.path(), LoadMode::Strict)
            .expect_err("strict mode must reject invalid .wasm");
        match err {
            ProviderError::ExecutionFailed { reason } => {
                assert!(
                    reason.contains("strict mode"),
                    "expected strict-mode reason, got: {reason}"
                );
            }
            other => panic!("expected ExecutionFailed, got {other:?}"),
        }
        assert_eq!(rt.cached_module_count(), 0);
    }

    #[tokio::test]
    async fn load_modules_lenient_skips_invalid_wasm_file() {
        let rt = WasmRuntime::new(1).unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("bad.wasm"), "not valid wasm bytes").unwrap();
        let count = rt
            .load_modules_from_dir(dir.path(), LoadMode::Lenient)
            .unwrap();
        assert_eq!(count, 0, "invalid .wasm must be skipped in lenient mode");
        assert_eq!(rt.cached_module_count(), 0);
    }
}
