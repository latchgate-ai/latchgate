//! Subsystem construction from config — single assembly point.
//!
//! [`build_state`] constructs every kernel subsystem (auth, crypto,
//! enforcement, runtime, registry, ledger, metrics) from a [`Config`] and
//! embedded content parameters. The API crate calls this once at startup;
//! route handlers never import sub-crates directly.
//!
//! # Design
//!
//! The kernel owns its sub-dependency wiring. The API layer passes in config
//! and embedded content; the kernel decides _how_ to construct each
//! subsystem. This keeps sub-crate construction details out of the API
//! layer and ensures that changes to subsystem internals only require
//! updates within the kernel.

use std::path::Path;
use std::sync::Arc;

use tracing::info;

use latchgate_config::Config;

use crate::state::{
    AppState, AppStateInit, AuthServicesInit, CryptoServicesInit, EnforcementServicesInit,
    LifecycleInit, RuntimeServicesInit,
};
use crate::verification::VerifierRegistry;

/// Structured startup error returned by [`build_state`].
///
/// Each variant carries a human-readable detail string and maps to a
/// machine-readable [`code`](InitError::code) for structured startup error
/// reporting (parsed by orchestrators).
#[derive(Debug, thiserror::Error)]
pub enum InitError {
    #[error("issuer: {0}")]
    Issuer(String),

    #[error("redis: {0}")]
    Redis(String),

    #[error("state_db: {0}")]
    StateDb(String),

    #[error("registry: {0}")]
    Registry(String),

    #[error("ledger: {0}")]
    Ledger(String),

    #[error("metrics: {0}")]
    Metrics(String),

    #[error("wasm_runtime: {0}")]
    WasmRuntime(String),

    #[error("wasm_modules: {0}")]
    WasmModules(String),

    #[error("host_io: {0}")]
    HostIo(String),

    #[error("signing_key: {0}")]
    SigningKey(String),

    #[error("fs_root: {0}")]
    FsRoot(String),

    #[error("config: {0}")]
    Config(String),
}

impl InitError {
    /// Machine-readable error code for structured startup error reporting.
    ///
    /// Orchestrators (LatchGate Platform provisioner) parse these to surface
    /// actionable errors in the management UI.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Issuer(_) => "issuer_init_failed",
            Self::Redis(_) => "redis_unreachable",
            Self::StateDb(_) => "state_db_open_failed",
            Self::Registry(_) => "registry_load_failed",
            Self::Ledger(_) => "ledger_open_failed",
            Self::Metrics(_) => "metrics_init_failed",
            Self::WasmRuntime(_) => "wasm_runtime_init_failed",
            Self::WasmModules(_) => "wasm_modules_load_failed",
            Self::HostIo(_) => "host_io_init_failed",
            Self::SigningKey(_) => "signing_key_failed",
            Self::FsRoot(_) => "fs_root_open_failed",
            Self::Config(_) => "config_validation_failed",
        }
    }
}

/// Parameters for [`build_state`].
///
/// Embedded content is passed in rather than imported directly so the kernel
/// has no dependency on `latchgate-embed`. The API layer collects these from
/// the embed crate and passes them here.
pub struct BuildParams {
    pub config: Config,
    /// Embedded manifest YAML pairs `(filename, yaml_content)`.
    pub embedded_manifests: Vec<(&'static str, &'static str)>,
    /// Embedded WASM provider modules `(name, wasm_bytes)`.
    pub embedded_providers: &'static [(&'static str, &'static [u8])],
    /// Embedded OPA Rego policy source.
    pub embedded_policy_rego: &'static str,
    /// Pre-loaded `data.json` content for the policy evaluator.
    pub policy_data_json: Option<String>,
    /// Webhook event sink. `None` when no webhook endpoints are configured.
    pub event_sink: Option<Arc<dyn latchgate_core::EventSink>>,
}

/// Metadata about the constructed state for startup reporting.
///
/// The API layer uses this for structured startup logging without needing
/// to reach into sub-crate internals.
pub struct StartupInfo {
    pub actions_total: usize,
    pub actions_embedded: usize,
    pub actions_from_dir: usize,
    pub actions_overrides: usize,
    pub wasm_embedded: usize,
    pub wasm_from_dir: usize,
    /// Receipt signer key ID for startup banner.
    pub receipt_signer_kid: String,
    /// Receipt signer verifying key hex for startup banner.
    pub receipt_signer_vk_hex: String,
    /// Grant signer key ID for startup banner.
    pub grant_signer_kid: String,
    /// Whether a SOPS secrets file is configured.
    pub secrets_configured: bool,
    /// Description of which state backend is in use.
    pub state_backend: StateBackendInfo,
    /// Description of policy backend.
    pub policy_backend: PolicyBackendInfo,
    /// Filesystem root path (if configured).
    pub fs_root_canonical: Option<String>,
}

/// Which state backend was selected during init.
pub enum StateBackendInfo {
    Redis {
        url: String,
    },
    Sqlite {
        state_db_path: String,
        max_replay_entries: usize,
    },
}

/// Which policy backend was selected during init.
pub enum PolicyBackendInfo {
    Http { opa_url: String },
    Embedded,
}

/// Construct all subsystems and return a ready-to-serve [`AppState`].
///
/// This is the single assembly point for the running gate. The API crate
/// calls this at startup and passes the result to axum route handlers.
///
/// # Security
///
/// The caller MUST call [`Config::validate_production_security`] before
/// calling this function. This function validates egress proxy coverage
/// and wildcard ACL constraints (which require the loaded registry), but
/// does not duplicate the production security check.
pub async fn build_state(params: BuildParams) -> Result<(AppState, StartupInfo), InitError> {
    let config = params.config;

    // -- Issuer ---------------------------------------------------------------
    let issuer = latchgate_auth::issuer::Issuer::new(
        config.policy.lease_ttl_seconds,
        latchgate_core::security_constants::MAX_LEASE_TTL_SECS,
    )
    .map_err(|e| InitError::Issuer(e.to_string()))?;

    info!(
        lease_ttl_seconds = config.policy.lease_ttl_seconds,
        max_lease_ttl_seconds = latchgate_core::security_constants::MAX_LEASE_TTL_SECS,
        "issuer initialised"
    );

    // -- State backends --------------------------------------------------------
    let (replay_cache, budget_manager, approval_store, state_backend) =
        init_state_backends(&config)?;

    // -- Registry -------------------------------------------------------------
    let (registry, actions_total, actions_embedded, actions_from_dir, actions_overrides) =
        init_registry(&config, &params.embedded_manifests)?;

    // -- Security constraints (egress proxy + wildcard ACL) -------------------
    validate_security_constraints(&config, &registry, params.policy_data_json.as_deref())?;

    // -- Policy client --------------------------------------------------------
    let (policy_client, policy_backend) = init_policy(
        &config,
        params.embedded_policy_rego,
        params.policy_data_json.as_deref(),
    );

    // -- Ledger ---------------------------------------------------------------
    let (ledger, metrics) = init_ledger(&config)?;

    // -- Secrets manager ------------------------------------------------------
    let (secrets_manager, secrets_configured) = init_secrets(&config);

    // -- WASM runtime ---------------------------------------------------------
    let (wasm_runtime, wasm_embedded, wasm_from_dir) =
        init_wasm_runtime(&config, params.embedded_providers).await?;

    let verifier_registry = VerifierRegistry::new();

    // -- Crypto ---------------------------------------------------------------
    let (receipt_signer, grant_signer, verifying_key_store) = init_crypto(&config)?;
    let receipt_signer_kid = receipt_signer.kid().to_string();
    let receipt_signer_vk_hex = receipt_signer.verifying_key_hex().to_string();
    let grant_signer_kid = grant_signer.kid().to_string();

    // -- Identity provider ----------------------------------------------------
    let identity_provider = latchgate_auth::build_identity_provider(&config.identity);
    info!(
        provider = ?config.identity.provider,
        "identity provider initialised"
    );

    // -- Filesystem root fd ---------------------------------------------------
    let (fs_root_fd, fs_root_canonical) = init_fs_root(&config)?;
    let fs_root_display = fs_root_canonical.as_ref().map(|p| p.display().to_string());

    // -- Per-session filesystem root map --------------------------------------
    let session_fs_roots = Arc::new(dashmap::DashMap::new());

    // -- Assemble AppState ----------------------------------------------------

    let state = AppState::new(AppStateInit {
        config,
        registry,
        embedded_manifests: params.embedded_manifests,
        ledger,
        metrics,
        auth: AuthServicesInit {
            issuer,
            replay_cache,
            identity_provider,
        },
        crypto: CryptoServicesInit {
            receipt_signer,
            grant_signer,
            verifying_key_store,
        },
        enforcement: EnforcementServicesInit {
            policy: policy_client,
            budget_manager,
            approval_store,
        },
        runtime: RuntimeServicesInit {
            wasm_runtime,
            secrets_manager,
            verifier_registry,
            fs_root_fd,
            fs_root_canonical,
            session_fs_roots,
        },
        lifecycle: LifecycleInit {
            event_sink: params.event_sink,
        },
    });

    // -- Background tasks -----------------------------------------------------

    // Session fs_root eviction — sweep every 60s.
    {
        let state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                state.evict_expired_session_fs_roots();
            }
        });
    }

    let info = StartupInfo {
        actions_total,
        actions_embedded,
        actions_from_dir,
        actions_overrides,
        wasm_embedded,
        wasm_from_dir,
        receipt_signer_kid,
        receipt_signer_vk_hex,
        grant_signer_kid,
        secrets_configured,
        state_backend,
        policy_backend,
        fs_root_canonical: fs_root_display,
    };

    Ok((state, info))
}

/// Initialise state backends (Redis or SQLite + bounded memory).
fn init_state_backends(
    config: &Config,
) -> Result<
    (
        latchgate_auth::ReplayCache,
        latchgate_state::BudgetManager,
        latchgate_state::ApprovalStore,
        StateBackendInfo,
    ),
    InitError,
> {
    let replay_ttl =
        std::time::Duration::from_secs(latchgate_core::security_constants::REPLAY_TTL_SECS);
    let approval_ttl =
        std::time::Duration::from_secs(latchgate_core::security_constants::APPROVAL_TTL_SECS);

    const MAX_REPLAY_ENTRIES: usize = 100_000;

    match config.storage.redis_url.as_deref() {
        Some(url) => {
            let replay = latchgate_auth::ReplayCache::new(
                url,
                replay_ttl,
                latchgate_core::security_constants::REDIS_KEY_PREFIX,
            )
            .map_err(|e| {
                InitError::Redis(format!(
                    "{e} — is Redis running? Check redis_url in latchgate.toml."
                ))
            })?;
            let budgets = latchgate_state::BudgetManager::new(url)
                .map_err(|e| InitError::Redis(e.to_string()))?;
            let approvals = latchgate_state::ApprovalStore::new(url, approval_ttl)
                .map_err(|e| InitError::Redis(e.to_string()))?;
            let backend = StateBackendInfo::Redis {
                url: url.to_string(),
            };
            info!(redis_url = %url, "state backends initialised (Redis)");
            Ok((replay, budgets, approvals, backend))
        }
        None => {
            let replay =
                latchgate_auth::ReplayCache::in_memory_bounded(replay_ttl, MAX_REPLAY_ENTRIES);

            let state_db_path =
                std::path::Path::new(&config.storage.ledger_db_path).with_file_name("state.db");
            let state_db = latchgate_state::SqliteStateDb::open(&state_db_path)
                .map_err(|e| InitError::StateDb(e.to_string()))?;
            let state_db = Arc::new(state_db);

            let budgets = latchgate_state::BudgetManager::sqlite(state_db.clone());
            let approvals = latchgate_state::ApprovalStore::sqlite(state_db, approval_ttl);
            let backend = StateBackendInfo::Sqlite {
                state_db_path: state_db_path.display().to_string(),
                max_replay_entries: MAX_REPLAY_ENTRIES,
            };
            info!(
                state_db = %state_db_path.display(),
                replay_max_entries = MAX_REPLAY_ENTRIES,
                "state backends initialised (SQLite + bounded memory)"
            );
            Ok((replay, budgets, approvals, backend))
        }
    }
}

/// Load embedded and directory manifests into the registry.
///
/// In dev posture, malformed manifests are skipped with a logged warning
/// rather than aborting the entire gate. Production posture stays
/// fail-closed: any unparseable manifest prevents startup.
fn init_registry(
    config: &Config,
    embedded_manifests: &[(&'static str, &'static str)],
) -> Result<
    (
        latchgate_registry::RegistryStore,
        usize,
        usize,
        usize,
        usize,
    ),
    InitError,
> {
    let mut builder = latchgate_registry::RegistryStore::builder()
        .add_embedded(embedded_manifests.iter().copied())
        .map_err(|e| InitError::Registry(e.to_string()))?;

    let is_dev = config.dev_mode();
    let mut total_skipped = 0usize;

    for dir in config.manifest_dirs() {
        if is_dev {
            let (b, skipped) = builder.add_dir_lenient(&dir).map_err(|e| {
                InitError::Registry(format!("{e} — check manifests dir: {}", dir.display()))
            })?;
            builder = b;
            for s in &skipped {
                tracing::warn!(
                    path = %s.path,
                    reason = %s.reason,
                    "skipped malformed manifest in dev mode"
                );
            }
            total_skipped += skipped.len();
        } else {
            builder = builder.add_dir(&dir).map_err(|e| {
                InitError::Registry(format!("{e} — check manifests dir: {}", dir.display()))
            })?;
        }
    }

    let registry = builder.build();

    let actions_embedded = registry
        .provenance_iter()
        .filter(|(_, s)| matches!(s, latchgate_registry::SourceKind::Embedded))
        .count();
    let actions_total = registry.len();
    let actions_from_dir = actions_total - actions_embedded;
    let actions_overrides = registry.override_count();

    info!(
        total = actions_total,
        embedded = actions_embedded,
        from_dir = actions_from_dir,
        overrides = actions_overrides,
        skipped = total_skipped,
        manifest_dirs = ?config.manifest_dirs(),
        "registry loaded"
    );
    if actions_overrides > 0 {
        tracing::warn!(
            actions_overrides,
            "embedded actions shadowed by user manifests — verify with: latchgate doctor"
        );
    }
    if total_skipped > 0 {
        tracing::warn!(
            total_skipped,
            "malformed manifests skipped (dev mode) — fix or remove before production"
        );
    }

    Ok((
        registry,
        actions_total,
        actions_embedded,
        actions_from_dir,
        actions_overrides,
    ))
}

/// Validate egress proxy coverage and wildcard ACL constraints.
///
/// SECURITY: these checks require the loaded registry and cannot run
/// during config validation alone.
fn validate_security_constraints(
    config: &Config,
    registry: &latchgate_registry::RegistryStore,
    policy_data_json: Option<&str>,
) -> Result<(), InitError> {
    // SECURITY: evaluate defense-in-depth egress posture.
    let action_egress_profiles = registry.list_actions().into_iter().filter_map(|spec| {
        spec.egress_profile()
            .ok()
            .map(|profile| (spec.action_id.as_str(), profile))
    });
    match config.validate_egress_proxy_coverage(action_egress_profiles) {
        latchgate_config::EgressCoverageResult::Covered => {}
        latchgate_config::EgressCoverageResult::KernelOnly { actions } => {
            // SECURITY: Layer 2 (proxy) is absent. Layer 1 (kernel sink
            // validation + SSRF protection + manifest domain allowlists)
            // still enforces. This is a conscious defense-in-depth
            // reduction documented in the startup banner.
            tracing::warn!(
                actions = ?actions,
                "no egress proxy configured — actions with proxy_allowlist \
                 will use kernel-only enforcement (Layer 1). For \
                 defense-in-depth proxy enforcement (Layer 2), set \
                 egress_proxy_url or use `latchgate up --infra`."
            );
        }
    }

    // SECURITY: reject wildcard ACL entries that grant high/critical risk
    // actions in production.
    if let Some(data_str) = policy_data_json {
        if let Ok(data_val) = serde_json::from_str::<serde_json::Value>(data_str) {
            let wildcard_actions = data_val
                .get("acl")
                .and_then(|acl| acl.get("*"))
                .and_then(|w| w.get("allowed_actions"))
                .and_then(|a| a.as_array());

            if let Some(actions) = wildcard_actions {
                let action_risk_pairs: Vec<(&str, latchgate_core::RiskLevel)> = actions
                    .iter()
                    .filter_map(|a| a.as_str())
                    .filter_map(|action_id| {
                        registry
                            .get_action(action_id)
                            .map(|spec| (action_id, spec.risk_level))
                    })
                    .collect();

                config
                    .validate_wildcard_acl(action_risk_pairs.iter().map(|(id, r)| (*id, *r)))
                    .map_err(|e| InitError::Config(e.to_string()))?;
            }
        }
    }

    Ok(())
}

/// Initialise the policy client (HTTP-OPA or embedded regorus).
fn init_policy(
    config: &Config,
    embedded_rego: &str,
    data_json: Option<&str>,
) -> (latchgate_policy::PolicyClient, PolicyBackendInfo) {
    let backend = match config.policy.opa_url.as_deref() {
        Some(url) => {
            info!(
                opa_url = %url,
                opa_timeout_ms = latchgate_core::security_constants::OPA_TIMEOUT_MS,
                "policy client initialised (HTTP-OPA)"
            );
            PolicyBackendInfo::Http {
                opa_url: url.to_string(),
            }
        }
        None => {
            info!("policy client initialised (embedded regorus)");
            PolicyBackendInfo::Embedded
        }
    };

    let client = match config.policy.opa_url.as_deref() {
        Some(url) => latchgate_policy::PolicyClient::new(
            url,
            std::time::Duration::from_millis(latchgate_core::security_constants::OPA_TIMEOUT_MS),
        ),
        None => latchgate_policy::PolicyClient::embedded(embedded_rego, data_json),
    };

    (client, backend)
}

/// Open the audit ledger and metrics store.
fn init_ledger(
    config: &Config,
) -> Result<(latchgate_ledger::LedgerStore, latchgate_ledger::Metrics), InitError> {
    let db_path = Path::new(&config.storage.ledger_db_path);
    if let Some(parent) = db_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)
                .map_err(|e| InitError::Ledger(format!("cannot create ledger directory: {e}")))?;
        }
    }

    let jsonl_path = config.storage.ledger_jsonl_path.as_deref();
    let ledger = latchgate_ledger::LedgerStore::open(db_path, jsonl_path.map(Path::new))
        .map_err(|e| InitError::Ledger(e.to_string()))?;

    info!(
        ledger_db_path = %config.storage.ledger_db_path,
        ledger_jsonl = ?config.storage.ledger_jsonl_path,
        "audit ledger initialised"
    );

    let metrics =
        latchgate_ledger::Metrics::new().map_err(|e| InitError::Metrics(e.to_string()))?;

    Ok((ledger, metrics))
}

/// Initialise the SOPS-backed secrets manager.
fn init_secrets(config: &Config) -> (latchgate_providers::secrets::SecretsManager, bool) {
    let secrets_configured = config.secrets.sops_secrets_file.is_some();
    let secrets_manager = latchgate_providers::secrets::SecretsManager::new(
        latchgate_core::security_constants::SOPS_BIN,
        config
            .secrets
            .sops_key_file
            .as_ref()
            .map(std::path::PathBuf::from),
    )
    .with_cache_ttl(std::time::Duration::from_secs(
        latchgate_core::security_constants::SOPS_CACHE_TTL_SECS,
    ));

    if secrets_configured {
        info!(
            sops_bin = %latchgate_core::security_constants::SOPS_BIN,
            sops_secrets_file = ?config.secrets.sops_secrets_file,
            "secrets manager initialised (SOPS enabled)"
        );
    } else {
        info!("secrets manager initialised (no sops_secrets_file configured)");
    }

    (secrets_manager, secrets_configured)
}

/// Initialise the WASM runtime, host I/O backends, and load provider modules.
async fn init_wasm_runtime(
    config: &Config,
    embedded_providers: &[(&str, &[u8])],
) -> Result<(latchgate_providers::WasmRuntime, usize, usize), InitError> {
    let wasm_runtime = latchgate_providers::WasmRuntime::new(
        latchgate_core::security_constants::MAX_CONCURRENT_EXECUTIONS,
    )
    .map_err(|e| InitError::WasmRuntime(e.to_string()))?;

    latchgate_providers::init_backends(&wasm_runtime, &config.host_io)
        .await
        .map_err(|e| InitError::HostIo(e.to_string()))?;

    if let Some(ref proxy_url) = config.egress.egress_proxy_url {
        wasm_runtime
            .init_http_proxy(proxy_url)
            .map_err(|e| InitError::HostIo(e.to_string()))?;
    }

    let wasm_embedded = wasm_runtime
        .load_embedded_modules(embedded_providers)
        .map_err(|e| InitError::WasmModules(e.to_string()))?;

    let providers_dirs = config.provider_dirs();
    let mut wasm_from_dir = 0usize;
    for dir in &providers_dirs {
        // SECURITY: operator-deployed builtins use strict loading. A
        // corrupted `.wasm` here is a deployment misconfiguration that
        // must surface at boot, not as ModuleNotFound at request time.
        wasm_from_dir += wasm_runtime
            .load_modules_from_dir(dir, latchgate_providers::LoadMode::Strict)
            .map_err(|e| InitError::WasmModules(e.to_string()))?;
    }

    info!(
        ?providers_dirs,
        embedded_modules = wasm_embedded,
        dir_modules = wasm_from_dir,
        max_concurrent = latchgate_core::security_constants::MAX_CONCURRENT_EXECUTIONS,
        "WASM runtime initialised"
    );

    Ok((wasm_runtime, wasm_embedded, wasm_from_dir))
}

/// Load or generate Ed25519 signing keys and the verifying key store.
fn init_crypto(
    config: &Config,
) -> Result<
    (
        latchgate_crypto::ReceiptSigner,
        latchgate_crypto::GrantSigner,
        latchgate_crypto::VerifyingKeyStore,
    ),
    InitError,
> {
    let receipt_signer = match &config.signing.receipt_signing_key_path {
        Some(path) => latchgate_crypto::ReceiptSigner::load_or_generate(Path::new(path))
            .map_err(|e| InitError::SigningKey(e.to_string()))?,
        None => {
            if !config.dev_mode() {
                return Err(InitError::SigningKey(
                    "receipt_signing_key_path is not set and dev_mode is off".into(),
                ));
            }
            info!("unsafe-dev: using ephemeral receipt signing key");
            latchgate_crypto::ReceiptSigner::generate()
        }
    };

    info!(
        kid = %receipt_signer.kid(),
        verifying_key = %receipt_signer.verifying_key_hex(),
        "receipt signer initialised (Ed25519)"
    );

    let grant_signer = match &config.signing.grant_signing_key_path {
        Some(path) => latchgate_crypto::GrantSigner::load_or_generate(Path::new(path))
            .map_err(|e| InitError::SigningKey(e.to_string()))?,
        None => {
            if !config.dev_mode() {
                return Err(InitError::SigningKey(
                    "grant_signing_key_path is not set and dev_mode is off".into(),
                ));
            }
            info!("unsafe-dev: using ephemeral grant signing key");
            latchgate_crypto::GrantSigner::generate()
        }
    };

    info!(kid = %grant_signer.kid(), "grant signer initialised (Ed25519)");

    let verifying_key_store = match &config.signing.receipt_keys_jwks_path {
        Some(path) => {
            let jwks_path = Path::new(path);
            let mut store = latchgate_crypto::VerifyingKeyStore::load_or_empty(jwks_path);
            store.ensure_contains(&receipt_signer, jwks_path);
            store
        }
        None => {
            if !config.dev_mode() {
                return Err(InitError::SigningKey(
                    "receipt_keys_jwks_path is not set and dev_mode is off".into(),
                ));
            }
            latchgate_crypto::VerifyingKeyStore::single(&receipt_signer)
        }
    };

    Ok((receipt_signer, grant_signer, verifying_key_store))
}

/// Open and validate the filesystem root directory.
fn init_fs_root(
    config: &Config,
) -> Result<
    (
        Option<Arc<std::os::fd::OwnedFd>>,
        Option<std::path::PathBuf>,
    ),
    InitError,
> {
    match config.fs_root_path.as_deref() {
        Some(path) => {
            let (fd, canonical) =
                latchgate_providers::open_root_fd(Path::new(path)).map_err(|e| {
                    InitError::FsRoot(format!("failed to open fs_root_path '{path}': {e}"))
                })?;
            info!(
                path = %path,
                canonical = %canonical.display(),
                "filesystem root opened"
            );
            Ok((Some(Arc::new(fd)), Some(canonical)))
        }
        None => Ok((None, None)),
    }
}
