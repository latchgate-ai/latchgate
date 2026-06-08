//! Shared application state (`AppState`) and its required-field input
//! (`AppStateInit`).
//!
//! `AppState` is cloned per-request by axum, so every field is an `Arc<T>`
//! (or trivially-copyable). Expensive state lives inside the `Arc`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;

use crate::verification::VerifierRegistry;
use latchgate_auth::issuer::Issuer;
use latchgate_auth::ReplayCache;
use latchgate_config::Config;
use latchgate_crypto::{GrantSigner, GrantVerifyingKeyStore, ReceiptSigner, VerifyingKeyStore};
use latchgate_ledger::{LedgerStore, Metrics};
use latchgate_policy::PolicyClient;
use latchgate_registry::RegistryStore;
use latchgate_state::{ApprovalStore, BudgetManager};

use crate::coarse_clock::CoarseClock;
use crate::rate_limit::TokenBucketRateLimiter;

#[derive(Clone)]
pub struct AuthServices {
    pub issuer: Arc<Issuer>,
    pub replay_cache: Arc<ReplayCache>,
    /// Pluggable caller identity verification at lease issuance time.
    pub identity_provider: Arc<dyn latchgate_auth::IdentityProvider>,
    /// Pre-computed DPoP `htu` prefix: `"{public_base_url}/v1/actions/"`.
    /// Avoids a `format!` allocation on every request in `step_authenticate`.
    pub htu_prefix: Arc<str>,
}

#[derive(Clone)]
pub struct CryptoServices {
    /// Signs `result_hash` to prevent receipt forgery.
    pub receipt_signer: Arc<ReceiptSigner>,
    /// Signs `ExecutionGrant` after construction. Separate key from receipts.
    pub grant_signer: Arc<GrantSigner>,
    /// Historical verifying keys for grant signature verification.
    pub grant_verifying_key_store: Arc<GrantVerifyingKeyStore>,
    /// Historical verifying keys for receipt signature verification.
    pub verifying_key_store: Arc<VerifyingKeyStore>,
}

#[derive(Clone)]
pub struct EnforcementServices {
    pub policy: Arc<PolicyClient>,
    /// Pending approval store. Persists action call context when OPA
    /// returns PendingApproval, so operators can approve/deny later.
    pub approval_store: Arc<ApprovalStore>,
    /// Stateful per-session budget enforcement.
    pub budget_manager: Arc<BudgetManager>,
}

/// Per-session filesystem root entry.
///
/// Stores the validated canonical path and the creation timestamp
/// for TTL-based eviction.
#[derive(Debug, Clone)]
pub struct SessionFsRoot {
    /// Canonical path validated at lease issuance time.
    pub canonical: std::path::PathBuf,
    /// When this entry was created (monotonic). Used for eviction.
    pub created_at: Instant,
}

#[derive(Clone)]
pub struct RuntimeServices {
    /// WASM provider runtime. Loads and executes .wasm provider modules
    /// in sandboxed instances with host-mediated I/O.
    pub wasm_runtime: Arc<latchgate_providers::WasmRuntime>,
    /// Decrypts SOPS-encrypted secrets at call time, filtered to only the
    /// keys declared in the action manifest.
    pub secrets_manager: Arc<latchgate_providers::SecretsManager>,
    /// Built-in verifier implementations dispatched by `VerifierKind`.
    pub verifier_registry: Arc<VerifierRegistry>,
    /// Open fd + canonical path to the filesystem root for fs providers.
    /// `None` when `fs_root_path` is not configured.
    pub fs_root_fd: Option<Arc<std::os::fd::OwnedFd>>,
    pub fs_root_canonical: Option<std::path::PathBuf>,
    /// Per-session filesystem roots. Keyed by server-issued `session_id`.
    ///
    /// Populated at lease issuance when the client sends `fs_root`.
    /// Read at execution time by the pipeline and approved-execution paths.
    /// Evicted after `lease_ttl + grace_period`.
    ///
    /// SECURITY: the session_id key comes from authenticated JWT claims
    /// (server-issued UUID v7). An attacker cannot forge a session_id to
    /// read another session's root.
    pub session_fs_roots: Arc<dashmap::DashMap<String, SessionFsRoot>>,
}

/// Process lifecycle: drain, revocation, rate limiting, webhook dispatch.
#[derive(Clone)]
pub struct LifecycleState {
    /// Coarse-grained second clock shared by all rate limiters. Replaces
    /// the previous global `static AtomicU32` so each `AppState` (and
    /// therefore each test) gets an isolated clock instance.
    pub clock: CoarseClock,
    /// Monotonic revocation epoch. Advancing this value invalidates all
    /// outstanding `ExecutionGrant`s whose `revocation_epoch` is lower.
    /// SECURITY: used as a kill-switch.
    pub revocation_epoch: Arc<AtomicU64>,
    /// Drain flag. When `true`, the gate rejects new action calls with 503.
    /// SECURITY: draining is irreversible within a process lifetime.
    pub is_draining: Arc<AtomicBool>,
    /// Process start time for uptime reporting.
    pub started_at: Instant,
    /// Outbound event sink. `None` when no endpoints configured.
    /// Decoupled from webhook types — the kernel dispatches through the
    /// [`EventSink`](latchgate_core::EventSink) trait.
    pub event_sink: Option<Arc<dyn latchgate_core::EventSink>>,
    /// Per-instance operator write endpoint rate limiter (token bucket).
    pub operator_rate_limiter: Arc<TokenBucketRateLimiter>,
    /// Per-instance operator read endpoint rate limiter.
    pub operator_read_rate_limiter: Arc<TokenBucketRateLimiter>,
    /// Per-instance lease issuance rate limiter.
    pub lease_rate_limiter: Arc<TokenBucketRateLimiter>,
    /// Per-session / per-peer rate limiter for the execute path.
    pub execute_rate_limiters: Arc<crate::rate_limit::ExecuteRateLimitMap>,

    // -- Test hooks (compiled only under `test-hooks` feature) ----------------
    #[cfg(feature = "test-hooks")]
    pub fault_after_budget_debit: Arc<AtomicBool>,
}

/// Shared application state. Axum clones this per request — all fields MUST
/// be cheap to clone (`Arc<T>` or sub-states whose fields are `Arc<T>`).
#[derive(Clone)]
pub struct AppState {
    // ── Cross-cutting (accessed everywhere, kept flat) ────────────────────
    pub config: Arc<Config>,
    pub metrics: Arc<Metrics>,
    pub ledger: Arc<LedgerStore>,
    pub registry: Arc<ArcSwap<RegistryStore>>,

    /// Embedded action manifests compiled into the binary. Retained for
    /// `reload_registry` which must re-include them when rebuilding the
    /// store from disk. `&'static` — zero per-clone cost.
    pub embedded_manifests: Arc<[(&'static str, &'static str)]>,

    // ── Grouped by responsibility ────────────────────────────────────────
    pub auth: AuthServices,
    pub crypto: CryptoServices,
    pub enforcement: EnforcementServices,
    pub runtime: RuntimeServices,
    pub lifecycle: LifecycleState,
}

impl AppState {
    /// Construct an `AppState` from a fully-populated [`AppStateInit`].
    ///
    /// Every required dependency is a field on [`AppStateInit`] — the
    /// compiler refuses a struct literal with a missing field. Derived
    /// fields (rate limiters, revocation epoch, drain flag, grant verifying
    /// key store, start timestamp) are initialised inside this constructor.
    pub fn new(init: AppStateInit) -> Self {
        // Derived: grant verifying key store registers the signer's public key.
        let mut grant_key_store = GrantVerifyingKeyStore::empty();
        grant_key_store.register(&init.crypto.grant_signer);

        // Extract rate-limit settings before moving `config` into the Arc.
        let operator_write_rps = init.config.rate_limits.operator_write_rps;
        let operator_read_rps = init.config.rate_limits.operator_read_rps;
        let lease_rps = init.config.rate_limits.lease_rps;
        let execute_session_rps = init.config.rate_limits.execute_rps_per_session;
        let execute_anon_rps = init.config.rate_limits.execute_rps_anonymous;

        // Pre-compute the DPoP htu prefix so step_authenticate avoids a
        // format! allocation on every request.
        let htu_prefix: Arc<str> = {
            let base = init.config.listener.public_base_url.trim_end_matches('/');
            let mut prefix = String::with_capacity(base.len() + "/v1/actions/".len());
            prefix.push_str(base);
            prefix.push_str("/v1/actions/");
            Arc::from(prefix)
        };

        // Create a shared coarse clock for all rate limiters in this
        // AppState. Each AppState (and its tests) gets an independent
        // clock instance — no global mutable state.
        let clock = CoarseClock::new();

        Self {
            config: Arc::new(init.config),
            metrics: Arc::new(init.metrics),
            ledger: Arc::new(init.ledger),
            registry: Arc::new(ArcSwap::from_pointee(init.registry)),
            embedded_manifests: Arc::from(init.embedded_manifests),

            auth: AuthServices {
                issuer: Arc::new(init.auth.issuer),
                replay_cache: Arc::new(init.auth.replay_cache),
                identity_provider: Arc::from(init.auth.identity_provider),
                htu_prefix,
            },
            crypto: CryptoServices {
                receipt_signer: Arc::new(init.crypto.receipt_signer),
                grant_signer: Arc::new(init.crypto.grant_signer),
                grant_verifying_key_store: Arc::new(grant_key_store),
                verifying_key_store: Arc::new(init.crypto.verifying_key_store),
            },
            enforcement: EnforcementServices {
                policy: Arc::new(init.enforcement.policy),
                approval_store: Arc::new(init.enforcement.approval_store),
                budget_manager: Arc::new(init.enforcement.budget_manager),
            },
            runtime: RuntimeServices {
                wasm_runtime: Arc::new(init.runtime.wasm_runtime),
                secrets_manager: Arc::new(init.runtime.secrets_manager),
                verifier_registry: Arc::new(init.runtime.verifier_registry),
                fs_root_fd: init.runtime.fs_root_fd,
                fs_root_canonical: init.runtime.fs_root_canonical,
                session_fs_roots: init.runtime.session_fs_roots,
            },
            lifecycle: LifecycleState {
                clock: clock.clone(),
                revocation_epoch: Arc::new(AtomicU64::new(0)),
                is_draining: Arc::new(AtomicBool::new(false)),
                started_at: Instant::now(),
                event_sink: init.lifecycle.event_sink,
                operator_rate_limiter: Arc::new(TokenBucketRateLimiter::new(
                    operator_write_rps,
                    clock.clone(),
                )),
                operator_read_rate_limiter: Arc::new(TokenBucketRateLimiter::new(
                    operator_read_rps,
                    clock.clone(),
                )),
                lease_rate_limiter: Arc::new(TokenBucketRateLimiter::new(lease_rps, clock.clone())),
                execute_rate_limiters: Arc::new(crate::rate_limit::ExecuteRateLimitMap::new(
                    execute_session_rps,
                    execute_anon_rps,
                    clock,
                )),
                #[cfg(feature = "test-hooks")]
                fault_after_budget_debit: Arc::new(AtomicBool::new(false)),
            },
        }
    }

    /// Return the current revocation epoch value.
    #[must_use]
    pub fn current_revocation_epoch(&self) -> u64 {
        self.lifecycle.revocation_epoch.load(Ordering::Acquire)
    }

    /// Atomically advance the revocation epoch by 1 and return the new value.
    ///
    /// SECURITY: this is the kill-switch. Every `ExecutionGrant` issued before
    /// this call carries the old epoch and will fail `is_valid()` checks.
    #[must_use = "new epoch must be recorded or propagated — dropping it silently skips revocation"]
    pub fn advance_revocation_epoch(&self) -> u64 {
        self.lifecycle
            .revocation_epoch
            .fetch_add(1, Ordering::AcqRel)
            + 1
    }

    /// Emit a domain event. If an event sink is configured, dispatches through it.
    pub fn emit(&self, event: latchgate_core::DomainEvent) {
        if let Some(ref sink) = self.lifecycle.event_sink {
            sink.emit(&event);
        }
    }

    /// Begin graceful drain. Irreversible within this process lifetime.
    #[must_use = "returns whether this call initiated drain — ignoring it risks duplicate drain handling"]
    pub fn start_drain(&self) -> bool {
        !self.lifecycle.is_draining.swap(true, Ordering::AcqRel)
    }

    /// Check whether the gate is in drain mode.
    #[must_use]
    pub fn draining(&self) -> bool {
        self.lifecycle.is_draining.load(Ordering::Acquire)
    }

    /// Evict expired session filesystem roots.
    ///
    /// Called periodically by a background task. Removes entries older
    /// than `lease_ttl + EVICTION_GRACE_SECS`. Returns the number of
    /// entries removed.
    pub fn evict_expired_session_fs_roots(&self) -> usize {
        let ttl = std::time::Duration::from_secs(
            self.config.policy.lease_ttl_seconds
                + latchgate_core::security_constants::SESSION_FS_ROOT_EVICTION_GRACE_SECS,
        );
        let now = Instant::now();
        let before = self.runtime.session_fs_roots.len();
        self.runtime
            .session_fs_roots
            .retain(|_session_id, entry| now.duration_since(entry.created_at) < ttl);
        let removed = before - self.runtime.session_fs_roots.len();
        if removed > 0 {
            tracing::debug!(removed, "evicted expired session fs_roots");
        }
        removed
    }

    /// Reload OPA policy data after a `data.json` mutation.
    ///
    /// Re-builds the embedded Rego engine with the provided sources. Only
    /// reloads data — Rego rule changes require a full gate restart.
    ///
    /// For external OPA backends this is a no-op; the operator must reload
    /// OPA out-of-band (e.g. via the OPA management API).
    pub fn reload_policy_data(&self, rego_source: &str, data_json: Option<&str>) {
        self.enforcement
            .policy
            .reload_embedded_data(rego_source, data_json);
    }

    /// Atomically replace the registry with a fresh build from `manifests_dir`.
    ///
    /// Builds the new [`RegistryStore`] to completion before swapping.
    /// Callers see either the old registry or the new one — never partial
    /// state. On failure the previous registry remains active.
    ///
    /// Returns the new action count on success.
    pub fn reload_registry(&self, manifests_dir: &std::path::Path) -> Result<usize, String> {
        let new_store = RegistryStore::builder()
            .add_embedded(self.embedded_manifests.iter().copied())
            .map_err(|e| format!("embedded manifests: {e}"))?
            .add_dir(manifests_dir)
            .map_err(|e| format!("manifests dir: {e}"))?
            .build();
        let count = new_store.len();
        self.registry.store(Arc::new(new_store));
        Ok(count)
    }

    // -- Test hooks (compiled only under `test-hooks` feature) ----------------

    #[cfg(feature = "test-hooks")]
    pub fn arm_fault_after_budget_debit(&self) {
        self.lifecycle
            .fault_after_budget_debit
            .store(true, Ordering::Release);
    }
}

/// Input for [`AuthServices`]. Owned (non-Arc) values.
pub struct AuthServicesInit {
    pub issuer: Issuer,
    pub replay_cache: ReplayCache,
    pub identity_provider: Box<dyn latchgate_auth::IdentityProvider>,
}

/// Input for [`CryptoServices`]. Owned (non-Arc) values.
pub struct CryptoServicesInit {
    pub receipt_signer: ReceiptSigner,
    pub grant_signer: GrantSigner,
    pub verifying_key_store: VerifyingKeyStore,
}

/// Input for [`EnforcementServices`]. Owned (non-Arc) values.
pub struct EnforcementServicesInit {
    pub policy: PolicyClient,
    pub approval_store: ApprovalStore,
    pub budget_manager: BudgetManager,
}

/// Input for [`RuntimeServices`]. Owned (non-Arc) values.
pub struct RuntimeServicesInit {
    pub wasm_runtime: latchgate_providers::WasmRuntime,
    pub secrets_manager: latchgate_providers::SecretsManager,
    pub verifier_registry: VerifierRegistry,
    pub fs_root_fd: Option<Arc<std::os::fd::OwnedFd>>,
    pub fs_root_canonical: Option<std::path::PathBuf>,
    pub session_fs_roots: Arc<dashmap::DashMap<String, SessionFsRoot>>,
}

/// Input for [`LifecycleState`] — only the non-derived fields.
pub struct LifecycleInit {
    pub event_sink: Option<Arc<dyn latchgate_core::EventSink>>,
}

/// Fully-populated input for [`AppState::new`].
///
/// Every required dependency appears as a field. Constructing it with a
/// missing field is a compile error. Derived fields (rate limiters,
/// revocation epoch, drain flag, grant verifying key store, start
/// timestamp) are NOT here — they are initialised inside [`AppState::new`].
pub struct AppStateInit {
    pub config: Config,
    pub metrics: Metrics,
    pub ledger: LedgerStore,
    pub registry: RegistryStore,
    pub embedded_manifests: Vec<(&'static str, &'static str)>,
    pub auth: AuthServicesInit,
    pub crypto: CryptoServicesInit,
    pub enforcement: EnforcementServicesInit,
    pub runtime: RuntimeServicesInit,
    pub lifecycle: LifecycleInit,
}
