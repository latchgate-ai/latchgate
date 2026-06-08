//! Shared test infrastructure for `latchgate-kernel` and downstream crates.
//!
//! Provides [`test_app_state`] and variants for constructing a minimal
//! [`AppState`] with all in-memory backends. Used by kernel tests directly
//! and by `latchgate-api` tests via the `test-support` feature gate.
//!
//! # Single source of truth
//!
//! All test `AppState` construction flows through [`test_app_state_with_config`].
//! Downstream crates (API, integration tests) call this with their own
//! `Config` overlay (e.g. operator credentials) instead of duplicating
//! the construction logic.

// This module is test infrastructure (gated behind `cfg(any(test, feature =
// "test-support"))`). When compiled via the `test-support` feature for
// downstream test suites, `cfg(test)` is false so the crate-level
// `deny(clippy::unwrap_used, clippy::expect_used)` fires. Suppress it here —
// panicking on infallible test setup is acceptable and idiomatic.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use latchgate_crypto::{GrantSigner, ReceiptSigner, VerifyingKeyStore};

use crate::state::{
    AppState, AppStateInit, AuthServicesInit, CryptoServicesInit, EnforcementServicesInit,
    LifecycleInit, RuntimeServicesInit,
};

/// Minimal action manifest YAML for tests.
///
/// Declares a `test_action` with `builtin:http_api`, no schema, no egress,
/// low risk. Sufficient for exercising pipeline steps up to policy evaluation.
pub const TEST_ACTION_YAML: &str = r#"
action_id: "test_action"
version: "1.0.0"
provider_module_digest: "builtin:http_api"
required_imports:
  - "latchgate:io/http"
  - "latchgate:io/log"
template:
  method: GET
  url_template: "https://example.com/{{path}}"
io:
  max_request_bytes: 65536
  max_response_bytes: 1048576
risk_level: low
"#;

/// Construct a minimal `AppState` with all in-memory backends and an
/// empty registry. Suitable for testing deny paths.
pub fn test_app_state() -> (AppState, GrantSigner) {
    test_app_state_with_registry(latchgate_registry::RegistryStore::empty())
}

/// Construct a minimal `AppState` with a pre-built registry.
/// Suitable for testing success paths that need manifest lookup.
pub fn test_app_state_with_registry(
    registry: latchgate_registry::RegistryStore,
) -> (AppState, GrantSigner) {
    test_app_state_with_config(
        latchgate_config::Config::default(),
        registry,
        Box::new(latchgate_auth::identity::NoneProvider),
    )
}

/// Construct an `AppState` with full control over config, registry, and
/// identity provider.
///
/// This is the canonical constructor — all other `test_app_state*` variants
/// delegate here. Downstream crates use this to overlay operator credentials,
/// custom identity providers, or non-default config without duplicating the
/// 50-line construction sequence.
///
/// # Defaults applied
///
/// - **WASM runtime**: 1 thread (sufficient for tests; avoids thread-pool
///   overhead in parallel test binaries).
/// - **Secrets**: SOPS backend with no key file (secrets resolve to errors
///   unless explicitly configured).
/// - **Policy**: HTTP client pointing at `127.0.0.1:8181` (the OPA dev
///   default). Tests that don't exercise policy never reach this endpoint.
/// - **Ledger / Metrics / Budget / Approval**: all in-memory.
/// - **Event sink**: `None` (no webhook dispatch in tests by default).
pub fn test_app_state_with_config(
    config: latchgate_config::Config,
    registry: latchgate_registry::RegistryStore,
    identity_provider: Box<dyn latchgate_auth::IdentityProvider>,
) -> (AppState, GrantSigner) {
    let grant_signer = GrantSigner::generate();
    let receipt_signer = ReceiptSigner::generate();

    let issuer = latchgate_auth::issuer::Issuer::new(
        config.policy.lease_ttl_seconds,
        latchgate_core::security_constants::MAX_LEASE_TTL_SECS,
    )
    .expect("issuer init");

    let replay_cache = latchgate_auth::ReplayCache::in_memory(Duration::from_secs(
        latchgate_core::security_constants::REPLAY_TTL_SECS,
    ));

    let policy = latchgate_policy::PolicyClient::new(
        config
            .policy
            .opa_url
            .as_deref()
            .unwrap_or("http://127.0.0.1:8181"),
        Duration::from_millis(latchgate_core::security_constants::OPA_TIMEOUT_MS),
    );

    let state = AppState::new(AppStateInit {
        config,
        ledger: latchgate_ledger::LedgerStore::open_in_memory(None).expect("in-memory ledger"),
        metrics: latchgate_ledger::Metrics::new().expect("metrics"),
        registry,
        embedded_manifests: vec![],
        auth: AuthServicesInit {
            issuer,
            replay_cache,
            identity_provider,
        },
        crypto: CryptoServicesInit {
            receipt_signer: receipt_signer.clone(),
            grant_signer: grant_signer.clone(),
            verifying_key_store: VerifyingKeyStore::single(&receipt_signer),
        },
        enforcement: EnforcementServicesInit {
            policy,
            budget_manager: latchgate_state::BudgetManager::in_memory_for_tests(),
            approval_store: latchgate_state::approvals::ApprovalStore::in_memory_for_tests(
                Duration::from_secs(latchgate_core::security_constants::APPROVAL_TTL_SECS),
            ),
        },
        runtime: RuntimeServicesInit {
            wasm_runtime: latchgate_providers::WasmRuntime::new(1).expect("WASM runtime init"),
            secrets_manager: latchgate_providers::SecretsManager::new("sops", None),
            verifier_registry: crate::verification::VerifierRegistry::new(),
            fs_root_fd: None,
            fs_root_canonical: None,
            session_fs_roots: std::sync::Arc::new(dashmap::DashMap::new()),
        },
        lifecycle: LifecycleInit { event_sink: None },
    });

    (state, grant_signer)
}

/// Build a `RegistryStore` containing a single `test_action` from
/// [`TEST_ACTION_YAML`].
pub fn registry_with_test_action() -> latchgate_registry::RegistryStore {
    latchgate_registry::RegistryBuilder::new()
        .add_embedded([("test_action.yaml", TEST_ACTION_YAML)].into_iter())
        .expect("test manifest should parse")
        .build()
}
