//! Shared test helpers for API integration tests.
//!
//! Re-used across `health`, `leases`, `admin`, `approvals`, `audit`,
//! `receipts`, and `metrics` test modules to avoid duplicating AppState
//! construction, DPoP key generation, and HTTP helpers.
//!
//! # AppState construction
//!
//! All state construction delegates to [`latchgate_kernel::test_support`]
//! (enabled via the `test-support` feature in dev-dependencies). This
//! module adds only the API-specific overlay: DPoP operator credentials
//! and manifest loading from `config.manifests_dir`.

use std::sync::LazyLock;

use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt;

use latchgate_config::Config;
use latchgate_kernel::AppState;
use latchgate_registry::RegistryStore;

/// Test operator API key for approval endpoint tests.
pub const TEST_OPERATOR_KEY: &str = "test-operator-key";

/// Default base URL used by test `Config` (matches `Config::default()`).
const TEST_BASE_URL: &str = "http://localhost:3000";

/// DPoP-capable operator credential for tests.
///
/// Holds a signing key and the matching `dpop_jkt`. All tests use this
/// to authenticate operator requests via `operator_headers()`.
pub struct OperatorDPoP {
    pub dpop_jkt: String,
    signing_key: latchgate_auth::DPoPSigningKey,
}

impl OperatorDPoP {
    fn generate() -> Self {
        let (sk, pk) = latchgate_auth::dpop::generate_dpop_keypair().unwrap();
        let jkt = latchgate_auth::dpop::compute_jwk_thumbprint(&pk.x, &pk.y).unwrap();
        Self {
            dpop_jkt: jkt,
            signing_key: sk,
        }
    }

    /// Build `OperatorCredential` matching this keypair.
    pub fn credential(&self) -> latchgate_config::OperatorCredential {
        latchgate_config::OperatorCredential {
            api_key: TEST_OPERATOR_KEY.into(),
            dpop_jkt: Some(self.dpop_jkt.clone()),
        }
    }

    /// Produce `(Authorization, DPoP)` header values for a request.
    ///
    /// Each call generates a fresh `jti`, so proofs are never replayed.
    pub fn headers(&self, method: &str, path: &str) -> (String, String) {
        self.headers_with_key(TEST_OPERATOR_KEY, method, path)
    }

    /// Produce headers using a specific api_key (for custom credential tests).
    pub fn headers_with_key(&self, api_key: &str, method: &str, path: &str) -> (String, String) {
        let htu = format!("{}{}", TEST_BASE_URL.trim_end_matches('/'), path);
        let ath = latchgate_auth::dpop::compute_ath(api_key);
        let jti = uuid::Uuid::now_v7().to_string();
        let proof =
            latchgate_auth::dpop::sign_dpop_proof(&self.signing_key, method, &htu, &ath, &jti)
                .unwrap();
        (format!("DPoP {api_key}"), proof)
    }
}

/// Lazily-initialized test operator. Single keypair shared across all tests
/// in the binary — the `test_state()` credentials match this keypair.
pub static TEST_OPERATOR: LazyLock<OperatorDPoP> = LazyLock::new(OperatorDPoP::generate);

/// Convenience: produce `(Authorization, DPoP)` header values for a request.
///
/// Uses the shared `TEST_OPERATOR` keypair and `TEST_OPERATOR_KEY`.
pub fn operator_headers(method: &str, path: &str) -> (String, String) {
    TEST_OPERATOR.headers(method, path)
}

/// Redis URL for tests. Reads `LATCHGATE_REDIS_URL` or falls back to the
/// docker-compose default (includes the `changeme` password from Makefile).
#[allow(dead_code)] // used by approvals_tests; lint false-positive in some test configurations
pub fn test_redis_url() -> String {
    std::env::var("LATCHGATE_REDIS_URL")
        .unwrap_or_else(|_| "redis://:changeme@127.0.0.1:6379".to_string())
}

/// Create a test AppState with DPoP-enabled operator credentials.
///
/// Uses in-memory replay cache (no Redis dependency for DPoP jti checks).
/// Uses real Redis for ApprovalStore and BudgetManager — tests that exercise
/// those paths guard with `redis_available()`.
pub fn test_state() -> AppState {
    let config = Config {
        operator_credentials: std::collections::HashMap::from([(
            "test-operator".to_string(),
            TEST_OPERATOR.credential(),
        )]),
        storage: latchgate_config::StorageConfig {
            redis_url: None,
            ..Default::default()
        },
        ..Config::default()
    };
    build_app_state(config)
}

/// Build a test router with default AppState.
pub fn test_router() -> axum::Router {
    crate::router(test_state())
}

/// Generate a random DPoP public key as a JSON Value (for lease issuance).
pub fn dpop_jwk_json() -> serde_json::Value {
    let (_, pk) = latchgate_auth::dpop::generate_dpop_keypair().unwrap();
    serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": pk.x,
        "y": pk.y,
    })
}

/// Build a test AppState with a custom operator credential and in-memory
/// replay cache. Returns `(AppState, OperatorDPoP)` so the caller can
/// produce DPoP proofs for the custom credential.
///
/// Use this when a test needs a specific operator identity (e.g. "alice")
/// rather than the shared `TEST_OPERATOR`.
#[allow(dead_code)] // used by approvals_tests; lint false-positive in some test configurations
pub fn test_state_with_operator(operator_id: &str, api_key: &str) -> (AppState, OperatorDPoP) {
    let operator = OperatorDPoP::generate();
    let config = Config {
        operator_credentials: std::collections::HashMap::from([(
            operator_id.to_string(),
            latchgate_config::OperatorCredential {
                api_key: api_key.into(),
                dpop_jkt: Some(operator.dpop_jkt.clone()),
            },
        )]),
        storage: latchgate_config::StorageConfig {
            redis_url: None,
            ..Default::default()
        },
        ..Config::default()
    };
    (build_app_state(config), operator)
}

/// Core AppState construction shared by all test helpers.
pub(crate) fn build_app_state(config: Config) -> AppState {
    build_app_state_with_identity(config, Box::new(latchgate_auth::identity::NoneProvider))
}

/// Core AppState construction with a custom identity provider.
///
/// Delegates to [`latchgate_kernel::test_support::test_app_state_with_config`]
/// so there is exactly one place that assembles `AppStateInit`. This module
/// adds only the API-specific concern: loading manifests from
/// `config.manifests_dir` when the directory exists.
pub(crate) fn build_app_state_with_identity(
    config: Config,
    identity_provider: Box<dyn latchgate_auth::IdentityProvider>,
) -> AppState {
    let registry = RegistryStore::load_from_dir(std::path::Path::new(&config.manifests_dir))
        .unwrap_or_else(|_| RegistryStore::empty());

    let (state, _signer) = latchgate_kernel::test_support::test_app_state_with_config(
        config,
        registry,
        identity_provider,
    );
    state
}

/// POST to /v1/leases with the given body JSON.
pub async fn post_lease(app: axum::Router, body: &serde_json::Value) -> axum::http::Response<Body> {
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri("/v1/leases")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap(),
    )
    .await
    .unwrap()
}

/// Extract JSON body from an HTTP response.
pub async fn body_json(resp: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Extract raw bytes from an HTTP response.
pub async fn body_bytes(resp: axum::http::Response<Body>) -> Vec<u8> {
    axum::body::to_bytes(resp.into_body(), 65536)
        .await
        .unwrap()
        .to_vec()
}

/// Returns true if Redis is reachable **and usable with the configured
/// credentials**.
///
/// A bare TCP probe is insufficient: when Redis runs with `requirepass`
/// (the dev-compose default), the socket accepts connections but every
/// command fails authentication. Tests that construct a Redis-backed store
/// would then panic on the first operation instead of skipping. This guard
/// performs an authenticated `PING` through the same URL the stores use, so
/// it returns `false` (skip) unless Redis is genuinely usable.
pub async fn redis_available() -> bool {
    match latchgate_state::approvals::ApprovalStore::new(
        &test_redis_url(),
        std::time::Duration::from_secs(1),
    ) {
        Ok(store) => store.ping().await,
        Err(_) => false,
    }
}
