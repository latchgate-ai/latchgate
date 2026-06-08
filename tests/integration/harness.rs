//! Shared test harness for integration tests against a live Gate stack.
//!
//! Extracted from `e2e.rs` so approval test modules can reuse the same
//! infrastructure without duplication.
//!
//! # Requirements
//!
//! Redis on 127.0.0.1:6379 and OPA on 127.0.0.1:8181 MUST be running.
//! Start with `make dev` or `docker compose up redis opa`.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use std::sync::LazyLock;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use latchgate_auth::dpop::{
    compute_ath, compute_jwk_thumbprint, generate_dpop_keypair, sign_dpop_proof, DPoPPublicKey,
    DPoPSigningKey,
};
use latchgate_auth::issuer::Issuer;
use latchgate_auth::ReplayCache;
use latchgate_config::Config;
use latchgate_kernel::AppState;
use latchgate_ledger::{LedgerStore, Metrics};
use latchgate_policy::PolicyClient;
use latchgate_registry::RegistryStore;
use latchgate_state::approvals::ApprovalStore;
use latchgate_state::BudgetManager;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Operator API key used across all integration tests.
pub const OPERATOR_KEY: &str = "test-operator-key-e2e";

/// Base URL matching `Config::default().public_base_url`.
const BASE_URL: &str = "http://localhost:3000";

// ---------------------------------------------------------------------------
// Operator DPoP keypair (shared across all integration tests)
// ---------------------------------------------------------------------------

struct OperatorKeys {
    signing_key: DPoPSigningKey,
    dpop_jkt: String,
}

static OPERATOR_KEYS: LazyLock<OperatorKeys> = LazyLock::new(|| {
    let (sk, pk) = generate_dpop_keypair().unwrap();
    let jkt = compute_jwk_thumbprint(&pk.x, &pk.y).unwrap();
    OperatorKeys {
        signing_key: sk,
        dpop_jkt: jkt,
    }
});

/// Produce `(Authorization, DPoP)` header values for operator auth.
pub fn operator_dpop_headers(method: &str, path: &str) -> (String, String) {
    let htu = format!("{}{}", BASE_URL.trim_end_matches('/'), path);
    let ath = compute_ath(OPERATOR_KEY);
    let jti = uuid_v4();
    let proof = sign_dpop_proof(&OPERATOR_KEYS.signing_key, method, &htu, &ath, &jti).unwrap();
    (format!("DPoP {OPERATOR_KEY}"), proof)
}

/// JWK thumbprint of the shared operator keypair.
pub fn operator_jkt() -> String {
    OPERATOR_KEYS.dpop_jkt.clone()
}

// ---------------------------------------------------------------------------
// Test state construction
// ---------------------------------------------------------------------------

/// Redis URL for integration tests. Reads `LATCHGATE_REDIS_URL` or falls
/// back to the docker-compose default (includes the `changeme` password).
pub fn test_redis_url() -> String {
    std::env::var("LATCHGATE_REDIS_URL")
        .unwrap_or_else(|_| "redis://:changeme@127.0.0.1:6379".to_string())
}

/// Build a minimal but realistic AppState for integration tests.
///
/// Uses the REAL production stack:
/// - Real Redis-backed ReplayCache, BudgetManager, ApprovalStore
/// - Real OPA PolicyClient (queries the running OPA instance)
/// - Real WasmRuntime, VerifierRegistry, SecretsManager
/// - Real Issuer (fresh EC keypair per test binary run)
/// - Real in-memory LedgerStore (inspectable within test)
/// - Manifests loaded from `definitions/manifests/` (same as production)
pub fn test_state_with_ledger() -> (AppState, Arc<LedgerStore>) {
    assert!(
        std::net::TcpStream::connect_timeout(
            &"127.0.0.1:6379".parse().unwrap(),
            Duration::from_millis(500),
        )
        .is_ok(),
        "Redis must be running on 127.0.0.1:6379 — run `make dev` first"
    );
    let opa_reachable = std::net::TcpStream::connect_timeout(
        &"127.0.0.1:8181".parse().unwrap(),
        Duration::from_millis(500),
    )
    .is_ok();

    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("tests crate must be inside workspace root");
    let manifests_dir = workspace_root
        .join("definitions/manifests")
        .to_string_lossy()
        .into_owned();

    let config = Config {
        listener: latchgate_config::ListenerConfig {
            listen_http_addr: Some("127.0.0.1:0".parse().unwrap()),
            unsafe_expose_http: true,
            public_base_url: "http://localhost:3000".into(),
            ..Default::default()
        },
        manifests_dir,
        storage: latchgate_config::StorageConfig {
            redis_url: Some(test_redis_url()),
            ..Default::default()
        },
        operator_credentials: std::collections::HashMap::from([(
            "test-operator".to_string(),
            latchgate_config::OperatorCredential {
                api_key: OPERATOR_KEY.into(),
                dpop_jkt: Some(OPERATOR_KEYS.dpop_jkt.clone()),
            },
        )]),
        ..Config::default()
    };
    let issuer = Issuer::new(
        config.policy.lease_ttl_seconds,
        latchgate_core::security_constants::MAX_LEASE_TTL_SECS,
    )
    .unwrap();
    let replay_cache = ReplayCache::new(
        config
            .storage
            .redis_url
            .as_deref()
            .expect("redis_url required for integration tests"),
        Duration::from_secs(latchgate_core::security_constants::REPLAY_TTL_SECS),
        latchgate_core::security_constants::REDIS_KEY_PREFIX,
    )
    .unwrap();
    let registry = RegistryStore::load_from_dir(Path::new(&config.manifests_dir))
        .unwrap_or_else(|_| RegistryStore::empty());
    let policy = if opa_reachable {
        PolicyClient::new(
            config
                .policy
                .opa_url
                .as_deref()
                .unwrap_or("http://127.0.0.1:8181"),
            Duration::from_millis(latchgate_core::security_constants::OPA_TIMEOUT_MS),
        )
    } else {
        let rego = latchgate_cli::embedded_policies::POLICY_REGO;
        let data_json =
            std::fs::read_to_string(workspace_root.join("definitions/policies/opa/data.json")).ok();
        PolicyClient::embedded(rego, data_json.as_deref())
    };
    let ledger = LedgerStore::open_in_memory(None).unwrap();
    let metrics = Metrics::new().unwrap();
    let budget_manager = BudgetManager::new(
        config
            .storage
            .redis_url
            .as_deref()
            .expect("redis_url required"),
    )
    .unwrap();
    let approval_store = ApprovalStore::new(
        config
            .storage
            .redis_url
            .as_deref()
            .expect("redis_url required for integration tests"),
        Duration::from_secs(latchgate_core::security_constants::APPROVAL_TTL_SECS),
    )
    .unwrap();
    let wasm_runtime = latchgate_providers::WasmRuntime::new(4).unwrap();
    let secrets_manager = latchgate_providers::SecretsManager::new("sops", None);
    let state = AppState::new(latchgate_kernel::AppStateInit {
        config,
        registry,
        embedded_manifests: vec![],
        ledger,
        metrics,
        auth: latchgate_kernel::AuthServicesInit {
            issuer,
            replay_cache,
            identity_provider: Box::new(latchgate_auth::identity::NoneProvider),
        },
        crypto: latchgate_kernel::CryptoServicesInit {
            receipt_signer: latchgate_crypto::ReceiptSigner::generate(),
            grant_signer: latchgate_crypto::GrantSigner::generate(),
            verifying_key_store: latchgate_crypto::VerifyingKeyStore::single(
                &latchgate_crypto::ReceiptSigner::generate(),
            ),
        },
        enforcement: latchgate_kernel::EnforcementServicesInit {
            policy,
            budget_manager,
            approval_store,
        },
        runtime: latchgate_kernel::RuntimeServicesInit {
            wasm_runtime,
            secrets_manager,
            verifier_registry: latchgate_kernel::VerifierRegistry::new(),
            fs_root_fd: None,
            fs_root_canonical: None,
            session_fs_roots: std::sync::Arc::new(dashmap::DashMap::new()),
        },
        lifecycle: latchgate_kernel::LifecycleInit { event_sink: None },
    });
    let ledger_ref = Arc::clone(&state.ledger);
    (state, ledger_ref)
}

pub fn test_router() -> (axum::Router, Arc<LedgerStore>) {
    let (state, ledger) = test_state_with_ledger();
    (latchgate_api::router(state), ledger)
}

// ---------------------------------------------------------------------------
// Probe-enabled state — loads the `evidence_probe` WASM fixture + manifest
// ---------------------------------------------------------------------------

/// Action ID declared by the probe manifest. Matches
/// `tests/fixtures/manifests/evidence_probe.yaml`.
pub const PROBE_ACTION_ID: &str = "evidence_probe";

/// Action ID for the high-risk sibling. Same WASM fixture, but the
/// OPA policy routes high-risk actions through human approval — lets
/// tests exercise the approval-path security invariants without a
/// network-bound provider. See
/// `tests/fixtures/manifests/evidence_probe_approval.yaml`.
pub const PROBE_APPROVAL_ACTION_ID: &str = "evidence_probe_approval";

/// Build an `AppState` whose registry and WASM runtime have the
/// evidence-probe fixture loaded, alongside all production manifests.
///
/// Panics with a diagnostic message if the fixture WASM has not been
/// built (`make test-fixtures`) — the tests that consume this helper
/// cannot run without it, so failing loudly at setup is the right
/// behaviour, not silent skipping.
///
/// Returns `(state, ledger)` where `ledger` is an `Arc` clone over the
/// same store `state.ledger` wraps, letting tests arm fault-injection
/// hooks and query audit rows without going through the kernel.
pub fn test_state_with_probe() -> (AppState, Arc<LedgerStore>) {
    assert!(
        std::net::TcpStream::connect_timeout(
            &"127.0.0.1:6379".parse().unwrap(),
            Duration::from_millis(500),
        )
        .is_ok(),
        "Redis must be running on 127.0.0.1:6379 — run `make dev` first"
    );
    let opa_reachable = std::net::TcpStream::connect_timeout(
        &"127.0.0.1:8181".parse().unwrap(),
        Duration::from_millis(500),
    )
    .is_ok();

    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("tests crate must be inside workspace root");

    // Assemble a temporary manifest directory: production manifests
    // from definitions/manifests/ plus the probe fixture manifest. Using a
    // tempdir keeps the test hermetic — no test artifact is written
    // into definitions/ which is shipped verbatim to operators.
    let manifest_tempdir = tempfile::Builder::new()
        .prefix("latchgate-test-manifests-")
        .tempdir()
        .expect("tempdir for test manifests");
    let prod_manifests = workspace_root.join("definitions/manifests");
    for entry in std::fs::read_dir(&prod_manifests).expect("read definitions/manifests") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        let is_yaml = path
            .extension()
            .map(|e| e == "yaml" || e == "yml")
            .unwrap_or(false);
        if !is_yaml {
            continue;
        }
        let dest = manifest_tempdir.path().join(path.file_name().unwrap());
        std::fs::copy(&path, &dest).expect("copy manifest into tempdir");
    }
    // Load the evidence-probe WASM fixture into a fresh runtime. The
    // runtime is not persistent across tests, so a fresh instance per
    // invocation is fine — precompile cost is a few tens of ms.
    let fixtures_dir = workspace_root.join("target/test-fixtures");
    let probe_wasm_path = fixtures_dir.join("fixture_evidence_probe.wasm");
    assert!(
        probe_wasm_path.exists(),
        "probe WASM fixture missing at {probe_wasm_path:?} — run `make test-fixtures` first"
    );

    // Content-addressed trust: compute the fixture's digest once, use
    // it both as `provider_module_digest` in the manifest and as the cache key
    // for the precompiled module. Manifest-vs-runtime divergence would
    // surface as a digest mismatch; here the two are derived from the
    // same file bytes, so they agree by construction.
    let probe_wasm_bytes = std::fs::read(&probe_wasm_path).expect("read probe WASM fixture");
    let probe_digest = {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(&probe_wasm_bytes);
        format!("sha256:{}", hex::encode(hash))
    };

    let probe_manifest_yaml: &str = include_str!("../fixtures/manifests/evidence_probe.yaml");
    let probe_manifest_resolved = probe_manifest_yaml.replace("{{PROVIDER_DIGEST}}", &probe_digest);
    std::fs::write(
        manifest_tempdir.path().join("evidence_probe.yaml"),
        probe_manifest_resolved,
    )
    .expect("write probe manifest into tempdir");

    // High-risk sibling shares the same WASM digest but declares
    // risk_level: high so the policy layer routes it through the
    // human-approval flow. Same placeholder substitution.
    let probe_approval_yaml: &str =
        include_str!("../fixtures/manifests/evidence_probe_approval.yaml");
    let probe_approval_resolved = probe_approval_yaml.replace("{{PROVIDER_DIGEST}}", &probe_digest);
    std::fs::write(
        manifest_tempdir.path().join("evidence_probe_approval.yaml"),
        probe_approval_resolved,
    )
    .expect("write approval probe manifest into tempdir");

    let manifests_dir = manifest_tempdir.path().to_string_lossy().into_owned();

    let config = Config {
        listener: latchgate_config::ListenerConfig {
            listen_http_addr: Some("127.0.0.1:0".parse().unwrap()),
            unsafe_expose_http: true,
            public_base_url: "http://localhost:3000".into(),
            ..Default::default()
        },
        manifests_dir: manifests_dir.clone(),
        storage: latchgate_config::StorageConfig {
            redis_url: Some(test_redis_url()),
            ..Default::default()
        },
        operator_credentials: std::collections::HashMap::from([(
            "test-operator".to_string(),
            latchgate_config::OperatorCredential {
                api_key: OPERATOR_KEY.into(),
                dpop_jkt: Some(OPERATOR_KEYS.dpop_jkt.clone()),
            },
        )]),
        ..Config::default()
    };
    let issuer = Issuer::new(
        config.policy.lease_ttl_seconds,
        latchgate_core::security_constants::MAX_LEASE_TTL_SECS,
    )
    .unwrap();
    let replay_cache = ReplayCache::new(
        config
            .storage
            .redis_url
            .as_deref()
            .expect("redis_url required for integration tests"),
        Duration::from_secs(latchgate_core::security_constants::REPLAY_TTL_SECS),
        latchgate_core::security_constants::REDIS_KEY_PREFIX,
    )
    .unwrap();
    let registry = RegistryStore::load_from_dir(Path::new(&manifests_dir))
        .expect("registry must load from tempdir containing probe fixture");
    assert!(
        registry.get_action(PROBE_ACTION_ID).is_some(),
        "probe action missing from loaded registry — check fixture manifest"
    );
    let policy = if opa_reachable {
        PolicyClient::new(
            config
                .policy
                .opa_url
                .as_deref()
                .unwrap_or("http://127.0.0.1:8181"),
            Duration::from_millis(latchgate_core::security_constants::OPA_TIMEOUT_MS),
        )
    } else {
        let rego = latchgate_cli::embedded_policies::POLICY_REGO;
        let data_json =
            std::fs::read_to_string(workspace_root.join("definitions/policies/opa/data.json")).ok();
        PolicyClient::embedded(rego, data_json.as_deref())
    };
    let ledger = LedgerStore::open_in_memory(None).unwrap();
    let metrics = Metrics::new().unwrap();
    let budget_manager = BudgetManager::new(
        config
            .storage
            .redis_url
            .as_deref()
            .expect("redis_url required"),
    )
    .unwrap();
    let approval_store = ApprovalStore::new(
        config
            .storage
            .redis_url
            .as_deref()
            .expect("redis_url required for integration tests"),
        Duration::from_secs(latchgate_core::security_constants::APPROVAL_TTL_SECS),
    )
    .unwrap();

    // Load the evidence-probe WASM fixture into a fresh runtime. The
    // runtime is not persistent across tests, so a fresh instance per
    // invocation is fine — precompile cost is a few tens of ms.
    let wasm_runtime = latchgate_providers::WasmRuntime::new(4).unwrap();
    let fixtures_dir = workspace_root.join("target/test-fixtures");
    let probe_wasm = fixtures_dir.join("fixture_evidence_probe.wasm");
    assert!(
        probe_wasm.exists(),
        "probe WASM fixture missing at {probe_wasm:?} — run `make test-fixtures` first"
    );
    // Precompile the probe directly against the computed digest. We
    // avoid `load_modules_from_dir` because (a) that API also registers
    // a `builtin:<file-stem>` name, which our content-addressed manifest
    // does not use, and (b) it would eagerly precompile sibling
    // fixtures (infinite_loop, memory_hog) that are unrelated to this
    // test path.
    wasm_runtime
        .precompile(&probe_wasm_bytes, &probe_digest)
        .expect("precompile probe WASM fixture");

    let secrets_manager = latchgate_providers::SecretsManager::new("sops", None);
    let state = AppState::new(latchgate_kernel::AppStateInit {
        config,
        registry,
        embedded_manifests: vec![],
        ledger,
        metrics,
        auth: latchgate_kernel::AuthServicesInit {
            issuer,
            replay_cache,
            identity_provider: Box::new(latchgate_auth::identity::NoneProvider),
        },
        crypto: latchgate_kernel::CryptoServicesInit {
            receipt_signer: latchgate_crypto::ReceiptSigner::generate(),
            grant_signer: latchgate_crypto::GrantSigner::generate(),
            verifying_key_store: latchgate_crypto::VerifyingKeyStore::single(
                &latchgate_crypto::ReceiptSigner::generate(),
            ),
        },
        enforcement: latchgate_kernel::EnforcementServicesInit {
            policy,
            budget_manager,
            approval_store,
        },
        runtime: latchgate_kernel::RuntimeServicesInit {
            wasm_runtime,
            secrets_manager,
            verifier_registry: latchgate_kernel::VerifierRegistry::new(),
            fs_root_fd: None,
            fs_root_canonical: None,
            session_fs_roots: std::sync::Arc::new(dashmap::DashMap::new()),
        },
        lifecycle: latchgate_kernel::LifecycleInit { event_sink: None },
    });

    // Leak the tempdir guard for the lifetime of the returned state —
    // the registry has already read the files, so deletion now would
    // only matter if the kernel re-read manifests at runtime (it does
    // not). Leaking on purpose keeps the API signature simple; the OS
    // reclaims the space at process exit.
    std::mem::forget(manifest_tempdir);

    let ledger_ref = Arc::clone(&state.ledger);
    (state, ledger_ref)
}

/// Router variant of [`test_state_with_probe`] — returns an axum
/// router wired around the probe-enabled state plus the ledger handle.
pub fn test_router_with_probe() -> (axum::Router, Arc<LedgerStore>, AppState) {
    let (state, ledger) = test_state_with_probe();
    let router = latchgate_api::router(state.clone());
    (router, ledger, state)
}

// ---------------------------------------------------------------------------
// DPoP helpers
// ---------------------------------------------------------------------------

pub struct Agent {
    pub signing_key: DPoPSigningKey,
    pub pub_key: DPoPPublicKey,
}

impl Agent {
    pub fn new() -> Self {
        let (signing_key, pub_key) = generate_dpop_keypair().unwrap();
        Self {
            signing_key,
            pub_key,
        }
    }

    pub fn jwk_json(&self) -> serde_json::Value {
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": self.pub_key.x,
            "y": self.pub_key.y,
        })
    }

    pub fn lease_request(&self) -> serde_json::Value {
        serde_json::json!({
            "dpop_jwk": self.jwk_json(),
            "scopes": ["tools:call"],
        })
    }

    pub fn lease_request_with_budget(&self, max_calls: u64) -> serde_json::Value {
        serde_json::json!({
            "dpop_jwk": self.jwk_json(),
            "scopes": ["tools:call"],
            "budgets": { "max_calls": max_calls },
        })
    }

    pub fn dpop_proof(&self, htm: &str, htu: &str, lease_jwt: &str) -> String {
        let ath = compute_ath(lease_jwt);
        let jti = uuid_v4();
        sign_dpop_proof(&self.signing_key, htm, htu, &ath, &jti).unwrap()
    }
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

pub async fn post_json(
    app: &axum::Router,
    path: &str,
    body: &serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

pub async fn get_json(app: &axum::Router, path: &str) -> (StatusCode, serde_json::Value) {
    let resp = app
        .clone()
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

pub async fn post_with_auth(
    app: &axum::Router,
    path: &str,
    lease_jwt: &str,
    dpop_proof: &str,
    body: &serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("authorization", format!("DPoP {lease_jwt}"))
                .header("dpop", dpop_proof)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

pub async fn get_json_operator(app: &axum::Router, path: &str) -> (StatusCode, serde_json::Value) {
    let (authz, dpop) = operator_dpop_headers("GET", path);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .header("authorization", &authz)
                .header("dpop", &dpop)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

pub async fn post_json_operator(
    app: &axum::Router,
    path: &str,
    body: &serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let (authz, dpop) = operator_dpop_headers("POST", path);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("authorization", &authz)
                .header("dpop", &dpop)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

// ---------------------------------------------------------------------------
// Lease helpers
// ---------------------------------------------------------------------------

pub async fn issue_lease(app: &axum::Router, agent: &Agent) -> (String, String) {
    let (status, json) = post_json(app, "/v1/leases", &agent.lease_request()).await;
    assert_eq!(status, StatusCode::OK, "lease issuance failed: {json}");
    let jwt = json["lease_jwt"].as_str().unwrap().to_string();
    let sid = json["session_id"].as_str().unwrap().to_string();
    (jwt, sid)
}

pub async fn issue_lease_with_budget(
    app: &axum::Router,
    agent: &Agent,
    max_calls: u64,
) -> (String, String) {
    let (status, json) = post_json(
        app,
        "/v1/leases",
        &agent.lease_request_with_budget(max_calls),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "budgeted lease issuance failed: {json}"
    );
    let jwt = json["lease_jwt"].as_str().unwrap().to_string();
    let sid = json["session_id"].as_str().unwrap().to_string();
    (jwt, sid)
}

/// Base URL used in DPoP `htu` computation.
pub fn action_url(action_id: &str) -> String {
    format!("http://localhost:3000/v1/actions/{action_id}/execute")
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

pub fn uuid_v4() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    format!("{:08x}-{:04x}", nanos, rand_u16())
}

fn rand_u16() -> u16 {
    let x: u64 = 0;
    ((&x as *const u64 as u64) & 0xffff) as u16
}
