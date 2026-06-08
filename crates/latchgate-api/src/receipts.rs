//! Receipt retrieval endpoints.
//!
//! Two handlers serve the same receipt data with different auth models:
//!
//! - [`get_receipt`] — **admin socket**, requires operator authentication
//!   (DPoP proof-of-possession).
//!
//! - [`get_receipt_client`] — **client socket**, requires lease-based DPoP
//!   authentication (same as action execution). Allows agent processes to
//!   retrieve receipts for actions they have executed without requiring
//!   access to the admin socket.
//!
//! Both handlers return identical response bodies. The receipt is read-only
//! and receipt IDs are unguessable (UUID v7), so no principal scoping is
//! required beyond valid authentication.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use tracing::instrument;

use latchgate_kernel::AppState;

use crate::admin::require_operator_auth;
use crate::json_response::JsonResponse as ApiError;

/// Look up a receipt by ID and return the JSON response with signature status.
///
/// Shared between the admin and client handlers — only auth differs.
async fn lookup_receipt(
    state: &AppState,
    receipt_id: &str,
) -> Result<Json<serde_json::Value>, ApiError> {
    match latchgate_kernel::ops::receipts::lookup(state, receipt_id).await {
        Ok(Some(resp)) => Ok(Json(resp.value)),
        Ok(None) => Err(ApiError::new(StatusCode::NOT_FOUND, "not_found")),
        Err(e) => {
            tracing::error!(error = %e, receipt_id = %receipt_id, "receipt lookup failed");
            Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
            ))
        }
    }
}

/// Retrieve a stored execution receipt (admin socket, operator auth).
#[instrument(
    name = "api.get_receipt",
    skip(state, headers),
    fields(receipt_id = %receipt_id),
)]
pub async fn get_receipt(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(receipt_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_operator_auth(
        &state,
        &headers,
        "GET",
        &format!("/v1/receipts/{receipt_id}"),
    )
    .await?;

    lookup_receipt(&state, &receipt_id).await
}

/// Retrieve a stored execution receipt (client socket, lease-based DPoP auth).
///
/// Uses the same authentication mechanism as `POST /v1/actions/{id}/execute`:
/// the caller must present a valid lease JWT with a DPoP proof bound to
/// `GET /v1/receipts/{receipt_id}`.
///
/// # Security
///
/// - Receipt IDs are UUID v7 and unguessable. Any caller with a valid lease
///   can retrieve any receipt by ID. This is intentional: the receipt is a
///   read-only audit artifact, and the caller already knows the receipt_id
///   (returned from `execute()`).
/// - The DPoP proof is bound to the exact HTTP method and URI (including the
///   receipt_id), preventing proof reuse across receipts.
/// - Replay protection via jti ensures each proof is single-use.
#[instrument(
    name = "api.get_receipt_client",
    skip(state, headers),
    fields(receipt_id = %receipt_id),
)]
pub async fn get_receipt_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(receipt_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // SECURITY: htu from server config, never from Host / X-Forwarded-*.
    let htu = format!(
        "{}/v1/receipts/{}",
        state.config.listener.public_base_url.trim_end_matches('/'),
        receipt_id
    );

    let authorization = headers.get("authorization").and_then(|v| v.to_str().ok());
    let dpop_header = headers.get("dpop").and_then(|v| v.to_str().ok());

    // Authenticate the caller. The AuthContext is not used downstream
    // because receipt lookup is identity-agnostic, but authentication
    // must still be enforced (replay cache, lease validity).
    let _auth_ctx = latchgate_auth::authenticate(
        authorization,
        dpop_header,
        "GET",
        &htu,
        state.auth.issuer.jwks(),
        &state.auth.replay_cache,
    )
    .await
    .map_err(|e| {
        use latchgate_auth::AuthError;
        let (status, code) = match &e {
            AuthError::LeaseExpired => (StatusCode::UNAUTHORIZED, "lease_expired"),
            AuthError::InvalidLease { .. } => (StatusCode::UNAUTHORIZED, "invalid_lease"),
            AuthError::InvalidDPoP { .. } => (StatusCode::UNAUTHORIZED, "invalid_dpop"),
            AuthError::ReplayDetected { .. } => (StatusCode::UNAUTHORIZED, "replay_detected"),
            AuthError::MissingHeader { .. } => (StatusCode::UNAUTHORIZED, "missing_auth_header"),
            // Operator-specific variants — unreachable from the agent auth
            // path used here, but required for exhaustive matching.
            AuthError::InvalidAuthScheme => (StatusCode::UNAUTHORIZED, "invalid_auth_scheme"),
            AuthError::InvalidOperatorToken => (StatusCode::UNAUTHORIZED, "invalid_operator_token"),
            AuthError::MissingDpopHeader => (StatusCode::UNAUTHORIZED, "missing_dpop_header"),
            AuthError::KeyBindingFailed { .. } => (StatusCode::UNAUTHORIZED, "key_binding_failed"),
            AuthError::ReplayCacheUnavailable => {
                (StatusCode::SERVICE_UNAVAILABLE, "replay_cache_unavailable")
            }
            AuthError::ClockError => (StatusCode::SERVICE_UNAVAILABLE, "clock_error"),
        };
        ApiError::new(status, code)
    })?;

    lookup_receipt(&state, &receipt_id).await
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use latchgate_crypto::ReceiptExt;
    use tower::ServiceExt;

    use crate::test_support::{operator_headers, test_state, TEST_OPERATOR};
    use latchgate_core::types::{GrantId, ReceiptId};
    use latchgate_core::{ExecutionReceipt, NormalizedResult, VerificationOutcome};

    fn sample_receipt(receipt_id: &str) -> ExecutionReceipt {
        let now = chrono::Utc::now();
        let mut r = ExecutionReceipt {
            receipt_id: ReceiptId::from(receipt_id),
            grant_id: GrantId::from("grant-api-001"),
            provider_module_digest:
                "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".into(),
            provider_receipt: std::sync::Arc::new(serde_json::json!({"status": 200})),
            normalized_result: NormalizedResult::Success {
                summary: "HTTP 200 OK".into(),
            },
            verification_outcome: VerificationOutcome::Verified {
                evidence: serde_json::json!({"status_code": 200}),
            },
            effect_evidence: vec![],
            result_hash: String::new(),
            receipt_signature: None,
            signing_key_id: None,
            started_at: now - chrono::Duration::seconds(1),
            finished_at: now,
            failure_class: None,
        };
        r.result_hash = r.compute_result_hash();
        r
    }

    fn test_router() -> axum::Router {
        crate::router(test_state())
    }

    #[tokio::test]
    async fn get_receipt_returns_404_when_not_found() {
        let app = test_router();
        let (authz, dpop) = operator_headers("GET", "/v1/receipts/nonexistent-receipt-id");
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/receipts/nonexistent-receipt-id")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_receipt_requires_auth() {
        let app = test_router();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/receipts/anything")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn get_receipt_rejects_invalid_token() {
        let app = test_router();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/receipts/anything")
                    .header("authorization", "DPoP wrong-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    use latchgate_auth::dpop::{
        compute_ath, compute_jwk_thumbprint, generate_dpop_keypair, sign_dpop_proof,
    };

    /// Build a DPoP-enabled test state with a separate operator keypair.
    /// Returns (AppState, api_key, signing_key).
    fn dpop_test_state() -> (
        latchgate_kernel::AppState,
        String,
        latchgate_auth::DPoPSigningKey,
    ) {
        let (sk, pk) = generate_dpop_keypair().unwrap();
        let jkt = compute_jwk_thumbprint(&pk.x, &pk.y).unwrap();
        let api_key = "dpop-operator-key-receipts".to_string();

        let config = latchgate_config::Config {
            operator_credentials: std::collections::HashMap::from([(
                "dpop-operator".to_string(),
                latchgate_config::OperatorCredential {
                    api_key: api_key.clone(),
                    dpop_jkt: Some(jkt),
                },
            )]),
            ..latchgate_config::Config::default()
        };
        let issuer = latchgate_auth::issuer::Issuer::new(
            config.policy.lease_ttl_seconds,
            latchgate_core::security_constants::MAX_LEASE_TTL_SECS,
        )
        .unwrap();
        let replay_cache =
            latchgate_auth::ReplayCache::in_memory(std::time::Duration::from_secs(180));
        let registry = latchgate_registry::RegistryStore::empty();
        let policy = latchgate_policy::PolicyClient::new(
            config
                .policy
                .opa_url
                .as_deref()
                .unwrap_or("http://127.0.0.1:8181"),
            std::time::Duration::from_millis(latchgate_core::security_constants::OPA_TIMEOUT_MS),
        );
        let ledger = latchgate_ledger::LedgerStore::open_in_memory(None).unwrap();
        let metrics = latchgate_ledger::Metrics::new().unwrap();
        let budget_manager = latchgate_state::BudgetManager::in_memory_for_tests();
        let approval_store = latchgate_state::approvals::ApprovalStore::in_memory_for_tests(
            std::time::Duration::from_secs(latchgate_core::security_constants::APPROVAL_TTL_SECS),
        );
        let wasm_runtime = latchgate_providers::WasmRuntime::new(4).expect("WASM runtime init");
        let secrets_manager = latchgate_providers::SecretsManager::new("sops", None);
        let receipt_signer = latchgate_crypto::ReceiptSigner::generate();
        let grant_signer = latchgate_crypto::GrantSigner::generate();
        let verifying_key_store = latchgate_crypto::VerifyingKeyStore::single(&receipt_signer);

        let state = latchgate_kernel::AppState::new(latchgate_kernel::AppStateInit {
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
                receipt_signer,
                grant_signer,
                verifying_key_store,
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

        (state, api_key, sk)
    }

    #[tokio::test]
    async fn dpop_proof_with_correct_receipt_path_is_accepted() {
        let (state, api_key, sk) = dpop_test_state();
        let mut receipt = sample_receipt("rcpt-dpop-001");
        receipt.sign(&state.crypto.receipt_signer);
        state.ledger.write_receipt(&receipt).unwrap();

        // htu must match what the handler constructs:
        // {public_base_url}/v1/receipts/{receipt_id}
        let htu = format!(
            "{}/v1/receipts/rcpt-dpop-001",
            state.config.listener.public_base_url.trim_end_matches('/')
        );
        let ath = compute_ath(&api_key);
        let jti = uuid::Uuid::now_v7().to_string();
        let proof = sign_dpop_proof(&sk, "GET", &htu, &ath, &jti).unwrap();

        let app = crate::router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/receipts/rcpt-dpop-001")
                    .header("authorization", format!("DPoP {api_key}"))
                    .header("dpop", &proof)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "DPoP proof with correct htu (including receipt_id) must be accepted"
        );
    }

    #[tokio::test]
    async fn dpop_proof_with_wrong_htu_is_rejected() {
        let (state, api_key, sk) = dpop_test_state();
        let mut receipt = sample_receipt("rcpt-dpop-002");
        receipt.sign(&state.crypto.receipt_signer);
        state.ledger.write_receipt(&receipt).unwrap();

        // Proof bound to /v1/receipts (without receipt_id) — this was the old
        // bug: the handler passed a static path instead of the parameterised one.
        let wrong_htu = format!(
            "{}/v1/receipts",
            state.config.listener.public_base_url.trim_end_matches('/')
        );
        let ath = compute_ath(&api_key);
        let jti = uuid::Uuid::now_v7().to_string();
        let proof = sign_dpop_proof(&sk, "GET", &wrong_htu, &ath, &jti).unwrap();

        let app = crate::router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/receipts/rcpt-dpop-002")
                    .header("authorization", format!("DPoP {api_key}"))
                    .header("dpop", &proof)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "DPoP proof with htu missing receipt_id must be rejected"
        );
    }

    #[tokio::test]
    async fn get_receipt_returns_stored_receipt() {
        let state = test_state();
        let mut receipt = sample_receipt("rcpt-api-test-001");
        receipt.sign(&state.crypto.receipt_signer);
        state.ledger.write_receipt(&receipt).unwrap();

        let app = crate::router(state);
        let (authz, dpop) = operator_headers("GET", "/v1/receipts/rcpt-api-test-001");
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/receipts/rcpt-api-test-001")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["receipt_id"], "rcpt-api-test-001");
        assert_eq!(json["grant_id"], "grant-api-001");
        assert_eq!(json["signature_status"], "valid");
    }

    #[tokio::test]
    async fn get_receipt_fully_successful_field_present() {
        let state = test_state();
        let receipt = sample_receipt("rcpt-api-test-002");
        state.ledger.write_receipt(&receipt).unwrap();

        let app = crate::router(state);
        let (authz, dpop) = operator_headers("GET", "/v1/receipts/rcpt-api-test-002");
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/receipts/rcpt-api-test-002")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["verification_outcome"]["status"], "verified");
    }

    #[tokio::test]
    async fn receipt_endpoint_uses_key_store_not_current_signer() {
        // Sign receipt with signer_old, then build state with signer_new as
        // current signer but both keys in the verifying key store. The
        // endpoint must still verify the old receipt correctly.
        let signer_old = latchgate_crypto::ReceiptSigner::generate();
        let signer_new = latchgate_crypto::ReceiptSigner::generate();

        let mut store = latchgate_crypto::VerifyingKeyStore::empty();
        let jwks_path = std::env::temp_dir().join(format!(
            "latchgate-test-ev1-api-{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        store.ensure_contains(&signer_old, &jwks_path);
        store.ensure_contains(&signer_new, &jwks_path);

        let mut receipt = sample_receipt("rcpt-key-store-001");
        receipt.sign(&signer_old);

        // Build state with TEST_OPERATOR credential for auth, custom signers
        // for the key-store verification test.
        let config = latchgate_config::Config {
            operator_credentials: std::collections::HashMap::from([(
                "test-operator".to_string(),
                TEST_OPERATOR.credential(),
            )]),
            ..latchgate_config::Config::default()
        };
        let issuer = latchgate_auth::issuer::Issuer::new(
            config.policy.lease_ttl_seconds,
            latchgate_core::security_constants::MAX_LEASE_TTL_SECS,
        )
        .unwrap();
        let replay_cache =
            latchgate_auth::ReplayCache::in_memory(std::time::Duration::from_secs(180));
        let registry = latchgate_registry::RegistryStore::empty();
        let policy = latchgate_policy::PolicyClient::new(
            config
                .policy
                .opa_url
                .as_deref()
                .unwrap_or("http://127.0.0.1:8181"),
            std::time::Duration::from_millis(latchgate_core::security_constants::OPA_TIMEOUT_MS),
        );
        let ledger = latchgate_ledger::LedgerStore::open_in_memory(None).unwrap();
        let metrics = latchgate_ledger::Metrics::new().unwrap();
        let budget_manager = latchgate_state::BudgetManager::in_memory_for_tests();
        let approval_store = latchgate_state::approvals::ApprovalStore::in_memory_for_tests(
            std::time::Duration::from_secs(latchgate_core::security_constants::APPROVAL_TTL_SECS),
        );
        let wasm_runtime = latchgate_providers::WasmRuntime::new(4).expect("WASM runtime init");
        let secrets_manager = latchgate_providers::SecretsManager::new("sops", None);
        let grant_signer = latchgate_crypto::GrantSigner::generate();

        let state = latchgate_kernel::AppState::new(latchgate_kernel::AppStateInit {
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
                receipt_signer: signer_new,
                grant_signer,
                verifying_key_store: store,
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
                // current signer is NEW — old key is NOT the current one
                fs_root_fd: None,
                fs_root_canonical: None,
                session_fs_roots: std::sync::Arc::new(dashmap::DashMap::new()),
            },
            lifecycle: latchgate_kernel::LifecycleInit { event_sink: None },
        });

        state.ledger.write_receipt(&receipt).unwrap();

        let app = crate::router(state);
        let (authz, dpop) = operator_headers("GET", "/v1/receipts/rcpt-key-store-001");
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/receipts/rcpt-key-store-001")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["signature_status"], "valid",
            "signature_status must be 'valid'"
        );
    }

    #[tokio::test]
    async fn unsigned_receipt_returns_missing_signature_status() {
        let state = test_state();
        let receipt = sample_receipt("rcpt-unsigned-001");
        // NOT signed — tests that the endpoint honestly reports missing signatures.
        state.ledger.write_receipt(&receipt).unwrap();

        let app = crate::router(state);
        let (authz, dpop) = operator_headers("GET", "/v1/receipts/rcpt-unsigned-001");
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/receipts/rcpt-unsigned-001")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["signature_status"], "missing_signature");
    }
}
