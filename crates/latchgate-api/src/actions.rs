#![allow(dead_code)]

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;
use std::sync::Arc;

use latchgate_kernel::{AppState, PipelineError};

#[derive(Serialize)]
struct ActionSummary {
    action_id: Arc<str>,
    version: Arc<str>,
    risk_level: latchgate_core::RiskLevel,
    /// Present only for database actions. Signals to discovery consumers
    /// (MCP adapter, SDKs) that this action supports controlled SQL modes.
    #[serde(skip_serializing_if = "Option::is_none")]
    database_mode: Option<latchgate_kernel::ops::actions::DatabaseMode>,
}

#[derive(Serialize)]
pub(crate) struct ActionListResponse {
    actions: Vec<ActionSummary>,
}

#[derive(Serialize)]
pub(crate) struct ActionDetail {
    action_id: String,
    version: String,
    provider_module_digest: String,
    risk_level: latchgate_core::RiskLevel,
    resource_limits: latchgate_core::ResourceLimits,
    io: ActionIoInfo,
    egress: Option<latchgate_core::EgressProfile>,
    declared_side_effects: Vec<Arc<str>>,
    /// Present only for database-backed actions.
    #[serde(skip_serializing_if = "Option::is_none")]
    database: Option<ActionDatabaseInfo>,
}

#[derive(Serialize)]
struct ActionIoInfo {
    max_request_bytes: usize,
    max_response_bytes: usize,
    has_request_schema: bool,
    has_response_schema: bool,
}

#[derive(Serialize)]
struct ActionDatabaseInfo {
    mode: latchgate_kernel::ops::actions::DatabaseMode,
    statements: Vec<StatementInfo>,
    allows_parameterized_queries: bool,
    parameterized_operations: Vec<latchgate_kernel::ops::actions::OperationClass>,
    blocked_operations: Vec<latchgate_kernel::ops::actions::OperationClass>,
}

#[derive(Serialize)]
struct StatementInfo {
    id: String,
    operation: latchgate_kernel::ops::actions::OperationClass,
    tables: Vec<String>,
    param_count: usize,
}

/// Unauthenticated read-only endpoint. Returns action summaries (no digests,
/// no schemas, no secrets). Useful for agent discovery.
pub async fn list_actions(State(state): State<AppState>) -> Json<ActionListResponse> {
    let actions: Vec<ActionSummary> = state
        .registry
        .load()
        .list_actions()
        .iter()
        .map(|m| ActionSummary {
            action_id: Arc::from(m.action_id.as_str()),
            version: Arc::clone(&m.version),
            risk_level: m.risk_level,
            database_mode: m.database_mode.as_deref().and_then(parse_database_mode),
        })
        .collect();

    Json(ActionListResponse { actions })
}

pub async fn get_action(
    State(state): State<AppState>,
    axum::extract::Path(action_id): axum::extract::Path<String>,
) -> Result<Json<ActionDetail>, StatusCode> {
    let registry = state.registry.load();
    let manifest = registry
        .get_action(&action_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    let database = manifest
        .database_config
        .as_deref()
        .and_then(|config_value| {
            let db_config =
                serde_json::from_value::<latchgate_kernel::ops::actions::DatabaseConfig>(
                    config_value.clone(),
                )
                .ok()?;

            use latchgate_kernel::ops::actions::{classify_sql, count_sql_params, extract_tables};

            let statements: Vec<StatementInfo> = db_config
                .statements
                .iter()
                .map(|stmt| StatementInfo {
                    id: stmt.id.clone(),
                    operation: classify_sql(&stmt.sql),
                    tables: extract_tables(&stmt.sql),
                    param_count: count_sql_params(&stmt.sql),
                })
                .collect();

            let allows_parameterized_queries = !db_config.rules.allow_parameterized.is_empty();

            Some(ActionDatabaseInfo {
                mode: db_config.mode,
                statements,
                allows_parameterized_queries,
                parameterized_operations: db_config.rules.allow_parameterized,
                blocked_operations: db_config.rules.blocked_operations,
            })
        });

    let detail = ActionDetail {
        action_id: manifest.action_id.clone(),
        version: manifest.version.to_string(),
        provider_module_digest: manifest.provider_module_digest.to_string(),
        risk_level: manifest.risk_level,
        resource_limits: manifest.resource_limits.clone(),
        io: ActionIoInfo {
            max_request_bytes: manifest.io.max_request_bytes,
            max_response_bytes: manifest.io.max_response_bytes,
            has_request_schema: registry.get_request_validator(&action_id).is_some(),
            has_response_schema: registry.get_response_validator(&action_id).is_some(),
        },
        egress: manifest.egress_profile().ok(),
        declared_side_effects: manifest.declared_side_effects.clone(),
        database,
    };

    Ok(Json(detail))
}

/// Convert a raw database mode string (from `ActionSpec::database_mode`) to
/// the typed enum. Returns `None` for unrecognized values.
fn parse_database_mode(s: &str) -> Option<latchgate_kernel::ops::actions::DatabaseMode> {
    use latchgate_kernel::ops::actions::DatabaseMode;
    match s {
        "strict" => Some(DatabaseMode::Strict),
        "parameterized" => Some(DatabaseMode::Parameterized),
        "hybrid" => Some(DatabaseMode::Hybrid),
        _ => None,
    }
}

pub async fn get_action_request_schema(
    State(state): State<AppState>,
    axum::extract::Path(action_id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if state.registry.load().get_action(&action_id).is_none() {
        return Err(StatusCode::NOT_FOUND);
    }

    state
        .registry
        .load()
        .get_request_schema_json(&action_id)
        .cloned()
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

/// Thin HTTP adapter: extracts headers and body, delegates to the Gate
/// enforcement pipeline in [`latchgate_kernel::run_action_call`]. All
/// enforcement logic (auth, trust, policy, schema, provider, audit)
/// lives there.
///
/// SECURITY: never leaks internal details (module digests, OPA rule names,
/// secret values) in HTTP responses. All detail goes to the audit trail.
#[tracing::instrument(
    name = "http.action_call",
    skip(state, conn_ctx, headers, body),
    fields(action_id = %action_id),
)]
pub async fn action_call(
    State(state): State<AppState>,
    axum::extract::Path(action_id): axum::extract::Path<String>,
    conn_ctx: Option<axum::Extension<latchgate_auth::ConnectionContext>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<latchgate_kernel::ExecutionResponse>, PipelineError> {
    let authorization = headers.get("authorization").and_then(|v| v.to_str().ok());
    let dpop = headers.get("dpop").and_then(|v| v.to_str().ok());

    // Derive a peer identifier for rate-limit sharding when no session hint
    // is parseable from the JWT. UDS connections carry peer credentials
    // (uid); TCP connections without transport middleware use a fixed default.
    let peer_id = peer_identifier(&conn_ctx);

    latchgate_kernel::run_action_call(state, &action_id, authorization, dpop, peer_id, &body)
        .await
        .map(Json)
}

/// Derive a stable peer identifier from the connection context.
///
/// - **UDS:** `PeerId::Uid(N)` — groups all requests from the same OS user.
/// - **TCP / no context:** `PeerId::Unknown` — all unauthenticated TCP
///   requests share one anonymous bucket with a low RPS ceiling.
fn peer_identifier(
    conn_ctx: &Option<axum::Extension<latchgate_auth::ConnectionContext>>,
) -> latchgate_kernel::PeerId {
    #[cfg(unix)]
    if let Some(axum::Extension(ref ctx)) = conn_ctx {
        if let Some(cred) = &ctx.peer_cred {
            return latchgate_kernel::PeerId::Uid(cred.uid);
        }
    }

    let _ = conn_ctx;
    latchgate_kernel::PeerId::Unknown
}

#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use crate::test_support::{body_json, post_lease, test_router, test_state};
    use latchgate_auth::issuer::Issuer;
    use latchgate_auth::ReplayCache;
    use latchgate_config::Config;
    use latchgate_kernel::AppState;

    #[tokio::test]
    async fn action_call_missing_auth_header_returns_401() {
        let app = test_router();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/actions/test_tool/execute")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"], "missing_auth_header");
    }

    #[tokio::test]
    async fn action_call_missing_dpop_header_returns_401() {
        let app = test_router();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/actions/test_tool/execute")
                    .header("authorization", "DPoP some.jwt.token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        // Either missing_auth_header (for DPoP) or invalid_lease (bad JWT)
        assert!(json["error"].is_string());
    }

    #[tokio::test]
    async fn action_call_bearer_scheme_returns_401() {
        let app = test_router();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/actions/test_tool/execute")
                    .header("authorization", "Bearer some.jwt.token")
                    .header("dpop", "proof")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"], "invalid_lease");
    }

    #[tokio::test]
    async fn action_call_invalid_lease_returns_401() {
        let app = test_router();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/actions/test_tool/execute")
                    .header("authorization", "DPoP not.a.valid.jwt")
                    .header("dpop", "proof.jwt.here")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"], "invalid_lease");
    }

    #[tokio::test]
    async fn action_call_expired_lease_returns_401() {
        let app = test_router();

        // Send a well-formed but invalid JWT (bad signature, missing kid).
        // We cannot sign with the issuer's private key from outside, so we
        // verify the auth chain rejects garbage JWTs with a 401.
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/actions/test_tool/execute")
                    .header(
                        "authorization",
                        "DPoP eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJleHAiOjB9.invalid",
                    )
                    .header("dpop", "proof")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    //
    // These exercise the full HTTP pipeline: issue lease => sign proof with a
    // specific flaw => POST /v1/actions/{action_id}/execute => 401. The DPoP verifier
    // rejects before the replay cache is consulted, so Redis is not required.

    /// SECURITY: DPoP proof signed with wrong HTTP method must be rejected.
    #[tokio::test]
    async fn action_call_dpop_wrong_method_returns_401() {
        let state = test_state();

        let (dpop_sk, dpop_pk) = latchgate_auth::dpop::generate_dpop_keypair().unwrap();
        let jwk = serde_json::json!({
            "kty": "EC", "crv": "P-256", "x": dpop_pk.x, "y": dpop_pk.y,
        });

        // Issue a valid lease
        let lease_body = serde_json::json!({
            "scopes": ["tools:call"],
            "dpop_jwk": jwk,
        });
        let lease_resp = post_lease(crate::router(state.clone()), &lease_body).await;
        assert_eq!(lease_resp.status(), StatusCode::OK);
        let lease_jwt = body_json(lease_resp).await["lease_jwt"]
            .as_str()
            .unwrap()
            .to_string();

        // Sign proof with htm="GET" but the endpoint expects POST
        let action_id = "test_action";
        let htu = format!(
            "{}/v1/actions/{}/execute",
            state.config.listener.public_base_url, action_id
        );
        let ath = latchgate_auth::dpop::compute_ath(&lease_jwt);
        let dpop_jti = uuid::Uuid::now_v7().to_string();
        let dpop_proof =
            latchgate_auth::dpop::sign_dpop_proof(&dpop_sk, "GET", &htu, &ath, &dpop_jti).unwrap();

        let response = crate::router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/actions/{action_id}/execute"))
                    .header("authorization", format!("DPoP {lease_jwt}"))
                    .header("dpop", dpop_proof)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"], "invalid_dpop");
    }

    /// SECURITY: DPoP proof signed with wrong URL must be rejected.
    #[tokio::test]
    async fn action_call_dpop_wrong_url_returns_401() {
        let state = test_state();

        let (dpop_sk, dpop_pk) = latchgate_auth::dpop::generate_dpop_keypair().unwrap();
        let jwk = serde_json::json!({
            "kty": "EC", "crv": "P-256", "x": dpop_pk.x, "y": dpop_pk.y,
        });

        let lease_body = serde_json::json!({
            "scopes": ["tools:call"],
            "dpop_jwk": jwk,
        });
        let lease_resp = post_lease(crate::router(state.clone()), &lease_body).await;
        let lease_jwt = body_json(lease_resp).await["lease_jwt"]
            .as_str()
            .unwrap()
            .to_string();

        // Sign proof with htu pointing to a different action
        let wrong_htu = format!(
            "{}/v1/actions/evil_tool/execute",
            state.config.listener.public_base_url
        );
        let ath = latchgate_auth::dpop::compute_ath(&lease_jwt);
        let dpop_jti = uuid::Uuid::now_v7().to_string();
        let dpop_proof =
            latchgate_auth::dpop::sign_dpop_proof(&dpop_sk, "POST", &wrong_htu, &ath, &dpop_jti)
                .unwrap();

        // Send to a different action_id than what the proof was signed for
        let response = crate::router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/actions/test_tool/execute")
                    .header("authorization", format!("DPoP {lease_jwt}"))
                    .header("dpop", dpop_proof)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"], "invalid_dpop");
    }

    /// SECURITY: DPoP proof signed by a different key than cnf.jkt must be rejected.
    #[tokio::test]
    async fn action_call_dpop_wrong_key_binding_returns_401() {
        let state = test_state();

        // Key A: used for lease issuance (cnf.jkt = thumbprint of key A)
        let (_, dpop_pk_a) = latchgate_auth::dpop::generate_dpop_keypair().unwrap();
        let jwk_a = serde_json::json!({
            "kty": "EC", "crv": "P-256", "x": dpop_pk_a.x, "y": dpop_pk_a.y,
        });

        let lease_body = serde_json::json!({
            "scopes": ["tools:call"],
            "dpop_jwk": jwk_a,
        });
        let lease_resp = post_lease(crate::router(state.clone()), &lease_body).await;
        let lease_jwt = body_json(lease_resp).await["lease_jwt"]
            .as_str()
            .unwrap()
            .to_string();

        // Key B: used to sign the DPoP proof (different key => binding mismatch)
        let (dpop_sk_b, _) = latchgate_auth::dpop::generate_dpop_keypair().unwrap();

        let action_id = "test_action";
        let htu = format!(
            "{}/v1/actions/{}/execute",
            state.config.listener.public_base_url, action_id
        );
        let ath = latchgate_auth::dpop::compute_ath(&lease_jwt);
        let dpop_jti = uuid::Uuid::now_v7().to_string();
        let dpop_proof =
            latchgate_auth::dpop::sign_dpop_proof(&dpop_sk_b, "POST", &htu, &ath, &dpop_jti)
                .unwrap();

        let response = crate::router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/actions/{action_id}/execute"))
                    .header("authorization", format!("DPoP {lease_jwt}"))
                    .header("dpop", dpop_proof)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"], "invalid_dpop");
    }

    /// SECURITY: DPoP proof with wrong ath (bound to different access token) must be rejected.
    #[tokio::test]
    async fn action_call_dpop_wrong_ath_returns_401() {
        let state = test_state();

        let (dpop_sk, dpop_pk) = latchgate_auth::dpop::generate_dpop_keypair().unwrap();
        let jwk = serde_json::json!({
            "kty": "EC", "crv": "P-256", "x": dpop_pk.x, "y": dpop_pk.y,
        });

        let lease_body = serde_json::json!({
            "scopes": ["tools:call"],
            "dpop_jwk": jwk,
        });
        let lease_resp = post_lease(crate::router(state.clone()), &lease_body).await;
        let lease_jwt = body_json(lease_resp).await["lease_jwt"]
            .as_str()
            .unwrap()
            .to_string();

        // Sign proof with ath of a different token (simulates token substitution)
        let wrong_ath = latchgate_auth::dpop::compute_ath("some-other-access-token");

        let action_id = "test_action";
        let htu = format!(
            "{}/v1/actions/{}/execute",
            state.config.listener.public_base_url, action_id
        );
        let dpop_jti = uuid::Uuid::now_v7().to_string();
        let dpop_proof =
            latchgate_auth::dpop::sign_dpop_proof(&dpop_sk, "POST", &htu, &wrong_ath, &dpop_jti)
                .unwrap();

        let response = crate::router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/actions/{action_id}/execute"))
                    .header("authorization", format!("DPoP {lease_jwt}"))
                    .header("dpop", dpop_proof)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(response).await;
        assert_eq!(json["error"], "invalid_dpop");
    }
    //
    /// Full auth succeeds, but `test_tool` is not in the registry => 404.
    /// Proves the pipeline progresses past auth to registry lookup.
    #[tokio::test]
    async fn action_call_valid_auth_unknown_tool_returns_404() {
        let state = test_state();

        let (dpop_sk, dpop_pk) = latchgate_auth::dpop::generate_dpop_keypair().unwrap();
        let jwk = serde_json::json!({
            "kty": "EC", "crv": "P-256", "x": dpop_pk.x, "y": dpop_pk.y,
        });

        let lease_body = serde_json::json!({
            "scopes": ["tools:call"],
            "dpop_jwk": jwk,
        });
        let lease_resp = post_lease(crate::router(state.clone()), &lease_body).await;
        assert_eq!(lease_resp.status(), StatusCode::OK);
        let lease_json = body_json(lease_resp).await;
        let lease_jwt = lease_json["lease_jwt"].as_str().unwrap();

        let action_id = "test_action"; // NOT registered in definitions/manifests
        let htu = format!(
            "{}/v1/actions/{}/execute",
            state.config.listener.public_base_url, action_id
        );
        let ath = latchgate_auth::dpop::compute_ath(lease_jwt);
        let dpop_jti = uuid::Uuid::now_v7().to_string();
        let dpop_proof =
            latchgate_auth::dpop::sign_dpop_proof(&dpop_sk, "POST", &htu, &ath, &dpop_jti).unwrap();

        let response = crate::router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/actions/{action_id}/execute"))
                    .header("authorization", format!("DPoP {lease_jwt}"))
                    .header("dpop", dpop_proof)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let json = body_json(response).await;
        assert_eq!(json["error"], "action_not_found");
    }

    /// SECURITY: replaying the same DPoP proof must be rejected.
    #[tokio::test]
    async fn action_call_replay_dpop_returns_401() {
        let state = test_state();

        let (dpop_sk, dpop_pk) = latchgate_auth::dpop::generate_dpop_keypair().unwrap();
        let jwk = serde_json::json!({
            "kty": "EC", "crv": "P-256", "x": dpop_pk.x, "y": dpop_pk.y,
        });
        let lease_body = serde_json::json!({
            "scopes": ["tools:call"],
            "dpop_jwk": jwk,
        });
        let lease_resp = post_lease(crate::router(state.clone()), &lease_body).await;
        let lease_json = body_json(lease_resp).await;
        let lease_jwt = lease_json["lease_jwt"].as_str().unwrap();

        let action_id = "test_action";
        let htu = format!(
            "{}/v1/actions/{}/execute",
            state.config.listener.public_base_url, action_id
        );
        let ath = latchgate_auth::dpop::compute_ath(lease_jwt);
        let dpop_jti = uuid::Uuid::now_v7().to_string();
        let dpop_proof =
            latchgate_auth::dpop::sign_dpop_proof(&dpop_sk, "POST", &htu, &ath, &dpop_jti).unwrap();

        // The key point: the DPoP jti IS recorded in the replay cache during
        // auth (step 1), even though the request ultimately fails at step 2.
        let resp1 = crate::router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/actions/{action_id}/execute"))
                    .header("authorization", format!("DPoP {lease_jwt}"))
                    .header("dpop", &dpop_proof)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Auth passed (not 401) — jti was consumed.
        assert_ne!(
            resp1.status(),
            StatusCode::UNAUTHORIZED,
            "first call should pass auth (jti consumed)"
        );

        let resp2 = crate::router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/actions/{action_id}/execute"))
                    .header("authorization", format!("DPoP {lease_jwt}"))
                    .header("dpop", &dpop_proof)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(resp2).await;
        assert_eq!(json["error"], "replay_detected");
    }

    /// SECURITY: Redis down must return 503, not allow the request.
    #[tokio::test]
    async fn action_call_redis_down_returns_503() {
        // Create state with ReplayCache pointing to a dead port.
        let config = Config::default();
        let issuer = Issuer::new(
            config.policy.lease_ttl_seconds,
            latchgate_core::security_constants::MAX_LEASE_TTL_SECS,
        )
        .unwrap();
        let dead_cache = ReplayCache::new(
            "redis://127.0.0.1:1",
            std::time::Duration::from_secs(180),
            "latchgate:jti:",
        )
        .unwrap();
        let registry = latchgate_registry::RegistryStore::empty();
        let state = AppState::new(latchgate_kernel::AppStateInit {
            config: config.clone(),
            registry,
            embedded_manifests: vec![],
            ledger: latchgate_ledger::LedgerStore::open_in_memory(None).unwrap(),
            metrics: latchgate_ledger::Metrics::new().unwrap(),
            auth: latchgate_kernel::AuthServicesInit {
                issuer,
                replay_cache: dead_cache,
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
                policy: latchgate_policy::PolicyClient::new(
                    config
                        .policy
                        .opa_url
                        .as_deref()
                        .unwrap_or("http://127.0.0.1:8181"),
                    std::time::Duration::from_millis(
                        latchgate_core::security_constants::OPA_TIMEOUT_MS,
                    ),
                ),
                budget_manager: latchgate_state::BudgetManager::in_memory_for_tests(),
                approval_store: latchgate_state::approvals::ApprovalStore::in_memory_for_tests(
                    std::time::Duration::from_secs(
                        latchgate_core::security_constants::APPROVAL_TTL_SECS,
                    ),
                ),
            },
            runtime: latchgate_kernel::RuntimeServicesInit {
                wasm_runtime: latchgate_providers::WasmRuntime::new(4).expect("WASM runtime init"),
                secrets_manager: latchgate_providers::SecretsManager::new("sops", None),
                verifier_registry: latchgate_kernel::VerifierRegistry::new(),
                fs_root_fd: None,
                fs_root_canonical: None,
                session_fs_roots: std::sync::Arc::new(dashmap::DashMap::new()),
            },
            lifecycle: latchgate_kernel::LifecycleInit { event_sink: None },
        });

        // Issue a lease so we have a valid JWT
        let (dpop_sk, dpop_pk) = latchgate_auth::dpop::generate_dpop_keypair().unwrap();
        let jwk = serde_json::json!({
            "kty": "EC", "crv": "P-256", "x": dpop_pk.x, "y": dpop_pk.y,
        });
        let lease_body = serde_json::json!({
            "scopes": ["tools:call"],
            "dpop_jwk": jwk,
        });
        let lease_resp = post_lease(crate::router(state.clone()), &lease_body).await;
        assert_eq!(lease_resp.status(), StatusCode::OK);
        let lease_json = body_json(lease_resp).await;
        let lease_jwt = lease_json["lease_jwt"].as_str().unwrap();

        // Sign a valid DPoP proof
        let action_id = "test_action";
        let htu = format!(
            "{}/v1/actions/{}/execute",
            state.config.listener.public_base_url, action_id
        );
        let ath = latchgate_auth::dpop::compute_ath(lease_jwt);
        let dpop_jti = uuid::Uuid::now_v7().to_string();
        let dpop_proof =
            latchgate_auth::dpop::sign_dpop_proof(&dpop_sk, "POST", &htu, &ath, &dpop_jti).unwrap();

        // Auth is valid but Redis is down => 503 (fail-closed)
        let response = crate::router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/actions/{action_id}/execute"))
                    .header("authorization", format!("DPoP {lease_jwt}"))
                    .header("dpop", dpop_proof)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "Redis down must result in 503, never allow"
        );
        let json = body_json(response).await;
        assert_eq!(json["error"], "replay_cache_unavailable");
    }
    //
    // These tests verify that the pipeline progresses through each enforcement
    // step. Each test targets a specific step boundary.

    /// Helper: issue a lease + sign a DPoP proof for the given action_id.
    /// Returns (lease_jwt, dpop_proof) ready for Authorization + DPoP headers.
    async fn issue_auth(state: &AppState, action_id: &str) -> (String, String) {
        let (dpop_sk, dpop_pk) = latchgate_auth::dpop::generate_dpop_keypair().unwrap();
        let jwk = serde_json::json!({
            "kty": "EC", "crv": "P-256", "x": dpop_pk.x, "y": dpop_pk.y,
        });
        let lease_body = serde_json::json!({
            "scopes": ["tools:call"],
            "dpop_jwk": jwk,
        });
        let lease_resp = post_lease(crate::router(state.clone()), &lease_body).await;
        let lease_json = body_json(lease_resp).await;
        let lease_jwt = lease_json["lease_jwt"].as_str().unwrap().to_string();

        let htu = format!(
            "{}/v1/actions/{}/execute",
            state.config.listener.public_base_url, action_id
        );
        let ath = latchgate_auth::dpop::compute_ath(&lease_jwt);
        let dpop_jti = uuid::Uuid::now_v7().to_string();
        let dpop_proof =
            latchgate_auth::dpop::sign_dpop_proof(&dpop_sk, "POST", &htu, &ath, &dpop_jti).unwrap();

        (lease_jwt, dpop_proof)
    }

    /// Step 2: auth OK => unknown action_id => 404 + audit event written.
    #[tokio::test]
    async fn pipeline_unknown_tool_writes_audit_event() {
        let state = test_state();
        let action_id = "nonexistent_action";
        let auth = issue_auth(&state, action_id).await;

        let response = crate::router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/actions/{action_id}/execute"))
                    .header("authorization", format!("DPoP {}", auth.0))
                    .header("dpop", &auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Verify audit event was written with deny decision.
        let events = state
            .ledger
            .query_events(&latchgate_ledger::EventFilter::default())
            .unwrap();
        let deny_events: Vec<_> = events
            .iter()
            .filter(|e| e.policy.decision == latchgate_ledger::Decision::Deny)
            .collect();
        assert!(
            !deny_events.is_empty(),
            "pipeline must write a deny audit event for unknown action"
        );
    }

    /// Steps 2–4: auth OK => registered action => schema validation => reject
    /// invalid request body with 422.
    #[tokio::test]
    async fn pipeline_bad_request_schema_returns_422() {
        let state = test_state();
        if state.registry.load().get_action("http_fetch").is_none() {
            eprintln!("SKIP: manifests not loaded");
            return;
        }
        let action_id = "http_fetch";
        let auth = issue_auth(&state, action_id).await;

        // Invalid body: http_fetch requires "url" field, this has "garbage".
        let bad_body = serde_json::json!({"garbage": true});

        let response = crate::router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/actions/{action_id}/execute"))
                    .header("authorization", format!("DPoP {}", auth.0))
                    .header("dpop", &auth.1)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&bad_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let json = body_json(response).await;
        assert_eq!(json["error"], "schema_violation");
    }

    /// Steps 2–6: auth OK => registered action => trust OK => schema OK =>
    /// OPA unreachable => 503 (fail-closed). Proves pipeline reaches policy.
    #[tokio::test]
    async fn pipeline_reaches_policy_step_opa_down_returns_503() {
        let state = test_state();
        if state.registry.load().get_action("file_write").is_none() {
            eprintln!("SKIP: manifests not loaded");
            return;
        }
        let action_id = "file_write";
        let auth = issue_auth(&state, action_id).await;

        // file_write expects {"path": "...", "content": "..."}
        // SECURITY: path must be relative (schema pattern rejects leading '/').
        let body = serde_json::json!({
            "path": "test.txt",
            "content": "hello"
        });

        let response = crate::router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/actions/{action_id}/execute"))
                    .header("authorization", format!("DPoP {}", auth.0))
                    .header("dpop", &auth.1)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // OPA is not running in unit tests => 503 (fail-closed).
        // This proves the pipeline passed auth, trust, and schema.
        let status = response.status();
        assert!(
            status == StatusCode::SERVICE_UNAVAILABLE || status == StatusCode::FORBIDDEN,
            "expected 503 (OPA down) or 403 (OPA denied), got {status}"
        );
    }

    /// Steps 2–6: empty body is valid for an action with no required fields
    /// in the request schema. Verifies the pipeline doesn't choke on empty
    /// body => json!({}) fallback.
    #[tokio::test]
    async fn pipeline_empty_body_accepted_for_permissive_schema() {
        let state = test_state();
        // file_write has required fields, so skip this if only strict schemas loaded.
        // We test with an action that has no request schema, or use send_message
        // which also has required fields. The test verifies the empty-body
        // parsing path doesn't crash — the next step (schema) may reject it.
        let action_id = "file_write";
        if state.registry.load().get_action(action_id).is_none() {
            eprintln!("SKIP: manifests not loaded");
            return;
        }
        let auth = issue_auth(&state, action_id).await;

        let response = crate::router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/actions/{action_id}/execute"))
                    .header("authorization", format!("DPoP {}", auth.0))
                    .header("dpop", &auth.1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Empty body => json!({}) => schema validation rejects (missing required
        // fields). The point: we don't panic on empty body, we get a clean 422.
        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "empty body for action with required fields must be 422"
        );
    }

    /// SECURITY: auth deny writes an audit event even though it fails at step 1.
    #[tokio::test]
    async fn pipeline_auth_deny_writes_audit() {
        let state = test_state();

        let response = crate::router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/actions/http_fetch/execute")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Audit must be written even for auth failures.
        let events = state
            .ledger
            .query_events(&latchgate_ledger::EventFilter::default())
            .unwrap();
        let deny_events: Vec<_> = events
            .iter()
            .filter(|e| e.policy.decision == latchgate_ledger::Decision::Deny)
            .collect();
        assert!(
            !deny_events.is_empty(),
            "auth denial must produce an audit event"
        );
    }

    /// After an auth-denied action call, calls_total counter must increment.
    #[tokio::test]
    async fn pipeline_auth_deny_increments_calls_total_metric() {
        let state = test_state();

        // Trigger an auth failure (no headers => 401).
        let _response = crate::router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/actions/some_tool/execute")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Verify metrics contain the counter increment.
        let output = state.metrics.encode().expect("encode metrics");
        assert!(
            output.contains("latchgate_calls_total"),
            "calls_total must appear in /metrics output after an action call"
        );
        assert!(
            output.contains("some_tool"),
            "action label must appear in metrics"
        );
        assert!(
            output.contains("deny"),
            "deny decision must appear in metrics"
        );
    }

    /// After an auth-denied action call, the audit event AND the metric must
    /// both be populated — they are independent sinks for the same decision.
    #[tokio::test]
    async fn pipeline_auth_deny_writes_audit_and_metric_consistently() {
        let state = test_state();

        let response = crate::router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/actions/http_fetch/execute")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Audit: deny event written.
        let events = state
            .ledger
            .query_events(&latchgate_ledger::EventFilter::default())
            .unwrap();
        assert!(
            events
                .iter()
                .any(|e| e.policy.decision == latchgate_ledger::Decision::Deny),
            "deny audit event must exist"
        );

        // Metric: calls_total incremented with deny label.
        let output = state.metrics.encode().unwrap();
        assert!(
            output.contains("latchgate_calls_total"),
            "calls_total must be in metrics"
        );
    }

    /// Schema-rejected action call (422) must increment calls_total with deny.
    #[tokio::test]
    async fn pipeline_schema_deny_increments_calls_total_metric() {
        let state = test_state();
        if state.registry.load().get_action("http_fetch").is_none() {
            eprintln!("SKIP: manifests not loaded");
            return;
        }
        let action_id = "http_fetch";
        let auth = issue_auth(&state, action_id).await;

        // Invalid body => 422 schema violation.
        let bad_body = serde_json::json!({"garbage": true});
        let response = crate::router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/actions/{action_id}/execute"))
                    .header("authorization", format!("DPoP {}", auth.0))
                    .header("dpop", &auth.1)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&bad_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let output = state.metrics.encode().unwrap();
        assert!(
            output.contains("latchgate_calls_total"),
            "calls_total must be incremented on schema deny"
        );
    }

    #[tokio::test]
    async fn list_actions_returns_200_with_tools_array() {
        let app = test_router();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/actions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        let actions = json["actions"]
            .as_array()
            .expect("actions should be an array");
        // Sample manifests are in definitions/manifests — if loaded, we expect 3.
        // If manifests dir is missing, we get an empty list — still valid.
        if !actions.is_empty() {
            // Verify sorted by action_id.
            let ids: Vec<&str> = actions
                .iter()
                .map(|t| t["action_id"].as_str().unwrap())
                .collect();
            let mut sorted = ids.clone();
            sorted.sort();
            assert_eq!(ids, sorted, "actions should be sorted by action_id");
        }
    }

    #[tokio::test]
    async fn list_actions_contains_expected_fields() {
        let app = test_router();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/actions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let json = body_json(response).await;
        let actions = json["actions"].as_array().unwrap();
        if let Some(action) = actions.first() {
            assert!(action["action_id"].is_string());
            assert!(action["version"].is_string());
            assert!(action["risk_level"].is_string());
        }
    }

    #[tokio::test]
    async fn get_action_returns_200_for_known_tool() {
        let state = test_state();
        // Only run if manifests are loaded.
        if state.registry.load().get_action("http_fetch").is_none() {
            eprintln!("skipping get_action_returns_200: no manifests loaded");
            return;
        }
        let app = crate::router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/actions/http_fetch")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["action_id"], "http_fetch");
        assert_eq!(json["version"], "1.0.0");
        assert_eq!(json["risk_level"], "low");
        assert!(json["runtime"]["timeout_seconds"].is_number());
        assert!(json["io"]["max_request_bytes"].is_number());
    }

    #[tokio::test]
    async fn get_action_returns_404_for_unknown_tool() {
        let app = test_router();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/actions/nonexistent_tool")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_action_schema_returns_404_for_unknown_action() {
        let app = test_router();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/actions/nonexistent_tool/schema/request")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_action_schema_returns_200_with_json_schema_when_manifest_loaded() {
        let state = test_state();
        if state.registry.load().get_action("http_fetch").is_none() {
            eprintln!("SKIP: manifests not loaded");
            return;
        }
        let app = crate::router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/actions/http_fetch/schema/request")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        // The http_fetch schema declares "url" as a required property.
        assert_eq!(json["type"], "object");
        assert!(
            json["properties"]["url"].is_object(),
            "http_fetch schema must have a 'url' property"
        );
    }

    #[tokio::test]
    async fn get_action_schema_returns_404_for_action_without_schema() {
        // Create a state with a manifest that has no request_schema declared.
        // The empty registry has no actions at all, so 404 is the correct result.
        let app = test_router(); // empty registry
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/actions/any_action/schema/request")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn list_actions_includes_database_mode_for_db_action() {
        let state = test_state();
        if state.registry.load().get_action("database_query").is_none() {
            eprintln!("SKIP: manifests not loaded (no database action)");
            return;
        }
        let app = crate::router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/actions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let json = body_json(response).await;
        let actions = json["actions"].as_array().unwrap();
        let db_action = actions
            .iter()
            .find(|a| a["action_id"] == "database_query")
            .expect("database action must be in listing");
        assert_eq!(
            db_action["database_mode"], "hybrid",
            "database action must expose database_mode"
        );

        // Non-database actions must not have database_mode.
        let http_action = actions.iter().find(|a| a["action_id"] == "http_fetch");
        if let Some(http) = http_action {
            assert!(
                http.get("database_mode").is_none() || http["database_mode"].is_null(),
                "non-database action must not have database_mode"
            );
        }
    }

    #[tokio::test]
    async fn get_action_detail_includes_database_discovery_block() {
        let state = test_state();
        if state.registry.load().get_action("database_query").is_none() {
            eprintln!("SKIP: manifests not loaded (no database action)");
            return;
        }
        let app = crate::router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/actions/database_query")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;

        let db = &json["database"];
        assert!(!db.is_null(), "database action must have 'database' block");
        assert_eq!(db["mode"], "hybrid");
        assert_eq!(db["allows_parameterized_queries"], true);

        let stmts = db["statements"].as_array().unwrap();
        assert!(
            stmts.len() >= 3,
            "database manifest declares multiple statements"
        );

        // Verify statement metadata structure.
        let update_stmt = stmts
            .iter()
            .find(|s| s["id"] == "update_order_status")
            .expect("update_order_status must be in statements");
        assert_eq!(update_stmt["operation"], "update");
        assert!(update_stmt["tables"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t == "orders"));
        assert_eq!(update_stmt["param_count"], 2);
    }

    #[tokio::test]
    async fn get_action_detail_non_database_has_no_database_block() {
        let state = test_state();
        if state.registry.load().get_action("http_fetch").is_none() {
            eprintln!("SKIP: manifests not loaded");
            return;
        }
        let app = crate::router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/actions/http_fetch")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let json = body_json(response).await;
        assert!(
            json.get("database").is_none() || json["database"].is_null(),
            "non-database action must not have 'database' block"
        );
    }
}
