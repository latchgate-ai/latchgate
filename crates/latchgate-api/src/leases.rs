use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use tracing::{instrument, warn};

use latchgate_auth::issuer::{IssueError, IssueLeaseRequest};
use latchgate_kernel::AppState;

use crate::json_response::JsonResponse as ApiError;

/// POST /v1/leases — issue a Lease JWT bound to the client's DPoP key.
///
/// SECURITY: this endpoint is intentionally unauthenticated. It is the
/// authentication bootstrapping point — the client calls it *to obtain*
/// a Lease, so it cannot already have one. Access control on lease issuance
/// is achieved through:
/// - The DPoP key binding (`cnf.jkt`) which makes the lease useless without
///   the client's private key.
/// - Network isolation: in production, Gate is UDS-only (no TCP), so only
///   processes with filesystem access to the socket can reach this endpoint.
/// - Short TTL (default 5 min) limits the blast radius.
#[instrument(name = "api.issue_lease", skip_all)]
pub async fn issue_lease(
    State(state): State<AppState>,
    // SECURITY: ConnectionContext is populated by transport middleware (UDS
    // peer creds, TLS client cert, etc.). When no middleware is present
    // (e.g. TCP dev mode), the default empty context is used — identity
    // providers that require transport-level evidence (PeerCredProvider)
    // will correctly reject the request.
    conn_ctx: Option<axum::Extension<latchgate_auth::ConnectionContext>>,
    Json(body): Json<IssueLeaseRequest>,
) -> impl IntoResponse {
    if !state.lifecycle.lease_rate_limiter.check() {
        warn!("lease rate limit exceeded");
        return ApiError::new(StatusCode::TOO_MANY_REQUESTS, "rate_limit_exceeded").into_response();
    }

    if state.draining() {
        return ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "draining").into_response();
    }

    // SECURITY: verify caller identity before issuing a lease.
    // The identity provider determines the principal (who the caller is)
    // and the maximum scopes they may request. This prevents any process
    // with socket access from self-asserting arbitrary identity.
    let ctx = conn_ctx.map(|ext| ext.0).unwrap_or_default();
    let verified = match state.auth.identity_provider.authenticate(&ctx).await {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "lease identity verification failed");
            let (status, code) = match &e {
                latchgate_auth::IdentityError::Unauthenticated { .. } => {
                    (StatusCode::UNAUTHORIZED, "identity_unauthenticated")
                }
                latchgate_auth::IdentityError::Forbidden { .. } => {
                    (StatusCode::FORBIDDEN, "identity_forbidden")
                }
                latchgate_auth::IdentityError::ProviderUnavailable { .. } => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "identity_provider_unavailable",
                ),
            };
            return ApiError::new(status, code).into_response();
        }
    };

    let effective_scopes =
        match latchgate_auth::identity::intersect_scopes(&body.scopes, &verified.max_scopes) {
            Ok(scopes) => scopes,
            Err(e) => {
                warn!(
                    principal = %verified.principal,
                    identity_method = verified.identity_method,
                    error = %e,
                    "lease scope intersection failed"
                );
                return ApiError::new(StatusCode::FORBIDDEN, "scope_not_permitted").into_response();
            }
        };

    // Build the lease request with identity-verified principal and scopes.
    // SECURITY: fs_root is extracted before building the request — it is
    // validated below, not passed to the issuer (which treats it as opaque).
    let requested_fs_root = body.fs_root;
    let identity_aware_body = IssueLeaseRequest {
        scopes: effective_scopes,
        dpop_jwk: body.dpop_jwk,
        budgets: body.budgets.clone(),
        fs_root: None, // issuer does not inspect fs_root
    };

    // --- Per-session filesystem root validation ---
    //
    // SECURITY: validate BEFORE issuing the lease. If validation fails,
    // no lease is issued — the session never exists. This prevents a
    // partially-configured session from entering the system.
    let session_fs_root: Option<std::path::PathBuf> = match requested_fs_root.as_deref() {
        Some(requested) => {
            match latchgate_config::validate_session_fs_root(
                requested,
                &state.config.fs_root_allowed_prefixes,
            ) {
                Ok(canonical) => {
                    tracing::info!(
                        requested = %requested,
                        canonical = %canonical.display(),
                        "per-session fs_root validated"
                    );
                    Some(canonical)
                }
                Err(latchgate_config::FsRootError::Invalid { reason }) => {
                    warn!(requested = %requested, reason = %reason, "fs_root invalid");
                    return ApiError::new(StatusCode::BAD_REQUEST, "invalid_fs_root")
                        .field("message", &reason)
                        .into_response();
                }
                Err(latchgate_config::FsRootError::Denied { reason }) => {
                    warn!(requested = %requested, reason = %reason, "fs_root denied");
                    return ApiError::new(StatusCode::FORBIDDEN, "fs_root_denied")
                        .field("message", &reason)
                        .into_response();
                }
            }
        }
        None => None,
    };

    let budgets = identity_aware_body.budgets.clone();

    match state.auth.issuer.issue_lease(
        &identity_aware_body,
        Some(&verified.principal),
        verified.owner.as_deref(),
    ) {
        Ok(mut resp) => {
            // session_id is server-issued; use it for budget keying and audit.
            let session_id = resp.session_id.clone();

            // If the lease carries budget constraints, initialise stateful
            // counters in Redis so the pipeline can enforce them atomically.
            if let Some(ref b) = budgets {
                let calls = b.max_calls.unwrap_or(u64::MAX);
                // TTL = lease TTL + 60s grace for in-flight requests at expiry.
                let ttl =
                    std::time::Duration::from_secs(state.config.policy.lease_ttl_seconds + 60);
                let redis_start = std::time::Instant::now();
                let init_result = state
                    .enforcement
                    .budget_manager
                    .init_budgets(&session_id, calls, ttl)
                    .await;
                state
                    .metrics
                    .record_redis_duration("budget_init", redis_start.elapsed());
                if let Err(e) = init_result {
                    warn!(
                        session_id = %session_id,
                        error = %e,
                        "failed to initialise budgets in Redis"
                    );
                    return ApiError::new(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "budget_store_unavailable",
                    )
                    .into_response();
                }
            }

            // Store validated fs_root in the per-session map.
            if let Some(ref canonical) = session_fs_root {
                state.runtime.session_fs_roots.insert(
                    session_id.clone(),
                    latchgate_kernel::SessionFsRoot {
                        canonical: canonical.clone(),
                        created_at: std::time::Instant::now(),
                    },
                );
            }

            // Set fs_root in response so the client knows which canonical
            // path was accepted.
            resp.fs_root = session_fs_root.map(|p| p.to_string_lossy().into_owned());

            // SECURITY: audit every lease issuance for forensic reconstruction.
            // SECURITY: record the identity-verified principal and the
            // method used to verify it (e.g. "peercred", "oidc", "none").
            // Without this, post-incident analysis cannot determine how a
            // principal was authenticated — a critical gap for triage.
            latchgate_kernel::ops::audit::write_lease_audit(
                &state,
                verified.principal.clone(),
                session_id.clone(),
                resp.lease_jti.clone(),
                verified.identity_method.to_string(),
                verified.owner.clone(),
            )
            .await;

            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(e) => issue_error_response(e).into_response(),
    }
}

/// Map `IssueError` to HTTP response.
///
/// SECURITY: error bodies contain only a machine-readable `error` code.
/// For client-fixable errors (400), a safe `message` is included so the
/// client knows what to fix. For internal errors (500/503), no details
/// are exposed — they are logged server-side only.
fn issue_error_response(err: IssueError) -> impl IntoResponse {
    let (status, code, message) = match &err {
        IssueError::InvalidRequest { reason } => {
            // SECURITY: only expose the reason for client-fixable errors.
            (
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some(reason.clone()),
            )
        }
        IssueError::Signing(detail) => {
            // SECURITY: log the detail server-side but never expose it —
            // signing internals could reveal key configuration.
            warn!(error = %detail, "lease signing failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal_error", None)
        }
        IssueError::KeyGeneration(detail) => {
            warn!(error = %detail, "key generation failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal_error", None)
        }
        IssueError::ClockError => {
            warn!("clock error during lease issuance");
            (StatusCode::SERVICE_UNAVAILABLE, "clock_error", None)
        }
    };

    match message {
        Some(msg) => ApiError::new(status, code).field("message", &msg),
        // SECURITY: no message field for internal errors — prevents info leak.
        None => ApiError::new(status, code),
    }
}

/// GET /.well-known/jwks.json — public keys for Lease JWT verification.
///
/// Returns the issuer's public key(s) in JWKS format. Consumers (e.g.
/// external verifiers, SDKs) use this to verify Lease JWT signatures.
///
/// This endpoint does not require authentication — public keys are public.
pub async fn jwks(State(state): State<AppState>) -> impl IntoResponse {
    // Clone is required: axum Json takes T by value. JwksResponse is small
    // (one key entry with ~6 short strings) — clone cost is negligible.
    (
        StatusCode::OK,
        Json(state.auth.issuer.jwks_response().clone()),
    )
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use crate::test_support::{body_json, dpop_jwk_json, post_lease, test_router, test_state};

    #[tokio::test]
    async fn valid_request_returns_200_with_jwt() {
        let app = test_router();
        let body = serde_json::json!({
            "scopes": ["tools:call"],
            "dpop_jwk": dpop_jwk_json(),
        });

        let response = post_lease(app, &body).await;
        assert_eq!(response.status(), StatusCode::OK);

        let json = body_json(response).await;
        assert!(json["lease_jwt"].is_string(), "must contain lease_jwt");
        assert!(json["expires_at"].is_string(), "must contain expires_at");
        assert!(
            json["session_id"].is_string(),
            "must contain server-issued session_id"
        );

        let jwt = json["lease_jwt"].as_str().unwrap();
        assert_eq!(jwt.split('.').count(), 3, "lease must be a 3-part JWT");
    }

    #[tokio::test]
    async fn issued_lease_verifiable_via_issuer_jwks() {
        let state = test_state();
        let app = crate::router(state.clone());
        let body = serde_json::json!({
            "scopes": ["tools:call"],
            "dpop_jwk": dpop_jwk_json(),
        });

        let resp = post_lease(app, &body).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let json = body_json(resp).await;
        let lease_jwt = json["lease_jwt"].as_str().unwrap();
        let returned_session_id = json["session_id"].as_str().unwrap();

        let claims = latchgate_auth::verify_lease(
            lease_jwt,
            state.auth.issuer.jwks(),
            latchgate_auth::issuer::ISSUER_NAME,
            latchgate_auth::issuer::AUDIENCE,
        )
        .expect("issued lease must verify against issuer's JWKS");

        // session_id is server-generated; verify it matches the response field.
        assert!(!claims.session_id.is_empty());
        assert_eq!(claims.session_id, returned_session_id);
        assert_eq!(claims.scope, vec!["tools:call"]);
    }

    #[tokio::test]
    async fn cnf_jkt_matches_provided_dpop_jwk_thumbprint() {
        let state = test_state();
        let app = crate::router(state.clone());
        let (_, pk) = latchgate_auth::dpop::generate_dpop_keypair().unwrap();
        let jwk = serde_json::json!({
            "kty": "EC", "crv": "P-256", "x": pk.x, "y": pk.y,
        });
        let expected_jkt = latchgate_auth::dpop::compute_jwk_thumbprint(&pk.x, &pk.y).unwrap();

        let body = serde_json::json!({
            "scopes": ["tools:call"],
            "dpop_jwk": jwk,
        });
        let resp = post_lease(app, &body).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let json = body_json(resp).await;
        let lease_jwt = json["lease_jwt"].as_str().unwrap();

        let claims = latchgate_auth::verify_lease(
            lease_jwt,
            state.auth.issuer.jwks(),
            latchgate_auth::issuer::ISSUER_NAME,
            latchgate_auth::issuer::AUDIENCE,
        )
        .unwrap();

        assert_eq!(
            claims.cnf.jkt, expected_jkt,
            "cnf.jkt must match the thumbprint of the provided DPoP JWK"
        );
    }

    #[tokio::test]
    async fn invalid_key_type_returns_400() {
        let app = test_router();
        let body = serde_json::json!({
            "scopes": ["tools:call"],
            "dpop_jwk": { "kty": "RSA", "crv": "P-256", "x": "aaa", "y": "bbb" },
        });

        let response = post_lease(app, &body).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let json = body_json(response).await;
        assert_eq!(json["error"], "invalid_request");
        assert!(
            json["message"].as_str().unwrap().contains("EC"),
            "400 message should tell client what's wrong"
        );
    }

    #[tokio::test]
    async fn empty_scopes_returns_400() {
        let app = test_router();
        let body = serde_json::json!({
            "scopes": [],
            "dpop_jwk": dpop_jwk_json(),
        });

        let response = post_lease(app, &body).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn invalid_scope_format_returns_400() {
        // Scopes must pass namespace:name format validation: [a-z0-9:_-],
        // 4-64 chars, no uppercase, no special chars outside the allowed set.
        // Valid custom scopes (e.g. "admin:everything") are now accepted --
        // the issuer uses format-based validation rather than a static allowlist.
        let app = test_router();
        let body = serde_json::json!({
            // Uppercase letter -- invalid format
            "scopes": ["Admin:Everything"],
            "dpop_jwk": dpop_jwk_json(),
        });

        let response = post_lease(app, &body).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let json = body_json(response).await;
        assert_eq!(json["error"], "invalid_request");
        assert!(
            json["message"]
                .as_str()
                .unwrap()
                .contains("Admin:Everything"),
            "400 message must name the offending scope"
        );
    }

    #[tokio::test]
    async fn scope_without_separator_returns_400() {
        let app = test_router();
        let body = serde_json::json!({
            "scopes": ["toolscall"],
            "dpop_jwk": dpop_jwk_json(),
        });
        let response = post_lease(app, &body).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = body_json(response).await;
        assert_eq!(json["error"], "invalid_request");
    }

    #[tokio::test]
    async fn scope_with_special_chars_returns_400() {
        let app = test_router();
        let body = serde_json::json!({
            "scopes": ["tools:call!"],
            "dpop_jwk": dpop_jwk_json(),
        });
        let response = post_lease(app, &body).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = body_json(response).await;
        assert_eq!(json["error"], "invalid_request");
    }

    #[tokio::test]
    async fn valid_custom_scope_returns_200() {
        // Custom scopes in namespace:name format with [a-z0-9:_-] are valid.
        let app = test_router();
        let body = serde_json::json!({
            "scopes": ["tools:call", "email:send"],
            "dpop_jwk": dpop_jwk_json(),
        });
        let response = post_lease(app, &body).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn session_id_in_request_body_is_rejected() {
        // Clients must not be able to supply session_id. The request schema
        // uses deny_unknown_fields, so any client sending the old field gets
        // a hard 422 rather than a silent no-op.
        let app = test_router();
        let body = serde_json::json!({
            "scopes": ["tools:call"],
            "dpop_jwk": dpop_jwk_json(),
            "session_id": "attacker-controlled-principal",
        });

        let response = post_lease(app, &body).await;
        assert!(
            response.status().is_client_error(),
            "request with unknown field session_id must be rejected (got {})",
            response.status()
        );
    }

    #[tokio::test]
    async fn malformed_json_returns_client_error() {
        let app = test_router();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/leases")
                    .header("content-type", "application/json")
                    .body(Body::from(b"not json".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Axum returns 422 for deserialization failures by default.
        assert!(
            response.status().is_client_error(),
            "malformed JSON must be rejected"
        );
    }

    #[tokio::test]
    async fn missing_required_fields_returns_client_error() {
        let app = test_router();
        let body = serde_json::json!({
            "scopes": ["tools:call"],
            // Missing dpop_jwk and session_id.
        });

        let response = post_lease(app, &body).await;
        assert!(
            response.status().is_client_error(),
            "missing required fields must be rejected"
        );
    }

    #[tokio::test]
    async fn wrong_http_method_returns_405() {
        let app = test_router();
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/leases")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "GET on POST-only endpoint must return 405"
        );
    }

    /// SECURITY regression: 400 error body must contain `error` and `message`
    /// (actionable for the client), but no internal details.
    #[tokio::test]
    async fn error_400_body_has_error_and_message_only() {
        let app = test_router();
        let body = serde_json::json!({
            "scopes": ["tools:call"],
            "dpop_jwk": { "kty": "RSA", "crv": "P-256", "x": "a", "y": "b" },
        });

        let response = post_lease(app, &body).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let json = body_json(response).await;
        let obj = json.as_object().unwrap();
        assert!(obj.contains_key("error"), "must have 'error'");
        assert!(obj.contains_key("message"), "400 must have 'message'");
        assert_eq!(obj.len(), 2, "400 body must have exactly error + message");
    }

    #[tokio::test]
    async fn jwks_endpoint_returns_200_with_ec_key() {
        let app = test_router();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/jwks.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let json = body_json(response).await;
        assert!(json["keys"].is_array());

        let keys = json["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kty"], "EC");
        assert_eq!(keys[0]["crv"], "P-256");
        assert_eq!(keys[0]["alg"], "ES256");
        assert_eq!(keys[0]["use"], "sig");
        assert!(keys[0]["kid"].is_string());
        assert!(keys[0]["x"].is_string());
        assert!(keys[0]["y"].is_string());
    }

    #[tokio::test]
    async fn jwks_stable_across_requests() {
        let state = test_state();

        let app1 = crate::router(state.clone());
        let resp1 = app1
            .oneshot(
                Request::builder()
                    .uri("/.well-known/jwks.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body1 = axum::body::to_bytes(resp1.into_body(), 4096).await.unwrap();

        let app2 = crate::router(state);
        let resp2 = app2
            .oneshot(
                Request::builder()
                    .uri("/.well-known/jwks.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body2 = axum::body::to_bytes(resp2.into_body(), 4096).await.unwrap();

        assert_eq!(body1, body2, "JWKS must be stable across requests");
    }

    #[tokio::test]
    async fn lease_audit_records_verified_principal_not_session_id() {
        let state = test_state();
        let app = crate::router(state.clone());
        let body = serde_json::json!({
            "scopes": ["tools:call"],
            "dpop_jwk": dpop_jwk_json(),
        });
        let response = post_lease(app, &body).await;
        assert_eq!(response.status(), StatusCode::OK);

        // Give the spawn_blocking audit write a moment to complete.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let events = state
            .ledger
            .query_events(&latchgate_ledger::EventFilter::default())
            .unwrap();
        let lease_event = events
            .iter()
            .find(|e| e.event_type == latchgate_ledger::EventType::LeaseIssued)
            .expect("LeaseIssued event must exist");

        // NoneProvider returns "dev:anonymous" as principal.
        assert_eq!(
            &*lease_event.subject.principal, "dev:anonymous",
            "audit principal must be the verified identity, not session_id"
        );
        assert_ne!(
            lease_event.subject.principal, lease_event.subject.session_id,
            "principal must differ from session_id (session_id is a UUID)"
        );
    }

    #[tokio::test]
    async fn lease_audit_records_identity_method() {
        let state = test_state();
        let app = crate::router(state.clone());
        let body = serde_json::json!({
            "scopes": ["tools:call"],
            "dpop_jwk": dpop_jwk_json(),
        });
        let response = post_lease(app, &body).await;
        assert_eq!(response.status(), StatusCode::OK);

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let events = state
            .ledger
            .query_events(&latchgate_ledger::EventFilter::default())
            .unwrap();
        let lease_event = events
            .iter()
            .find(|e| e.event_type == latchgate_ledger::EventType::LeaseIssued)
            .expect("LeaseIssued event must exist");

        assert_eq!(
            lease_event.subject.identity_method.as_deref(),
            Some("none"),
            "identity_method must be recorded (NoneProvider = 'none')"
        );
    }

    #[tokio::test]
    async fn lease_audit_records_lease_jti() {
        let state = test_state();
        let app = crate::router(state.clone());
        let body = serde_json::json!({
            "scopes": ["tools:call"],
            "dpop_jwk": dpop_jwk_json(),
        });
        let response = post_lease(app, &body).await;
        assert_eq!(response.status(), StatusCode::OK);

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let events = state
            .ledger
            .query_events(&latchgate_ledger::EventFilter::default())
            .unwrap();
        let lease_event = events
            .iter()
            .find(|e| e.event_type == latchgate_ledger::EventType::LeaseIssued)
            .expect("LeaseIssued event must exist");

        assert!(
            !lease_event.subject.lease_jti.is_empty(),
            "lease_jti must not be empty — it's the forensic link to the issued JWT"
        );
    }

    #[tokio::test]
    async fn lease_response_includes_lease_jti() {
        let app = test_router();
        let body = serde_json::json!({
            "scopes": ["tools:call"],
            "dpop_jwk": dpop_jwk_json(),
        });
        let response = post_lease(app, &body).await;
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert!(
            json["lease_jti"].is_string(),
            "lease response must include lease_jti"
        );
        assert!(
            !json["lease_jti"].as_str().unwrap().is_empty(),
            "lease_jti must not be empty"
        );
    }
}
