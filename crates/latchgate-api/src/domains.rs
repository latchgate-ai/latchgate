//! Domain management endpoints for the admin router.
//!
//! Thin resource module: implements [`AdminCrudOps`] for domains and exposes
//! public handler functions that delegate to the generic CRUD skeleton in
//! [`admin_crud`]. Domain-specific logic (hostname validation, ledger calls)
//! lives in the trait impl; auth, rate limiting, and audit are shared.

use axum::http::StatusCode;
use serde_json::json;

use latchgate_kernel::AppState;
use latchgate_ledger::EventType;

use crate::admin_crud::{self, AdminCrudOps};
use crate::json_response::JsonResponse as ApiError;

/// Learned-domain resource for the admin CRUD framework.
pub(crate) struct DomainResource;

impl AdminCrudOps for DomainResource {
    fn validate(value: &str) -> Result<(), ApiError> {
        validate_domain_input(value)
    }

    async fn list(
        state: &AppState,
        action_id: Option<&str>,
    ) -> Result<Vec<serde_json::Value>, String> {
        let domains = latchgate_kernel::ops::domains::list(state, action_id).await?;
        Ok(domains
            .into_iter()
            .map(|d| {
                json!({
                    "action_id": d.action_id,
                    "domain": d.domain,
                    "added_by": d.added_by,
                    "added_at": d.added_at,
                    "source": d.source,
                    "approval_id": d.approval_id,
                })
            })
            .collect())
    }

    async fn add(
        state: &AppState,
        action_id: &str,
        value: &str,
        operator_id: &str,
    ) -> Result<bool, String> {
        latchgate_kernel::ops::domains::add(
            state,
            action_id,
            value,
            operator_id,
            latchgate_kernel::ops::domains::DomainAddSource::Api,
            None,
        )
        .await
    }

    async fn remove(state: &AppState, action_id: &str, value: &str) -> Result<bool, String> {
        latchgate_kernel::ops::domains::remove(state, action_id, value).await
    }

    async fn clear(state: &AppState, action_id: &str) -> Result<usize, String> {
        latchgate_kernel::ops::domains::clear_for_action(state, action_id).await
    }

    fn resource_name() -> &'static str {
        "domain"
    }
    fn value_key() -> &'static str {
        "domain"
    }
    fn list_key() -> &'static str {
        "domains"
    }
    fn add_event() -> EventType {
        EventType::DomainAdd
    }
    fn remove_event() -> EventType {
        EventType::DomainRemove
    }
    fn clear_event() -> EventType {
        EventType::DomainClear
    }
    fn base_path() -> &'static str {
        "/v1/admin/domains"
    }
}

/// Validate a domain via the canonical learned-domain validator.
///
/// Delegates to [`latchgate_core::net::validate_domain_entry`] with
/// `allow_unsafe_wildcard = false` (the API never accepts broad wildcards;
/// only the CLI with `--force` can opt in). The normalized form is
/// discarded — normalization is authoritative at the ledger write path.
fn validate_domain_input(domain: &str) -> Result<(), ApiError> {
    latchgate_core::net::validate_domain_entry(domain, false)
        .map(|_normalized| ())
        .map_err(|e| {
            ApiError::new(StatusCode::BAD_REQUEST, "invalid_domain").field("detail", &e.to_string())
        })
}

pub async fn list_domains(
    state: axum::extract::State<AppState>,
    headers: axum::http::HeaderMap,
    query: axum::extract::Query<admin_crud::ListQuery>,
) -> Result<axum::Json<serde_json::Value>, ApiError> {
    admin_crud::handle_list::<DomainResource>(state, headers, query).await
}

pub async fn add_domain(
    state: axum::extract::State<AppState>,
    headers: axum::http::HeaderMap,
    body: axum::Json<admin_crud::MutateBody>,
) -> Result<axum::Json<serde_json::Value>, ApiError> {
    admin_crud::handle_add::<DomainResource>(state, headers, body).await
}

pub async fn remove_domain(
    state: axum::extract::State<AppState>,
    headers: axum::http::HeaderMap,
    body: axum::Json<admin_crud::MutateBody>,
) -> Result<axum::Json<serde_json::Value>, ApiError> {
    admin_crud::handle_remove::<DomainResource>(state, headers, body).await
}

pub async fn clear_domains(
    state: axum::extract::State<AppState>,
    headers: axum::http::HeaderMap,
    query: axum::extract::Query<admin_crud::ClearQuery>,
) -> Result<axum::Json<serde_json::Value>, ApiError> {
    admin_crud::handle_clear::<DomainResource>(state, headers, query).await
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use crate::test_support::{body_json, operator_headers, test_router};

    // -- Auth tests ----------------------------------------------------------

    #[tokio::test]
    async fn list_domains_requires_auth() {
        let app = test_router();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/domains")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn add_domain_requires_auth() {
        let app = test_router();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/domains")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action_id":"web_read","domain":"example.com"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn remove_domain_requires_auth() {
        let app = test_router();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/admin/domains")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action_id":"web_read","domain":"example.com"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn clear_domains_requires_auth() {
        let app = test_router();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/admin/domains/clear?action=web_read")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // -- Functional tests ----------------------------------------------------

    #[tokio::test]
    async fn add_list_remove_roundtrip() {
        let app = test_router();

        // Add a domain.
        let (authz, dpop) = operator_headers("POST", "/v1/admin/domains");
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/domains")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action_id":"web_read","domain":"example.com"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["inserted"], true);

        // List all — should contain it.
        let (authz, dpop) = operator_headers("GET", "/v1/admin/domains");
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/domains")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        let domains = json["domains"].as_array().unwrap();
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0]["domain"], "example.com");
        assert_eq!(domains[0]["action_id"], "web_read");
        assert_eq!(domains[0]["source"], "api");

        // List filtered by action.
        let (authz, dpop) = operator_headers("GET", "/v1/admin/domains");
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/domains?action=web_read")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_json(resp).await;
        assert_eq!(json["domains"].as_array().unwrap().len(), 1);

        // List filtered by different action — empty.
        let (authz, dpop) = operator_headers("GET", "/v1/admin/domains");
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/domains?action=slack_post")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_json(resp).await;
        assert!(json["domains"].as_array().unwrap().is_empty());

        // Remove the domain.
        let (authz, dpop) = operator_headers("DELETE", "/v1/admin/domains");
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/admin/domains")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action_id":"web_read","domain":"example.com"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["deleted"], true);

        // List again — empty.
        let (authz, dpop) = operator_headers("GET", "/v1/admin/domains");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/domains")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_json(resp).await;
        assert!(json["domains"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn add_domain_idempotent() {
        let app = test_router();

        let (authz, dpop) = operator_headers("POST", "/v1/admin/domains");
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/domains")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action_id":"web_read","domain":"example.com"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        let (authz, dpop) = operator_headers("POST", "/v1/admin/domains");
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/domains")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action_id":"web_read","domain":"example.com"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["inserted"], false);
    }

    #[tokio::test]
    async fn remove_nonexistent_returns_deleted_false() {
        let app = test_router();

        let (authz, dpop) = operator_headers("DELETE", "/v1/admin/domains");
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/admin/domains")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action_id":"web_read","domain":"nope.com"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["deleted"], false);
    }

    #[tokio::test]
    async fn clear_domains_removes_all_for_action() {
        let app = test_router();

        // Add two domains for web_read and one for slack_post.
        for domain in ["a.com", "b.com"] {
            let (authz, dpop) = operator_headers("POST", "/v1/admin/domains");
            let _ = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/admin/domains")
                        .header("authorization", &authz)
                        .header("dpop", &dpop)
                        .header("content-type", "application/json")
                        .body(Body::from(format!(
                            r#"{{"action_id":"web_read","domain":"{domain}"}}"#
                        )))
                        .unwrap(),
                )
                .await
                .unwrap();
        }
        let (authz, dpop) = operator_headers("POST", "/v1/admin/domains");
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/domains")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action_id":"slack_post","domain":"hooks.slack.com"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Clear web_read.
        let (authz, dpop) = operator_headers("DELETE", "/v1/admin/domains/clear");
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/admin/domains/clear?action=web_read")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["deleted_count"], 2);

        // slack_post domain must still exist.
        let (authz, dpop) = operator_headers("GET", "/v1/admin/domains");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/domains?action=slack_post")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_json(resp).await;
        assert_eq!(json["domains"].as_array().unwrap().len(), 1);
    }

    // -- Validation tests ----------------------------------------------------
    //
    // The API pre-validator delegates to latchgate_core::net::validate_domain_entry.
    // These tests verify the API-level error shape (400 + "invalid_domain") for
    // the cases the canonical validator rejects. Exhaustive coverage of the
    // validator itself lives in latchgate-core/src/net.rs tests.

    #[tokio::test]
    async fn rejects_domain_with_path() {
        let app = test_router();
        let (authz, dpop) = operator_headers("POST", "/v1/admin/domains");
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/domains")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action_id":"web_read","domain":"example.com/path"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = body_json(resp).await;
        assert_eq!(json["error"], "invalid_domain");
    }

    #[tokio::test]
    async fn rejects_empty_action_id() {
        let app = test_router();
        let (authz, dpop) = operator_headers("POST", "/v1/admin/domains");
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/domains")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"action_id":"","domain":"example.com"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = body_json(resp).await;
        assert_eq!(json["error"], "invalid_action_id");
    }

    #[tokio::test]
    async fn rejects_domain_with_scheme() {
        let app = test_router();
        let (authz, dpop) = operator_headers("POST", "/v1/admin/domains");
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/domains")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action_id":"web_read","domain":"https://example.com"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn rejects_localhost() {
        let app = test_router();
        let (authz, dpop) = operator_headers("POST", "/v1/admin/domains");
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/domains")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action_id":"web_read","domain":"localhost"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = body_json(resp).await;
        assert_eq!(json["error"], "invalid_domain");
        assert!(
            json["detail"].as_str().unwrap_or("").contains("localhost"),
            "detail should mention localhost, got: {}",
            json["detail"]
        );
    }

    #[tokio::test]
    async fn rejects_private_ip() {
        let app = test_router();
        let (authz, dpop) = operator_headers("POST", "/v1/admin/domains");
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/domains")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action_id":"web_read","domain":"192.168.1.1"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = body_json(resp).await;
        assert_eq!(json["error"], "invalid_domain");
        assert!(
            json["detail"].as_str().unwrap_or("").contains("private"),
            "detail should mention private/reserved, got: {}",
            json["detail"]
        );
    }

    #[tokio::test]
    async fn rejects_single_label_hostname() {
        let app = test_router();
        let (authz, dpop) = operator_headers("POST", "/v1/admin/domains");
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/domains")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action_id":"web_read","domain":"intranet"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = body_json(resp).await;
        assert_eq!(json["error"], "invalid_domain");
    }

    #[tokio::test]
    async fn rejects_empty_domain() {
        let app = test_router();
        let (authz, dpop) = operator_headers("POST", "/v1/admin/domains");
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/domains")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"action_id":"web_read","domain":""}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = body_json(resp).await;
        assert_eq!(json["error"], "invalid_domain");
    }

    #[tokio::test]
    async fn rejects_unsafe_wildcard_via_api() {
        let app = test_router();
        let (authz, dpop) = operator_headers("POST", "/v1/admin/domains");
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/domains")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action_id":"web_read","domain":"*.example.com"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = body_json(resp).await;
        assert_eq!(json["error"], "invalid_domain");
    }

    /// Safe wildcards (≥ 3 labels in suffix) pass pre-validation.
    #[tokio::test]
    async fn accepts_safe_wildcard() {
        let app = test_router();
        let (authz, dpop) = operator_headers("POST", "/v1/admin/domains");
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/domains")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action_id":"web_read","domain":"*.s3.amazonaws.com"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Uppercase input passes pre-validation (the canonical validator
    /// normalizes to lowercase). The ledger stores the normalized form.
    #[tokio::test]
    async fn accepts_uppercase_domain_via_normalization() {
        let app = test_router();
        let (authz, dpop) = operator_headers("POST", "/v1/admin/domains");
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/domains")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action_id":"web_read","domain":"API.GitHub.COM"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify stored form is lowercase.
        let (authz, dpop) = operator_headers("GET", "/v1/admin/domains");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/domains?action=web_read")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_json(resp).await;
        let domains = json["domains"].as_array().unwrap();
        assert_eq!(domains.len(), 1);
        assert_eq!(
            domains[0]["domain"], "api.github.com",
            "ledger must store the lowercase-normalized form"
        );
    }
}
