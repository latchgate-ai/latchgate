//! Learned path management endpoints for the admin router.
//!
//! Thin resource module: implements [`AdminCrudOps`] for filesystem path
//! globs and exposes public handler functions that delegate to the generic
//! CRUD skeleton in [`admin_crud`]. Path-specific logic (glob validation,
//! ledger calls) lives in the trait impl; auth, rate limiting, and audit
//! are shared.

use axum::http::StatusCode;
use serde_json::json;

use latchgate_kernel::AppState;
use latchgate_ledger::EventType;

use crate::admin_crud::{self, AdminCrudOps};
use crate::json_response::JsonResponse as ApiError;

/// Maximum length for path_glob inputs.
///
/// Path globs are relative project paths. Generous limit to accommodate
/// deep directory structures. Independent of `MAX_ACTION_ID_LEN` (shared
/// via `admin::validate_action_id`).
const MAX_PATH_GLOB_LEN: usize = 1024;

/// Learned-path resource for the admin CRUD framework.
pub(crate) struct PathResource;

impl AdminCrudOps for PathResource {
    fn validate(value: &str) -> Result<(), ApiError> {
        validate_path_glob_input(value)
    }

    async fn list(
        state: &AppState,
        action_id: Option<&str>,
    ) -> Result<Vec<serde_json::Value>, String> {
        let paths = latchgate_kernel::ops::paths::list(state, action_id).await?;
        Ok(paths
            .into_iter()
            .map(|p| {
                json!({
                    "action_id": p.action_id,
                    "path_glob": p.path_glob,
                    "added_by": p.added_by,
                    "added_at": p.added_at,
                    "source": p.source,
                    "approval_id": p.approval_id,
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
        latchgate_kernel::ops::paths::add(
            state,
            action_id,
            value,
            operator_id,
            latchgate_kernel::ops::paths::PathAddSource::Api,
            None,
        )
        .await
    }

    async fn remove(state: &AppState, action_id: &str, value: &str) -> Result<bool, String> {
        latchgate_kernel::ops::paths::remove(state, action_id, value).await
    }

    async fn clear(state: &AppState, action_id: &str) -> Result<usize, String> {
        latchgate_kernel::ops::paths::clear_for_action(state, action_id).await
    }

    fn resource_name() -> &'static str {
        "path_glob"
    }
    fn value_key() -> &'static str {
        "path_glob"
    }
    fn list_key() -> &'static str {
        "paths"
    }
    fn add_event() -> EventType {
        EventType::PathAdd
    }
    fn remove_event() -> EventType {
        EventType::PathRemove
    }
    fn clear_event() -> EventType {
        EventType::PathClear
    }
    fn base_path() -> &'static str {
        "/v1/admin/paths"
    }
}

/// Validate a path glob: delegates to [`latchgate_kernel::ops::paths::validate_path_glob`]
/// after length checks. Rejects traversal, absolute paths, null bytes,
/// control characters, and catch-all patterns.
fn validate_path_glob_input(path_glob: &str) -> Result<(), ApiError> {
    if path_glob.is_empty() || path_glob.len() > MAX_PATH_GLOB_LEN {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "invalid_path_glob")
            .field("detail", "path_glob must be 1-1024 characters"));
    }
    latchgate_kernel::ops::paths::validate_path_glob(path_glob).map_err(|detail| {
        ApiError::new(StatusCode::BAD_REQUEST, "invalid_path_glob").field("detail", &detail)
    })
}

pub async fn list_paths(
    state: axum::extract::State<AppState>,
    headers: axum::http::HeaderMap,
    query: axum::extract::Query<admin_crud::ListQuery>,
) -> Result<axum::Json<serde_json::Value>, ApiError> {
    admin_crud::handle_list::<PathResource>(state, headers, query).await
}

pub async fn add_path(
    state: axum::extract::State<AppState>,
    headers: axum::http::HeaderMap,
    body: axum::Json<admin_crud::MutateBody>,
) -> Result<axum::Json<serde_json::Value>, ApiError> {
    admin_crud::handle_add::<PathResource>(state, headers, body).await
}

pub async fn remove_path(
    state: axum::extract::State<AppState>,
    headers: axum::http::HeaderMap,
    body: axum::Json<admin_crud::MutateBody>,
) -> Result<axum::Json<serde_json::Value>, ApiError> {
    admin_crud::handle_remove::<PathResource>(state, headers, body).await
}

pub async fn clear_paths(
    state: axum::extract::State<AppState>,
    headers: axum::http::HeaderMap,
    query: axum::extract::Query<admin_crud::ClearQuery>,
) -> Result<axum::Json<serde_json::Value>, ApiError> {
    admin_crud::handle_clear::<PathResource>(state, headers, query).await
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use crate::test_support::{body_json, operator_headers, test_router};

    // -- Auth tests ----------------------------------------------------------

    #[tokio::test]
    async fn list_paths_requires_auth() {
        let app = test_router();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/paths")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn add_path_requires_auth() {
        let app = test_router();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/paths")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action_id":"fs_read","path_glob":"src/**"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn remove_path_requires_auth() {
        let app = test_router();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/admin/paths")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action_id":"fs_read","path_glob":"src/**"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn clear_paths_requires_auth() {
        let app = test_router();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/admin/paths/clear?action=fs_read")
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

        // Add a path.
        let (authz, dpop) = operator_headers("POST", "/v1/admin/paths");
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/paths")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action_id":"fs_read","path_glob":"src/**"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["inserted"], true);

        // List all — should contain it.
        let (authz, dpop) = operator_headers("GET", "/v1/admin/paths");
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/paths")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        let paths = json["paths"].as_array().unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0]["action_id"], "fs_read");
        assert_eq!(paths[0]["path_glob"], "src/**");
        assert_eq!(paths[0]["source"], "api");

        // Remove it.
        let (authz, dpop) = operator_headers("DELETE", "/v1/admin/paths");
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/admin/paths")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action_id":"fs_read","path_glob":"src/**"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["deleted"], true);

        // List again — empty.
        let (authz, dpop) = operator_headers("GET", "/v1/admin/paths");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/paths")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_json(resp).await;
        assert!(json["paths"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn list_paths_filtered_by_action() {
        let app = test_router();

        // Add paths for two different actions.
        for (action, glob) in [("fs_read", "src/**"), ("fs_write", "docs/**")] {
            let (authz, dpop) = operator_headers("POST", "/v1/admin/paths");
            let _ = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/admin/paths")
                        .header("authorization", &authz)
                        .header("dpop", &dpop)
                        .header("content-type", "application/json")
                        .body(Body::from(format!(
                            r#"{{"action_id":"{action}","path_glob":"{glob}"}}"#
                        )))
                        .unwrap(),
                )
                .await
                .unwrap();
        }

        // Filter to fs_read only.
        let (authz, dpop) = operator_headers("GET", "/v1/admin/paths");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/paths?action=fs_read")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_json(resp).await;
        let paths = json["paths"].as_array().unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0]["path_glob"], "src/**");
    }

    #[tokio::test]
    async fn add_path_idempotent() {
        let app = test_router();

        let (authz, dpop) = operator_headers("POST", "/v1/admin/paths");
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/paths")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action_id":"fs_read","path_glob":"src/**"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        let (authz, dpop) = operator_headers("POST", "/v1/admin/paths");
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/paths")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action_id":"fs_read","path_glob":"src/**"}"#,
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

        let (authz, dpop) = operator_headers("DELETE", "/v1/admin/paths");
        let resp = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/admin/paths")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action_id":"fs_read","path_glob":"nope/**"}"#,
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
    async fn clear_paths_removes_all_for_action() {
        let app = test_router();

        // Add two paths for fs_read and one for fs_write.
        for glob in ["src/**", "tests/**"] {
            let (authz, dpop) = operator_headers("POST", "/v1/admin/paths");
            let _ = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/admin/paths")
                        .header("authorization", &authz)
                        .header("dpop", &dpop)
                        .header("content-type", "application/json")
                        .body(Body::from(format!(
                            r#"{{"action_id":"fs_read","path_glob":"{glob}"}}"#
                        )))
                        .unwrap(),
                )
                .await
                .unwrap();
        }
        let (authz, dpop) = operator_headers("POST", "/v1/admin/paths");
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/paths")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action_id":"fs_write","path_glob":"docs/**"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Clear fs_read.
        let (authz, dpop) = operator_headers("DELETE", "/v1/admin/paths/clear");
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/admin/paths/clear?action=fs_read")
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

        // fs_write path must still exist.
        let (authz, dpop) = operator_headers("GET", "/v1/admin/paths");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/paths?action=fs_write")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_json(resp).await;
        assert_eq!(json["paths"].as_array().unwrap().len(), 1);
    }

    // -- Validation tests ----------------------------------------------------

    #[tokio::test]
    async fn rejects_absolute_path() {
        let app = test_router();
        let (authz, dpop) = operator_headers("POST", "/v1/admin/paths");
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/paths")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action_id":"fs_read","path_glob":"/etc/passwd"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = body_json(resp).await;
        assert_eq!(json["error"], "invalid_path_glob");
    }

    #[tokio::test]
    async fn rejects_traversal_path() {
        let app = test_router();
        let (authz, dpop) = operator_headers("POST", "/v1/admin/paths");
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/paths")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"action_id":"fs_read","path_glob":"src/../../etc"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = body_json(resp).await;
        assert_eq!(json["error"], "invalid_path_glob");
    }

    #[tokio::test]
    async fn rejects_catch_all_glob() {
        let app = test_router();
        let (authz, dpop) = operator_headers("POST", "/v1/admin/paths");
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/paths")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"action_id":"fs_read","path_glob":"**"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn rejects_empty_action_id() {
        let app = test_router();
        let (authz, dpop) = operator_headers("POST", "/v1/admin/paths");
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/paths")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"action_id":"","path_glob":"src/**"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = body_json(resp).await;
        assert_eq!(json["error"], "invalid_action_id");
    }

    #[tokio::test]
    async fn rejects_empty_path_glob() {
        let app = test_router();
        let (authz, dpop) = operator_headers("POST", "/v1/admin/paths");
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/paths")
                    .header("authorization", &authz)
                    .header("dpop", &dpop)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"action_id":"fs_read","path_glob":""}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = body_json(resp).await;
        assert_eq!(json["error"], "invalid_path_glob");
    }
}
