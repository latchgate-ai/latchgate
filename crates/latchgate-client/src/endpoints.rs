//! GateClient endpoint methods.
//!
//! Each method maps to one Gate HTTP endpoint. Authentication headers are
//! built per-request via the core helpers in `lib.rs`.

use serde_json::Value;

use super::auth::OperatorAuth;
use super::{query_path, AuditParams, ClientError, GateClient};

impl GateClient {
    /// `GET /healthz` => `true` if gate is up and responsive.
    pub async fn healthz(&self) -> Result<bool, ClientError> {
        match self.get("/healthz").await {
            Ok(_) => Ok(true),
            Err(ClientError::NotReachable(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// `GET /v1/actions` => list of action summaries.
    pub async fn list_actions(&self) -> Result<Vec<Value>, ClientError> {
        let body = self.get("/v1/actions").await?;
        Self::parse_json_array(&body, "actions")
    }

    /// `GET /v1/actions/{action_id}` => full action manifest detail.
    pub async fn get_action(&self, action_id: &str) -> Result<Value, ClientError> {
        self.get_json(&format!("/v1/actions/{action_id}")).await
    }

    /// `GET /v1/audit/events?...` => filtered audit events.
    ///
    /// Requires operator authentication — the ledger is an admin-only resource.
    pub async fn audit_events(
        &self,
        auth: &OperatorAuth,
        params: &AuditParams,
    ) -> Result<Vec<Value>, ClientError> {
        let qs = params.to_query();
        let path = if qs.is_empty() {
            "/v1/audit/events".to_string()
        } else {
            format!("/v1/audit/events?{qs}")
        };
        self.get_array_auth(&path, "events", auth).await
    }

    /// `GET /v1/audit/verify` => ledger hash-chain integrity report.
    ///
    /// Expensive for large ledgers — callers should not poll on tight intervals.
    pub async fn verify_chain(&self, auth: &OperatorAuth) -> Result<Value, ClientError> {
        self.get_json_auth("/v1/audit/verify", auth).await
    }

    /// `POST /v1/admin/revoke-all` => new epoch value.
    pub async fn revoke_all(&self, auth: &OperatorAuth) -> Result<Value, ClientError> {
        self.post_json_auth("/v1/admin/revoke-all", None, auth)
            .await
    }

    /// `POST /v1/admin/reload` => hot-reload manifests and policy data.
    ///
    /// Returns `{ "ok": true, "actions": N, "policy_version": "...", "reloaded_at": "..." }`.
    pub async fn admin_reload(&self, auth: &OperatorAuth) -> Result<Value, ClientError> {
        self.post_json_auth("/v1/admin/reload", None, auth).await
    }

    /// `GET /v1/approvals` => list of approval summaries.
    pub async fn list_approvals(
        &self,
        auth: &OperatorAuth,
        status_filter: Option<&str>,
        limit: Option<usize>,
    ) -> Result<Vec<Value>, ClientError> {
        let limit_str = limit.map(|n| n.to_string());
        let mut params = Vec::<(&str, &str)>::new();
        if let Some(s) = status_filter {
            params.push(("status", s));
        }
        if let Some(ref n) = limit_str {
            params.push(("limit", n));
        }
        let path = query_path("/v1/approvals", &params);
        self.get_array_auth(&path, "approvals", auth).await
    }

    /// `GET /v1/approvals/{id}` => full approval detail for operator review.
    pub async fn get_approval(
        &self,
        auth: &OperatorAuth,
        approval_id: &str,
    ) -> Result<Value, ClientError> {
        self.get_json_auth(&format!("/v1/approvals/{approval_id}"), auth)
            .await
    }

    /// `POST /v1/approvals/{id}/approve` => approve and execute.
    ///
    /// Both `learn_domain` and `learn_path` are optional query parameters
    /// forwarded to the server. When present, the server persists the
    /// domain/path glob in the action's learned allowlist after successful
    /// execution.
    pub async fn approve_approval(
        &self,
        auth: &OperatorAuth,
        approval_id: &str,
        learn_domain: Option<&str>,
        learn_path: Option<&str>,
    ) -> Result<Value, ClientError> {
        let mut params = Vec::<(&str, &str)>::new();
        if let Some(d) = learn_domain {
            params.push(("learn_domain", d));
        }
        if let Some(p) = learn_path {
            params.push(("learn_path", p));
        }
        let path = query_path(&format!("/v1/approvals/{approval_id}/approve"), &params);
        self.post_json_auth(&path, None, auth).await
    }

    /// `POST /v1/approvals/{id}/deny` => deny without execution.
    pub async fn deny_approval(
        &self,
        auth: &OperatorAuth,
        approval_id: &str,
        reason: Option<&str>,
    ) -> Result<Value, ClientError> {
        let body = reason.map(|r| serde_json::json!({ "reason": r }));
        self.post_json_auth(
            &format!("/v1/approvals/{approval_id}/deny"),
            body.as_ref(),
            auth,
        )
        .await
    }

    /// `GET /v1/admin/status` => operational status snapshot.
    pub async fn status(&self, auth: &OperatorAuth) -> Result<Value, ClientError> {
        self.get_json_auth("/v1/admin/status", auth).await
    }

    /// `GET /v1/admin/domains` => list learned domains.
    pub async fn list_domains(
        &self,
        auth: &OperatorAuth,
        action_filter: Option<&str>,
    ) -> Result<Vec<Value>, ClientError> {
        let params: Vec<(&str, &str)> = action_filter.iter().map(|a| ("action", *a)).collect();
        let path = query_path("/v1/admin/domains", &params);
        self.get_array_auth(&path, "domains", auth).await
    }

    /// `POST /v1/admin/domains` => add a learned domain.
    pub async fn add_domain(
        &self,
        auth: &OperatorAuth,
        action_id: &str,
        domain: &str,
    ) -> Result<Value, ClientError> {
        let body = serde_json::json!({
            "action_id": action_id,
            "domain": domain,
        });
        self.post_json_auth("/v1/admin/domains", Some(&body), auth)
            .await
    }

    /// `DELETE /v1/admin/domains` => remove a learned domain.
    pub async fn remove_domain(
        &self,
        auth: &OperatorAuth,
        action_id: &str,
        domain: &str,
    ) -> Result<Value, ClientError> {
        let body = serde_json::json!({
            "action_id": action_id,
            "domain": domain,
        });
        self.delete_json_auth("/v1/admin/domains", Some(&body), auth)
            .await
    }

    /// `DELETE /v1/admin/domains/clear?action=<action_id>` => clear all learned domains for an action.
    pub async fn clear_domains(
        &self,
        auth: &OperatorAuth,
        action_id: &str,
    ) -> Result<Value, ClientError> {
        let path = query_path("/v1/admin/domains/clear", &[("action", action_id)]);
        self.delete_json_auth(&path, None, auth).await
    }

    /// `GET /v1/admin/paths` => list learned path globs.
    pub async fn list_paths(
        &self,
        auth: &OperatorAuth,
        action_filter: Option<&str>,
    ) -> Result<Vec<Value>, ClientError> {
        let params: Vec<(&str, &str)> = action_filter.iter().map(|a| ("action", *a)).collect();
        let path = query_path("/v1/admin/paths", &params);
        self.get_array_auth(&path, "paths", auth).await
    }

    /// `POST /v1/admin/paths` => add a learned path glob.
    pub async fn add_path(
        &self,
        auth: &OperatorAuth,
        action_id: &str,
        path_glob: &str,
    ) -> Result<Value, ClientError> {
        let body = serde_json::json!({
            "action_id": action_id,
            "path_glob": path_glob,
        });
        self.post_json_auth("/v1/admin/paths", Some(&body), auth)
            .await
    }

    /// `DELETE /v1/admin/paths` => remove a learned path glob.
    pub async fn remove_path(
        &self,
        auth: &OperatorAuth,
        action_id: &str,
        path_glob: &str,
    ) -> Result<Value, ClientError> {
        let body = serde_json::json!({
            "action_id": action_id,
            "path_glob": path_glob,
        });
        self.delete_json_auth("/v1/admin/paths", Some(&body), auth)
            .await
    }

    /// `DELETE /v1/admin/paths/clear?action=<action_id>` => clear all learned paths for an action.
    pub async fn clear_paths(
        &self,
        auth: &OperatorAuth,
        action_id: &str,
    ) -> Result<Value, ClientError> {
        let path = query_path("/v1/admin/paths/clear", &[("action", action_id)]);
        self.delete_json_auth(&path, None, auth).await
    }

    /// `GET /v1/admin/policy` => show full ACL.
    pub async fn policy_show(
        &self,
        auth: &OperatorAuth,
        principal: Option<&str>,
    ) -> Result<Value, ClientError> {
        let path = match principal {
            Some(p) => format!("/v1/admin/policy/{p}"),
            None => "/v1/admin/policy".to_string(),
        };
        self.get_json_auth(&path, auth).await
    }

    /// `POST /v1/admin/policy/grant` => grant actions to a principal.
    pub async fn policy_grant(
        &self,
        auth: &OperatorAuth,
        principal: &str,
        actions: &[&str],
    ) -> Result<Value, ClientError> {
        let body = serde_json::json!({
            "principal": principal,
            "actions": actions,
        });
        self.post_json_auth("/v1/admin/policy/grant", Some(&body), auth)
            .await
    }

    /// `POST /v1/admin/policy/revoke` => revoke actions from a principal.
    pub async fn policy_revoke(
        &self,
        auth: &OperatorAuth,
        principal: &str,
        actions: &[&str],
    ) -> Result<Value, ClientError> {
        let body = serde_json::json!({
            "principal": principal,
            "actions": actions,
        });
        self.post_json_auth("/v1/admin/policy/revoke", Some(&body), auth)
            .await
    }
}
