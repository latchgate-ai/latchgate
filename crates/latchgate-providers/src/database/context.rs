//! Database-specific policy context builder.
//!
//! Builds the opaque `serde_json::Value` sent to OPA for database actions.
//! Moved from `latchgate-kernel::pipeline` so the kernel no longer imports
//! any database domain types.

use super::classify::{classify_sql, extract_tables};
use super::types::*;

/// Build database-specific policy context from provider config and request body.
///
/// Returns `None` for non-database actions or if the database_config is not
/// a valid DatabaseConfig.
///
/// SECURITY: classification happens before OPA so the policy engine receives
/// accurate operation metadata.
pub(crate) fn build_database_policy_context(
    database_config: Option<&serde_json::Value>,
    request_body: &serde_json::Value,
) -> Option<serde_json::Value> {
    let config_value = database_config?;
    let db_config: DatabaseConfig = serde_json::from_value(config_value.clone()).ok()?;

    let statement_id = request_body
        .get("statement_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let query = request_body
        .get("query")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let params: Vec<String> = request_body
        .get("params")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|v| v.as_str().unwrap_or("").to_string())
                .collect()
        })
        .unwrap_or_default();

    // Resolve SQL for classification.
    let (sql, stmt_mode, resolved_stmt_id) = if let Some(ref sid) = statement_id {
        match db_config.resolve_statement(sid) {
            Some(stmt) => (
                stmt.sql.clone(),
                StatementMode::Predeclared,
                Some(sid.clone()),
            ),
            None => {
                // Unknown statement — classify as Unknown for policy to deny.
                let ctx = DatabasePolicyContext {
                    statement_mode: StatementMode::Predeclared,
                    operation_class: OperationClass::Unknown,
                    statement_id: Some(sid.clone()),
                    tables: vec![],
                    requires_approval_candidate: true,
                    request_summary: DatabaseRequestSummary {
                        kind: format!("unknown_statement:{sid}"),
                        params_preview: Some(redact_params(&params)),
                        query_shape: None,
                    },
                    database_mode: db_config.mode,
                    allowed_without_approval: false,
                    requires_approval_by_config: true,
                    max_rows_affected_without_approval: db_config
                        .rules
                        .max_rows_affected_without_approval,
                };
                return serde_json::to_value(ctx).ok();
            }
        }
    } else if let Some(ref q) = query {
        (q.clone(), StatementMode::Parameterized, None)
    } else {
        return None;
    };

    let op = classify_sql(&sql);
    let tables = extract_tables(&sql);

    let requires_approval_candidate = op.is_dml_write()
        || db_config.rules.require_approval_for.contains(&op)
        || op.is_always_blocked();

    let summary = DatabaseRequestSummary {
        kind: resolved_stmt_id
            .clone()
            .unwrap_or_else(|| "parameterized_query".into()),
        params_preview: Some(redact_params(&params)),
        query_shape: if stmt_mode == StatementMode::Parameterized {
            Some(sql.clone())
        } else {
            None
        },
    };

    let allowed_without_approval = db_config.rules.allow_without_approval.contains(&op);
    let requires_approval_by_config = db_config.rules.require_approval_for.contains(&op);

    let ctx = DatabasePolicyContext {
        statement_mode: stmt_mode,
        operation_class: op,
        statement_id: resolved_stmt_id,
        tables,
        requires_approval_candidate,
        request_summary: summary,
        database_mode: db_config.mode,
        allowed_without_approval,
        requires_approval_by_config,
        max_rows_affected_without_approval: db_config.rules.max_rows_affected_without_approval,
    };
    serde_json::to_value(ctx).ok()
}

/// Redact parameter values for policy context and operator review.
pub(crate) fn redact_params(params: &[String]) -> Vec<String> {
    params
        .iter()
        .map(|p| {
            if p.len() <= 32
                && p.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
            {
                p.clone()
            } else {
                format!("[{} chars]", p.len())
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_db_config_value() -> serde_json::Value {
        serde_json::to_value(DatabaseConfig {
            mode: DatabaseMode::Hybrid,
            statements: vec![DatabaseStatement {
                id: "get_order".into(),
                sql: "SELECT * FROM orders WHERE id = $1".into(),
            }],
            rules: DatabaseRules::mvp_defaults(),
        })
        .unwrap()
    }

    #[test]
    fn returns_none_for_no_database_config() {
        let body = serde_json::json!({"statement_id": "get_order"});
        assert!(build_database_policy_context(None, &body).is_none());
    }

    #[test]
    fn returns_none_for_non_database_config() {
        // A JSON string (not an object) cannot deserialize to DatabaseConfig.
        let not_db = serde_json::json!("just_a_string");
        let body = serde_json::json!({"statement_id": "x"});
        assert!(build_database_policy_context(Some(&not_db), &body).is_none());
    }

    #[test]
    fn returns_context_for_predeclared_statement() {
        let config = make_db_config_value();
        let body = serde_json::json!({"statement_id": "get_order", "params": ["order-123"]});
        let ctx = build_database_policy_context(Some(&config), &body).unwrap();

        assert_eq!(ctx["statement_mode"], "predeclared");
        assert_eq!(ctx["operation_class"], "select");
        assert_eq!(ctx["statement_id"], "get_order");
        assert!(ctx["tables"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("orders")));
    }

    #[test]
    fn returns_context_for_parameterized_query() {
        let config = make_db_config_value();
        let body = serde_json::json!({"query": "SELECT * FROM users WHERE active = $1", "params": ["true"]});
        let ctx = build_database_policy_context(Some(&config), &body).unwrap();

        assert_eq!(ctx["statement_mode"], "parameterized");
        assert_eq!(ctx["operation_class"], "select");
    }

    #[test]
    fn unknown_statement_returns_unknown_class() {
        let config = make_db_config_value();
        let body = serde_json::json!({"statement_id": "nonexistent"});
        let ctx = build_database_policy_context(Some(&config), &body).unwrap();

        assert_eq!(ctx["operation_class"], "unknown");
        assert_eq!(ctx["requires_approval_candidate"], true);
    }

    #[test]
    fn returns_none_for_empty_request() {
        let config = make_db_config_value();
        let body = serde_json::json!({});
        assert!(build_database_policy_context(Some(&config), &body).is_none());
    }
}
