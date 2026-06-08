//! Host-side database request validation and mode enforcement.
//!
//! Validates every database request against the action manifest's
//! `DatabaseConfig` before any SQL reaches the database. Enforces:
//!
//! - Mode rules (strict/parameterized/hybrid)
//! - Operation classification
//! - Blocked operation rejection
//! - WHERE clause requirements
//! - Statement resolution from manifest
//!
//! SECURITY: all validation runs in the host, not in the WASM provider.
//! The provider cannot bypass these checks.

use super::classify::{classify_sql, has_where_clause};
use super::types::{DatabaseConfig, DatabaseMode, OperationClass};

// Validation errors

/// Database request validation failure.
#[derive(Debug, thiserror::Error)]
pub(crate) enum DatabaseValidationError {
    #[error("ambiguous request: statement_id and query are mutually exclusive")]
    AmbiguousRequest,

    #[error("empty request: either statement_id or query is required")]
    EmptyRequest,

    #[error("parameterized queries are not allowed in strict mode")]
    ParameterizedInStrictMode,

    #[error("statement_id '{id}' not found in manifest")]
    StatementNotFound { id: String },

    #[error("parameterized {op} is not allowed in hybrid mode; use a predeclared statement")]
    ParameterizedWriteInHybridMode { op: OperationClass },

    #[error("operation {op} is blocked by host rules")]
    OperationBlocked { op: OperationClass },

    #[error("{op} requires a WHERE clause")]
    MissingWhereClause { op: OperationClass },
}

// Validated request

/// A database request that has passed host-side validation.
///
/// Contains the resolved SQL (from manifest statement or validated query),
/// the classified operation, and the parameters to bind.
#[derive(Debug)]
pub(crate) struct ValidatedDatabaseRequest {
    /// The resolved SQL to execute.
    pub sql: String,
    /// Bound parameters.
    pub params: Vec<String>,
    /// Classified operation type.
    pub operation_class: OperationClass,
    /// Whether this was a predeclared statement or parameterized query.
    pub is_predeclared: bool,
    /// The statement ID if predeclared.
    pub statement_id: Option<String>,
    /// Whether the database rules flag this operation as requiring approval.
    ///
    /// SECURITY (10): computed from `DatabaseRules::require_approval_for` and
    /// `allow_without_approval`. Used by the host I/O layer to determine
    /// whether `max_rows_affected_without_approval` applies (it only applies
    /// to writes that were auto-allowed, not approval-backed writes).
    pub requires_approval: bool,
}

// Validation

/// Validate a database request against the manifest's DatabaseConfig.
///
/// Returns a `ValidatedDatabaseRequest` with resolved SQL and classification,
/// or a denial error.
///
/// SECURITY: this is the single enforcement point for database mode rules.
/// Called from the host I/O handler before any SQL reaches the database.
pub(crate) fn validate_database_request(
    statement_id: Option<&str>,
    query: Option<&str>,
    params: &[String],
    config: &DatabaseConfig,
) -> Result<ValidatedDatabaseRequest, DatabaseValidationError> {
    // Step 1: reject ambiguous or empty requests.
    match (statement_id, query) {
        (Some(_), Some(_)) => return Err(DatabaseValidationError::AmbiguousRequest),
        (None, None) => return Err(DatabaseValidationError::EmptyRequest),
        _ => {}
    }

    // Step 2: resolve SQL and classify.
    if let Some(stmt_id) = statement_id {
        // Predeclared statement path.
        validate_predeclared(stmt_id, params, config)
    } else if let Some(raw_query) = query {
        // Parameterized query path.
        validate_parameterized(raw_query, params, config)
    } else {
        // Unreachable: (None, None) was rejected in Step 1.
        // Fail-closed rather than panic.
        Err(DatabaseValidationError::EmptyRequest)
    }
}

/// Validate a predeclared statement request.
fn validate_predeclared(
    stmt_id: &str,
    params: &[String],
    config: &DatabaseConfig,
) -> Result<ValidatedDatabaseRequest, DatabaseValidationError> {
    // Resolve statement from manifest.
    let stmt = config.resolve_statement(stmt_id).ok_or_else(|| {
        DatabaseValidationError::StatementNotFound {
            id: stmt_id.to_string(),
        }
    })?;

    let op = classify_sql(&stmt.sql);

    // Even predeclared statements must not be always-blocked operations.
    // This catches manifest misconfiguration (e.g. a DDL statement declared
    // by mistake).
    if op.is_always_blocked() {
        return Err(DatabaseValidationError::OperationBlocked { op });
    }

    // SECURITY (10): determine whether this operation requires approval
    // based on DatabaseRules. Used by host I/O to decide whether
    // max_rows_affected_without_approval applies.
    let requires_approval = config.rules.require_approval_for.contains(&op)
        && !config.rules.allow_without_approval.contains(&op);

    Ok(ValidatedDatabaseRequest {
        sql: stmt.sql.clone(),
        params: params.to_vec(),
        operation_class: op,
        is_predeclared: true,
        statement_id: Some(stmt_id.to_string()),
        requires_approval,
    })
}

/// Validate a parameterized query request.
fn validate_parameterized(
    query: &str,
    params: &[String],
    config: &DatabaseConfig,
) -> Result<ValidatedDatabaseRequest, DatabaseValidationError> {
    // Step 1: strict mode rejects all parameterized queries.
    if config.mode == DatabaseMode::Strict {
        return Err(DatabaseValidationError::ParameterizedInStrictMode);
    }

    // Step 2: classify the operation.
    let op = classify_sql(query);

    // Step 3: always-blocked operations are rejected regardless of mode.
    if op.is_always_blocked() {
        return Err(DatabaseValidationError::OperationBlocked { op });
    }

    // Step 4: check explicitly blocked operations from rules.
    if config.rules.blocked_operations.contains(&op) {
        return Err(DatabaseValidationError::OperationBlocked { op });
    }

    // Step 5: hybrid mode restricts parameterized to allowed operations.
    if config.mode == DatabaseMode::Hybrid && !config.rules.allow_parameterized.contains(&op) {
        if op.is_dml_write() {
            return Err(DatabaseValidationError::ParameterizedWriteInHybridMode { op });
        }
        return Err(DatabaseValidationError::OperationBlocked { op });
    }

    // Step 6: check WHERE clause requirement.
    if config.rules.require_where_for.contains(&op) && !has_where_clause(query) {
        return Err(DatabaseValidationError::MissingWhereClause { op });
    }

    // SECURITY (10): determine whether this operation requires approval.
    //
    // An operation requires approval if it is in `require_approval_for`
    // AND it is NOT in `allow_without_approval`. The `allow_without_approval`
    // list acts as an explicit override that permits certain operation classes
    // to proceed without human approval (subject to other guardrails like
    // `max_rows_affected_without_approval`).
    let requires_approval = config.rules.require_approval_for.contains(&op)
        && !config.rules.allow_without_approval.contains(&op);

    Ok(ValidatedDatabaseRequest {
        sql: query.to_string(),
        params: params.to_vec(),
        operation_class: op,
        is_predeclared: false,
        statement_id: None,
        requires_approval,
    })
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::types::{DatabaseRules, DatabaseStatement};

    fn hybrid_config() -> DatabaseConfig {
        DatabaseConfig {
            mode: DatabaseMode::Hybrid,
            statements: vec![
                DatabaseStatement {
                    id: "get_order".into(),
                    sql: "SELECT * FROM orders WHERE id = $1".into(),
                },
                DatabaseStatement {
                    id: "update_order_status".into(),
                    sql: "UPDATE orders SET status = $1 WHERE id = $2".into(),
                },
                DatabaseStatement {
                    id: "delete_order".into(),
                    sql: "DELETE FROM orders WHERE id = $1".into(),
                },
            ],
            rules: DatabaseRules::mvp_defaults(),
        }
    }

    fn strict_config() -> DatabaseConfig {
        DatabaseConfig {
            mode: DatabaseMode::Strict,
            statements: vec![DatabaseStatement {
                id: "get_order".into(),
                sql: "SELECT * FROM orders WHERE id = $1".into(),
            }],
            rules: DatabaseRules::default(),
        }
    }

    fn parameterized_config() -> DatabaseConfig {
        DatabaseConfig {
            mode: DatabaseMode::Parameterized,
            statements: vec![],
            rules: DatabaseRules::mvp_defaults(),
        }
    }

    // -- Ambiguous / empty --

    #[test]
    fn both_statement_and_query_rejected() {
        let config = hybrid_config();
        let err = validate_database_request(Some("get_order"), Some("SELECT 1"), &[], &config)
            .unwrap_err();
        assert!(matches!(err, DatabaseValidationError::AmbiguousRequest));
    }

    #[test]
    fn neither_statement_nor_query_rejected() {
        let config = hybrid_config();
        let err = validate_database_request(None, None, &[], &config).unwrap_err();
        assert!(matches!(err, DatabaseValidationError::EmptyRequest));
    }

    // -- Strict mode --

    #[test]
    fn strict_mode_predeclared_select_works() {
        let config = strict_config();
        let result =
            validate_database_request(Some("get_order"), None, &["order-123".into()], &config)
                .unwrap();
        assert_eq!(result.operation_class, OperationClass::Select);
        assert!(result.is_predeclared);
    }

    #[test]
    fn strict_mode_parameterized_rejected() {
        let config = strict_config();
        let err = validate_database_request(None, Some("SELECT 1"), &[], &config).unwrap_err();
        assert!(matches!(
            err,
            DatabaseValidationError::ParameterizedInStrictMode
        ));
    }

    #[test]
    fn strict_mode_unknown_statement_rejected() {
        let config = strict_config();
        let err = validate_database_request(Some("nonexistent"), None, &[], &config).unwrap_err();
        assert!(matches!(
            err,
            DatabaseValidationError::StatementNotFound { .. }
        ));
    }

    // -- Hybrid mode --

    #[test]
    fn hybrid_parameterized_select_works() {
        let config = hybrid_config();
        let result = validate_database_request(
            None,
            Some("SELECT id, status FROM orders WHERE created_at > $1"),
            &["2026-01-01".into()],
            &config,
        )
        .unwrap();
        assert_eq!(result.operation_class, OperationClass::Select);
        assert!(!result.is_predeclared);
    }

    #[test]
    fn hybrid_parameterized_update_rejected() {
        let config = hybrid_config();
        let err = validate_database_request(
            None,
            Some("UPDATE orders SET status = $1 WHERE id = $2"),
            &["shipped".into(), "order-123".into()],
            &config,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            DatabaseValidationError::ParameterizedWriteInHybridMode { .. }
        ));
    }

    #[test]
    fn hybrid_predeclared_update_works() {
        let config = hybrid_config();
        let result = validate_database_request(
            Some("update_order_status"),
            None,
            &["shipped".into(), "order-123".into()],
            &config,
        )
        .unwrap();
        assert_eq!(result.operation_class, OperationClass::Update);
        assert!(result.is_predeclared);
    }

    #[test]
    fn hybrid_parameterized_delete_rejected() {
        let config = hybrid_config();
        let err = validate_database_request(
            None,
            Some("DELETE FROM orders WHERE id = $1"),
            &["order-123".into()],
            &config,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            DatabaseValidationError::ParameterizedWriteInHybridMode { .. }
        ));
    }

    // -- Parameterized mode --

    #[test]
    fn parameterized_select_works() {
        let config = parameterized_config();
        let result = validate_database_request(
            None,
            Some("SELECT * FROM orders WHERE id = $1"),
            &["order-123".into()],
            &config,
        )
        .unwrap();
        assert_eq!(result.operation_class, OperationClass::Select);
    }

    #[test]
    fn parameterized_update_with_where_works() {
        let mut config = parameterized_config();
        config.rules.blocked_operations.clear();
        let result = validate_database_request(
            None,
            Some("UPDATE orders SET status = $1 WHERE id = $2"),
            &["shipped".into(), "order-123".into()],
            &config,
        )
        .unwrap();
        assert_eq!(result.operation_class, OperationClass::Update);
    }

    #[test]
    fn parameterized_update_without_where_rejected() {
        let mut config = parameterized_config();
        config.rules.blocked_operations.clear();
        config.rules.require_where_for = vec![OperationClass::Update];
        let err = validate_database_request(
            None,
            Some("UPDATE orders SET status = $1"),
            &["shipped".into()],
            &config,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            DatabaseValidationError::MissingWhereClause { .. }
        ));
    }

    // -- Always-blocked operations --

    #[test]
    fn ddl_always_blocked() {
        let config = hybrid_config();
        let err =
            validate_database_request(None, Some("DROP TABLE orders"), &[], &config).unwrap_err();
        assert!(matches!(
            err,
            DatabaseValidationError::OperationBlocked { .. }
        ));
    }

    #[test]
    fn multi_statement_always_blocked() {
        let config = parameterized_config();
        let err =
            validate_database_request(None, Some("SELECT 1; DROP TABLE orders"), &[], &config)
                .unwrap_err();
        assert!(matches!(
            err,
            DatabaseValidationError::OperationBlocked { .. }
        ));
    }

    #[test]
    fn grant_always_blocked() {
        let config = parameterized_config();
        let err = validate_database_request(
            None,
            Some("GRANT SELECT ON orders TO attacker"),
            &[],
            &config,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            DatabaseValidationError::OperationBlocked { .. }
        ));
    }

    #[test]
    fn copy_always_blocked() {
        let config = parameterized_config();
        let err =
            validate_database_request(None, Some("COPY orders TO '/tmp/evil.csv'"), &[], &config)
                .unwrap_err();
        assert!(matches!(
            err,
            DatabaseValidationError::OperationBlocked { .. }
        ));
    }

    // -- requires_approval computation (10) --

    #[test]
    fn select_in_allow_without_approval_does_not_require_approval() {
        let config = hybrid_config();
        let result = validate_database_request(
            None,
            Some("SELECT * FROM orders WHERE id = $1"),
            &["order-123".into()],
            &config,
        )
        .unwrap();
        assert!(
            !result.requires_approval,
            "SELECT should not require approval"
        );
    }

    #[test]
    fn update_in_require_approval_requires_approval() {
        let config = hybrid_config();
        // UPDATE is in require_approval_for but not in allow_without_approval
        // in mvp_defaults, so predeclared UPDATE requires approval.
        let result = validate_database_request(
            Some("update_order_status"),
            None,
            &["shipped".into(), "order-123".into()],
            &config,
        )
        .unwrap();
        assert!(
            result.requires_approval,
            "UPDATE should require approval per mvp_defaults"
        );
    }

    #[test]
    fn insert_in_allow_without_approval_does_not_require_approval() {
        // In mvp_defaults: Insert is in allow_without_approval.
        let config = hybrid_config();
        let result =
            validate_database_request(Some("get_order"), None, &["order-123".into()], &config)
                .unwrap();
        assert!(
            !result.requires_approval,
            "SELECT is not in require_approval_for"
        );
    }

    #[test]
    fn delete_requires_approval_per_mvp_defaults() {
        let config = hybrid_config();
        let result =
            validate_database_request(Some("delete_order"), None, &["order-123".into()], &config)
                .unwrap();
        assert!(
            result.requires_approval,
            "DELETE should require approval per mvp_defaults"
        );
    }

    #[test]
    fn op_in_both_require_and_allow_does_not_require_approval() {
        // If an operation is in BOTH require_approval_for AND allow_without_approval,
        // allow_without_approval wins (explicit override).
        let mut config = parameterized_config();
        config.rules.require_approval_for = vec![OperationClass::Select];
        config.rules.allow_without_approval = vec![OperationClass::Select];
        config.rules.blocked_operations.clear();

        let result = validate_database_request(
            None,
            Some("SELECT * FROM orders WHERE id = $1"),
            &["order-123".into()],
            &config,
        )
        .unwrap();
        assert!(
            !result.requires_approval,
            "allow_without_approval overrides require_approval_for"
        );
    }
}
