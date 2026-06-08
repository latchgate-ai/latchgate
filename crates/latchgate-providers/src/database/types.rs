//! Database-specific domain types for controlled SQL modes.
//!
//! Moved from `latchgate-core` to `latchgate-providers` so that core, kernel,
//! policy, and registry remain provider-agnostic. Only `latchgate-providers`
//! (and crates that depend on it) know about these types.

use serde::{Deserialize, Serialize};

use super::classify::classify_sql;

// DatabaseMode

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseMode {
    Strict,
    Parameterized,
    #[default]
    Hybrid,
}

// OperationClass

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationClass {
    Select,
    Insert,
    Update,
    Delete,
    Ddl,
    GrantRevoke,
    CopyIo,
    TransactionControl,
    MultiStatement,
    Unknown,
}

impl OperationClass {
    pub fn is_read(&self) -> bool {
        matches!(self, OperationClass::Select)
    }

    pub fn is_dml_write(&self) -> bool {
        matches!(
            self,
            OperationClass::Insert | OperationClass::Update | OperationClass::Delete
        )
    }

    pub fn is_always_blocked(&self) -> bool {
        matches!(
            self,
            OperationClass::Ddl
                | OperationClass::GrantRevoke
                | OperationClass::CopyIo
                | OperationClass::TransactionControl
                | OperationClass::MultiStatement
                | OperationClass::Unknown
        )
    }
}

impl std::fmt::Display for OperationClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            OperationClass::Select => "select",
            OperationClass::Insert => "insert",
            OperationClass::Update => "update",
            OperationClass::Delete => "delete",
            OperationClass::Ddl => "ddl",
            OperationClass::GrantRevoke => "grant_revoke",
            OperationClass::CopyIo => "copy_io",
            OperationClass::TransactionControl => "transaction_control",
            OperationClass::MultiStatement => "multi_statement",
            OperationClass::Unknown => "unknown",
        };
        write!(f, "{s}")
    }
}

// DatabaseStatement

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseStatement {
    pub id: String,
    pub sql: String,
}

// DatabaseRules

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DatabaseRules {
    pub blocked_operations: Vec<OperationClass>,
    pub require_approval_for: Vec<OperationClass>,
    pub allow_without_approval: Vec<OperationClass>,
    pub allow_parameterized: Vec<OperationClass>,
    pub require_where_for: Vec<OperationClass>,
    pub max_rows_affected_without_approval: Option<u64>,
}

impl DatabaseRules {
    pub fn mvp_defaults() -> Self {
        Self {
            blocked_operations: vec![
                OperationClass::Ddl,
                OperationClass::GrantRevoke,
                OperationClass::CopyIo,
                OperationClass::TransactionControl,
                OperationClass::MultiStatement,
                OperationClass::Unknown,
            ],
            require_approval_for: vec![OperationClass::Delete, OperationClass::Update],
            allow_without_approval: vec![OperationClass::Select, OperationClass::Insert],
            allow_parameterized: vec![OperationClass::Select],
            require_where_for: vec![OperationClass::Update, OperationClass::Delete],
            max_rows_affected_without_approval: Some(1),
        }
    }
}

// DatabaseConfig

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseConfig {
    #[serde(default)]
    pub mode: DatabaseMode,
    #[serde(default)]
    pub statements: Vec<DatabaseStatement>,
    #[serde(default)]
    pub rules: DatabaseRules,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            mode: DatabaseMode::Hybrid,
            statements: Vec::new(),
            rules: DatabaseRules::mvp_defaults(),
        }
    }
}

impl DatabaseConfig {
    /// Validate configuration invariants.
    ///
    /// SECURITY: strict mode without statements is a configuration error —
    /// it would deny every request silently. Fail at load time.
    pub fn validate(&self) -> Result<(), String> {
        if self.mode == DatabaseMode::Strict && self.statements.is_empty() {
            return Err(
                "database_config: strict mode requires at least one predeclared statement".into(),
            );
        }

        let mut seen_ids = std::collections::HashSet::new();
        for stmt in &self.statements {
            if stmt.id.is_empty() {
                return Err("database_config: statement id must not be empty".into());
            }
            if stmt.id.len() > 128 {
                return Err(format!(
                    "database_config: statement id '{}' exceeds 128 characters",
                    stmt.id
                ));
            }
            if !stmt
                .id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                return Err(format!(
                    "database_config: statement id '{}' contains invalid characters; \
                     only [a-zA-Z0-9_-] are permitted",
                    stmt.id
                ));
            }
            if !seen_ids.insert(&stmt.id) {
                return Err(format!(
                    "database_config: duplicate statement id '{}'",
                    stmt.id
                ));
            }
            if stmt.sql.trim().is_empty() {
                return Err(format!(
                    "database_config: statement '{}' has empty SQL",
                    stmt.id
                ));
            }

            let op = classify_sql(&stmt.sql);
            if op.is_always_blocked() {
                return Err(format!(
                    "database_config: statement '{}' contains a blocked operation ({op}); \
                     DDL, GRANT, COPY, transaction control, multi-statement, and \
                     unclassifiable SQL are not permitted in predeclared statements",
                    stmt.id
                ));
            }
        }

        Ok(())
    }

    pub fn resolve_statement(&self, id: &str) -> Option<&DatabaseStatement> {
        self.statements.iter().find(|s| s.id == id)
    }
}

// StatementMode

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatementMode {
    Predeclared,
    Parameterized,
}

// DatabasePolicyContext

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DatabasePolicyContext {
    pub statement_mode: StatementMode,
    pub operation_class: OperationClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement_id: Option<String>,
    pub tables: Vec<String>,
    pub requires_approval_candidate: bool,
    pub request_summary: DatabaseRequestSummary,
    pub database_mode: DatabaseMode,
    pub allowed_without_approval: bool,
    pub requires_approval_by_config: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_rows_affected_without_approval: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DatabaseRequestSummary {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params_preview: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_shape: Option<String>,
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    // -- classify_sql coverage is in classify.rs --

    // -- DatabaseConfig validation --

    #[test]
    fn strict_mode_without_statements_rejected() {
        let config = DatabaseConfig {
            mode: DatabaseMode::Strict,
            statements: vec![],
            rules: DatabaseRules::default(),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn strict_mode_with_statements_ok() {
        let config = DatabaseConfig {
            mode: DatabaseMode::Strict,
            statements: vec![DatabaseStatement {
                id: "get_order".into(),
                sql: "SELECT * FROM orders WHERE id = $1".into(),
            }],
            rules: DatabaseRules::default(),
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn duplicate_statement_id_rejected() {
        let config = DatabaseConfig {
            mode: DatabaseMode::Strict,
            statements: vec![
                DatabaseStatement {
                    id: "get_order".into(),
                    sql: "SELECT * FROM orders WHERE id = $1".into(),
                },
                DatabaseStatement {
                    id: "get_order".into(),
                    sql: "SELECT * FROM orders WHERE id = $2".into(),
                },
            ],
            rules: DatabaseRules::default(),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn empty_statement_id_rejected() {
        let config = DatabaseConfig {
            mode: DatabaseMode::Strict,
            statements: vec![DatabaseStatement {
                id: "".into(),
                sql: "SELECT 1".into(),
            }],
            rules: DatabaseRules::default(),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn statement_with_ddl_rejected_at_validate() {
        let config = DatabaseConfig {
            mode: DatabaseMode::Strict,
            statements: vec![DatabaseStatement {
                id: "evil_ddl".into(),
                sql: "DROP TABLE orders".into(),
            }],
            rules: DatabaseRules::default(),
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("blocked operation") && err.contains("evil_ddl"),
            "must reject DDL at load time: {err}"
        );
    }

    #[test]
    fn statement_id_with_special_chars_rejected() {
        for bad_id in ["drop;table", "evil/path", "foo bar", "sql\"inject"] {
            let config = DatabaseConfig {
                mode: DatabaseMode::Strict,
                statements: vec![DatabaseStatement {
                    id: bad_id.into(),
                    sql: "SELECT 1".into(),
                }],
                rules: DatabaseRules::default(),
            };
            assert!(
                config.validate().is_err(),
                "statement id with special chars must be rejected: {bad_id}"
            );
        }
    }

    #[test]
    fn hybrid_mode_default_is_valid() {
        let config = DatabaseConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.mode, DatabaseMode::Hybrid);
    }

    #[test]
    fn resolve_statement_finds_match() {
        let config = DatabaseConfig {
            mode: DatabaseMode::Strict,
            statements: vec![
                DatabaseStatement {
                    id: "get_order".into(),
                    sql: "SELECT * FROM orders WHERE id = $1".into(),
                },
                DatabaseStatement {
                    id: "update_status".into(),
                    sql: "UPDATE orders SET status = $1 WHERE id = $2".into(),
                },
            ],
            rules: DatabaseRules::default(),
        };
        let stmt = config.resolve_statement("update_status").unwrap();
        assert!(stmt.sql.starts_with("UPDATE"));
        assert!(config.resolve_statement("nonexistent").is_none());
    }

    #[test]
    fn operation_class_is_read() {
        assert!(OperationClass::Select.is_read());
        assert!(!OperationClass::Insert.is_read());
    }

    #[test]
    fn operation_class_is_dml_write() {
        assert!(OperationClass::Insert.is_dml_write());
        assert!(OperationClass::Update.is_dml_write());
        assert!(OperationClass::Delete.is_dml_write());
        assert!(!OperationClass::Select.is_dml_write());
        assert!(!OperationClass::Ddl.is_dml_write());
    }

    #[test]
    fn operation_class_always_blocked() {
        assert!(OperationClass::Ddl.is_always_blocked());
        assert!(OperationClass::GrantRevoke.is_always_blocked());
        assert!(OperationClass::CopyIo.is_always_blocked());
        assert!(OperationClass::TransactionControl.is_always_blocked());
        assert!(OperationClass::MultiStatement.is_always_blocked());
        assert!(OperationClass::Unknown.is_always_blocked());
        assert!(!OperationClass::Select.is_always_blocked());
    }

    #[test]
    fn database_mode_round_trips() {
        for mode in [
            DatabaseMode::Strict,
            DatabaseMode::Parameterized,
            DatabaseMode::Hybrid,
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            let parsed: DatabaseMode = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, mode);
        }
    }

    #[test]
    fn database_config_serialization_roundtrip() {
        let config = DatabaseConfig {
            mode: DatabaseMode::Hybrid,
            statements: vec![DatabaseStatement {
                id: "update_order".into(),
                sql: "UPDATE orders SET status = $1 WHERE id = $2".into(),
            }],
            rules: DatabaseRules::mvp_defaults(),
        };

        let json = serde_json::to_string(&config).unwrap();
        let parsed: DatabaseConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.mode, config.mode);
        assert_eq!(parsed.statements.len(), 1);
        assert_eq!(parsed.statements[0].id, "update_order");
    }

    #[test]
    fn mvp_defaults_block_dangerous_operations() {
        let rules = DatabaseRules::mvp_defaults();
        assert!(rules.blocked_operations.contains(&OperationClass::Ddl));
        assert!(rules
            .blocked_operations
            .contains(&OperationClass::GrantRevoke));
        assert!(rules.blocked_operations.contains(&OperationClass::CopyIo));
        assert!(rules.blocked_operations.contains(&OperationClass::Unknown));
    }

    #[test]
    fn mvp_defaults_require_approval_for_destructive_writes() {
        let rules = DatabaseRules::mvp_defaults();
        assert!(rules.require_approval_for.contains(&OperationClass::Delete));
        assert!(rules.require_approval_for.contains(&OperationClass::Update));
    }

    #[test]
    fn mvp_defaults_limit_rows_affected() {
        let rules = DatabaseRules::mvp_defaults();
        assert_eq!(rules.max_rows_affected_without_approval, Some(1));
    }
}
