//! LatchGate Database provider — controlled SQL modes.
//!
//! Supports two request shapes:
//!
//! 1. **Predeclared statement** — agent sends `statement_id` + params.
//!    Host resolves SQL from the action manifest.
//!
//! 2. **Parameterized query** — agent sends `query` + params.
//!    Host validates against mode rules before execution.
//!
//! Both shapes go through the host `execute-query` import, which enforces
//! database_mode rules, classifies the operation, and manages credentials.

wit_bindgen::generate!({
    world: "provider",
    path: "../wit",
});

use serde::{Deserialize, Serialize};

use crate::latchgate::provider::io_database;
use crate::latchgate::provider::io_log;

/// Agent request: predeclared statement OR parameterized query.
///
/// SECURITY: sending both `statement_id` and `query` is rejected.
/// Sending neither is also rejected.
#[derive(Deserialize)]
struct DbRequest {
    /// Predeclared statement identifier from the manifest.
    #[serde(default)]
    statement_id: Option<String>,
    /// Parameterized SQL query (agent-authored).
    #[serde(default)]
    query: Option<String>,
    /// Positional parameters.
    #[serde(default)]
    params: Vec<String>,
}

#[derive(Serialize)]
struct DbResponse {
    rows_affected: u64,
    transaction_id: String,
    columns: Vec<String>,
    rows_json: String,
}

struct DatabaseProvider;

impl Guest for DatabaseProvider {
    fn execute(task_json: String) -> Result<String, String> {
        io_log::log_info("database provider: parsing request");

        let req: DbRequest = serde_json::from_str(&task_json)
            .map_err(|e| format!("invalid request JSON: {e}"))?;

        // SECURITY: reject ambiguous requests at the provider level too
        // (belt and suspenders — host enforces this as well).
        match (&req.statement_id, &req.query) {
            (Some(_), Some(_)) => {
                return Err(
                    "invalid request: statement_id and query are mutually exclusive".into(),
                );
            }
            (None, None) => {
                return Err("invalid request: either statement_id or query is required".into());
            }
            _ => {}
        }

        let db_req = io_database::DatabaseRequest {
            statement_id: req.statement_id,
            query: req.query,
            params: req.params,
        };

        let result = io_database::execute_query(&db_req)?;

        let response = DbResponse {
            rows_affected: result.rows_affected,
            transaction_id: result.transaction_id,
            columns: result.columns,
            rows_json: result.rows_json,
        };

        serde_json::to_string(&response)
            .map_err(|e| format!("failed to serialise response: {e}"))
    }
}

export!(DatabaseProvider);
