//! Host implementation for `latchgate:io/database` — SQL query execution.
//!
//! SECURITY: every database request passes host-side validation against
//! the manifest database_config before any SQL reaches the database.
//! Writes with row-count limits execute inside a transaction with rollback
//! on limit violation.

use sqlx::Row as _;
use tracing::{debug, info, warn};

use super::latchgate;
use super::WasmHostState;

impl latchgate::provider::io_database::Host for WasmHostState {
    async fn execute_query(
        &mut self,
        req: latchgate::provider::io_database::DatabaseRequest,
    ) -> Result<latchgate::provider::io_database::QueryResult, String> {
        debug!(
            trace_id = %self.host_io.trace_id,
            has_statement_id = req.statement_id.is_some(),
            has_query = req.query.is_some(),
            "host_io.database: execute_query"
        );

        if let Err(e) = self.host_io.check_import_allowed("latchgate:io/database") {
            return Err(format!("{e}"));
        }
        if let Err(e) = self.host_io.consume_io_call() {
            return Err(format!("{e}"));
        }

        let pool = self.resources.db_pool.as_ref().ok_or_else(|| {
            "database host import unavailable: database_url is not configured in latchgate.toml"
                .to_string()
        })?;

        // ---------------------------------------------------------------
        // SECURITY: validate request against manifest database config.
        //
        // Every database action MUST have a database_config in the manifest.
        // If present, every request must pass host-side validation before
        // any SQL reaches the database. If absent, the action is denied.
        // ---------------------------------------------------------------

        let validated = if let Some(ref db_config) = self.host_io.database_config {
            match crate::database::validate_database_request(
                req.statement_id.as_deref(),
                req.query.as_deref(),
                &req.params,
                db_config,
            ) {
                Ok(v) => v,
                Err(e) => {
                    warn!(
                        trace_id = %self.host_io.trace_id,
                        error = %e,
                        "host_io.database: request validation failed (DENY)"
                    );
                    return Err(format!("database request denied: {e}"));
                }
            }
        } else {
            // SECURITY: every database action MUST have an explicit
            // database_config in the manifest. Without it, the host cannot
            // enforce mode rules (strict/parameterized/hybrid), approval
            // thresholds, WHERE clause requirements, or row-affected limits.
            // There is no fallback path. No exceptions.
            warn!(
                trace_id = %self.host_io.trace_id,
                "host_io.database: DENY — no database_config in manifest"
            );
            return Err("database action denied: database_config required in manifest".into());
        };

        info!(
            trace_id = %self.host_io.trace_id,
            operation = %validated.operation_class,
            is_predeclared = validated.is_predeclared,
            statement_id = ?validated.statement_id,
            "host_io.database: executing validated query"
        );

        // Execute the validated SQL.
        if validated.operation_class.is_read() {
            let mut q = sqlx::query(&validated.sql);
            for p in &validated.params {
                q = q.bind(p.as_str());
            }
            let rows = q
                .fetch_all(pool)
                .await
                .map_err(|e| format!("database query failed: {e}"))?;

            use sqlx::Column as _;
            let columns: Vec<String> = rows
                .first()
                .map(|r| {
                    sqlx::postgres::PgRow::columns(r)
                        .iter()
                        .map(|c| c.name().to_string())
                        .collect()
                })
                .unwrap_or_default();

            let rows_data: Vec<serde_json::Map<String, serde_json::Value>> = rows
                .iter()
                .map(|row| {
                    let mut obj = serde_json::Map::new();
                    for col in sqlx::postgres::PgRow::columns(row) {
                        let val = row
                            .try_get::<String, _>(col.name())
                            .map(serde_json::Value::String)
                            .unwrap_or(serde_json::Value::Null);
                        obj.insert(col.name().to_string(), val);
                    }
                    obj
                })
                .collect();

            let rows_json =
                serde_json::to_string(&rows_data).map_err(|e| format!("serialize rows: {e}"))?;

            debug!(
                trace_id = %self.host_io.trace_id,
                row_count = rows_data.len(),
                "host_io.database: SELECT returned rows"
            );

            Ok(latchgate::provider::io_database::QueryResult {
                rows_affected: 0,
                transaction_id: String::new(),
                columns,
                rows_json,
            })
        } else {
            // SECURITY: when max_rows_affected_without_approval is configured
            // for auto-allowed writes, execute inside a transaction so the
            // mutation can be rolled back if the limit is violated. Without
            // this, the side effect persists even though the caller receives
            // an error.
            let needs_row_guard = !validated.requires_approval
                && self
                    .host_io
                    .database_config
                    .as_ref()
                    .and_then(|c| c.rules.max_rows_affected_without_approval)
                    .is_some();

            if needs_row_guard {
                let max_rows = self
                    .host_io
                    .database_config
                    .as_ref()
                    .and_then(|c| c.rules.max_rows_affected_without_approval)
                    .ok_or("database_config with max_rows_affected_without_approval required for row guard")?;

                let mut tx = pool
                    .begin()
                    .await
                    .map_err(|e| format!("database begin transaction failed: {e}"))?;

                let mut q = sqlx::query(&validated.sql);
                for p in &validated.params {
                    q = q.bind(p.as_str());
                }
                let result = q
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| format!("database execute failed: {e}"))?;

                let rows = result.rows_affected();

                if rows > max_rows {
                    // Rollback — the mutation never commits.
                    tx.rollback()
                        .await
                        .map_err(|e| format!("database rollback failed: {e}"))?;
                    warn!(
                        trace_id = %self.host_io.trace_id,
                        rows_affected = rows,
                        max_allowed = max_rows,
                        operation = %validated.operation_class,
                        "host_io.database: rows_affected ({rows}) exceeds limit ({max_rows}) \
                         — transaction rolled back",
                    );
                    return Err(format!(
                        "rows_affected violation: {rows} rows affected, \
                         max_rows_affected_without_approval is {max_rows} \
                         (transaction rolled back)"
                    ));
                }

                tx.commit()
                    .await
                    .map_err(|e| format!("database commit failed: {e}"))?;

                debug!(
                    trace_id = %self.host_io.trace_id,
                    rows_affected = rows,
                    operation = %validated.operation_class,
                    "host_io.database: DML committed within row limit"
                );

                Ok(latchgate::provider::io_database::QueryResult {
                    rows_affected: rows,
                    transaction_id: String::new(),
                    columns: vec![],
                    rows_json: "[]".to_string(),
                })
            } else {
                // No row guard needed: either approved, or no limit configured.
                let mut q = sqlx::query(&validated.sql);
                for p in &validated.params {
                    q = q.bind(p.as_str());
                }
                let result = q
                    .execute(pool)
                    .await
                    .map_err(|e| format!("database execute failed: {e}"))?;

                let rows = result.rows_affected();

                debug!(
                    trace_id = %self.host_io.trace_id,
                    rows_affected = rows,
                    operation = %validated.operation_class,
                    "host_io.database: DML executed"
                );

                Ok(latchgate::provider::io_database::QueryResult {
                    rows_affected: rows,
                    transaction_id: String::new(),
                    columns: vec![],
                    rows_json: "[]".to_string(),
                })
            }
        }
    }
}
