//! SQLite backend for the approval store.
//!
//! State transitions use `BEGIN IMMEDIATE` for single-writer atomicity.

use std::sync::Arc;

use crate::approval_types::*;
use crate::approvals::ApprovalStore;
use crate::sqlite::SqliteStateDb;

// ApprovalStore

// SQLite row helpers

/// Intermediate row for reconstructing ApprovalRecord from SQLite.
struct SqliteApprovalRow {
    claim_token: Option<String>,
    claimed_by: Option<String>,
    claimed_at: Option<String>,
    claim_expires_at_unix: Option<i64>,
    completed_at: Option<String>,
    terminal_trace_id: Option<String>,
    receipt_id: Option<String>,
    deny_reason: Option<String>,
    error_code: Option<String>,
    terminal_outcome_kind: Option<String>,
    terminal_outcome_at: Option<String>,
    terminal_outcome_detail: Option<String>,
}

/// Convert a flat SQLite row into the grouped ApprovalRecord structure.
fn record_from_row(
    state: ApprovalState,
    payload: PendingApproval,
    row: SqliteApprovalRow,
) -> ApprovalRecord {
    let claim = match (
        row.claimed_by,
        row.claimed_at,
        row.claim_token,
        row.claim_expires_at_unix,
    ) {
        (Some(by), Some(at), Some(tok), Some(exp)) => Some(ClaimInfo {
            claimed_by: by,
            claimed_at: at,
            claim_token: tok,
            claim_expires_at_unix: exp,
        }),
        _ => None,
    };

    let outcome_marker = match (
        row.terminal_outcome_kind,
        row.terminal_outcome_at,
        row.terminal_outcome_detail,
    ) {
        (Some(kind), Some(at), Some(detail)) => Some(OutcomeMarker { kind, at, detail }),
        _ => None,
    };

    let completion = match (row.completed_at, row.terminal_trace_id) {
        (Some(completed_at), Some(trace_id)) => Some(CompletionInfo {
            completed_at,
            trace_id,
            receipt_id: row.receipt_id,
            deny_reason: row.deny_reason,
            error_code: row.error_code,
        }),
        _ => None,
    };

    ApprovalRecord {
        state,
        payload,
        claim,
        outcome_marker,
        completion,
    }
}

/// Approval lifecycle store backed by Redis or an in-memory store.
///
/// All state transitions are atomic. Created once at startup; shared via
impl ApprovalStore {
    pub(crate) async fn sqlite_create(
        &self,
        db: &Arc<SqliteStateDb>,
        record: &ApprovalRecord,
    ) -> Result<(), ApprovalError> {
        let db = db.clone();
        let aid = record.payload.approval_id.clone();
        let state_str = record.state.as_str().to_string();
        let payload_json = serde_json::to_string(&record.payload)
            .map_err(|e| ApprovalError::DataCorrupted(e.to_string()))?;
        let created_at = record.payload.created_at.clone();
        let ttl_secs = self.default_ttl.as_secs() as i64;
        let expires = chrono::Utc::now().timestamp() + ttl_secs;

        tokio::task::spawn_blocking(move || {
            let conn = db
                .conn()
                .map_err(|e| ApprovalError::DataCorrupted(e.to_string()))?;
            let inserted = conn
                .prepare_cached(
                    "INSERT OR IGNORE INTO pending_approvals
                     (approval_id, state, payload_json, created_at, expires_at_unix)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                )
                .map_err(|e| ApprovalError::DataCorrupted(e.to_string()))?
                .execute(rusqlite::params![
                    aid,
                    state_str,
                    payload_json,
                    created_at,
                    expires
                ])
                .map_err(|e| ApprovalError::DataCorrupted(e.to_string()))?;
            if inserted == 0 {
                return Err(ApprovalError::AlreadyExists { approval_id: aid });
            }
            Ok(())
        })
        .await
        .map_err(|e| ApprovalError::Unavailable(e.to_string()))?
    }

    pub(crate) async fn sqlite_get_pending(
        &self,
        db: &Arc<SqliteStateDb>,
        approval_id: &str,
    ) -> Result<Option<PendingApproval>, ApprovalError> {
        let db = db.clone();
        let aid = approval_id.to_string();
        let now = chrono::Utc::now().timestamp();

        tokio::task::spawn_blocking(move || {
            let conn = db
                .conn()
                .map_err(|e| ApprovalError::DataCorrupted(e.to_string()))?;
            let result: Result<String, _> = conn
                .prepare_cached(
                    "SELECT payload_json FROM pending_approvals
                 WHERE approval_id = ?1 AND state = 'pending' AND expires_at_unix > ?2",
                )
                .map_err(|e| ApprovalError::Unavailable(e.to_string()))?
                .query_row(rusqlite::params![aid, now], |row| row.get(0));
            match result {
                Ok(json) => {
                    let pending: PendingApproval = serde_json::from_str(&json)
                        .map_err(|e| ApprovalError::DataCorrupted(e.to_string()))?;
                    Ok(Some(pending))
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(ApprovalError::Unavailable(e.to_string())),
            }
        })
        .await
        .map_err(|e| ApprovalError::Unavailable(e.to_string()))?
    }

    /// Retrieve the approval payload regardless of lifecycle state.
    pub(crate) async fn sqlite_get_payload(
        &self,
        db: &Arc<SqliteStateDb>,
        approval_id: &str,
    ) -> Result<Option<PendingApproval>, ApprovalError> {
        let db = db.clone();
        let aid = approval_id.to_string();

        tokio::task::spawn_blocking(move || {
            let conn = db
                .conn()
                .map_err(|e| ApprovalError::DataCorrupted(e.to_string()))?;
            let result: Result<String, _> = conn
                .prepare_cached("SELECT payload_json FROM pending_approvals WHERE approval_id = ?1")
                .map_err(|e| ApprovalError::Unavailable(e.to_string()))?
                .query_row(rusqlite::params![aid], |row| row.get(0));
            match result {
                Ok(json) => {
                    let pending: PendingApproval = serde_json::from_str(&json)
                        .map_err(|e| ApprovalError::DataCorrupted(e.to_string()))?;
                    Ok(Some(pending))
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(ApprovalError::Unavailable(e.to_string())),
            }
        })
        .await
        .map_err(|e| ApprovalError::Unavailable(e.to_string()))?
    }

    pub(crate) async fn sqlite_get_record(
        &self,
        db: &Arc<SqliteStateDb>,
        approval_id: &str,
    ) -> Result<Option<ApprovalRecord>, ApprovalError> {
        let db = db.clone();
        let aid = approval_id.to_string();

        tokio::task::spawn_blocking(move || {
            let conn = db
                .conn()
                .map_err(|e| ApprovalError::DataCorrupted(e.to_string()))?;
            let result = conn
                .prepare_cached(
                    "SELECT state, payload_json, claim_token, claimed_by, claimed_at,
                        claim_expires_at_unix, completed_at, terminal_trace_id,
                        receipt_id, deny_reason, error_code,
                        terminal_outcome_kind, terminal_outcome_at, terminal_outcome_detail
                 FROM pending_approvals WHERE approval_id = ?1",
                )
                .map_err(|e| ApprovalError::Unavailable(e.to_string()))?
                .query_row(rusqlite::params![aid], |row| {
                    let state_str: String = row.get(0)?;
                    let payload_json: String = row.get(1)?;
                    Ok((
                        state_str,
                        payload_json,
                        SqliteApprovalRow {
                            claim_token: row.get(2)?,
                            claimed_by: row.get(3)?,
                            claimed_at: row.get(4)?,
                            claim_expires_at_unix: row.get(5)?,
                            completed_at: row.get(6)?,
                            terminal_trace_id: row.get(7)?,
                            receipt_id: row.get(8)?,
                            deny_reason: row.get(9)?,
                            error_code: row.get(10)?,
                            terminal_outcome_kind: row.get(11)?,
                            terminal_outcome_at: row.get(12)?,
                            terminal_outcome_detail: row.get(13)?,
                        },
                    ))
                });
            match result {
                Ok((state_str, payload_json, row)) => {
                    let state = ApprovalState::from_db_str(&state_str).ok_or_else(|| {
                        ApprovalError::DataCorrupted(format!(
                            "unknown approval state in database: {state_str}"
                        ))
                    })?;
                    let payload: PendingApproval = serde_json::from_str(&payload_json)
                        .map_err(|e| ApprovalError::DataCorrupted(e.to_string()))?;
                    Ok(Some(record_from_row(state, payload, row)))
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(ApprovalError::Unavailable(e.to_string())),
            }
        })
        .await
        .map_err(|e| ApprovalError::Unavailable(e.to_string()))?
    }

    pub(crate) async fn sqlite_list(
        &self,
        db: &Arc<SqliteStateDb>,
        state_filter: Option<ApprovalState>,
        limit: usize,
    ) -> Result<Vec<ApprovalSummary>, ApprovalError> {
        let db = db.clone();

        tokio::task::spawn_blocking(move || {
            let conn = db
                .conn()
                .map_err(|e| ApprovalError::DataCorrupted(e.to_string()))?;
            let (sql, params): (&str, Vec<Box<dyn rusqlite::types::ToSql>>) = match state_filter {
                Some(s) => (
                    "SELECT state, payload_json, claimed_by
                         FROM pending_approvals WHERE state = ?1
                         ORDER BY created_at DESC LIMIT ?2",
                    vec![
                        Box::new(s.as_str().to_string()) as Box<dyn rusqlite::types::ToSql>,
                        Box::new(limit as i64),
                    ],
                ),
                None => (
                    "SELECT state, payload_json, claimed_by
                     FROM pending_approvals
                     ORDER BY created_at DESC LIMIT ?1",
                    vec![Box::new(limit as i64) as Box<dyn rusqlite::types::ToSql>],
                ),
            };

            let mut stmt = conn
                .prepare_cached(sql)
                .map_err(|e| ApprovalError::Unavailable(e.to_string()))?;
            let params_refs: Vec<&dyn rusqlite::types::ToSql> =
                params.iter().map(|p| p.as_ref()).collect();
            let rows = stmt
                .query_map(params_refs.as_slice(), |row| {
                    let state_str: String = row.get(0)?;
                    let payload_json: String = row.get(1)?;
                    let claimed_by: Option<String> = row.get(2)?;
                    Ok((state_str, payload_json, claimed_by))
                })
                .map_err(|e| ApprovalError::Unavailable(e.to_string()))?;

            let mut results = Vec::new();
            for row in rows {
                let (state_str, payload_json, claimed_by) =
                    row.map_err(|e| ApprovalError::Unavailable(e.to_string()))?;
                let state = match ApprovalState::from_db_str(&state_str) {
                    Some(s) => s,
                    None => continue, // skip corrupted
                };
                let payload: PendingApproval = match serde_json::from_str(&payload_json) {
                    Ok(p) => p,
                    Err(_) => continue, // skip corrupted
                };
                results.push(ApprovalSummary {
                    approval_id: payload.approval_id.clone(),
                    state,
                    action_id: Arc::clone(&payload.action_id),
                    action_version: Arc::clone(&payload.plan.action_version),
                    principal: Arc::clone(&payload.auth_context.principal),
                    session_id: Arc::clone(&payload.auth_context.session_id),
                    owner: payload.auth_context.owner.clone(),
                    risk_level: payload.plan.risk_level,
                    request_hash: Arc::clone(&payload.request_hash),
                    created_at: payload.created_at,
                    expires_at: payload.plan.core.expires_at.to_rfc3339(),
                    claimed_by,
                });
            }
            Ok(results)
        })
        .await
        .map_err(|e| ApprovalError::Unavailable(e.to_string()))?
    }

    pub(crate) async fn sqlite_claim(
        &self,
        db: &Arc<SqliteStateDb>,
        approval_id: &str,
        operator_id: &str,
        claim_token: &str,
        now_unix: i64,
        claimed_at: &str,
    ) -> Result<ClaimedApproval, ApprovalError> {
        let db = db.clone();
        let aid = approval_id.to_string();
        let op = operator_id.to_string();
        let tok = claim_token.to_string();
        let cat = claimed_at.to_string();
        let claim_ttl = self.claim_ttl_secs;
        let default_ttl_secs = self.default_ttl.as_secs() as i64;

        tokio::task::spawn_blocking(move || {
            let conn = db
                .conn()
                .map_err(|e| ApprovalError::DataCorrupted(e.to_string()))?;
            let tx = conn
                .unchecked_transaction()
                .map_err(|e| ApprovalError::Unavailable(e.to_string()))?;

            // Read current state.
            let row: Result<(String, String, Option<String>, Option<i64>), _> = tx
                .prepare_cached(
                    "SELECT state, payload_json, terminal_outcome_kind, claim_expires_at_unix
                 FROM pending_approvals
                 WHERE approval_id = ?1 AND expires_at_unix > ?2",
                )
                .map_err(|e| ApprovalError::Unavailable(e.to_string()))?
                .query_row(
                    rusqlite::params![aid, now_unix - default_ttl_secs.max(0)],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                );

            let (state_str, payload_json, outcome_kind, claim_exp) = match row {
                Ok(r) => r,
                Err(rusqlite::Error::QueryReturnedNoRows) => {
                    return Err(ApprovalError::NotFound { approval_id: aid });
                }
                Err(e) => return Err(ApprovalError::Unavailable(e.to_string())),
            };

            let state = ApprovalState::from_db_str(&state_str).ok_or_else(|| {
                ApprovalError::DataCorrupted(format!("unknown state: {state_str}"))
            })?;
            validate_claim_transition(state, outcome_kind.is_some(), claim_exp, now_unix, &aid)?;

            let claim_exp_new = now_unix + claim_ttl as i64;
            tx.prepare_cached(
                "UPDATE pending_approvals
                 SET state = 'claimed', claimed_by = ?1, claimed_at = ?2,
                     claim_token = ?3, claim_expires_at_unix = ?4
                 WHERE approval_id = ?5",
            )
            .map_err(|e| ApprovalError::Unavailable(e.to_string()))?
            .execute(rusqlite::params![op, cat, tok, claim_exp_new, aid])
            .map_err(|e| ApprovalError::Unavailable(e.to_string()))?;

            tx.commit()
                .map_err(|e| ApprovalError::Unavailable(e.to_string()))?;

            let payload: PendingApproval = serde_json::from_str(&payload_json)
                .map_err(|e| ApprovalError::DataCorrupted(e.to_string()))?;

            Ok(ClaimedApproval {
                pending: payload,
                claim_token: tok,
                claimed_at: cat,
                claimed_by: op,
            })
        })
        .await
        .map_err(|e| ApprovalError::Unavailable(e.to_string()))?
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn sqlite_complete(
        &self,
        db: &Arc<SqliteStateDb>,
        approval_id: &str,
        claim_token: &str,
        state_str: &str,
        trace_id: &str,
        completed_at: &str,
        detail_key: &str,
        detail_value: &str,
    ) -> Result<(), ApprovalError> {
        let db = db.clone();
        let aid = approval_id.to_string();
        let tok = claim_token.to_string();
        let st = state_str.to_string();
        let tid = trace_id.to_string();
        let cat = completed_at.to_string();
        let dk = detail_key.to_string();
        let dv = detail_value.to_string();

        tokio::task::spawn_blocking(move || {
            let conn = db
                .conn()
                .map_err(|e| ApprovalError::DataCorrupted(e.to_string()))?;
            let tx = conn
                .unchecked_transaction()
                .map_err(|e| ApprovalError::Unavailable(e.to_string()))?;

            let (cur_state, cur_token): (String, Option<String>) = tx
                .prepare_cached(
                    "SELECT state, claim_token FROM pending_approvals WHERE approval_id = ?1",
                )
                .map_err(|e| ApprovalError::Unavailable(e.to_string()))?
                .query_row(rusqlite::params![aid], |r| Ok((r.get(0)?, r.get(1)?)))
                .map_err(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => ApprovalError::NotFound {
                        approval_id: aid.clone(),
                    },
                    e => ApprovalError::Unavailable(e.to_string()),
                })?;

            let cur_state = ApprovalState::from_db_str(&cur_state).ok_or_else(|| {
                ApprovalError::DataCorrupted(format!(
                    "unknown approval state in database: {cur_state}"
                ))
            })?;
            require_claimed_with_token(cur_state, cur_token.as_deref(), &tok, &aid)?;

            // Set the detail column.
            let (receipt_id, deny_reason, error_code) = match dk.as_str() {
                "receipt_id" => (Some(dv.clone()), None, None),
                "deny_reason" => (None, Some(dv.clone()), None),
                "error_code" => (None, None, Some(dv.clone())),
                _ => (None, None, None),
            };

            tx.prepare_cached(
                "UPDATE pending_approvals
                 SET state = ?1, completed_at = ?2, terminal_trace_id = ?3,
                     receipt_id = COALESCE(?4, receipt_id),
                     deny_reason = COALESCE(?5, deny_reason),
                     error_code = COALESCE(?6, error_code)
                 WHERE approval_id = ?7",
            )
            .map_err(|e| ApprovalError::Unavailable(e.to_string()))?
            .execute(rusqlite::params![
                st,
                cat,
                tid,
                receipt_id,
                deny_reason,
                error_code,
                aid
            ])
            .map_err(|e| ApprovalError::Unavailable(e.to_string()))?;

            tx.commit()
                .map_err(|e| ApprovalError::Unavailable(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| ApprovalError::Unavailable(e.to_string()))?
    }

    pub(crate) async fn sqlite_write_outcome(
        &self,
        db: &Arc<SqliteStateDb>,
        approval_id: &str,
        claim_token: &str,
        outcome_kind: &str,
        outcome_detail: &str,
        outcome_at: &str,
    ) -> Result<(), ApprovalError> {
        let db = db.clone();
        let aid = approval_id.to_string();
        let tok = claim_token.to_string();
        let ok = outcome_kind.to_string();
        let od = outcome_detail.to_string();
        let oa = outcome_at.to_string();

        tokio::task::spawn_blocking(move || {
            let conn = db
                .conn()
                .map_err(|e| ApprovalError::DataCorrupted(e.to_string()))?;
            let tx = conn
                .unchecked_transaction()
                .map_err(|e| ApprovalError::Unavailable(e.to_string()))?;

            let (cur_state, cur_token, existing_outcome): (String, Option<String>, Option<String>) =
                tx.prepare_cached(
                    "SELECT state, claim_token, terminal_outcome_kind
                     FROM pending_approvals WHERE approval_id = ?1",
                )
                .map_err(|e| ApprovalError::Unavailable(e.to_string()))?
                .query_row(rusqlite::params![aid], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })
                .map_err(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => ApprovalError::NotFound {
                        approval_id: aid.clone(),
                    },
                    e => ApprovalError::Unavailable(e.to_string()),
                })?;

            // Idempotent
            if existing_outcome.is_some() {
                tx.commit()
                    .map_err(|e| ApprovalError::Unavailable(e.to_string()))?;
                return Ok(());
            }

            let cur_state = ApprovalState::from_db_str(&cur_state).ok_or_else(|| {
                ApprovalError::DataCorrupted(format!(
                    "unknown approval state in database: {cur_state}"
                ))
            })?;
            require_claimed_with_token(cur_state, cur_token.as_deref(), &tok, &aid)?;

            tx.prepare_cached(
                "UPDATE pending_approvals
                 SET terminal_outcome_kind = ?1, terminal_outcome_at = ?2,
                     terminal_outcome_detail = ?3
                 WHERE approval_id = ?4",
            )
            .map_err(|e| ApprovalError::Unavailable(e.to_string()))?
            .execute(rusqlite::params![ok, oa, od, aid])
            .map_err(|e| ApprovalError::Unavailable(e.to_string()))?;

            tx.commit()
                .map_err(|e| ApprovalError::Unavailable(e.to_string()))?;
            Ok(())
        })
        .await
        .map_err(|e| ApprovalError::Unavailable(e.to_string()))?
    }
}

// Tests — SQLite backend: contract tests + SQLite-specific tests

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use crate::approval_contract_tests as contract;
    use crate::approvals::ApprovalStore;
    use crate::sqlite::SqliteStateDb;

    // Helpers

    fn store() -> ApprovalStore {
        let db = Arc::new(SqliteStateDb::open_in_memory().unwrap());
        ApprovalStore::sqlite(db, Duration::from_secs(300))
    }

    fn store_short_claim() -> ApprovalStore {
        ApprovalStore {
            claim_ttl_secs: 1,
            ..store()
        }
    }

    // Contract tests

    #[tokio::test]
    async fn contract_create_and_get() {
        contract::create_and_get(&store()).await;
    }

    #[tokio::test]
    async fn contract_get_nonexistent_returns_none() {
        contract::get_nonexistent_returns_none(&store()).await;
    }

    #[tokio::test]
    async fn contract_create_duplicate_returns_already_exists() {
        contract::create_duplicate_returns_already_exists(&store()).await;
    }

    #[tokio::test]
    async fn contract_full_approve_lifecycle() {
        contract::full_approve_lifecycle(&store()).await;
    }

    #[tokio::test]
    async fn contract_full_deny_lifecycle() {
        contract::full_deny_lifecycle(&store()).await;
    }

    #[tokio::test]
    async fn contract_full_failed_lifecycle() {
        contract::full_failed_lifecycle(&store()).await;
    }

    #[tokio::test]
    async fn contract_double_claim_rejected() {
        contract::double_claim_rejected(&store()).await;
    }

    #[tokio::test]
    async fn contract_terminal_state_blocks_reclaim() {
        contract::terminal_state_blocks_reclaim(&store()).await;
    }

    #[tokio::test]
    async fn contract_wrong_claim_token_rejected() {
        contract::wrong_claim_token_rejected(&store()).await;
    }

    #[tokio::test]
    async fn contract_expired_claim_can_be_reclaimed() {
        contract::expired_claim_can_be_reclaimed(&store_short_claim()).await;
    }

    #[tokio::test]
    async fn contract_outcome_marker_blocks_reclaim() {
        contract::outcome_marker_blocks_reclaim(&store_short_claim()).await;
    }

    #[tokio::test]
    async fn contract_outcome_marker_is_idempotent() {
        contract::outcome_marker_is_idempotent(&store()).await;
    }

    #[tokio::test]
    async fn contract_outcome_marker_rejects_wrong_token() {
        contract::outcome_marker_rejects_wrong_token(&store()).await;
    }

    #[tokio::test]
    async fn contract_outcome_marker_rejects_unclaimed() {
        contract::outcome_marker_rejects_unclaimed(&store()).await;
    }

    #[tokio::test]
    async fn contract_get_status_synthesizes_from_outcome_marker() {
        contract::get_status_synthesizes_from_outcome_marker(&store()).await;
    }

    #[tokio::test]
    async fn contract_complete_after_outcome_marker() {
        contract::complete_after_outcome_marker(&store()).await;
    }

    #[tokio::test]
    async fn contract_list_returns_all() {
        contract::list_returns_all(&store()).await;
    }

    #[tokio::test]
    async fn contract_list_filters_by_state() {
        contract::list_filters_by_state(&store()).await;
    }

    #[tokio::test]
    async fn contract_list_respects_limit() {
        contract::list_respects_limit(&store()).await;
    }

    #[tokio::test]
    async fn contract_plan_hash_survives_roundtrip() {
        contract::plan_hash_survives_roundtrip(&store()).await;
    }

    #[tokio::test]
    async fn contract_unresolved_domains_survive_roundtrip() {
        contract::unresolved_domains_survive_roundtrip(&store()).await;
    }

    #[tokio::test]
    async fn contract_unresolved_paths_survive_roundtrip() {
        contract::unresolved_paths_survive_roundtrip(&store()).await;
    }
}
