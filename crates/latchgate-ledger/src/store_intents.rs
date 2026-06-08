//! Execution intents, one-shot grant guard, and evidence finalization.
//!
//! The pre-dispatch intent + consumed-grant guard ensure that each grant
//! dispatches at most once, and that crash-recovery can detect intents
//! without matching receipts. Evidence finalization atomically persists
//! the receipt and final audit event — the success response is gated on
//! this transaction.

use std::io::Write;

use tracing::instrument;

use crate::events::AuditEvent;
use crate::store::{compute_event_hash, ExecutionIntent, LedgerError, LedgerStore};
use latchgate_core::ExecutionReceipt;

impl LedgerStore {
    /// Persist a pre-dispatch [`ExecutionIntent`].
    #[instrument(
        name = "ledger.write_intent",
        skip(self, intent),
        fields(trace_id = %intent.trace_id, grant_id = %intent.grant_id),
    )]
    pub fn write_intent(&self, intent: &ExecutionIntent) -> Result<(), LedgerError> {
        let inner = self.writer.lock().map_err(|_| LedgerError::LockPoisoned)?;
        inner
            .conn
            .prepare_cached(
                "INSERT OR IGNORE INTO execution_intents \
             (trace_id, grant_id, action_id, principal, provider_module_digest, \
              request_hash, approved_by, started_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?
            .execute(rusqlite::params![
                &*intent.trace_id,
                &*intent.grant_id,
                &*intent.action_id,
                &*intent.principal,
                &*intent.provider_module_digest,
                &*intent.request_hash,
                intent.approved_by.as_deref(),
                &*intent.started_at,
            ])?;
        Ok(())
    }

    /// for a given `grant_id` and [`LedgerError::GrantAlreadyConsumed`] on
    /// any subsequent call.
    ///
    /// # Security purpose
    ///
    /// This is the **independent one-shot execution guard**. It enforces
    /// that a given grant can dispatch a provider at most once, regardless
    /// of whether the session has budget limits. The kernel calls this
    /// immediately before WASM dispatch (after the `ExecutionIntent` write
    /// and before `wasm_runtime.execute()`). If the INSERT fails due to the
    /// UNIQUE constraint, the grant was already consumed — possibly by a
    /// concurrent request or a retry after crash — and dispatch is denied.
    ///
    /// This guard is independent of the budget system. Sessions with
    /// unbounded budgets (`i64::MAX`) are still protected.
    ///
    /// # Blocking
    ///
    /// Performs synchronous SQLite I/O while holding the Mutex. Callers on
    /// a tokio runtime MUST wrap in `spawn_blocking`.
    pub fn try_consume_grant(
        &self,
        grant_id: &str,
        action_id: &str,
        principal: &str,
    ) -> Result<(), LedgerError> {
        let inner = self.writer.lock().map_err(|_| LedgerError::LockPoisoned)?;
        let result = inner
            .conn
            .prepare_cached(
                "INSERT INTO consumed_grants (grant_id, action_id, principal, consumed_at) \
             VALUES (?1, ?2, ?3, ?4)",
            )
            .and_then(|mut stmt| {
                stmt.execute(rusqlite::params![
                    grant_id,
                    action_id,
                    principal,
                    chrono::Utc::now().to_rfc3339(),
                ])
            });
        match result {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Err(LedgerError::GrantAlreadyConsumed {
                    grant_id: grant_id.to_string(),
                })
            }
            Err(e) => Err(LedgerError::Sqlite(e)),
        }
    }

    /// Write execution intent and mark the grant consumed in a single
    /// `BEGIN IMMEDIATE` transaction.
    ///
    /// Combines [`Self::write_intent`] and [`Self::try_consume_grant`] to eliminate a
    /// second mutex acquisition and SQLite journal sync on the pre-dispatch
    /// hot path.
    ///
    /// # Transaction semantics
    ///
    /// Both writes occur atomically. If the grant was already consumed
    /// (UNIQUE constraint violation on `consumed_grants`), the intent
    /// write is rolled back — no partial state is persisted. This is safe
    /// because the prior execution that consumed the grant wrote its own
    /// intent.
    ///
    /// # Errors
    ///
    /// - [`LedgerError::GrantAlreadyConsumed`] — the one-shot guard fired;
    ///   the grant was dispatched by a prior execution.
    /// - Any other [`LedgerError`] — I/O or lock failure; fail-closed.
    ///
    /// # Blocking
    ///
    /// Performs synchronous SQLite I/O while holding the Mutex. Callers on
    /// a tokio runtime MUST wrap in `spawn_blocking`.
    #[instrument(
        name = "ledger.write_intent_and_consume",
        skip(self, intent),
        fields(trace_id = %intent.trace_id, grant_id = %intent.grant_id),
    )]

    pub fn write_intent_and_consume_grant(
        &self,
        intent: &ExecutionIntent,
        action_id: &str,
        principal: &str,
    ) -> Result<(), LedgerError> {
        let inner = self.writer.lock().map_err(|_| LedgerError::LockPoisoned)?;

        inner.conn.execute_batch("BEGIN IMMEDIATE")?;

        let result =
            (|| -> Result<(), LedgerError> {
                inner
                    .conn
                    .prepare_cached(
                        "INSERT OR IGNORE INTO execution_intents \
                 (trace_id, grant_id, action_id, principal, provider_module_digest, \
                  request_hash, approved_by, started_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    )?
                    .execute(rusqlite::params![
                        &*intent.trace_id,
                        &*intent.grant_id,
                        &*intent.action_id,
                        &*intent.principal,
                        &*intent.provider_module_digest,
                        &*intent.request_hash,
                        intent.approved_by.as_deref(),
                        &*intent.started_at,
                    ])?;

                let consume_result = inner.conn.prepare_cached(
                "INSERT INTO consumed_grants (grant_id, action_id, principal, consumed_at) \
                 VALUES (?1, ?2, ?3, ?4)",
            ).and_then(|mut stmt| stmt.execute(
                rusqlite::params![
                    intent.grant_id,
                    action_id,
                    principal,
                    chrono::Utc::now().to_rfc3339(),
                ],
            ));

                match consume_result {
                    Ok(_) => Ok(()),
                    Err(rusqlite::Error::SqliteFailure(err, _))
                        if err.code == rusqlite::ErrorCode::ConstraintViolation =>
                    {
                        Err(LedgerError::GrantAlreadyConsumed {
                            grant_id: intent.grant_id.to_string(),
                        })
                    }
                    Err(e) => Err(LedgerError::Sqlite(e)),
                }
            })();

        match result {
            Ok(()) => {
                inner.conn.execute_batch("COMMIT")?;
                Ok(())
            }
            Err(e) => {
                // Best-effort rollback. If this fails the connection is
                // left in a broken transaction state, but the Mutex
                // serialises all subsequent access and SQLite will
                // auto-rollback on the next statement.
                let _ = inner.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    /// Atomically persist a receipt and its final audit event in a single
    /// SQLite transaction. This is the **evidence finalization** step.
    ///
    /// The success response to the client is gated on this method returning
    /// `Ok(())`. If the transaction fails, neither the receipt nor the audit
    /// event is durable, and the client receives an error — not a false success.
    ///
    /// The audit event is hash-chained to the ledger (same as `write_event`).
    ///
    /// # Blocking
    ///
    /// Performs synchronous SQLite I/O while holding the Mutex. Callers on
    /// a tokio runtime MUST wrap in `spawn_blocking`.
    #[instrument(
        name = "ledger.finalize_evidence",
        skip(self, receipt, event),
        fields(
            trace_id = %event.trace_id,
            receipt_id = %receipt.receipt_id,
            grant_id = %receipt.grant_id,
        ),
    )]
    pub fn finalize_evidence(
        &self,
        receipt: &ExecutionReceipt,
        event: &mut AuditEvent,
    ) -> Result<(), LedgerError> {
        #[cfg(feature = "test-hooks")]
        {
            // One-shot fault: if armed, clear the flag and return an I/O
            // error without touching the database. Gives integration tests
            // a deterministic way to exercise the post-dispatch evidence-
            // failure branch of the execution pipeline.
            if self
                .fail_next_finalize
                .swap(false, std::sync::atomic::Ordering::AcqRel)
            {
                return Err(LedgerError::Io(std::io::Error::other(
                    "finalize_evidence: fault injected via test-hooks",
                )));
            }
        }

        // Pre-serialize receipt and column extracts outside the lock.
        // Receipt serialization can be expensive (includes provider output)
        // and is completely independent of the hash-chain state.
        let receipt_json = serde_json::to_string(receipt)?;
        let event_type_str = event.event_type.as_str();
        let decision_str = event.policy.decision.as_str();

        let mut inner = self.writer.lock().map_err(|_| LedgerError::LockPoisoned)?;

        // Hash-chain the audit event.
        event.prev_hash = inner.chain_head.clone();

        // Serialize to string directly — single pass, no intermediate Value
        // tree. The Value for canonical hashing is built via from_str after
        // the transaction commits (only on the success path).
        let event_json = serde_json::to_string(&*event)?;

        // Begin immediate transaction — acquires the write lock up front so
        // concurrent readers (WAL mode) are not blocked, but no other writer
        // can interleave.
        inner.conn.execute_batch("BEGIN IMMEDIATE")?;

        let commit_result = (|| -> Result<(), LedgerError> {
            // Write receipt (idempotent).
            inner.conn.prepare_cached(
                "INSERT OR IGNORE INTO receipts (receipt_id, grant_id, receipt_json, created_at) \
                 VALUES (?1, ?2, ?3, datetime('now'))",
            )?.execute(
                rusqlite::params![
                    receipt.receipt_id.as_str(),
                    receipt.grant_id.as_str(),
                    receipt_json,
                ],
            )?;

            // Write audit event (hash-chained).
            inner.conn.prepare_cached(
                "INSERT INTO audit_events \
                 (trace_id, timestamp, event_type, principal, session_id, action_id, decision, event_json) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?.execute(
                rusqlite::params![
                    &*event.trace_id,
                    event.timestamp,
                    event_type_str,
                    &*event.subject.principal,
                    &*event.subject.session_id,
                    &*event.action.action_id,
                    decision_str,
                    event_json,
                ],
            )?;

            inner.conn.execute_batch("COMMIT")?;
            Ok(())
        })();

        match commit_result {
            Ok(()) => {
                // Transaction committed — update chain head. Parse the
                // already-serialized JSON for the JCS canonicalizer.
                let event_value: serde_json::Value = serde_json::from_str(&event_json)?;
                inner.chain_head = Some(compute_event_hash(&event_value)?);

                // JSONL export (best-effort, outside transaction).
                if let Some(ref mut writer) = inner.jsonl_writer {
                    if let Err(e) = writeln!(writer, "{event_json}").and_then(|()| writer.flush()) {
                        tracing::warn!(error = %e, "JSONL append failed after evidence commit");
                    }
                }

                Ok(())
            }
            Err(e) => {
                // Rollback on any failure — neither receipt nor audit is durable.
                // chain_head stays unchanged.
                let _ = inner.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    /// Retrieve a stored [`ExecutionIntent`] by grant_id.
    ///
    /// Used by recovery tooling to find intents that may lack a matching
    /// receipt (dispatch happened but evidence finalization failed).
    #[instrument(name = "ledger.get_intent", skip(self), fields(%grant_id))]

    pub fn get_intent(&self, grant_id: &str) -> Result<Option<ExecutionIntent>, LedgerError> {
        self.with_reader(|conn| {
            let result = conn
                .prepare_cached(
                    "SELECT trace_id, grant_id, action_id, principal, provider_module_digest, \
             request_hash, approved_by, started_at \
             FROM execution_intents WHERE grant_id = ?1",
                )?
                .query_row([grant_id], |row| {
                    Ok(ExecutionIntent {
                        trace_id: row.get(0)?,
                        grant_id: row.get(1)?,
                        action_id: row.get(2)?,
                        principal: row.get(3)?,
                        provider_module_digest: row.get(4)?,
                        request_hash: row.get(5)?,
                        approved_by: row.get(6)?,
                        started_at: row.get(7)?,
                    })
                });
            match result {
                Ok(intent) => Ok(Some(intent)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(LedgerError::Sqlite(e)),
            }
        })
    }

    /// Find intents that have no matching receipt — potential evidence gaps.
    ///
    /// Returns intents where `grant_id` does not appear in the receipts table.
    /// Each result represents a dispatch that may have produced a side effect
    /// without durable evidence. Operators should investigate these.
    #[instrument(name = "ledger.get_unresolved_intents", skip(self))]

    pub fn get_unresolved_intents(&self) -> Result<Vec<ExecutionIntent>, LedgerError> {
        self.with_reader(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT i.trace_id, i.grant_id, i.action_id, i.principal, \
             i.provider_module_digest, i.request_hash, i.approved_by, i.started_at \
             FROM execution_intents i \
             LEFT JOIN receipts r ON i.grant_id = r.grant_id \
             WHERE r.grant_id IS NULL \
             ORDER BY i.started_at ASC",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(ExecutionIntent {
                    trace_id: row.get(0)?,
                    grant_id: row.get(1)?,
                    action_id: row.get(2)?,
                    principal: row.get(3)?,
                    provider_module_digest: row.get(4)?,
                    request_hash: row.get(5)?,
                    approved_by: row.get(6)?,
                    started_at: row.get(7)?,
                })
            })?;
            let mut intents = Vec::new();
            for row in rows {
                intents.push(row?);
            }
            Ok(intents)
        })
    }
}

// Fault-injection API (test-hooks feature only)

/// Test-only fault-injection surface.
///
/// Compiled only when the `test-hooks` cargo feature is enabled (the
/// `latchgate-tests` workspace member opts in; no release crate does).
/// Lets integration tests drive the evidence-failure branch of the
/// execution pipeline deterministically without relying on disk errors
/// or process crashes.
///
/// SECURITY: because the feature is off by default, the methods below
/// do not exist in production builds — there is no ABI path to arm a
/// fault from operator-controlled input. Removing the feature would
/// elide both the field on [`LedgerStore`] and every entry point here.
#[cfg(feature = "test-hooks")]
impl LedgerStore {
    /// Arm a one-shot fault: the next call to [`Self::finalize_evidence`]
    /// will fail with [`LedgerError::Io`], then the flag clears itself.
    ///
    /// Re-arm explicitly if more than one failure is needed. The
    /// one-shot semantics match how evidence failures are triaged in
    /// production — each is an independent durable-write failure, not
    /// a sticky state.
    pub fn arm_finalize_failure(&self) {
        self.fail_next_finalize
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Disarm a previously armed one-shot fault without consuming it.
    ///
    /// Useful for tests that set up state under a guard that must be
    /// released before asserting. The normal one-shot path (fault
    /// fires, flag clears) makes this rarely needed.
    pub fn disarm_finalize_failure(&self) {
        self.fail_next_finalize
            .store(false, std::sync::atomic::Ordering::Release);
    }
}

#[cfg(test)]
mod tests {

    use crate::events::{AuditEvent, AuditEventBuilder, Decision, EventType};
    use crate::store::LedgerError;
    use crate::store::{ExecutionIntent, LedgerStore};
    use latchgate_core::ExecutionReceipt;

    fn test_event(trace_id: &str, action_id: &str, decision: Decision) -> AuditEvent {
        AuditEventBuilder::new(trace_id, EventType::ActionCall)
            .principal("agent:test", "sess-1", "jti-1")
            .action(action_id, None, "sha256:abc", "digest_ok")
            .request("sha256:req", None)
            .policy(decision, None, None)
            .build()
    }

    // -- Write and query by trace_id --

    fn sample_intent(grant_id: &str) -> ExecutionIntent {
        ExecutionIntent {
            trace_id: format!("trace-{grant_id}"),
            grant_id: grant_id.to_string(),
            action_id: "http_api.create_ticket".to_string(),
            principal: "agent:test".to_string(),
            provider_module_digest: "sha256:aabbccdd".to_string(),
            request_hash: "sha256:reqhash".to_string(),
            approved_by: None,
            started_at: "2026-03-08T12:00:00.000Z".to_string(),
        }
    }

    fn sample_receipt() -> ExecutionReceipt {
        use latchgate_core::types::{GrantId, ReceiptId};
        use latchgate_core::{NormalizedResult, VerificationOutcome};

        let now = chrono::Utc::now();
        let mut r = ExecutionReceipt {
            receipt_id: ReceiptId::from("rcpt-test-001"),
            grant_id: GrantId::from("grant-test-001"),
            provider_module_digest:
                "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".into(),
            provider_receipt: std::sync::Arc::new(serde_json::json!({"status": 200})),
            normalized_result: NormalizedResult::Success {
                summary: "HTTP 200 OK".into(),
            },
            verification_outcome: VerificationOutcome::Verified {
                evidence: serde_json::json!({"status_code": 200}),
            },
            effect_evidence: vec![],
            result_hash: String::new(),
            receipt_signature: None,
            signing_key_id: None,
            started_at: now - chrono::Duration::seconds(1),
            finished_at: now,
            failure_class: None,
        };
        r.result_hash = r.compute_result_hash();
        r
    }

    #[test]

    fn write_and_get_intent_roundtrip() {
        let store = LedgerStore::open_in_memory(None).unwrap();
        let intent = sample_intent("grant-001");

        store.write_intent(&intent).unwrap();

        let found = store.get_intent("grant-001").unwrap();
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(&*found.trace_id, "trace-grant-001");
        assert_eq!(&*found.grant_id, "grant-001");
        assert_eq!(&*found.action_id, "http_api.create_ticket");
        assert_eq!(&*found.principal, "agent:test");
        assert!(found.approved_by.is_none());
    }

    #[test]
    fn get_intent_not_found() {
        let store = LedgerStore::open_in_memory(None).unwrap();
        let found = store.get_intent("nonexistent").unwrap();
        assert!(found.is_none());
    }

    #[test]
    fn write_intent_duplicate_is_idempotent() {
        let store = LedgerStore::open_in_memory(None).unwrap();
        let intent = sample_intent("grant-dup");
        store.write_intent(&intent).unwrap();
        let result = store.write_intent(&intent);
        assert!(result.is_ok(), "duplicate intent write must be idempotent");
    }

    #[test]
    fn intent_with_approved_by_roundtrips() {
        let store = LedgerStore::open_in_memory(None).unwrap();
        let mut intent = sample_intent("grant-approved");
        intent.approved_by = Some("alice".into());
        store.write_intent(&intent).unwrap();

        let found = store.get_intent("grant-approved").unwrap().unwrap();
        assert_eq!(found.approved_by.as_deref(), Some("alice"));
    }

    // -- Consumed grants (one-shot guard) --

    #[test]
    fn try_consume_grant_succeeds_on_first_call() {
        let store = LedgerStore::open_in_memory(None).unwrap();
        store
            .try_consume_grant("grant-001", "http_fetch", "agent:test")
            .unwrap();
    }

    #[test]
    fn try_consume_grant_rejects_duplicate() {
        let store = LedgerStore::open_in_memory(None).unwrap();
        store
            .try_consume_grant("grant-dup", "http_fetch", "agent:test")
            .unwrap();
        let err = store
            .try_consume_grant("grant-dup", "http_fetch", "agent:test")
            .unwrap_err();
        assert!(
            matches!(err, LedgerError::GrantAlreadyConsumed { ref grant_id } if grant_id == "grant-dup"),
            "expected GrantAlreadyConsumed, got: {err}"
        );
    }

    #[test]
    fn try_consume_grant_different_grants_both_succeed() {
        let store = LedgerStore::open_in_memory(None).unwrap();
        store
            .try_consume_grant("grant-a", "http_fetch", "agent:test")
            .unwrap();
        store
            .try_consume_grant("grant-b", "http_fetch", "agent:test")
            .unwrap();
    }

    // -- Combined intent + consume (transactional) --

    #[test]
    fn write_intent_and_consume_grant_succeeds() {
        let store = LedgerStore::open_in_memory(None).unwrap();
        let intent = sample_intent("grant-combined");
        store
            .write_intent_and_consume_grant(&intent, "http_fetch", "agent:test")
            .unwrap();

        // Intent was written.
        let found = store.get_intent("grant-combined").unwrap();
        assert!(found.is_some());
        assert_eq!(&*found.unwrap().grant_id, "grant-combined");
    }

    #[test]
    fn write_intent_and_consume_grant_rejects_duplicate() {
        let store = LedgerStore::open_in_memory(None).unwrap();
        let intent = sample_intent("grant-dup-combined");
        store
            .write_intent_and_consume_grant(&intent, "http_fetch", "agent:test")
            .unwrap();
        let err = store
            .write_intent_and_consume_grant(&intent, "http_fetch", "agent:test")
            .unwrap_err();
        assert!(
            matches!(err, LedgerError::GrantAlreadyConsumed { ref grant_id } if grant_id == "grant-dup-combined"),
            "expected GrantAlreadyConsumed, got: {err}"
        );
    }

    #[test]
    fn write_intent_and_consume_grant_rolls_back_intent_on_duplicate() {
        let store = LedgerStore::open_in_memory(None).unwrap();

        // First: consume the grant via the standalone method (no intent).
        store
            .try_consume_grant("grant-rollback", "http_fetch", "agent:test")
            .unwrap();

        // Second: combined call with a *different* intent trace_id.
        let mut intent = sample_intent("grant-rollback");
        intent.trace_id = "trace-second-attempt".into();
        let err = store
            .write_intent_and_consume_grant(&intent, "http_fetch", "agent:test")
            .unwrap_err();
        assert!(matches!(err, LedgerError::GrantAlreadyConsumed { .. }));

        // The intent from the rolled-back transaction must NOT exist.
        // Only the original intent (if any) should be present.
        let found = store.get_intent("grant-rollback").unwrap();
        assert!(
            found.is_none(),
            "intent must be rolled back when grant consume fails"
        );
    }

    #[test]
    fn write_intent_and_consume_grant_independent_grants() {
        let store = LedgerStore::open_in_memory(None).unwrap();
        store
            .write_intent_and_consume_grant(
                &sample_intent("grant-ind-a"),
                "http_fetch",
                "agent:test",
            )
            .unwrap();
        store
            .write_intent_and_consume_grant(
                &sample_intent("grant-ind-b"),
                "http_fetch",
                "agent:test",
            )
            .unwrap();
    }

    // -- Unresolved intents --

    #[test]
    fn unresolved_intents_returns_intents_without_receipts() {
        let store = LedgerStore::open_in_memory(None).unwrap();

        // Write two intents.
        store.write_intent(&sample_intent("grant-a")).unwrap();
        store.write_intent(&sample_intent("grant-b")).unwrap();

        // Write a receipt matching only grant-a.
        let mut receipt = sample_receipt();
        receipt.grant_id = latchgate_core::types::GrantId::from("grant-a");
        receipt.receipt_id = latchgate_core::types::ReceiptId::from("rcpt-a");
        receipt.result_hash = receipt.compute_result_hash();
        store.write_receipt(&receipt).unwrap();

        // Only grant-b should be unresolved.
        let unresolved = store.get_unresolved_intents().unwrap();
        assert_eq!(unresolved.len(), 1);
        assert_eq!(&*unresolved[0].grant_id, "grant-b");
    }

    #[test]
    fn unresolved_intents_empty_when_all_resolved() {
        let store = LedgerStore::open_in_memory(None).unwrap();

        store.write_intent(&sample_intent("grant-c")).unwrap();

        let mut receipt = sample_receipt();
        receipt.grant_id = latchgate_core::types::GrantId::from("grant-c");
        receipt.receipt_id = latchgate_core::types::ReceiptId::from("rcpt-c");
        receipt.result_hash = receipt.compute_result_hash();
        store.write_receipt(&receipt).unwrap();

        let unresolved = store.get_unresolved_intents().unwrap();
        assert!(unresolved.is_empty());
    }

    // -- finalize_evidence --

    #[test]
    fn finalize_evidence_writes_receipt_and_audit_atomically() {
        let store = LedgerStore::open_in_memory(None).unwrap();
        let receipt = sample_receipt();
        let mut event = test_event("trace-fin-001", "action", Decision::Allow);

        store.finalize_evidence(&receipt, &mut event).unwrap();

        // Both must be present.
        let found_receipt = store.get_receipt("rcpt-test-001").unwrap();
        assert!(found_receipt.is_some(), "receipt must be persisted");

        let found_event = store.query_by_trace_id("trace-fin-001").unwrap();
        assert!(found_event.is_some(), "audit event must be persisted");
    }

    #[test]
    fn finalize_evidence_chains_audit_event() {
        let store = LedgerStore::open_in_memory(None).unwrap();

        // Write a prior event to establish chain head.
        store
            .write_event(&mut test_event("trace-pre", "action", Decision::Allow))
            .unwrap();

        let receipt = sample_receipt();
        let mut event = test_event("trace-fin-chain", "action", Decision::Allow);
        store.finalize_evidence(&receipt, &mut event).unwrap();

        // The finalized event must be chained to the prior event.
        let chain = store.verify_chain().unwrap();
        assert!(chain.is_intact(), "chain must be intact: {chain:?}");
        assert_eq!(chain.total_events, 2);
    }

    #[test]
    fn finalize_evidence_receipt_idempotent_with_prior_write() {
        let store = LedgerStore::open_in_memory(None).unwrap();
        let receipt = sample_receipt();

        // Write receipt standalone first.
        store.write_receipt(&receipt).unwrap();

        // finalize_evidence with the same receipt must still succeed.
        let mut event = test_event("trace-fin-idem", "action", Decision::Allow);
        store.finalize_evidence(&receipt, &mut event).unwrap();

        let found = store.query_by_trace_id("trace-fin-idem").unwrap();
        assert!(found.is_some());
    }

    #[test]
    fn finalize_evidence_rolls_back_on_audit_failure() {
        let store = LedgerStore::open_in_memory(None).unwrap();
        let receipt = sample_receipt();

        // First finalize succeeds — establishes trace-fin-dup.
        let mut event1 = test_event("trace-fin-dup", "action", Decision::Allow);
        store.finalize_evidence(&receipt, &mut event1).unwrap();

        // Second finalize with DUPLICATE trace_id must fail (UNIQUE violation).
        let mut receipt2 = sample_receipt();
        receipt2.receipt_id = latchgate_core::types::ReceiptId::from("rcpt-test-002");
        receipt2.result_hash = receipt2.compute_result_hash();

        let mut event2 = test_event("trace-fin-dup", "action", Decision::Allow);
        let result = store.finalize_evidence(&receipt2, &mut event2);
        assert!(result.is_err(), "duplicate trace_id must fail");

        // The second receipt must NOT have been persisted (rollback).
        let found = store.get_receipt("rcpt-test-002").unwrap();
        assert!(
            found.is_none(),
            "receipt must be rolled back on audit failure"
        );
    }

    // ---- test-hooks fault-injection ---------------------------------------

    /// Arming a fault causes the next finalize_evidence to return Err
    /// without touching storage — verifies the hook short-circuits the
    /// transaction path entirely.
    #[cfg(feature = "test-hooks")]
    #[test]
    fn arm_finalize_failure_fires_one_shot() {
        let store = LedgerStore::open_in_memory(None).unwrap();
        let receipt = sample_receipt();

        store.arm_finalize_failure();

        let mut event = test_event("trace-armed", "action", Decision::Allow);
        let err = store
            .finalize_evidence(&receipt, &mut event)
            .expect_err("armed fault must cause finalize_evidence to fail");
        matches!(err, LedgerError::Io(_));

        // Armed fault is one-shot: receipt was NOT persisted because we
        // returned before the transaction, and the subsequent call
        // succeeds against a clean state.
        assert!(
            store
                .get_receipt(receipt.receipt_id.as_str())
                .unwrap()
                .is_none(),
            "armed fault must short-circuit before any write"
        );

        let mut event2 = test_event("trace-after-fault", "action", Decision::Allow);
        store
            .finalize_evidence(&receipt, &mut event2)
            .expect("second finalize must succeed — fault is one-shot");
    }

    /// Without arming, the hook is inert — finalize_evidence behaves
    /// exactly as it does without the feature.
    #[cfg(feature = "test-hooks")]
    #[test]
    fn finalize_evidence_without_arm_behaves_normally() {
        let store = LedgerStore::open_in_memory(None).unwrap();
        let receipt = sample_receipt();
        let mut event = test_event("trace-inert", "action", Decision::Allow);
        store
            .finalize_evidence(&receipt, &mut event)
            .expect("unarmed finalize must succeed");
    }

    /// Disarming a fault makes the following call succeed. Covers the
    /// "set up, abort, observe" pattern.
    #[cfg(feature = "test-hooks")]
    #[test]
    fn disarm_finalize_failure_cancels_armed_fault() {
        let store = LedgerStore::open_in_memory(None).unwrap();
        store.arm_finalize_failure();
        store.disarm_finalize_failure();

        let receipt = sample_receipt();
        let mut event = test_event("trace-disarmed", "action", Decision::Allow);
        store
            .finalize_evidence(&receipt, &mut event)
            .expect("disarmed fault must not fire");
    }
}
