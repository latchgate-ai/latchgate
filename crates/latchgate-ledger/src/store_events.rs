//! Audit event storage: write, query, export, hash-chain verification.
//!
//! Extends [`LedgerStore`] with event-specific operations. The hash-chain
//! invariant (each event's `prev_hash` = SHA-256 of predecessor's JCS form)
//! is maintained here.

use std::io::Write;

use tracing::instrument;

use crate::events::AuditEvent;
use crate::store::{compute_event_hash, ChainVerification, EventFilter, LedgerError, LedgerStore};

impl LedgerStore {
    pub fn write_event(&self, event: &mut AuditEvent) -> Result<(), LedgerError> {
        // Pre-compute column extracts outside the lock — these are derived
        // from enum discriminants that don't depend on prev_hash.
        let event_type_str = event.event_type.as_str();
        let decision_str = event.policy.decision.as_str();

        let mut inner = self.writer.lock().map_err(|_| LedgerError::LockPoisoned)?;

        // SECURITY: chain the event to the previous one. This allows detection
        // of tampered or deleted records in the audit trail.
        event.prev_hash = inner.chain_head.clone();

        // Serialize to string directly — single pass from the typed struct,
        // no intermediate `Value` tree allocation. The `Value` is only
        // materialized below for the JCS canonical hash (which requires a
        // `Value`), and is built cheaply via `from_str` (pure JSON parse)
        // rather than `to_value` (Serialize trait dispatch).
        let event_json = serde_json::to_string(&*event)?;

        inner.conn.prepare_cached(
            "INSERT INTO audit_events (trace_id, timestamp, event_type, principal, session_id, action_id, decision, event_json)
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

        // SECURITY: update chain head AFTER successful insert. If the insert
        // fails (e.g. duplicate trace_id), the chain head remains unchanged.
        // Parse the already-serialized JSON into a Value for the JCS
        // canonicalizer — from_str is a lightweight JSON parse, not a full
        // Serialize dispatch.
        let event_value: serde_json::Value = serde_json::from_str(&event_json)?;
        inner.chain_head = Some(compute_event_hash(&event_value)?);

        // SECURITY: JSONL write happens while still holding the mutex so that
        // concurrent calls produce JSONL lines in the same order as SQLite
        // rows. The persistent file handle eliminates per-write open/close
        // syscalls — the only I/O under the lock is a buffered write + flush.
        if let Some(ref mut writer) = inner.jsonl_writer {
            writeln!(writer, "{event_json}")?;
            writer.flush()?;
        }

        Ok(())
    }

    pub fn query_events(&self, filter: &EventFilter) -> Result<Vec<AuditEvent>, LedgerError> {
        self.with_reader(|conn| {
            let mut conditions = Vec::new();
            let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

            if let Some(ref v) = filter.trace_id {
                conditions.push("trace_id = ?");
                params.push(Box::new(v.clone()));
            }
            if let Some(ref v) = filter.event_type {
                conditions.push("event_type = ?");
                params.push(Box::new(v.clone()));
            }
            if let Some(ref v) = filter.action_id {
                conditions.push("action_id = ?");
                params.push(Box::new(v.clone()));
            }
            if let Some(ref v) = filter.principal {
                conditions.push("principal = ?");
                params.push(Box::new(v.clone()));
            }
            if let Some(ref v) = filter.session_id {
                conditions.push("session_id = ?");
                params.push(Box::new(v.clone()));
            }
            if let Some(ref v) = filter.decision {
                conditions.push("decision = ?");
                params.push(Box::new(v.clone()));
            }
            if let Some(ref v) = filter.after {
                conditions.push("timestamp > ?");
                params.push(Box::new(v.clone()));
            }
            if let Some(ref v) = filter.before {
                conditions.push("timestamp < ?");
                params.push(Box::new(v.clone()));
            }

            let limit = filter.limit.unwrap_or(100).clamp(1, 1000);

            let where_clause = if conditions.is_empty() {
                String::new()
            } else {
                format!("WHERE {}", conditions.join(" AND "))
            };

            let sql = format!(
            "SELECT event_json FROM audit_events {where_clause} ORDER BY timestamp DESC LIMIT ?"
        );
            params.push(Box::new(limit as i64));

            let param_refs: Vec<&dyn rusqlite::types::ToSql> =
                params.iter().map(|p| p.as_ref()).collect();
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(param_refs.as_slice(), |row| {
                let json_str: String = row.get(0)?;
                Ok(json_str)
            })?;

            let mut events = Vec::new();
            for row in rows {
                let json_str = row?;
                let event: AuditEvent = serde_json::from_str(&json_str).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?;
                events.push(event);
            }

            Ok(events)
        })
    }

    /// Fast lookup by trace_id (unique indexed column).
    #[instrument(name = "ledger.query_by_trace_id", skip(self), fields(%trace_id))]
    pub fn query_by_trace_id(&self, trace_id: &str) -> Result<Option<AuditEvent>, LedgerError> {
        self.with_reader(|conn| {
            let result = conn
                .prepare_cached("SELECT event_json FROM audit_events WHERE trace_id = ?1")?
                .query_row([trace_id], |row| {
                    let json_str: String = row.get(0)?;
                    Ok(json_str)
                });

            match result {
                Ok(json_str) => {
                    let event: AuditEvent = serde_json::from_str(&json_str)?;
                    Ok(Some(event))
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(LedgerError::Sqlite(e)),
            }
        })
    }

    /// Export all audit events as raw JSON strings, ordered by insertion.
    ///
    /// Returns the exact `event_json` bytes stored in SQLite. These are the
    /// bytes that the hash chain covers — re-serializing through `AuditEvent`
    /// would produce different bytes and break chain verification on import.
    ///
    /// Used by `latchgate ledger export` for the self-hosted => Platform
    /// upgrade path.
    pub fn export_events_raw(&self) -> Result<Vec<String>, LedgerError> {
        self.with_reader(|conn| {
            let mut stmt =
                conn.prepare_cached("SELECT event_json FROM audit_events ORDER BY id ASC")?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            let mut events = Vec::new();
            for row in rows {
                events.push(row?);
            }
            Ok(events)
        })
    }

    /// Count total audit events.
    pub fn event_count(&self) -> Result<usize, LedgerError> {
        self.with_reader(|conn| {
            let count: i64 =
                conn.query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))?;
            Ok(count as usize)
        })
    }

    /// Verify the integrity of the hash-chain.
    ///
    /// Walks all events in insertion order and checks that each `prev_hash`
    /// matches the SHA-256 of the preceding event's JCS-canonical JSON
    /// (RFC 8785). Returns a [`ChainVerification`] report.
    #[instrument(name = "ledger.verify_chain", skip(self))]
    pub fn verify_chain(&self) -> Result<ChainVerification, LedgerError> {
        self.with_reader(|conn| {
            let mut stmt =
                conn.prepare_cached("SELECT event_json FROM audit_events ORDER BY id ASC")?;
            let rows = stmt.query_map([], |row| {
                let json_str: String = row.get(0)?;
                Ok(json_str)
            })?;

            let mut expected_prev_hash: Option<String> = None;
            let mut total = 0usize;
            let mut verified = 0usize;

            for row in rows {
                let json_str = row?;
                let event: AuditEvent = serde_json::from_str(&json_str).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?;
                total += 1;

                if event.prev_hash != expected_prev_hash {
                    return Ok(ChainVerification {
                        total_events: total,
                        verified_links: verified,
                        broken_at: Some(event.trace_id.to_string()),
                    });
                }

                verified += 1;
                // Parse to Value for canonical hashing. The typed AuditEvent
                // deserialization above already validated structure; this parse
                // is purely for the canonicalizer.
                let value: serde_json::Value = serde_json::from_str(&json_str)?;
                expected_prev_hash = Some(compute_event_hash(&value)?);
            }

            Ok(ChainVerification {
                total_events: total,
                verified_links: verified,
                broken_at: None,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{AuditEventBuilder, Decision, EventType, RuntimeAudit};
    use crate::store::LedgerStore;
    use serde_json::json;

    fn test_event(trace_id: &str, action_id: &str, decision: Decision) -> AuditEvent {
        AuditEventBuilder::new(trace_id, EventType::ActionCall)
            .principal("agent:test", "sess-1", "jti-1")
            .action(action_id, None, "sha256:abc", "digest_ok")
            .request("sha256:req", None)
            .policy(decision, None, None)
            .build()
    }

    // -- Write and query by trace_id --

    #[test]
    fn write_and_query_by_trace_id() {
        let store = LedgerStore::open_in_memory(None).unwrap();
        let mut event = test_event("trace-001", "http_fetch", Decision::Allow);

        store.write_event(&mut event).unwrap();
        let found = store.query_by_trace_id("trace-001").unwrap();

        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(&*found.trace_id, "trace-001");
        assert_eq!(&*found.action.action_id, "http_fetch");
        assert_eq!(found.policy.decision, Decision::Allow);
    }

    #[test]
    fn query_by_trace_id_not_found() {
        let store = LedgerStore::open_in_memory(None).unwrap();
        let found = store.query_by_trace_id("nonexistent").unwrap();
        assert!(found.is_none());
    }

    // -- Query by action_id --

    #[test]
    fn query_by_action_id() {
        let store = LedgerStore::open_in_memory(None).unwrap();
        store
            .write_event(&mut test_event("t-1", "http_fetch", Decision::Allow))
            .unwrap();
        store
            .write_event(&mut test_event("t-2", "http_fetch", Decision::Deny))
            .unwrap();
        store
            .write_event(&mut test_event("t-3", "shell_exec", Decision::Allow))
            .unwrap();

        let results = store
            .query_events(&EventFilter {
                action_id: Some("http_fetch".into()),
                ..Default::default()
            })
            .unwrap();

        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|e| &*e.action.action_id == "http_fetch"));
    }

    // -- Query by decision --

    #[test]
    fn query_by_decision() {
        let store = LedgerStore::open_in_memory(None).unwrap();
        store
            .write_event(&mut test_event("t-a", "tool_a", Decision::Allow))
            .unwrap();
        store
            .write_event(&mut test_event("t-b", "tool_b", Decision::Deny))
            .unwrap();
        store
            .write_event(&mut test_event("t-c", "tool_c", Decision::Deny))
            .unwrap();

        let results = store
            .query_events(&EventFilter {
                decision: Some("deny".into()),
                ..Default::default()
            })
            .unwrap();

        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|e| e.policy.decision == Decision::Deny));
    }

    // -- Query by event_type --

    #[test]
    fn query_by_event_type() {
        let store = LedgerStore::open_in_memory(None).unwrap();

        // ActionCall events.
        store
            .write_event(&mut test_event("t-call-1", "http_fetch", Decision::Allow))
            .unwrap();
        store
            .write_event(&mut test_event("t-call-2", "shell_exec", Decision::Deny))
            .unwrap();

        // Admin event (different event_type).
        let mut admin = AuditEventBuilder::new("t-admin-1", EventType::AdminRevokeAll)
            .principal("operator:alice", "op-sess", "")
            .policy(Decision::Allow, None, None)
            .build();
        store.write_event(&mut admin).unwrap();

        // Lease event.
        let mut lease = AuditEventBuilder::new("t-lease-1", EventType::LeaseIssued)
            .principal("agent:bot", "sess-001", "jti-001")
            .build();
        store.write_event(&mut lease).unwrap();

        // Filter: only action_call.
        let results = store
            .query_events(&EventFilter {
                event_type: Some("action_call".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(results.len(), 2);
        assert!(results
            .iter()
            .all(|e| e.event_type == EventType::ActionCall));

        // Filter: only admin_revoke_all.
        let results = store
            .query_events(&EventFilter {
                event_type: Some("admin_revoke_all".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(&*results[0].trace_id, "t-admin-1");

        // Filter: only lease_issued.
        let results = store
            .query_events(&EventFilter {
                event_type: Some("lease_issued".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(&*results[0].trace_id, "t-lease-1");
    }

    // -- Query with time range --

    #[test]
    fn query_with_time_range() {
        let store = LedgerStore::open_in_memory(None).unwrap();

        let mut e1 = test_event("t-time-1", "action", Decision::Allow);
        store.write_event(&mut e1).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(10));
        let mut e2 = test_event("t-time-2", "action", Decision::Allow);
        store.write_event(&mut e2).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(10));
        let mut e3 = test_event("t-time-3", "action", Decision::Allow);
        store.write_event(&mut e3).unwrap();

        let results = store
            .query_events(&EventFilter {
                after: Some(e1.timestamp.clone()),
                ..Default::default()
            })
            .unwrap();

        assert_eq!(results.len(), 2);
        assert!(results.iter().any(|e| &*e.trace_id == "t-time-2"));
        assert!(results.iter().any(|e| &*e.trace_id == "t-time-3"));
    }

    // -- Query limit --

    #[test]
    fn query_limit() {
        let store = LedgerStore::open_in_memory(None).unwrap();
        for i in 0..10 {
            store
                .write_event(&mut test_event(
                    &format!("t-lim-{i}"),
                    "action",
                    Decision::Allow,
                ))
                .unwrap();
        }

        let results = store
            .query_events(&EventFilter {
                limit: Some(3),
                ..Default::default()
            })
            .unwrap();

        assert_eq!(results.len(), 3);
    }

    #[test]
    fn query_limit_clamped_to_max() {
        let store = LedgerStore::open_in_memory(None).unwrap();
        let results = store
            .query_events(&EventFilter {
                limit: Some(9999),
                ..Default::default()
            })
            .unwrap();
        assert!(results.is_empty());
    }

    // -- JSONL --

    #[test]
    fn jsonl_written() {
        let dir = tempfile::tempdir().unwrap();
        let jsonl_path = dir.path().join("audit.jsonl");
        let store = LedgerStore::open_in_memory(Some(&jsonl_path)).unwrap();

        let mut event = test_event("t-jsonl", "http_fetch", Decision::Allow);
        store.write_event(&mut event).unwrap();

        let content = std::fs::read_to_string(&jsonl_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1);

        let restored: AuditEvent = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(&*restored.trace_id, "t-jsonl");
    }

    #[test]
    fn jsonl_appends_multiple_events() {
        let dir = tempfile::tempdir().unwrap();
        let jsonl_path = dir.path().join("audit.jsonl");
        let store = LedgerStore::open_in_memory(Some(&jsonl_path)).unwrap();

        store
            .write_event(&mut test_event("t-j1", "action", Decision::Allow))
            .unwrap();
        store
            .write_event(&mut test_event("t-j2", "action", Decision::Deny))
            .unwrap();

        let content = std::fs::read_to_string(&jsonl_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
    }

    // -- SQLite WAL mode --

    #[test]
    fn db_wal_mode() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("audit.db");
        let store = LedgerStore::open(&db_path, None).unwrap();

        let inner = store.writer.lock().unwrap();
        let mode: String = inner
            .conn
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
    }

    // -- Concurrent writes --

    #[test]
    fn concurrent_writes() {
        use std::sync::Arc;

        let store = Arc::new(LedgerStore::open_in_memory(None).unwrap());
        let mut handles = Vec::new();

        for i in 0..10 {
            let store = Arc::clone(&store);
            handles.push(std::thread::spawn(move || {
                let mut event = test_event(&format!("t-conc-{i}"), "action", Decision::Allow);
                store.write_event(&mut event).unwrap();
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let results = store.query_events(&EventFilter::default()).unwrap();
        assert_eq!(results.len(), 10);
    }

    // -- Duplicate trace_id rejected --

    #[test]
    fn duplicate_trace_id_rejected() {
        let store = LedgerStore::open_in_memory(None).unwrap();
        let mut event = test_event("t-dup", "action", Decision::Allow);
        store.write_event(&mut event).unwrap();

        let mut dup = test_event("t-dup", "action", Decision::Allow);
        let result = store.write_event(&mut dup);
        assert!(
            result.is_err(),
            "duplicate trace_id must be rejected by UNIQUE constraint"
        );
    }

    // -- Query with no filter returns all --

    #[test]
    fn query_no_filter_returns_all() {
        let store = LedgerStore::open_in_memory(None).unwrap();
        store
            .write_event(&mut test_event("t-all-1", "a", Decision::Allow))
            .unwrap();
        store
            .write_event(&mut test_event("t-all-2", "b", Decision::Deny))
            .unwrap();

        let results = store.query_events(&EventFilter::default()).unwrap();
        assert_eq!(results.len(), 2);
    }

    // -- Full event roundtrip through SQLite --

    #[test]
    fn full_event_roundtrip_through_sqlite() {
        let store = LedgerStore::open_in_memory(None).unwrap();

        let mut event = AuditEventBuilder::new("t-full-rt", EventType::ActionCall)
            .principal("agent:x", "sess", "jti")
            .action("http_fetch", Some("1.0".into()), "sha256:d", "digest_ok")
            .request("sha256:r", Some("schema-v1".into()))
            .policy(Decision::Allow, Some("policy-v3".into()), None)
            .budgets(Some(json!({"calls": 10})), Some(json!({"calls": 9})))
            .runtime(RuntimeAudit {
                module_digest: "sha256:ctr-123".into(),
                egress_profile: "none".into(),
                duration_ms: 250,
                exit_code: 0,
                timeout_hit: false,
                fuel_consumed: 25_000,
                io_calls_made: 1,
            })
            .response("sha256:resp", 2048)
            .flags(true, false)
            .build();

        store.write_event(&mut event).unwrap();
        let restored = store.query_by_trace_id("t-full-rt").unwrap().unwrap();

        assert_eq!(&*restored.subject.principal, "agent:x");
        assert_eq!(restored.action.action_version.as_deref(), Some("1.0"));
        assert_eq!(restored.policy.policy_version.as_deref(), Some("policy-v3"));
        assert_eq!(
            restored.request.request_schema_id.as_deref(),
            Some("schema-v1")
        );
        assert_eq!(restored.budgets_before, Some(json!({"calls": 10})));
        assert_eq!(restored.execution.response_bytes, Some(2048));
        assert!(restored.dev_mode);
        assert!(!restored.sandbox_degraded);

        let rt = restored.execution.runtime.unwrap();
        assert_eq!(&*rt.module_digest, "sha256:ctr-123");
        assert_eq!(rt.duration_ms, 250);
        assert!(!rt.timeout_hit);
    }

    // -- Query by principal --

    #[test]
    fn query_by_principal() {
        let store = LedgerStore::open_in_memory(None).unwrap();

        let mut e1 = AuditEventBuilder::new("t-p1", EventType::ActionCall)
            .principal("agent:alice", "s", "j")
            .build();
        let mut e2 = AuditEventBuilder::new("t-p2", EventType::ActionCall)
            .principal("agent:bob", "s", "j")
            .build();

        store.write_event(&mut e1).unwrap();
        store.write_event(&mut e2).unwrap();

        let results = store
            .query_events(&EventFilter {
                principal: Some("agent:alice".into()),
                ..Default::default()
            })
            .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(&*results[0].subject.principal, "agent:alice");
    }

    // -- JSONL ordering under concurrent writes --

    #[test]
    fn concurrent_writes_jsonl_ordering() {
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let jsonl_path = dir.path().join("audit.jsonl");
        let store = Arc::new(LedgerStore::open_in_memory(Some(&jsonl_path)).unwrap());
        let mut handles = Vec::new();

        for i in 0..10 {
            let store = Arc::clone(&store);
            handles.push(std::thread::spawn(move || {
                let mut event = test_event(&format!("t-jsonl-conc-{i}"), "action", Decision::Allow);
                store.write_event(&mut event).unwrap();
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let content = std::fs::read_to_string(&jsonl_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 10, "JSONL must have one line per event");

        for (i, line) in lines.iter().enumerate() {
            let parsed: Result<AuditEvent, _> = serde_json::from_str(line);
            assert!(parsed.is_ok(), "JSONL line {i} is not valid JSON: {line}");
        }

        let db_events = store.query_events(&EventFilter::default()).unwrap();
        let mut db_ids: Vec<String> = db_events.iter().map(|e| e.trace_id.to_string()).collect();
        let mut jsonl_ids: Vec<String> = lines
            .iter()
            .map(|l| {
                serde_json::from_str::<AuditEvent>(l)
                    .unwrap()
                    .trace_id
                    .to_string()
            })
            .collect();
        db_ids.sort();
        jsonl_ids.sort();
        assert_eq!(db_ids, jsonl_ids);
    }

    // -- Hash-chain --

    #[test]
    fn first_event_has_no_prev_hash() {
        let store = LedgerStore::open_in_memory(None).unwrap();
        let mut event = test_event("t-first", "action", Decision::Allow);
        store.write_event(&mut event).unwrap();

        let stored = store.query_by_trace_id("t-first").unwrap().unwrap();
        assert!(
            stored.prev_hash.is_none(),
            "first event must have prev_hash=None"
        );
    }

    #[test]
    fn second_event_chains_to_first() {
        let store = LedgerStore::open_in_memory(None).unwrap();

        let mut e1 = test_event("t-chain-1", "action", Decision::Allow);
        store.write_event(&mut e1).unwrap();

        let mut e2 = test_event("t-chain-2", "action", Decision::Allow);
        store.write_event(&mut e2).unwrap();

        let stored1 = store.query_by_trace_id("t-chain-1").unwrap().unwrap();
        let stored2 = store.query_by_trace_id("t-chain-2").unwrap().unwrap();

        assert!(stored1.prev_hash.is_none());
        assert!(stored2.prev_hash.is_some());

        // Verify: hash of e1's JCS-canonical JSON == e2's prev_hash.
        let e1_value = serde_json::to_value(&stored1).unwrap();
        let expected_hash = compute_event_hash(&e1_value).unwrap();
        assert_eq!(stored2.prev_hash.as_deref(), Some(expected_hash.as_str()));
    }

    #[test]
    fn verify_chain_intact() {
        let store = LedgerStore::open_in_memory(None).unwrap();

        for i in 0..5 {
            store
                .write_event(&mut test_event(
                    &format!("t-vc-{i}"),
                    "action",
                    Decision::Allow,
                ))
                .unwrap();
        }

        let result = store.verify_chain().unwrap();
        assert!(result.is_intact(), "chain must be intact: {result:?}");
        assert_eq!(result.total_events, 5);
        assert_eq!(result.verified_links, 5);
    }

    #[test]
    fn verify_chain_empty_ledger() {
        let store = LedgerStore::open_in_memory(None).unwrap();
        let result = store.verify_chain().unwrap();
        assert!(result.is_intact());
        assert_eq!(result.total_events, 0);
        assert_eq!(result.verified_links, 0);
    }

    #[test]
    fn verify_chain_detects_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("audit.db");
        let store = LedgerStore::open(&db_path, None).unwrap();

        for i in 0..3 {
            store
                .write_event(&mut test_event(
                    &format!("t-tamper-{i}"),
                    "action",
                    Decision::Allow,
                ))
                .unwrap();
        }

        // Tamper: directly modify the second event's JSON in SQLite.
        {
            let inner = store.writer.lock().unwrap();
            inner
                .conn
                .execute(
                    "UPDATE audit_events SET event_json = '{\"trace_id\":\"t-tamper-1\",\"timestamp\":\"2026-01-01T00:00:00.000Z\",\"event_type\":\"action_call\",\"principal\":\"TAMPERED\",\"session_id\":\"\",\"lease_jti\":\"\",\"action_id\":\"\",\"action_version\":null,\"action_digest\":\"\",\"action_trust_verdict\":\"\",\"request_hash\":\"\",\"request_schema_id\":null,\"policy_version\":null,\"decision\":\"allow\",\"deny_reason\":null,\"budgets_before\":null,\"budgets_after\":null,\"runtime\":null,\"response_hash\":null,\"response_bytes\":null,\"prev_hash\":null,\"dev_mode\":false,\"sandbox_degraded\":false}' WHERE trace_id = 't-tamper-1'",
                    [],
                )
                .unwrap();
        }

        let result = store.verify_chain().unwrap();
        assert!(!result.is_intact(), "tampered chain must be detected");
        // The tampered event (t-tamper-1) has wrong prev_hash after we
        // rewrote its JSON. Or t-tamper-2's prev_hash no longer matches
        // the hash of the tampered t-tamper-1.
        assert!(result.broken_at.is_some());
    }

    #[test]
    fn chain_recovers_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("audit.db");

        // Write 2 events, drop the store (simulating restart).
        {
            let store = LedgerStore::open(&db_path, None).unwrap();
            store
                .write_event(&mut test_event("t-restart-1", "action", Decision::Allow))
                .unwrap();
            store
                .write_event(&mut test_event("t-restart-2", "action", Decision::Allow))
                .unwrap();
        }

        // Reopen — chain_head should be recovered from the last event.
        let store = LedgerStore::open(&db_path, None).unwrap();
        store
            .write_event(&mut test_event("t-restart-3", "action", Decision::Allow))
            .unwrap();

        // Full chain must be intact across the restart boundary.
        let result = store.verify_chain().unwrap();
        assert!(result.is_intact(), "chain must survive restart: {result:?}");
        assert_eq!(result.total_events, 3);
    }

    #[test]
    fn chain_head_not_updated_on_failed_insert() {
        let store = LedgerStore::open_in_memory(None).unwrap();

        let mut e1 = test_event("t-fail-1", "action", Decision::Allow);
        store.write_event(&mut e1).unwrap();

        // Duplicate insert fails (UNIQUE constraint on trace_id).
        let mut dup = test_event("t-fail-1", "action", Decision::Allow);
        let _ = store.write_event(&mut dup);

        // Third event must chain to e1 (not to the failed dup).
        let mut e3 = test_event("t-fail-3", "action", Decision::Allow);
        store.write_event(&mut e3).unwrap();

        let result = store.verify_chain().unwrap();
        assert!(result.is_intact(), "chain must be intact: {result:?}");
        assert_eq!(result.total_events, 2);
    }

    // -- JCS canonicalization (RFC 8785) --

    #[test]
    fn jcs_reordered_keys_produce_same_hash() {
        // Two raw JSON strings with identical content but different key order.
        // Parsing each into Value (BTreeMap-backed) normalizes order, and
        // canonical_hash applies JCS on top — both must yield the same hash.
        let json_a = r#"{"z_last":"val","a_first":"val","m_mid":42}"#;
        let json_b = r#"{"a_first":"val","m_mid":42,"z_last":"val"}"#;

        // Sanity: raw strings differ.
        assert_ne!(json_a, json_b);

        let val_a: serde_json::Value = serde_json::from_str(json_a).unwrap();
        let val_b: serde_json::Value = serde_json::from_str(json_b).unwrap();

        let hash_a = compute_event_hash(&val_a).unwrap();
        let hash_b = compute_event_hash(&val_b).unwrap();
        assert_eq!(hash_a, hash_b, "JCS hash must be key-order-independent");
    }

    #[test]
    fn jcs_hash_differs_from_plain_sha256_of_unsorted_json() {
        // A raw JSON string with non-alphabetical key order. The plain
        // SHA-256 of these bytes must differ from the canonical hash
        // (which sorts keys before hashing).
        let unsorted = r#"{"z":"last","a":"first","m":"mid"}"#;
        let plain_hash = latchgate_core::crypto::sha256_digest(unsorted.as_bytes());

        let value: serde_json::Value = serde_json::from_str(unsorted).unwrap();
        let jcs_hash = compute_event_hash(&value).unwrap();

        assert_ne!(
            jcs_hash, plain_hash,
            "JCS hash of sorted canonical form must differ from SHA-256 of unsorted input"
        );
    }

    #[test]
    fn verify_chain_detects_single_byte_mutation() {
        let store = LedgerStore::open_in_memory(None).unwrap();

        for i in 0..5 {
            store
                .write_event(&mut test_event(
                    &format!("t-byte-{i}"),
                    "action",
                    Decision::Allow,
                ))
                .unwrap();
        }

        // Mutate one byte of the middle event's stored JSON.
        // Target the timestamp field — it's free-text, so the mutation
        // won't break enum deserialization during verify_chain.
        {
            let inner = store.writer.lock().unwrap();
            let original: String = inner
                .conn
                .query_row(
                    "SELECT event_json FROM audit_events WHERE trace_id = 't-byte-2'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();

            // Flip one digit in the timestamp (e.g. "2026" => "2027").
            let mutated = original.replacen("202", "203", 1);
            assert_ne!(original, mutated);

            inner
                .conn
                .execute(
                    "UPDATE audit_events SET event_json = ?1 WHERE trace_id = 't-byte-2'",
                    [&mutated],
                )
                .unwrap();
        }

        let result = store.verify_chain().unwrap();
        assert!(!result.is_intact(), "single-byte mutation must break chain");
        assert!(result.broken_at.is_some());
    }

    // -- Receipt persistence --
}
