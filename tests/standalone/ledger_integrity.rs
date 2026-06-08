//! Ledger tamper detection — on-disk integrity verification.
//!
//! Validates that the tamper-evident hash chain detects direct database
//! manipulation (event deletion, field modification). These tests open
//! the SQLite database directly via rusqlite to simulate an attacker
//! with filesystem access — something unit tests against the `LedgerStore`
//! API cannot do.
//!
//! Hash chain construction, evidence finalization, intent/receipt lifecycle,
//! and concurrent write safety are covered by unit tests in
//! `latchgate-ledger::store`.

use latchgate_ledger::{AuditEventBuilder, Decision, EventType, LedgerStore};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_event(trace_id: &str, action_id: &str, decision: Decision) -> latchgate_ledger::AuditEvent {
    AuditEventBuilder::new(trace_id, EventType::ActionCall)
        .principal("agent:test", "sess-1", "jti-1")
        .action(action_id, None, "sha256:abc", "digest_ok")
        .request("sha256:req", None)
        .policy(decision, None, None)
        .build()
}

// ---------------------------------------------------------------------------
// Direct database manipulation — simulates attacker with fs access
// ---------------------------------------------------------------------------

/// Deleting an event from the SQLite database breaks the hash chain.
/// The `verify_chain` API detects the gap.
#[test]
fn chain_detects_deleted_event() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("audit.db");

    {
        let store = LedgerStore::open(&db_path, None).unwrap();
        for i in 0..5 {
            store
                .write_event(&mut test_event(
                    &format!("trace-del-{i}"),
                    "action",
                    Decision::Allow,
                ))
                .unwrap();
        }
    }

    // Tamper: delete the middle event via raw SQL.
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute(
            "DELETE FROM audit_events WHERE trace_id = 'trace-del-2'",
            [],
        )
        .unwrap();
    }

    let store = LedgerStore::open(&db_path, None).unwrap();
    let result = store.verify_chain().unwrap();
    assert!(
        !result.is_intact(),
        "deleting an event must break the chain"
    );
}

/// Modifying an event's content in the database breaks the hash chain.
/// The stored hash no longer matches the recomputed hash.
#[test]
fn chain_detects_modified_event() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("audit.db");

    {
        let store = LedgerStore::open(&db_path, None).unwrap();
        for i in 0..3 {
            store
                .write_event(&mut test_event(
                    &format!("trace-mod-{i}"),
                    "action",
                    Decision::Allow,
                ))
                .unwrap();
        }
    }

    // Tamper: modify the second event's principal via raw SQL.
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let original: String = conn
            .query_row(
                "SELECT event_json FROM audit_events WHERE trace_id = 'trace-mod-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let tampered = original.replace("agent:test", "agent:TAMPERED");
        conn.execute(
            "UPDATE audit_events SET event_json = ?1 WHERE trace_id = 'trace-mod-1'",
            [&tampered],
        )
        .unwrap();
    }

    let store = LedgerStore::open(&db_path, None).unwrap();
    let result = store.verify_chain().unwrap();
    assert!(
        !result.is_intact(),
        "modifying an event must break the chain"
    );
}

/// Repeated reads through the public API do not mutate stored events.
/// Guards against accidental side-effects in query paths.
#[test]
fn read_api_does_not_mutate_events() {
    let store = LedgerStore::open_in_memory(None).unwrap();
    store
        .write_event(&mut test_event("trace-ro", "action", Decision::Allow))
        .unwrap();

    let e1 = store.query_by_trace_id("trace-ro").unwrap().unwrap();
    let e2 = store.query_by_trace_id("trace-ro").unwrap().unwrap();

    assert_eq!(
        serde_json::to_string(&e1).unwrap(),
        serde_json::to_string(&e2).unwrap(),
        "repeated reads must return identical events"
    );

    let result = store.verify_chain().unwrap();
    assert!(result.is_intact());
}
