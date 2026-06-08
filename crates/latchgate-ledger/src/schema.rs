//! Ledger schema initialisation.
//!
//! Single `migrate()` call creates all tables and indices. No versioned
//! migration machinery — the project is pre-release and carries no
//! backward-compatibility debt. Wipe and re-create on schema changes.

use rusqlite::Connection;

use crate::store::LedgerError;

/// Tables that must exist after [`migrate`] succeeds.
///
/// Used by `latchgate doctor` to verify ledger health without opening a
/// full `LedgerStore`.
pub const REQUIRED_TABLES: &[&str] = &[
    "audit_events",
    "receipts",
    "execution_intents",
    "approval_outcomes",
    "learned_domains",
    "learned_paths",
    "consumed_grants",
    "ledger_metadata",
];

/// The chain hash format this build expects. Checked at startup to prevent
/// silently operating on a ledger written with an incompatible scheme.
pub const CHAIN_HASH_FORMAT: &str = "jcs-sha256";

/// Create all ledger tables and indices. Idempotent — safe to call on an
/// already-initialised database (`IF NOT EXISTS` throughout).
pub fn migrate(conn: &Connection) -> Result<(), LedgerError> {
    conn.execute_batch(SCHEMA_SQL)?;
    Ok(())
}

/// Verify the on-disk chain hash format matches this build.
///
/// Returns `Ok(())` if the stored format is `jcs-sha256`. Returns an error
/// if the metadata is missing or records a different format — the operator
/// must re-baseline the ledger before this build can use it.
pub fn validate_chain_format(conn: &Connection) -> Result<(), LedgerError> {
    let result = conn.query_row(
        "SELECT value FROM ledger_metadata WHERE key = 'chain_hash_format'",
        [],
        |row| row.get::<_, String>(0),
    );
    match result {
        Ok(ref format) if format == CHAIN_HASH_FORMAT => Ok(()),
        Ok(format) => Err(LedgerError::Io(std::io::Error::other(format!(
            "ledger chain format mismatch: expected '{CHAIN_HASH_FORMAT}', found '{format}' \
             — re-baseline the ledger for this build"
        )))),
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            Err(LedgerError::Io(std::io::Error::other(format!(
                "ledger metadata missing chain_hash_format — expected '{CHAIN_HASH_FORMAT}'; \
                 re-baseline the ledger for this build"
            ))))
        }
        Err(e) => Err(LedgerError::Sqlite(e)),
    }
}

const SCHEMA_SQL: &str = r#"
-- Tamper-evident audit trail. Hash-chained; append-only.
CREATE TABLE IF NOT EXISTS audit_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    trace_id    TEXT NOT NULL,
    timestamp   TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    principal   TEXT NOT NULL,
    session_id  TEXT NOT NULL,
    action_id   TEXT NOT NULL,
    decision    TEXT NOT NULL,
    event_json  TEXT NOT NULL,

    UNIQUE(trace_id)
);

CREATE INDEX IF NOT EXISTS idx_events_action_id   ON audit_events(action_id);
CREATE INDEX IF NOT EXISTS idx_events_principal   ON audit_events(principal);
CREATE INDEX IF NOT EXISTS idx_events_timestamp   ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_decision    ON audit_events(decision);
CREATE INDEX IF NOT EXISTS idx_events_event_type  ON audit_events(event_type);

-- Execution receipts (cryptographic evidence of completed actions).
CREATE TABLE IF NOT EXISTS receipts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    receipt_id   TEXT NOT NULL,
    grant_id     TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    created_at   TEXT NOT NULL,

    UNIQUE(receipt_id)
);

CREATE INDEX IF NOT EXISTS idx_receipts_grant_id ON receipts(grant_id);

-- Pre-dispatch durable intents. Written BEFORE provider execution so
-- crash-recovery can detect intents without matching receipts.
CREATE TABLE IF NOT EXISTS execution_intents (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    trace_id                TEXT NOT NULL,
    grant_id                TEXT NOT NULL,
    action_id               TEXT NOT NULL,
    principal               TEXT NOT NULL,
    provider_module_digest  TEXT NOT NULL,
    request_hash            TEXT NOT NULL,
    approved_by             TEXT,
    started_at              TEXT NOT NULL,

    UNIQUE(grant_id)
);

CREATE INDEX IF NOT EXISTS idx_intents_trace_id  ON execution_intents(trace_id);
CREATE INDEX IF NOT EXISTS idx_intents_action_id ON execution_intents(action_id);

-- Approval decision records.
CREATE TABLE IF NOT EXISTS approval_outcomes (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    approval_id      TEXT NOT NULL,
    outcome          TEXT NOT NULL,
    detail           TEXT NOT NULL,
    created_at       TEXT NOT NULL,

    UNIQUE(approval_id)
);

-- Operator-approved egress domains (per-action).
CREATE TABLE IF NOT EXISTS learned_domains (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id   TEXT NOT NULL,
    domain      TEXT NOT NULL,
    added_by    TEXT NOT NULL,
    added_at    TEXT NOT NULL,
    source      TEXT NOT NULL,
    approval_id TEXT,

    UNIQUE(action_id, domain)
);

CREATE INDEX IF NOT EXISTS idx_learned_domains_action
    ON learned_domains(action_id);

-- Operator-approved filesystem paths (per-action).
CREATE TABLE IF NOT EXISTS learned_paths (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id   TEXT NOT NULL,
    path_glob   TEXT NOT NULL,
    added_by    TEXT NOT NULL,
    added_at    TEXT NOT NULL,
    source      TEXT NOT NULL,
    approval_id TEXT,

    UNIQUE(action_id, path_glob)
);

CREATE INDEX IF NOT EXISTS idx_learned_paths_action
    ON learned_paths(action_id);

-- One-shot execution guard. Prevents re-dispatch of consumed grants
-- independently of the budget system.
CREATE TABLE IF NOT EXISTS consumed_grants (
    grant_id    TEXT PRIMARY KEY NOT NULL,
    action_id   TEXT NOT NULL,
    principal   TEXT NOT NULL,
    consumed_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_consumed_grants_action
    ON consumed_grants(action_id);

-- Ledger format metadata. Records the hash-chain format so tooling can
-- detect incompatible ledgers without a full chain walk.
CREATE TABLE IF NOT EXISTS ledger_metadata (
    key   TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
);

-- chain_hash_format: identifies the canonicalization scheme used for
-- prev_hash computation. 'jcs-sha256' = RFC 8785 JCS + SHA-256.
INSERT OR IGNORE INTO ledger_metadata (key, value)
    VALUES ('chain_hash_format', 'jcs-sha256');
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(&latchgate_state::SqliteInit::forensic().pragma_sql())
            .unwrap();
        conn
    }

    #[test]
    fn migrate_creates_all_tables() {
        let conn = fresh_conn();
        migrate(&conn).unwrap();

        for table in REQUIRED_TABLES {
            // ledger_metadata is seeded with the chain format marker during
            // migration, so it is not empty. All other tables start empty.
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                .unwrap();
            if *table == "ledger_metadata" {
                assert!(
                    count > 0,
                    "ledger_metadata should contain seed data after migrate"
                );
            } else {
                assert_eq!(count, 0, "table {table} should exist and be empty");
            }
        }
    }

    #[test]
    fn migrate_is_idempotent() {
        let conn = fresh_conn();
        migrate(&conn).unwrap();
        migrate(&conn).unwrap();

        for table in REQUIRED_TABLES {
            let exists: bool = conn
                .query_row(
                    "SELECT COUNT(*) > 0 FROM sqlite_master \
                     WHERE type = 'table' AND name = ?1",
                    [table],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(exists, "table {table} must exist after double migrate");
        }
    }

    #[test]
    fn required_tables_matches_schema() {
        let conn = fresh_conn();
        migrate(&conn).unwrap();

        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master \
                 WHERE type = 'table' AND name != 'sqlite_sequence' \
                 ORDER BY name",
            )
            .unwrap();
        let db_tables: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();

        let mut required: Vec<&str> = REQUIRED_TABLES.to_vec();
        required.sort();

        assert_eq!(
            db_tables,
            required.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            "REQUIRED_TABLES must list exactly the tables created by migrate"
        );
    }

    #[test]
    fn migrate_sets_chain_hash_format() {
        let conn = fresh_conn();
        migrate(&conn).unwrap();

        let format: String = conn
            .query_row(
                "SELECT value FROM ledger_metadata WHERE key = 'chain_hash_format'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(format, CHAIN_HASH_FORMAT);
    }

    #[test]
    fn validate_chain_format_passes_after_migrate() {
        let conn = fresh_conn();
        migrate(&conn).unwrap();
        validate_chain_format(&conn).unwrap();
    }

    #[test]
    fn validate_chain_format_rejects_wrong_format() {
        let conn = fresh_conn();
        migrate(&conn).unwrap();

        conn.execute(
            "UPDATE ledger_metadata SET value = 'plain-sha256' WHERE key = 'chain_hash_format'",
            [],
        )
        .unwrap();

        let err = validate_chain_format(&conn).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("mismatch"),
            "error should mention format mismatch: {msg}"
        );
    }
}
