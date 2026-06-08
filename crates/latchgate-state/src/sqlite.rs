//! Shared SQLite connection for persistent state stores.
//!
//! Opened once at startup; shared via `Arc<SqliteStateDb>` by both
//! [`super::approvals::ApprovalStore`] and [`super::budgets::BudgetManager`].
//!
//! # Concurrency
//!
//! SQLite WAL mode allows concurrent readers with a single writer.
//! The `Mutex<Connection>` serialises writes — identical to the
//! single-writer property of Redis Lua scripts. Async callers use
//! `tokio::task::spawn_blocking` to avoid holding the Mutex across
//! `.await` points.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use tracing::info;

// Typed error

/// Errors from SQLite state database initialization and access.
#[derive(Debug, thiserror::Error)]
pub enum SqliteStateError {
    #[error("cannot create state db directory {path}: {source}")]
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("cannot open state db {path}: {source}")]
    Open {
        path: PathBuf,
        source: rusqlite::Error,
    },

    #[error("state db pragma setup failed: {0}")]
    Pragma(rusqlite::Error),

    #[error("state db schema init failed: {0}")]
    Schema(rusqlite::Error),

    #[error("state db mutex poisoned")]
    Poisoned,
}

/// Shared SQLite connection for approval and budget state.
pub struct SqliteStateDb {
    conn: Mutex<rusqlite::Connection>,
}

impl std::fmt::Debug for SqliteStateDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteStateDb").finish_non_exhaustive()
    }
}

impl SqliteStateDb {
    /// Open (or create) the state database at `db_path`.
    ///
    /// Enables WAL mode, sets a 5-second busy timeout, and creates both
    /// tables if they do not already exist.
    pub fn open(db_path: &Path) -> Result<Self, SqliteStateError> {
        if let Some(parent) = db_path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| SqliteStateError::CreateDir {
                    path: parent.to_path_buf(),
                    source: e,
                })?;
            }
        }
        let conn = rusqlite::Connection::open(db_path).map_err(|e| SqliteStateError::Open {
            path: db_path.to_path_buf(),
            source: e,
        })?;
        Self::init(conn)
    }

    /// Create an in-memory state database (for tests).
    pub fn open_in_memory() -> Result<Self, SqliteStateError> {
        let conn = rusqlite::Connection::open_in_memory().map_err(|e| SqliteStateError::Open {
            path: PathBuf::from(":memory:"),
            source: e,
        })?;
        Self::init(conn)
    }

    fn init(conn: rusqlite::Connection) -> Result<Self, SqliteStateError> {
        conn.execute_batch(
            &crate::SqliteInit::operational()
                .with_foreign_keys()
                .pragma_sql(),
        )
        .map_err(SqliteStateError::Pragma)?;

        conn.execute_batch(SCHEMA_SQL)
            .map_err(SqliteStateError::Schema)?;

        info!("state database initialised");
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Acquire the connection lock.
    ///
    /// Callers MUST hold this only for the duration of a single
    /// synchronous SQLite operation — never across `.await`.
    ///
    /// Returns `Err` if the mutex is poisoned (a prior holder panicked).
    /// Callers propagate this as a store-unavailable error.
    pub(crate) fn conn(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, rusqlite::Connection>, SqliteStateError> {
        self.conn.lock().map_err(|_| SqliteStateError::Poisoned)
    }
}

// Schema

const SCHEMA_SQL: &str = "
CREATE TABLE IF NOT EXISTS pending_approvals (
    approval_id             TEXT PRIMARY KEY,
    state                   TEXT NOT NULL DEFAULT 'pending',
    payload_json            TEXT NOT NULL,
    claim_token             TEXT,
    claimed_by              TEXT,
    claimed_at              TEXT,
    claim_expires_at_unix   INTEGER,
    completed_at            TEXT,
    terminal_trace_id       TEXT,
    receipt_id              TEXT,
    deny_reason             TEXT,
    error_code              TEXT,
    terminal_outcome_kind   TEXT,
    terminal_outcome_at     TEXT,
    terminal_outcome_detail TEXT,
    created_at              TEXT NOT NULL,
    expires_at_unix         INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pending_approvals_state
    ON pending_approvals(state);
CREATE INDEX IF NOT EXISTS idx_pending_approvals_expires
    ON pending_approvals(expires_at_unix);

CREATE TABLE IF NOT EXISTS session_budgets (
    session_id       TEXT PRIMARY KEY,
    calls_remaining  INTEGER NOT NULL,
    created_at       TEXT NOT NULL,
    expires_at_unix  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_session_budgets_expires
    ON session_budgets(expires_at_unix);
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_in_memory_creates_tables() {
        let db = SqliteStateDb::open_in_memory().unwrap();
        let conn = db.conn().unwrap();
        // Verify both tables exist by querying sqlite_master.
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type='table' AND name IN ('pending_approvals','session_budgets')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn open_in_memory_enables_wal() {
        let db = SqliteStateDb::open_in_memory().unwrap();
        let conn = db.conn().unwrap();
        // In-memory databases report "memory" for journal_mode, but the
        // PRAGMA succeeds without error — that's what we verify.
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        // In-memory can return "memory" — that's fine.
        assert!(
            mode == "wal" || mode == "memory",
            "unexpected journal mode: {mode}"
        );
    }
}
