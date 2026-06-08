//! Persistent audit event storage: SQLite WAL + optional JSONL file sink.
//!
//! SQLite is the primary store with indexed columns for fast filtering.
//! JSONL is an optional SIEM-friendly export (one JSON line per event,
//! rotated externally by logrotate or a shipping agent).
//!
//! # Hash-chain
//!
//! Every event contains a `prev_hash` field: the SHA-256 of the previous
//! event's JCS-canonicalized JSON (RFC 8785). The first event has
//! `prev_hash: null`. Canonicalization ensures the hash is independent of
//! serializer key ordering — two JSON representations of the same event
//! always produce the same hash. This forms a tamper-evident chain —
//! deletion or mutation of any record breaks the chain and is detectable
//! via [`LedgerStore::verify_chain`].
//!
//! # Concurrency
//!
//! SQLite WAL supports concurrent reads alongside a single writer.
//! `LedgerStore` exploits this with two access paths:
//!
//! - **Writer** (`Mutex<WriterState>`): serialises all mutations. The JSONL
//!   sink is co-located here to preserve insertion order.
//! - **Read pool** (`ReadPool`): a bounded set of read-only connections.
//!   Admin queries, receipt lookups, and approval-outcome checks use
//!   these instead of contending with the writer mutex.
//!
//! For in-memory databases (tests), the read pool is unavailable and reads
//! fall back to the writer connection transparently.
//!
//! # Append-only
//!
//! The public API exposes no DELETE or UPDATE. Events are immutable once
//! written — this is a security property of the audit trail.

use std::path::Path;
use std::sync::{Mutex, RwLock};

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("lock poisoned")]
    LockPoisoned,

    /// Another LatchGate process holds an exclusive lock on this ledger.
    /// Only one writer is supported — running two instances against the
    /// same SQLite file corrupts the hash-chain.
    #[error("another LatchGate instance is using this ledger — only one writer is supported")]
    AnotherWriterActive,

    /// The grant has already been consumed by a prior execution. Returning
    /// this from [`LedgerStore::try_consume_grant`] prevents re-dispatch and
    /// enforces the one-shot execution invariant independently of the budget
    /// system.
    #[error("grant already consumed: {grant_id}")]
    GrantAlreadyConsumed { grant_id: String },

    /// JCS canonicalization of an audit event failed. This is a fatal
    /// integrity error — the event cannot be hash-chained without a
    /// deterministic canonical form.
    #[error("event canonicalization failed: {0}")]
    Canonicalization(#[from] latchgate_core::crypto::canonical::CanonicalError),
}

/// Pre-dispatch durable record. Written to SQLite BEFORE the WASM provider
/// executes. If the process crashes after dispatch but before the receipt is
/// persisted, operators can detect intents without matching receipts and
/// investigate whether the side effect occurred.
///
/// This type has no security-enforcement role — it is a durability artifact.
/// The kernel uses its existence to gate dispatch (fail-closed if the intent
/// cannot be persisted) and operators use it for forensic recovery.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExecutionIntent {
    pub trace_id: String,
    pub grant_id: String,
    pub action_id: String,
    pub principal: String,
    pub provider_module_digest: String,
    pub request_hash: String,
    pub approved_by: Option<String>,
    /// ISO 8601 timestamp of dispatch start.
    pub started_at: String,
}

/// Query filter for audit events. All fields are optional — unset fields
/// match everything. Results are ordered by timestamp descending (newest first).
#[derive(Debug, Default, serde::Deserialize)]
pub struct EventFilter {
    pub trace_id: Option<String>,
    pub event_type: Option<String>,
    pub action_id: Option<String>,
    pub principal: Option<String>,
    pub session_id: Option<String>,
    pub decision: Option<String>,
    pub after: Option<String>,
    pub before: Option<String>,
    /// Max results to return. Clamped to 1..=1000, default 100.
    pub limit: Option<usize>,
}

/// Result of [`LedgerStore::verify_chain`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainVerification {
    /// Total number of events inspected.
    pub total_events: usize,
    /// Number of verified links (event whose prev_hash matches).
    pub verified_links: usize,
    /// If the chain is broken, the `trace_id` of the first event whose
    /// `prev_hash` does not match the computed hash of its predecessor.
    /// `None` means the entire chain is intact.
    pub broken_at: Option<String>,
}

impl ChainVerification {
    /// Returns `true` if the entire chain is intact.
    pub fn is_intact(&self) -> bool {
        self.broken_at.is_none()
    }
}

/// State protected by the Mutex: SQLite connection + hash-chain head.
pub(crate) struct WriterState {
    pub(crate) conn: rusqlite::Connection,
    /// SHA-256 of the last written event's JCS-canonical JSON. `None` if the
    /// ledger is empty. Updated after every successful write.
    pub(crate) chain_head: Option<String>,
    /// Persistent JSONL file handle. Opened once at construction; writes
    /// stay under the mutex to preserve SQLite-row ordering without the
    /// per-write `open()` / `close()` syscall overhead of the old approach.
    /// `None` when no JSONL sink is configured.
    pub(crate) jsonl_writer: Option<std::io::BufWriter<std::fs::File>>,
}

use crate::learned_allowlist::LearnedSnapshot;

/// Maximum number of read connections in the pool.
///
/// Sized for typical admin + approval query concurrency. Each connection
/// holds a small amount of kernel memory (WAL snapshot, page cache share).
const READ_POOL_MAX: usize = 4;

/// Bounded pool of read-only SQLite connections for concurrent queries.
///
/// In WAL mode readers do not block the writer and vice versa. This pool
/// provides read-only connections so that admin queries, receipt lookups,
/// and approval-outcome checks do not contend with the writer mutex.
///
/// Connections are lazily created up to [`READ_POOL_MAX`] and returned to
/// the pool on drop via a RAII guard.
///
/// For in-memory databases (`db_path == None`), [`checkout`] returns `None`
/// and callers fall back to the writer connection.
pub(crate) struct ReadPool {
    available: Mutex<Vec<rusqlite::Connection>>,
    db_path: Option<std::path::PathBuf>,
}

impl ReadPool {
    /// Create a pool backed by the given database file.
    fn file_backed(db_path: &Path) -> Self {
        Self {
            available: Mutex::new(Vec::with_capacity(READ_POOL_MAX)),
            db_path: Some(db_path.to_path_buf()),
        }
    }

    /// Create an empty pool that always returns `None` (in-memory fallback).
    fn in_memory() -> Self {
        Self {
            available: Mutex::new(Vec::new()),
            db_path: None,
        }
    }

    /// Check out a read-only connection, creating one if the pool is empty.
    ///
    /// Returns `None` for in-memory databases (caller falls back to writer).
    fn checkout(&self) -> Result<Option<ReadGuard<'_>>, LedgerError> {
        let db_path = match &self.db_path {
            Some(p) => p,
            None => return Ok(None),
        };

        let conn = {
            let mut pool = self
                .available
                .lock()
                .map_err(|_| LedgerError::LockPoisoned)?;
            pool.pop()
        };

        let conn = match conn {
            Some(c) => c,
            None => Self::open_reader(db_path)?,
        };

        Ok(Some(ReadGuard {
            conn: Some(conn),
            pool: self,
        }))
    }

    /// Open a new read-only connection with WAL pragmas.
    fn open_reader(db_path: &Path) -> Result<rusqlite::Connection, LedgerError> {
        let conn = rusqlite::Connection::open_with_flags(
            db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.execute_batch(
            &latchgate_state::SqliteInit::forensic()
                .with_mmap_size(268_435_456)
                .with_cache_size_kb(8_000)
                .pragma_sql(),
        )?;
        Ok(conn)
    }
}

/// RAII guard that returns a read connection to the pool on drop.
///
/// `conn` is `Option<Connection>` solely so `Drop` can `.take()` it back
/// into the pool. The `Deref` impl is only callable while the guard is
/// alive (before drop), so `conn` is always `Some` during the guard's
/// usable lifetime. The `expect` in `Deref` cannot panic under correct
/// usage — it exists only as a defence against a hypothetical double-drop
/// or post-drop dereference, neither of which Rust's ownership rules permit.
pub(crate) struct ReadGuard<'a> {
    conn: Option<rusqlite::Connection>,
    pool: &'a ReadPool,
}

impl<'a> std::ops::Deref for ReadGuard<'a> {
    type Target = rusqlite::Connection;
    fn deref(&self) -> &rusqlite::Connection {
        // INVARIANT: `conn` is `Some` from construction until `Drop::drop`
        // calls `.take()`. Rust's ownership rules guarantee `Deref` is never
        // called after drop.
        self.conn
            .as_ref()
            .expect("ReadGuard: connection already returned")
    }
}

impl<'a> Drop for ReadGuard<'a> {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            if let Ok(mut pool) = self.pool.available.lock() {
                if pool.len() < READ_POOL_MAX {
                    pool.push(conn);
                }
            }
        }
    }
}

pub struct LedgerStore {
    pub(crate) writer: Mutex<WriterState>,

    /// Pool of read-only connections for concurrent queries.
    readers: ReadPool,

    /// Cross-process writer lock held for the store's lifetime.
    /// `None` for in-memory databases (no file to lock).
    /// The `File` handle is never read — holding it open is the lock.
    _writer_lock: Option<std::fs::File>,

    /// Cached learned domains. `None` = cache cold or invalidated.
    pub(crate) learned_cache: RwLock<Option<LearnedSnapshot>>,

    /// Cached learned paths. `None` = cache cold or invalidated.
    pub(crate) learned_paths_cache: RwLock<Option<LearnedSnapshot>>,

    /// One-shot fault-injection switch for [`finalize_evidence`].
    ///
    /// When armed via [`arm_finalize_failure`](Self::arm_finalize_failure),
    /// the next call to `finalize_evidence` clears the flag and returns
    /// [`LedgerError::Io`] without touching the database, simulating a
    /// durable-storage failure. Subsequent calls succeed normally.
    ///
    /// Gated on the `test-hooks` cargo feature so production builds
    /// neither compile the field nor expose any API to arm it.
    #[cfg(feature = "test-hooks")]
    pub(crate) fail_next_finalize: std::sync::atomic::AtomicBool,
}

impl LedgerStore {
    /// Open or create the ledger database and optional JSONL sink.
    ///
    /// Acquires an exclusive lock on the database file. If another LatchGate
    /// instance already holds the lock, returns `LedgerError::AnotherWriterActive`.
    /// This prevents concurrent writers which would corrupt the hash-chain.
    pub fn open(db_path: &Path, jsonl_path: Option<&Path>) -> Result<Self, LedgerError> {
        let writer_lock = Self::acquire_writer_lock(db_path)?;
        let conn = rusqlite::Connection::open(db_path)?;
        Self::init_connection(
            conn,
            jsonl_path,
            ReadPool::file_backed(db_path),
            Some(writer_lock),
        )
    }

    /// Create an in-memory ledger (for tests). No writer lock needed.
    pub fn open_in_memory(jsonl_path: Option<&Path>) -> Result<Self, LedgerError> {
        let conn = rusqlite::Connection::open_in_memory()?;
        Self::init_connection(conn, jsonl_path, ReadPool::in_memory(), None)
    }

    /// Acquire a cross-process writer lock via `flock` on a sibling lock file.
    ///
    /// SECURITY: single-writer enforcement. Two LatchGate instances writing to
    /// the same ledger file corrupts the hash-chain. The returned `File` handle
    /// holds the lock for the lifetime of the `LedgerStore`; dropping it
    /// releases the lock so a new instance can start.
    ///
    /// Uses `flock` (advisory, per-fd) rather than SQLite's `locking_mode =
    /// EXCLUSIVE` so that in-process read-only connections (the `ReadPool`)
    /// can access the WAL concurrently.
    fn acquire_writer_lock(db_path: &Path) -> Result<std::fs::File, LedgerError> {
        let lock_path = db_path.with_extension("lock");

        #[cfg(unix)]
        let lock_file = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .mode(0o600)
                .open(&lock_path)?
        };
        #[cfg(not(unix))]
        let lock_file = {
            std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(&lock_path)?
        };

        use rustix::fs::{flock, FlockOperation};
        match flock(&lock_file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(lock_file),
            Err(rustix::io::Errno::WOULDBLOCK) => Err(LedgerError::AnotherWriterActive),
            Err(e) => Err(LedgerError::Io(std::io::Error::from(e))),
        }
    }

    fn init_connection(
        conn: rusqlite::Connection,
        jsonl_path: Option<&Path>,
        readers: ReadPool,
        writer_lock: Option<std::fs::File>,
    ) -> Result<Self, LedgerError> {
        conn.execute_batch(
            &latchgate_state::SqliteInit::forensic()
                .with_mmap_size(268_435_456)
                .with_cache_size_kb(16_000)
                .pragma_sql(),
        )?;

        crate::schema::migrate(&conn)?;
        crate::schema::validate_chain_format(&conn)?;

        // SECURITY: recover hash-chain head from the last stored event so that
        // events written after a restart are correctly chained to the existing
        // ledger. Without this, a restart would reset prev_hash to None and
        // break the chain.
        let chain_head = recover_chain_head(&conn)?;

        let jsonl_writer = match jsonl_path {
            Some(path) => Some(open_jsonl_writer(path)?),
            None => None,
        };

        Ok(Self {
            writer: Mutex::new(WriterState {
                conn,
                chain_head,
                jsonl_writer,
            }),
            readers,
            _writer_lock: writer_lock,
            learned_cache: RwLock::new(None),
            learned_paths_cache: RwLock::new(None),
            #[cfg(feature = "test-hooks")]
            fail_next_finalize: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Execute a read-only closure against a pooled connection.
    ///
    /// On file-backed databases, acquires a connection from the read pool so
    /// the query does not contend with the writer mutex. On in-memory
    /// databases (tests), falls back to the writer connection transparently.
    pub(crate) fn with_reader<F, T>(&self, f: F) -> Result<T, LedgerError>
    where
        F: FnOnce(&rusqlite::Connection) -> Result<T, LedgerError>,
    {
        if let Some(guard) = self.readers.checkout()? {
            f(&guard)
        } else {
            let inner = self.writer.lock().map_err(|_| LedgerError::LockPoisoned)?;
            f(&inner.conn)
        }
    }

    ///
    /// `source_path` is the database file to back up. This is a static method
    /// because the backup opens its own read-only connection — it does not
    /// interfere with the running writer.
    pub fn backup_to(
        source_path: &std::path::Path,
        dest: &std::path::Path,
    ) -> Result<(), LedgerError> {
        let src = rusqlite::Connection::open_with_flags(
            source_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;

        let mut dst = rusqlite::Connection::open(dest)?;

        let backup = rusqlite::backup::Backup::new(&src, &mut dst)?;

        match backup.step(-1) {
            Ok(rusqlite::backup::StepResult::Done) => Ok(()),
            Ok(_) => Err(LedgerError::Io(std::io::Error::other(
                "SQLite backup did not complete in one step",
            ))),
            Err(e) => Err(LedgerError::Sqlite(e)),
        }
    }
}

/// Size and depth limits for JCS canonicalization of audit events.
///
/// Audit events contain hashes, identifiers, and policy metadata — not raw
/// provider payloads — so 256 KiB with depth 64 is generous. The limit exists
/// to bound canonicalizer memory, not to restrict legitimate events.
pub(crate) fn event_chain_limits() -> latchgate_core::crypto::canonical::Limits {
    latchgate_core::crypto::canonical::Limits {
        max_bytes: 256 * 1024,
        max_depth: 64,
    }
}

/// Compute the chain hash: SHA-256 of the JCS-canonical (RFC 8785) form.
///
/// SECURITY: the hash covers the complete event including `prev_hash`, so
/// modifying any field in any event invalidates all subsequent links.
/// Canonicalization ensures the hash is deterministic regardless of the
/// serializer's key ordering.
pub(crate) fn compute_event_hash(event: &serde_json::Value) -> Result<String, LedgerError> {
    Ok(latchgate_core::crypto::canonical::canonical_hash(
        event,
        &event_chain_limits(),
    )?)
}

/// Recover the chain head from the last event stored in SQLite.
///
/// Called once during [`LedgerStore`] initialisation so that events written
/// after a restart are correctly chained.
fn recover_chain_head(conn: &rusqlite::Connection) -> Result<Option<String>, LedgerError> {
    let result = conn.query_row(
        "SELECT event_json FROM audit_events ORDER BY id DESC LIMIT 1",
        [],
        |row| {
            let json_str: String = row.get(0)?;
            Ok(json_str)
        },
    );
    match result {
        Ok(json_str) => {
            let value: serde_json::Value = serde_json::from_str(&json_str)?;
            Ok(Some(compute_event_hash(&value)?))
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(LedgerError::Sqlite(e)),
    }
}

/// Open a persistent JSONL file handle for append-mode writes.
///
/// Called once during [`LedgerStore`] initialisation. The returned
/// `BufWriter` is stored inside `WriterState` and reused for every
/// audit event, eliminating the per-write `open()` / `close()` syscall
/// overhead.
///
/// SECURITY: on Unix, the file is created with mode 0600 (owner read/write
/// only) to prevent other users on the host from reading audit data which
/// may contain trace IDs, principal identifiers, and action call metadata.
fn open_jsonl_writer(path: &Path) -> Result<std::io::BufWriter<std::fs::File>, LedgerError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let file = opts.open(path)?;
    Ok(std::io::BufWriter::new(file))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_open_fails_with_another_writer_active() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("ledger.db");

        let _store1 = LedgerStore::open(&db_path, None).unwrap();

        let result = LedgerStore::open(&db_path, None);
        assert!(result.is_err(), "second open must fail");
        match result {
            Err(LedgerError::AnotherWriterActive) => {}
            Err(e) => panic!("expected AnotherWriterActive, got: {e}"),
            Ok(_) => panic!("second open must fail"),
        }
    }
}
