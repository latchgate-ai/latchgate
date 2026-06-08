//! Generic learned-allowlist CRUD and cache for the ledger.
//!
//! Both learned domains and learned paths share identical SQLite storage,
//! caching, and CRUD patterns. This module captures that shared logic.
//! Domain-specific modules ([`super::learned_domains`], [`super::learned_paths`])
//! provide validation, type definitions, and thin public wrappers.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex, RwLock};
use std::time::Instant;

use crate::store::{LedgerError, WriterState};

/// Pre-computed SQL statements for a learned-allowlist table.
///
/// Computed once at static initialization. Eliminates per-call `format!()`
/// allocations inside Mutex guards, reducing lock hold time to pure I/O.
struct TableSql {
    count_for_action: String,
    insert: String,
    delete_one: String,
    delete_all: String,
    select_all_filtered: String,
    select_all_unfiltered: String,
    select_values: String,
    exists: String,
    select_cache: String,
}

/// Pre-computed SQL for a learned-allowlist table.
///
/// Two static instances exist: [`DOMAINS`] and [`PATHS`]. SQL strings are
/// computed once at initialization — all CRUD functions reference them by
/// shared borrow and pass them through `prepare_cached`, so neither string
/// formatting nor statement parsing occurs inside the writer Mutex.
pub(crate) struct TableConfig {
    sql: TableSql,
}

impl TableConfig {
    fn new(table_name: &'static str, value_column: &'static str) -> Self {
        Self {
            sql: TableSql {
                count_for_action: format!("SELECT COUNT(*) FROM {table_name} WHERE action_id = ?1"),
                insert: format!(
                    "INSERT OR IGNORE INTO {table_name} \
                     (action_id, {value_column}, added_by, added_at, source, approval_id) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
                ),
                delete_one: format!(
                    "DELETE FROM {table_name} \
                     WHERE action_id = ?1 AND {value_column} = ?2"
                ),
                delete_all: format!("DELETE FROM {table_name} WHERE action_id = ?1"),
                select_all_filtered: format!(
                    "SELECT action_id, {value_column}, added_by, added_at, \
                     source, approval_id \
                     FROM {table_name} WHERE action_id = ?1 ORDER BY added_at ASC"
                ),
                select_all_unfiltered: format!(
                    "SELECT action_id, {value_column}, added_by, added_at, \
                     source, approval_id \
                     FROM {table_name} ORDER BY action_id, added_at ASC"
                ),
                select_values: format!(
                    "SELECT {value_column} FROM {table_name} \
                     WHERE action_id = ?1 ORDER BY {value_column}"
                ),
                exists: format!(
                    "SELECT COUNT(*) FROM {table_name} \
                     WHERE action_id = ?1 AND {value_column} = ?2"
                ),
                select_cache: format!(
                    "SELECT action_id, {value_column} FROM {table_name} \
                     ORDER BY action_id, {value_column}"
                ),
            },
        }
    }
}

pub(crate) static DOMAINS: LazyLock<TableConfig> =
    LazyLock::new(|| TableConfig::new("learned_domains", "domain"));

pub(crate) static PATHS: LazyLock<TableConfig> =
    LazyLock::new(|| TableConfig::new("learned_paths", "path_glob"));

/// Source of a learned allowlist entry (domain or path).
///
/// Records how the entry was created for provenance tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntrySource {
    /// Added during an approval flow.
    Approval,
    /// Added manually via the CLI.
    Cli,
    /// Bulk-imported via the CLI.
    Import,
    /// Added via the admin HTTP API.
    Api,
}

impl EntrySource {
    pub fn as_str(&self) -> &'static str {
        match self {
            EntrySource::Approval => "approval",
            EntrySource::Cli => "cli",
            EntrySource::Import => "import",
            EntrySource::Api => "api",
        }
    }
}

/// Raw row from a learned-allowlist table.
///
/// The `value` field corresponds to `domain` or `path_glob` depending on
/// which table was queried. Domain-specific modules convert this into
/// their typed structs ([`LearnedDomain`](super::learned_domains::LearnedDomain),
/// [`LearnedPath`](super::learned_paths::LearnedPath)).
pub(crate) struct EntryRow {
    pub action_id: String,
    pub value: String,
    pub added_by: String,
    pub added_at: String,
    pub source: String,
    pub approval_id: Option<String>,
}

/// In-memory snapshot of all learned entries for one table, keyed by action_id.
///
/// Populated lazily on first cache miss. Invalidated on every mutation
/// (`add`, `remove`, `clear`). Avoids `spawn_blocking` => SQLite round-trips
/// on the action-execution hot path.
///
/// Values are `Arc`-wrapped so hot-path consumers can borrow via cheap
/// reference-count increment instead of cloning the entire `Vec<String>`.
pub(crate) struct LearnedSnapshot {
    pub(crate) by_action: HashMap<String, Arc<Vec<String>>>,
    pub(crate) created_at: Instant,
}

/// Default TTL for the learned-entry cache.
///
/// Safety net — all mutations invalidate immediately. The TTL only matters
/// if an external process edits the SQLite file directly.
pub(crate) const CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(10);

/// Shared empty vec returned on cache miss for actions with no learned entries.
///
/// Avoids a fresh `Arc<Vec::new()>` allocation on every request for actions
/// that have no learned entries (the common case for most actions).
fn empty_entries() -> Arc<Vec<String>> {
    static EMPTY: std::sync::OnceLock<Arc<Vec<String>>> = std::sync::OnceLock::new();
    Arc::clone(EMPTY.get_or_init(|| Arc::new(Vec::new())))
}

/// Map a SQLite row to an [`EntryRow`].
///
/// Shared between the filtered and unfiltered `list_entries` paths to avoid
/// duplicating the column-index mapping.
fn map_entry_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EntryRow> {
    Ok(EntryRow {
        action_id: row.get(0)?,
        value: row.get(1)?,
        added_by: row.get(2)?,
        added_at: row.get(3)?,
        source: row.get(4)?,
        approval_id: row.get(5)?,
    })
}

/// Insert a learned entry. Idempotent (INSERT OR IGNORE).
///
/// Returns `true` if a new row was inserted, `false` if it already existed.
pub(crate) fn insert_entry(
    inner: &Mutex<WriterState>,
    cache: &RwLock<Option<LearnedSnapshot>>,
    table: &TableConfig,
    params: &InsertParams<'_>,
) -> Result<bool, LedgerError> {
    // Compute timestamp outside the lock — it is provenance metadata and
    // does not require transactional consistency with the INSERT.
    let now = chrono::Utc::now().to_rfc3339();

    let guard = inner.lock().map_err(|_| LedgerError::LockPoisoned)?;

    // Enforce per-action cap if configured.
    if let Some(cap) = params.max_per_action {
        let count: i64 = guard
            .conn
            .prepare_cached(&table.sql.count_for_action)?
            .query_row([params.action_id], |row| row.get(0))?;
        if count >= cap {
            return Err(LedgerError::Io(std::io::Error::other(format!(
                "action '{}' already has {count} learned entries \
                 (limit: {cap}) — widen the static allowlist in the manifest instead",
                params.action_id,
            ))));
        }
    }

    let rows = guard
        .conn
        .prepare_cached(&table.sql.insert)?
        .execute(rusqlite::params![
            params.action_id,
            params.value,
            params.added_by,
            now,
            params.source,
            params.approval_id,
        ])?;

    let inserted = rows > 0;
    if inserted {
        drop(guard);
        invalidate_cache(cache);
    }
    Ok(inserted)
}

/// Parameters for [`insert_entry`].
pub(crate) struct InsertParams<'a> {
    pub action_id: &'a str,
    pub value: &'a str,
    pub added_by: &'a str,
    pub source: &'a str,
    pub approval_id: Option<&'a str>,
    /// If `Some(n)`, enforces a per-action row cap before insertion.
    /// Domains pass `None`; paths pass `Some(50)`.
    pub max_per_action: Option<i64>,
}

/// Delete a single learned entry. Returns `true` if a row was deleted.
pub(crate) fn delete_entry(
    inner: &Mutex<WriterState>,
    cache: &RwLock<Option<LearnedSnapshot>>,
    table: &TableConfig,
    action_id: &str,
    value: &str,
) -> Result<bool, LedgerError> {
    let guard = inner.lock().map_err(|_| LedgerError::LockPoisoned)?;
    let rows = guard
        .conn
        .prepare_cached(&table.sql.delete_one)?
        .execute(rusqlite::params![action_id, value])?;
    let deleted = rows > 0;
    if deleted {
        drop(guard);
        invalidate_cache(cache);
    }
    Ok(deleted)
}

/// List all entries, optionally filtered by action_id. Returns full metadata.
pub(crate) fn list_entries(
    inner: &Mutex<WriterState>,
    table: &TableConfig,
    action_id: Option<&str>,
) -> Result<Vec<EntryRow>, LedgerError> {
    let guard = inner.lock().map_err(|_| LedgerError::LockPoisoned)?;

    match action_id {
        Some(aid) => {
            let mut stmt = guard.conn.prepare_cached(&table.sql.select_all_filtered)?;
            let rows = stmt.query_map([aid], map_entry_row)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
        }
        None => {
            let mut stmt = guard
                .conn
                .prepare_cached(&table.sql.select_all_unfiltered)?;
            let rows = stmt.query_map([], map_entry_row)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
        }
    }
}

/// Get all learned values for a specific action as a `Vec<String>`.
///
/// Hot path: used by the kernel to merge with static manifest allowlists.
pub(crate) fn get_values_for_action(
    inner: &Mutex<WriterState>,
    table: &TableConfig,
    action_id: &str,
) -> Result<Vec<String>, LedgerError> {
    let guard = inner.lock().map_err(|_| LedgerError::LockPoisoned)?;
    let mut stmt = guard.conn.prepare_cached(&table.sql.select_values)?;
    let rows = stmt.query_map([action_id], |row| row.get::<_, String>(0))?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

/// Check whether a specific value is learned for an action.
pub(crate) fn is_entry_present(
    inner: &Mutex<WriterState>,
    table: &TableConfig,
    action_id: &str,
    value: &str,
) -> Result<bool, LedgerError> {
    let guard = inner.lock().map_err(|_| LedgerError::LockPoisoned)?;
    let count: i64 = guard
        .conn
        .prepare_cached(&table.sql.exists)?
        .query_row(rusqlite::params![action_id, value], |row| row.get(0))?;
    Ok(count > 0)
}

/// Remove all learned entries for a given action. Returns count deleted.
pub(crate) fn clear_for_action(
    inner: &Mutex<WriterState>,
    cache: &RwLock<Option<LearnedSnapshot>>,
    table: &TableConfig,
    action_id: &str,
) -> Result<usize, LedgerError> {
    let guard = inner.lock().map_err(|_| LedgerError::LockPoisoned)?;
    let rows = guard
        .conn
        .prepare_cached(&table.sql.delete_all)?
        .execute([action_id])?;
    if rows > 0 {
        drop(guard);
        invalidate_cache(cache);
    }
    Ok(rows)
}

/// Retrieve learned values for an action, serving from cache when possible.
///
/// Returns an `Arc<Vec<String>>` — callers that only need read access
/// (membership checks, iteration) pay a single atomic increment instead
/// of cloning the entire vector.
///
/// On cache hit: returns immediately without touching SQLite.
/// On cache miss: queries SQLite and populates the cache for all actions.
pub(crate) fn get_cached(
    inner: &Mutex<WriterState>,
    cache: &RwLock<Option<LearnedSnapshot>>,
    table: &TableConfig,
    action_id: &str,
) -> Result<Arc<Vec<String>>, LedgerError> {
    // Fast path: read lock, check cache.
    {
        let guard = cache.read().map_err(|_| LedgerError::LockPoisoned)?;
        if let Some(snapshot) = guard.as_ref() {
            if snapshot.created_at.elapsed() < CACHE_TTL {
                return Ok(snapshot
                    .by_action
                    .get(action_id)
                    .map(Arc::clone)
                    .unwrap_or_else(empty_entries));
            }
        }
    }
    // Slow path: write lock, populate from SQLite.
    populate_cache(inner, cache, table)?;

    let guard = cache.read().map_err(|_| LedgerError::LockPoisoned)?;
    Ok(guard
        .as_ref()
        .and_then(|s| s.by_action.get(action_id).map(Arc::clone))
        .unwrap_or_else(empty_entries))
}

/// Invalidate the cache. Next read will re-query SQLite.
pub(crate) fn invalidate_cache(cache: &RwLock<Option<LearnedSnapshot>>) {
    if let Ok(mut guard) = cache.write() {
        *guard = None;
    }
}

/// Populate the cache from SQLite in one query covering all actions.
fn populate_cache(
    inner: &Mutex<WriterState>,
    cache: &RwLock<Option<LearnedSnapshot>>,
    table: &TableConfig,
) -> Result<(), LedgerError> {
    let mut guard = cache.write().map_err(|_| LedgerError::LockPoisoned)?;

    // Double-check: another thread may have populated while we waited.
    if let Some(snapshot) = guard.as_ref() {
        if snapshot.created_at.elapsed() < CACHE_TTL {
            return Ok(());
        }
    }

    let inner_guard = inner.lock().map_err(|_| LedgerError::LockPoisoned)?;
    let mut stmt = inner_guard.conn.prepare_cached(&table.sql.select_cache)?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;

    // Build with plain Vecs, then wrap each in Arc.
    let mut raw: HashMap<String, Vec<String>> = HashMap::new();
    for row in rows {
        let (action_id, value) = row?;
        raw.entry(action_id).or_default().push(value);
    }

    let by_action = raw.into_iter().map(|(k, v)| (k, Arc::new(v))).collect();

    *guard = Some(LearnedSnapshot {
        by_action,
        created_at: Instant::now(),
    });

    Ok(())
}
