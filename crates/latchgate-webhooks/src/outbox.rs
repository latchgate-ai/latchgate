//! Persistent webhook delivery outbox with its own SQLite connection.
//!
//! The outbox implements the "transactional outbox" pattern:
//! 1. **Enqueue**: persist delivery intent to SQLite before attempting delivery.
//! 2. **Poll**: background poller atomically claims pending entries.
//! 3. **Ack/Nack**: mark delivered or schedule retry with backoff.
//! 4. **Dead-letter**: entries exceeding max retries are dead-lettered for review.
//!
//! # Concurrent poller safety
//!
//! Multiple OS processes may point at the same SQLite outbox file. The in-process
//! `Mutex` serializes coroutines within a single process, but cross-process
//! safety requires atomic row claiming at the SQL level. `poll_pending` uses
//! `UPDATE … RETURNING` (SQLite ≥ 3.35) to atomically claim unclaimed rows,
//! preventing duplicate dispatch across concurrent pollers.
//!
//! # Separate DB file
//!
//! `WebhookOutbox` uses its own `webhook_outbox.db` file, separate from the
//! ledger's `ledger.db`. This is intentional — the ledger is a tamper-evident
//! audit trail with hash-chain integrity; webhook delivery state is operational
//! and disposable. Lost retries are harmless (at-least-once delivery).

use std::path::Path;
use std::sync::Mutex;

use rusqlite::Connection;
use tracing::instrument;

/// Claims older than this are considered stale and released for re-polling.
/// A crashed poller's rows become available to surviving pollers after this
/// duration. Five minutes is generous — a healthy poll cycle completes in
/// seconds, so this only fires on genuine crashes or hard hangs.
const STALE_CLAIM_SECONDS: u32 = 300;

/// Errors from webhook outbox operations.
#[derive(Debug, thiserror::Error)]
pub enum OutboxError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("outbox lock poisoned")]
    LockPoisoned,
}

/// A pending webhook delivery stored in the outbox.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OutboxEntry {
    pub id: i64,
    pub event_id: String,
    pub endpoint_name: String,
    pub payload_json: String,
    pub created_at: String,
    pub attempts: u32,
    pub next_attempt_at: String,
    pub last_error: Option<String>,
}

/// Summary of dead-lettered webhook deliveries.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeadLetterEntry {
    pub id: i64,
    pub event_id: String,
    pub endpoint_name: String,
    pub payload_json: String,
    pub created_at: String,
    pub attempts: u32,
    pub dead_lettered_at: String,
    pub last_error: Option<String>,
}

/// Persistent webhook delivery outbox backed by its own SQLite database.
///
/// Thread-safe via internal `Mutex<Connection>`. The connection is separate
/// from the forensic ledger — webhook polling never contends with audit writes.
pub struct WebhookOutbox {
    inner: Mutex<Connection>,
}

impl WebhookOutbox {
    /// Open (or create) the outbox database at the given path.
    ///
    /// Creates the `webhook_outbox` table and indexes if they don't exist.
    /// WAL mode is enabled for concurrent read/write performance.
    pub fn open(path: &Path) -> Result<Self, OutboxError> {
        let conn = Connection::open(path)?;
        conn.execute_batch(&latchgate_state::SqliteInit::operational().pragma_sql())?;
        Self::init_schema(&conn)?;
        Ok(Self {
            inner: Mutex::new(conn),
        })
    }

    /// Open an in-memory outbox (for tests).
    pub fn open_in_memory() -> Result<Self, OutboxError> {
        let conn = Connection::open_in_memory()?;
        Self::init_schema(&conn)?;
        Ok(Self {
            inner: Mutex::new(conn),
        })
    }

    fn init_schema(conn: &Connection) -> Result<(), OutboxError> {
        conn.execute_batch(
            r#"
CREATE TABLE IF NOT EXISTS webhook_outbox (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id         TEXT NOT NULL,
    endpoint_name    TEXT NOT NULL,
    payload_json     TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    attempts         INTEGER NOT NULL DEFAULT 0,
    next_attempt_at  TEXT NOT NULL,
    delivered_at     TEXT,
    dead_lettered_at TEXT,
    last_error       TEXT,
    claimed_by       TEXT,
    claimed_at       TEXT,

    UNIQUE(event_id, endpoint_name)
);

CREATE INDEX IF NOT EXISTS idx_outbox_pending
    ON webhook_outbox(next_attempt_at)
    WHERE delivered_at IS NULL
      AND dead_lettered_at IS NULL
      AND claimed_by IS NULL;

CREATE INDEX IF NOT EXISTS idx_outbox_dead_letter
    ON webhook_outbox(dead_lettered_at)
    WHERE dead_lettered_at IS NOT NULL;
"#,
        )?;
        Ok(())
    }

    /// Enqueue a webhook delivery for a specific endpoint.
    ///
    /// Duplicate (event_id, endpoint_name) pairs are silently ignored.
    #[instrument(name = "outbox.enqueue", skip(self, payload_json), fields(%event_id, %endpoint_name))]
    pub fn enqueue(
        &self,
        event_id: &str,
        endpoint_name: &str,
        payload_json: &str,
    ) -> Result<(), OutboxError> {
        let now = chrono::Utc::now().to_rfc3339();
        let conn = self.inner.lock().map_err(|_| OutboxError::LockPoisoned)?;
        conn.execute(
            "INSERT OR IGNORE INTO webhook_outbox \
             (event_id, endpoint_name, payload_json, created_at, next_attempt_at) \
             VALUES (?1, ?2, ?3, ?4, ?4)",
            rusqlite::params![event_id, endpoint_name, payload_json, now],
        )?;
        Ok(())
    }

    /// Atomically claim and return pending webhook deliveries ready for attempt.
    ///
    /// Uses `UPDATE … RETURNING` (SQLite ≥ 3.35) to atomically claim up to
    /// `limit` unclaimed rows for `poller_id`. Concurrent pollers on the same
    /// database file will never receive the same row.
    ///
    /// Stale claims from crashed pollers (older than `STALE_CLAIM_SECONDS`)
    /// are released before claiming new rows.
    #[instrument(name = "outbox.poll_pending", skip(self), fields(%poller_id))]
    pub fn poll_pending(
        &self,
        limit: u32,
        poller_id: &str,
    ) -> Result<Vec<OutboxEntry>, OutboxError> {
        let now = chrono::Utc::now().to_rfc3339();
        let conn = self.inner.lock().map_err(|_| OutboxError::LockPoisoned)?;

        // Release stale claims from crashed pollers. The negative interval
        // computes a threshold STALE_CLAIM_SECONDS in the past; any claim
        // older than that is considered abandoned.
        conn.execute(
            "UPDATE webhook_outbox \
             SET claimed_by = NULL, claimed_at = NULL \
             WHERE claimed_by IS NOT NULL \
               AND claimed_at < datetime(?1, ?2)",
            rusqlite::params![now, format!("-{STALE_CLAIM_SECONDS} seconds")],
        )?;

        // Atomically claim unclaimed rows ready for dispatch. The subquery
        // selects candidates; the outer UPDATE stamps them with our poller_id
        // and returns the claimed rows in a single statement — no TOCTOU gap.
        let mut stmt = conn.prepare_cached(
            "UPDATE webhook_outbox \
             SET claimed_by = ?1, claimed_at = ?2 \
             WHERE id IN ( \
                 SELECT id FROM webhook_outbox \
                 WHERE delivered_at IS NULL \
                   AND dead_lettered_at IS NULL \
                   AND claimed_by IS NULL \
                   AND next_attempt_at <= ?2 \
                 ORDER BY next_attempt_at ASC \
                 LIMIT ?3 \
             ) \
             RETURNING id, event_id, endpoint_name, payload_json, \
                       created_at, attempts, next_attempt_at, last_error",
        )?;
        let rows = stmt.query_map(rusqlite::params![poller_id, now, limit], |row| {
            Ok(OutboxEntry {
                id: row.get(0)?,
                event_id: row.get(1)?,
                endpoint_name: row.get(2)?,
                payload_json: row.get(3)?,
                created_at: row.get(4)?,
                attempts: row.get(5)?,
                next_attempt_at: row.get(6)?,
                last_error: row.get(7)?,
            })
        })?;
        let mut entries = Vec::new();
        for row in rows {
            entries.push(row?);
        }
        Ok(entries)
    }

    /// Mark a webhook delivery as successfully delivered.
    ///
    /// Clears the claim so the row is no longer held by any poller.
    #[instrument(name = "outbox.mark_delivered", skip(self), fields(%outbox_id))]
    pub fn mark_delivered(&self, outbox_id: i64) -> Result<(), OutboxError> {
        let now = chrono::Utc::now().to_rfc3339();
        let conn = self.inner.lock().map_err(|_| OutboxError::LockPoisoned)?;
        conn.execute(
            "UPDATE webhook_outbox \
             SET delivered_at = ?1, claimed_by = NULL, claimed_at = NULL \
             WHERE id = ?2",
            rusqlite::params![now, outbox_id],
        )?;
        Ok(())
    }

    /// Record a failed delivery attempt with backoff scheduling.
    ///
    /// Clears the claim so the row becomes available for the next poll cycle
    /// (after the backoff period). Returns `true` if the entry was
    /// dead-lettered (max attempts reached).
    #[instrument(name = "outbox.record_failure", skip(self, error), fields(%outbox_id))]
    pub fn record_failure(
        &self,
        outbox_id: i64,
        error: &str,
        max_attempts: u32,
        backoff_seconds: &[u64],
    ) -> Result<bool, OutboxError> {
        let now = chrono::Utc::now();
        let conn = self.inner.lock().map_err(|_| OutboxError::LockPoisoned)?;

        let current_attempts: u32 = conn.query_row(
            "SELECT attempts FROM webhook_outbox WHERE id = ?1",
            [outbox_id],
            |row| row.get(0),
        )?;

        let new_attempts = current_attempts + 1;

        if new_attempts >= max_attempts {
            conn.execute(
                "UPDATE webhook_outbox \
                 SET attempts = ?1, last_error = ?2, dead_lettered_at = ?3, \
                     claimed_by = NULL, claimed_at = NULL \
                 WHERE id = ?4",
                rusqlite::params![new_attempts, error, now.to_rfc3339(), outbox_id],
            )?;
            return Ok(true);
        }

        let backoff_idx = (new_attempts as usize).min(backoff_seconds.len().saturating_sub(1));
        let backoff = backoff_seconds.get(backoff_idx).copied().unwrap_or(60);
        let next = now + chrono::Duration::seconds(backoff as i64);

        conn.execute(
            "UPDATE webhook_outbox \
             SET attempts = ?1, last_error = ?2, next_attempt_at = ?3, \
                 claimed_by = NULL, claimed_at = NULL \
             WHERE id = ?4",
            rusqlite::params![new_attempts, error, next.to_rfc3339(), outbox_id],
        )?;
        Ok(false)
    }

    /// Count pending (undelivered, not dead-lettered) outbox entries.
    ///
    /// Includes entries currently claimed by a poller — this reflects the
    /// total backlog, not just the dispatchable subset.
    pub fn pending_count(&self) -> Result<usize, OutboxError> {
        let conn = self.inner.lock().map_err(|_| OutboxError::LockPoisoned)?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM webhook_outbox \
             WHERE delivered_at IS NULL AND dead_lettered_at IS NULL",
            [],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    /// List dead-lettered webhook entries for operator review.
    pub fn dead_letters(&self, limit: u32) -> Result<Vec<DeadLetterEntry>, OutboxError> {
        let conn = self.inner.lock().map_err(|_| OutboxError::LockPoisoned)?;
        let mut stmt = conn.prepare_cached(
            "SELECT id, event_id, endpoint_name, payload_json, created_at, \
             attempts, dead_lettered_at, last_error \
             FROM webhook_outbox \
             WHERE dead_lettered_at IS NOT NULL \
             ORDER BY dead_lettered_at DESC \
             LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], |row| {
            Ok(DeadLetterEntry {
                id: row.get(0)?,
                event_id: row.get(1)?,
                endpoint_name: row.get(2)?,
                payload_json: row.get(3)?,
                created_at: row.get(4)?,
                attempts: row.get(5)?,
                dead_lettered_at: row.get(6)?,
                last_error: row.get(7)?,
            })
        })?;
        let mut entries = Vec::new();
        for row in rows {
            entries.push(row?);
        }
        Ok(entries)
    }

    /// Re-enqueue a dead-lettered entry for retry.
    ///
    /// Clears dead-letter status, resets attempts, and releases any stale claim.
    pub fn retry_dead_letter(&self, outbox_id: i64) -> Result<(), OutboxError> {
        let now = chrono::Utc::now().to_rfc3339();
        let conn = self.inner.lock().map_err(|_| OutboxError::LockPoisoned)?;
        conn.execute(
            "UPDATE webhook_outbox \
             SET dead_lettered_at = NULL, last_error = NULL, \
                 attempts = 0, next_attempt_at = ?1, \
                 claimed_by = NULL, claimed_at = NULL \
             WHERE id = ?2",
            rusqlite::params![now, outbox_id],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed poller ID for single-poller tests.
    const TEST_POLLER: &str = "test-poller-01";

    fn test_outbox() -> WebhookOutbox {
        WebhookOutbox::open_in_memory().unwrap()
    }

    #[test]
    fn enqueue_and_poll() {
        let outbox = test_outbox();
        outbox
            .enqueue("evt-1", "slack", r#"{"id":"evt-1","type":"test"}"#)
            .unwrap();
        outbox
            .enqueue("evt-2", "siem", r#"{"id":"evt-2","type":"test"}"#)
            .unwrap();

        let pending = outbox.poll_pending(10, TEST_POLLER).unwrap();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].event_id, "evt-1");
        assert_eq!(pending[1].event_id, "evt-2");
        assert_eq!(pending[0].attempts, 0);
    }

    #[test]
    fn enqueue_is_idempotent() {
        let outbox = test_outbox();
        outbox
            .enqueue("evt-1", "slack", r#"{"id":"evt-1"}"#)
            .unwrap();
        outbox
            .enqueue("evt-1", "slack", r#"{"id":"evt-1"}"#)
            .unwrap();

        let pending = outbox.poll_pending(10, TEST_POLLER).unwrap();
        assert_eq!(pending.len(), 1, "duplicate should be ignored");
    }

    #[test]
    fn mark_delivered_removes_from_pending() {
        let outbox = test_outbox();
        outbox
            .enqueue("evt-1", "slack", r#"{"id":"evt-1"}"#)
            .unwrap();

        let pending = outbox.poll_pending(10, TEST_POLLER).unwrap();
        assert_eq!(pending.len(), 1);

        outbox.mark_delivered(pending[0].id).unwrap();

        let pending = outbox.poll_pending(10, TEST_POLLER).unwrap();
        assert!(pending.is_empty(), "delivered entry should not be pending");
        assert_eq!(outbox.pending_count().unwrap(), 0);
    }

    #[test]
    fn failure_schedules_backoff() {
        let outbox = test_outbox();
        outbox
            .enqueue("evt-1", "slack", r#"{"id":"evt-1"}"#)
            .unwrap();

        let pending = outbox.poll_pending(10, TEST_POLLER).unwrap();
        let id = pending[0].id;

        let dead = outbox
            .record_failure(id, "connection refused", 3, &[5, 30, 120])
            .unwrap();
        assert!(!dead, "should not be dead-lettered after 1 failure");
        assert_eq!(outbox.pending_count().unwrap(), 1);

        let dead_letters = outbox.dead_letters(10).unwrap();
        assert!(dead_letters.is_empty());
    }

    #[test]
    fn failure_dead_letters_at_max_attempts() {
        let outbox = test_outbox();
        outbox
            .enqueue("evt-1", "slack", r#"{"id":"evt-1"}"#)
            .unwrap();

        let pending = outbox.poll_pending(10, TEST_POLLER).unwrap();
        let id = pending[0].id;

        let dead = outbox.record_failure(id, "error 1", 2, &[1]).unwrap();
        assert!(!dead);

        let dead = outbox.record_failure(id, "error 2", 2, &[1]).unwrap();
        assert!(dead, "should be dead-lettered at max_attempts");

        assert_eq!(outbox.pending_count().unwrap(), 0);

        let dl = outbox.dead_letters(10).unwrap();
        assert_eq!(dl.len(), 1);
        assert_eq!(dl[0].event_id, "evt-1");
        assert_eq!(dl[0].attempts, 2);
        assert!(dl[0].last_error.as_deref() == Some("error 2"));
    }

    #[test]
    fn retry_dead_letter_re_enqueues() {
        let outbox = test_outbox();
        outbox
            .enqueue("evt-1", "slack", r#"{"id":"evt-1"}"#)
            .unwrap();

        let pending = outbox.poll_pending(10, TEST_POLLER).unwrap();
        let id = pending[0].id;

        outbox
            .record_failure(id, "permanent error", 0, &[])
            .unwrap();

        assert_eq!(outbox.dead_letters(10).unwrap().len(), 1);
        assert_eq!(outbox.pending_count().unwrap(), 0);

        outbox.retry_dead_letter(id).unwrap();

        assert_eq!(outbox.pending_count().unwrap(), 1);
        assert_eq!(outbox.dead_letters(10).unwrap().len(), 0);

        let pending = outbox.poll_pending(10, TEST_POLLER).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].attempts, 0, "attempts should be reset");
    }

    #[test]
    fn same_event_different_endpoints() {
        let outbox = test_outbox();
        outbox
            .enqueue("evt-1", "slack", r#"{"id":"evt-1"}"#)
            .unwrap();
        outbox
            .enqueue("evt-1", "siem", r#"{"id":"evt-1"}"#)
            .unwrap();

        let pending = outbox.poll_pending(10, TEST_POLLER).unwrap();
        assert_eq!(
            pending.len(),
            2,
            "same event for different endpoints = 2 entries"
        );
    }

    #[test]
    fn claimed_rows_invisible_to_other_pollers() {
        let outbox = test_outbox();
        outbox
            .enqueue("evt-1", "slack", r#"{"id":"evt-1"}"#)
            .unwrap();
        outbox
            .enqueue("evt-2", "slack", r#"{"id":"evt-2"}"#)
            .unwrap();
        outbox
            .enqueue("evt-3", "slack", r#"{"id":"evt-3"}"#)
            .unwrap();

        // Poller A claims all 3 rows.
        let batch_a = outbox.poll_pending(10, "poller-A").unwrap();
        assert_eq!(batch_a.len(), 3);

        // Poller B sees nothing — all rows are claimed by A.
        let batch_b = outbox.poll_pending(10, "poller-B").unwrap();
        assert!(
            batch_b.is_empty(),
            "claimed rows must be invisible to other pollers"
        );
    }

    #[test]
    fn concurrent_pollers_no_duplicates() {
        let outbox = test_outbox();
        for i in 0..20 {
            outbox
                .enqueue(
                    &format!("evt-{i}"),
                    "slack",
                    &format!(r#"{{"id":"evt-{i}"}}"#),
                )
                .unwrap();
        }

        // Two pollers each grab a batch of 10 from the same outbox.
        let batch_a = outbox.poll_pending(10, "poller-A").unwrap();
        let batch_b = outbox.poll_pending(10, "poller-B").unwrap();

        assert_eq!(batch_a.len(), 10);
        assert_eq!(batch_b.len(), 10);

        // Verify zero overlap.
        let ids_a: std::collections::HashSet<i64> = batch_a.iter().map(|e| e.id).collect();
        let ids_b: std::collections::HashSet<i64> = batch_b.iter().map(|e| e.id).collect();
        assert!(
            ids_a.is_disjoint(&ids_b),
            "pollers must never receive the same row: A={ids_a:?}, B={ids_b:?}"
        );
    }

    #[test]
    fn delivery_releases_claim_for_reuse() {
        let outbox = test_outbox();
        outbox
            .enqueue("evt-1", "slack", r#"{"id":"evt-1"}"#)
            .unwrap();

        // Poller A claims the row.
        let batch = outbox.poll_pending(10, "poller-A").unwrap();
        assert_eq!(batch.len(), 1);

        // Poller A marks it delivered — claim is cleared.
        outbox.mark_delivered(batch[0].id).unwrap();

        // The row is now delivered, so neither poller sees it.
        let batch_b = outbox.poll_pending(10, "poller-B").unwrap();
        assert!(batch_b.is_empty());
    }

    #[test]
    fn failure_releases_claim() {
        let outbox = test_outbox();
        outbox
            .enqueue("evt-1", "slack", r#"{"id":"evt-1"}"#)
            .unwrap();

        // Poller A claims the row.
        let batch = outbox.poll_pending(10, "poller-A").unwrap();
        assert_eq!(batch.len(), 1);

        // Poller A records failure — claim is released, row scheduled for later.
        outbox
            .record_failure(batch[0].id, "timeout", 3, &[0, 0, 0])
            .unwrap();

        // Poller B can now pick it up (backoff = 0 seconds for test).
        let batch_b = outbox.poll_pending(10, "poller-B").unwrap();
        assert_eq!(batch_b.len(), 1, "failure must release the claim");
        assert_eq!(batch_b[0].id, batch[0].id);
    }
}
