//! Durable approval outcome storage.
//!
//! Records whether an approval was executed (approved, denied, or failed)
//! in SQLite. Used as a fallback guard when Redis state is lost — prevents
//! re-execution of already-processed approvals.

use tracing::instrument;

use crate::store::{LedgerError, LedgerStore};

impl LedgerStore {
    /// Record a durable approval outcome in SQLite.
    ///
    /// Written after the WASM provider executes (success or failure) and
    /// **before** the Redis outcome marker. If Redis is unavailable, this
    /// SQLite record prevents re-execution when the Redis claim TTL expires:
    /// callers check [`Self::has_approval_outcome`] before attempting a claim.
    ///
    /// Duplicate approval_ids are silently ignored (INSERT OR IGNORE).
    #[instrument(
        name = "ledger.write_approval_outcome",
        skip(self),
        fields(%approval_id, %outcome),
    )]
    pub fn write_approval_outcome(
        &self,
        approval_id: &str,
        outcome: &str,
        detail: &str,
    ) -> Result<(), LedgerError> {
        let inner = self.writer.lock().map_err(|_| LedgerError::LockPoisoned)?;
        inner
            .conn
            .prepare_cached(
                "INSERT OR IGNORE INTO approval_outcomes \
             (approval_id, outcome, detail, created_at) \
             VALUES (?1, ?2, ?3, ?4)",
            )?
            .execute(rusqlite::params![
                approval_id,
                outcome,
                detail,
                chrono::Utc::now().to_rfc3339(),
            ])?;
        Ok(())
    }

    /// Check whether a durable approval outcome already exists.
    ///
    /// Returns `true` if the approval was already executed (approved, denied,
    /// or failed). Used as a guard before claiming a pending approval to
    /// prevent re-execution when Redis state was lost.
    pub fn has_approval_outcome(&self, approval_id: &str) -> Result<bool, LedgerError> {
        self.with_reader(|conn| {
            let count: i64 = conn
                .prepare_cached("SELECT COUNT(*) FROM approval_outcomes WHERE approval_id = ?1")?
                .query_row(rusqlite::params![approval_id], |row| row.get(0))?;
            Ok(count > 0)
        })
    }

    /// Retrieve the durable approval outcome from SQLite.
    ///
    /// Returns `(outcome, detail, created_at)` if found. Used as fallback
    /// when Redis is unavailable or has lost the approval record.
    pub fn get_approval_outcome(
        &self,
        approval_id: &str,
    ) -> Result<Option<(String, String, String)>, LedgerError> {
        self.with_reader(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT outcome, detail, created_at \
             FROM approval_outcomes WHERE approval_id = ?1",
            )?;
            let result = stmt.query_row(rusqlite::params![approval_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            });
            match result {
                Ok(row) => Ok(Some(row)),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(e) => Err(e.into()),
            }
        })
    }
}
