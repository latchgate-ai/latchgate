//! SQLite connection initialization — single source of truth for PRAGMA setup.
//!
//! Every SQLite database in LatchGate must be initialized through this module.
//! The builder generates a `PRAGMA` batch string that the caller passes to
//! `Connection::execute_batch`. This keeps `latchgate-core` free of a
//! `rusqlite` dependency while ensuring consistent, auditable configuration.
//!
//! # Security profiles
//!
//! Two named constructors encode the project's durability requirements:
//!
//! - [`SqliteInit::forensic`] — `synchronous = FULL`. Every commit is fsynced.
//!   Required for the audit ledger where a power failure must not lose events.
//!
//! - [`SqliteInit::operational`] — `synchronous = NORMAL`. WAL still guarantees
//!   crash-consistent recovery, but the last transaction before an OS crash may
//!   be lost. Acceptable for operational state (approvals, budgets, webhooks)
//!   where the data is disposable or reconstructible.

use std::fmt::Write;

/// Synchronous mode for SQLite WAL.
///
/// Controls the trade-off between durability and write throughput.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    /// `FULL` — every commit is fsynced to disk before returning. A power
    /// failure cannot lose committed data. Required for forensic / audit
    /// databases where data loss is unacceptable.
    Full,

    /// `NORMAL` — WAL guarantees crash-consistent recovery but the most
    /// recent transaction may be lost on an OS crash or power failure.
    /// Acceptable for operational data that can be reconstructed or retried.
    Normal,
}

/// SQLite connection PRAGMA configuration.
///
/// Construct via [`SqliteInit::forensic`] or [`SqliteInit::operational`],
/// then customize with builder methods if needed.
#[derive(Debug, Clone)]
pub struct SqliteInit {
    sync_mode: SyncMode,
    busy_timeout_ms: u32,
    foreign_keys: bool,
    mmap_size: Option<u64>,
    cache_size_kb: Option<i32>,
}

impl SqliteInit {
    /// Forensic profile — `synchronous = FULL`, WAL, 5 s busy timeout.
    ///
    /// Use for the audit ledger and any database where committed data must
    /// survive OS crash or power failure without loss.
    pub fn forensic() -> Self {
        Self {
            sync_mode: SyncMode::Full,
            busy_timeout_ms: 5_000,
            foreign_keys: false,
            mmap_size: None,
            cache_size_kb: None,
        }
    }

    /// Operational profile — `synchronous = NORMAL`, WAL, 5 s busy timeout.
    ///
    /// Use for state stores, outboxes, and other databases where losing the
    /// last transaction on OS crash is acceptable.
    pub fn operational() -> Self {
        Self {
            sync_mode: SyncMode::Normal,
            busy_timeout_ms: 5_000,
            foreign_keys: false,
            mmap_size: None,
            cache_size_kb: None,
        }
    }

    /// Enable `PRAGMA foreign_keys = ON`.
    pub fn with_foreign_keys(mut self) -> Self {
        self.foreign_keys = true;
        self
    }

    /// Set `PRAGMA mmap_size` (bytes). Pass `0` to disable memory-mapping.
    pub fn with_mmap_size(mut self, bytes: u64) -> Self {
        self.mmap_size = Some(bytes);
        self
    }

    /// Set `PRAGMA cache_size` in KiB (negative value per SQLite convention).
    ///
    /// Example: `with_cache_size_kb(16_000)` sets a ~16 MiB page cache.
    pub fn with_cache_size_kb(mut self, kb: i32) -> Self {
        self.cache_size_kb = Some(kb);
        self
    }

    /// Override the busy timeout (milliseconds). Default is 5 000 ms.
    pub fn with_busy_timeout_ms(mut self, ms: u32) -> Self {
        self.busy_timeout_ms = ms;
        self
    }

    /// Generate the `PRAGMA` batch SQL.
    ///
    /// The returned string is safe to pass to `Connection::execute_batch`.
    /// All pragmas are emitted in a fixed order for reproducibility.
    pub fn pragma_sql(&self) -> String {
        let mut sql = String::with_capacity(256);

        // WAL is unconditional — every LatchGate database uses it.
        sql.push_str("PRAGMA journal_mode = WAL;\n");

        let _ = writeln!(sql, "PRAGMA busy_timeout = {};", self.busy_timeout_ms);

        match self.sync_mode {
            SyncMode::Full => sql.push_str("PRAGMA synchronous = FULL;\n"),
            SyncMode::Normal => sql.push_str("PRAGMA synchronous = NORMAL;\n"),
        }

        if self.foreign_keys {
            sql.push_str("PRAGMA foreign_keys = ON;\n");
        }

        if let Some(bytes) = self.mmap_size {
            let _ = writeln!(sql, "PRAGMA mmap_size = {bytes};");
        }

        if let Some(kb) = self.cache_size_kb {
            // SQLite convention: negative = KiB.
            let _ = writeln!(sql, "PRAGMA cache_size = -{kb};");
        }

        sql
    }

    /// The configured synchronous mode.
    pub fn sync_mode(&self) -> SyncMode {
        self.sync_mode
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forensic_profile_uses_full_sync() {
        let init = SqliteInit::forensic();
        assert_eq!(init.sync_mode(), SyncMode::Full);
        let sql = init.pragma_sql();
        assert!(sql.contains("synchronous = FULL"), "{sql}");
        assert!(sql.contains("journal_mode = WAL"), "{sql}");
        assert!(sql.contains("busy_timeout = 5000"), "{sql}");
        assert!(!sql.contains("foreign_keys"), "{sql}");
    }

    #[test]
    fn operational_profile_uses_normal_sync() {
        let init = SqliteInit::operational();
        assert_eq!(init.sync_mode(), SyncMode::Normal);
        let sql = init.pragma_sql();
        assert!(sql.contains("synchronous = NORMAL"), "{sql}");
    }

    #[test]
    fn foreign_keys_opt_in() {
        let sql = SqliteInit::operational().with_foreign_keys().pragma_sql();
        assert!(sql.contains("foreign_keys = ON"), "{sql}");
    }

    #[test]
    fn mmap_and_cache_emitted() {
        let sql = SqliteInit::forensic()
            .with_mmap_size(268_435_456)
            .with_cache_size_kb(16_000)
            .pragma_sql();
        assert!(sql.contains("mmap_size = 268435456"), "{sql}");
        assert!(sql.contains("cache_size = -16000"), "{sql}");
    }

    #[test]
    fn custom_busy_timeout() {
        let sql = SqliteInit::forensic()
            .with_busy_timeout_ms(500)
            .pragma_sql();
        assert!(sql.contains("busy_timeout = 500"), "{sql}");
    }

    #[test]
    fn default_omits_optional_pragmas() {
        let sql = SqliteInit::operational().pragma_sql();
        assert!(!sql.contains("mmap_size"), "{sql}");
        assert!(!sql.contains("cache_size"), "{sql}");
        assert!(!sql.contains("foreign_keys"), "{sql}");
    }
}
