//! Operator-approved filesystem path globs persisted in the ledger.
//!
//! Learned paths augment the static manifest `allowed_paths` at runtime. They
//! are scoped per-action (`action_id`), validated at insert time, persisted in
//! SQLite, and cached in memory to avoid `spawn_blocking` round-trips.
//!
//! # Security properties
//!
//! - Per-action isolation: a path approved for `fs_write` is NOT available to
//!   `fs_delete`.
//! - Validated at insert: traversal patterns, absolute paths, null bytes,
//!   catch-all globs, and control characters are rejected before reaching the
//!   database or the runtime merge.
//! - Per-action cap: at most `MAX_LEARNED_PATHS_PER_ACTION` globs per action
//!   to prevent accidental over-permissioning.
//! - Writes do NOT participate in the hash-chain — they are mutable runtime
//!   authorization state, not immutable audit records.

use std::sync::Arc;

use tracing::instrument;

use crate::learned_allowlist::{self, EntrySource, PATHS};
use crate::store::{LedgerError, LedgerStore};

/// Maximum number of learned path globs per action.
///
/// Prevents accidental over-permissioning through unbounded path learning.
/// 50 covers realistic project structures; operators needing more should
/// widen the manifest's static `allowed_paths` instead.
const MAX_LEARNED_PATHS_PER_ACTION: i64 = 50;

/// A filesystem path glob that an operator approved for runtime use.
///
/// SECURITY: scoped per-action. Path globs are validated at insert time —
/// traversal patterns, absolute paths, and null bytes are rejected.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LearnedPath {
    pub action_id: String,
    pub path_glob: String,
    pub added_by: String,
    pub added_at: String,
    pub source: String,
    pub approval_id: Option<String>,
}

impl From<learned_allowlist::EntryRow> for LearnedPath {
    fn from(row: learned_allowlist::EntryRow) -> Self {
        Self {
            action_id: row.action_id,
            path_glob: row.value,
            added_by: row.added_by,
            added_at: row.added_at,
            source: row.source,
            approval_id: row.approval_id,
        }
    }
}

pub use latchgate_core::fs_path::validate_path_glob_entry as validate_path_glob;

impl LedgerStore {
    /// Add a learned path glob for an action. Idempotent (UNIQUE constraint).
    ///
    /// The glob is validated by [`validate_path_glob`] before insertion.
    /// Rejects catch-all patterns and enforces a per-action cap of
    /// `MAX_LEARNED_PATHS_PER_ACTION`.
    ///
    /// Returns `true` if a new row was inserted, `false` if it already existed.
    #[instrument(
        name = "ledger.add_learned_path",
        skip(self),
        fields(%action_id, %path_glob, %added_by),
    )]
    pub fn add_learned_path(
        &self,
        action_id: &str,
        path_glob: &str,
        added_by: &str,
        source: EntrySource,
        approval_id: Option<&str>,
    ) -> Result<bool, LedgerError> {
        // SECURITY: validate using the shared core validator. This is the
        // single enforcement point — every write path goes through here.
        latchgate_core::fs_path::validate_path_glob_entry(path_glob).map_err(|e| {
            LedgerError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                e.to_string(),
            ))
        })?;

        learned_allowlist::insert_entry(
            &self.writer,
            &self.learned_paths_cache,
            &PATHS,
            &learned_allowlist::InsertParams {
                action_id,
                value: path_glob,
                added_by,
                source: source.as_str(),
                approval_id,
                max_per_action: Some(MAX_LEARNED_PATHS_PER_ACTION),
            },
        )
    }

    /// Remove a learned path. Returns `true` if a row was deleted.
    #[instrument(
        name = "ledger.remove_learned_path",
        skip(self),
        fields(%action_id, %path_glob),
    )]
    pub fn remove_learned_path(
        &self,
        action_id: &str,
        path_glob: &str,
    ) -> Result<bool, LedgerError> {
        learned_allowlist::delete_entry(
            &self.writer,
            &self.learned_paths_cache,
            &PATHS,
            action_id,
            path_glob,
        )
    }

    /// List all learned paths, optionally filtered by action_id.
    pub fn list_learned_paths(
        &self,
        action_id: Option<&str>,
    ) -> Result<Vec<LearnedPath>, LedgerError> {
        let rows = learned_allowlist::list_entries(&self.writer, &PATHS, action_id)?;
        Ok(rows.into_iter().map(LearnedPath::from).collect())
    }

    /// Get all learned path globs for a specific action as a `Vec<String>`.
    ///
    /// Hot path: used by the kernel to merge with manifest `allowed_paths`.
    pub fn get_learned_paths_for_action(
        &self,
        action_id: &str,
    ) -> Result<Vec<String>, LedgerError> {
        learned_allowlist::get_values_for_action(&self.writer, &PATHS, action_id)
    }

    /// Check whether a specific path glob is learned for an action.
    pub fn is_path_learned(&self, action_id: &str, path_glob: &str) -> Result<bool, LedgerError> {
        learned_allowlist::is_entry_present(&self.writer, &PATHS, action_id, path_glob)
    }

    /// Remove all learned paths for a given action. Returns count deleted.
    pub fn clear_learned_paths_for_action(&self, action_id: &str) -> Result<usize, LedgerError> {
        learned_allowlist::clear_for_action(
            &self.writer,
            &self.learned_paths_cache,
            &PATHS,
            action_id,
        )
    }

    /// Retrieve learned paths for an action, serving from cache when possible.
    ///
    /// Returns an `Arc<Vec<String>>` — callers pay a single atomic increment
    /// instead of cloning the entire vector on every hot-path cache hit.
    pub fn get_learned_paths_cached(
        &self,
        action_id: &str,
    ) -> Result<Arc<Vec<String>>, LedgerError> {
        learned_allowlist::get_cached(&self.writer, &self.learned_paths_cache, &PATHS, action_id)
    }

    /// Invalidate the learned paths cache.
    pub fn invalidate_learned_paths_cache(&self) {
        learned_allowlist::invalidate_cache(&self.learned_paths_cache);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> LedgerStore {
        LedgerStore::open_in_memory(None).unwrap()
    }

    #[test]
    fn add_inserts_and_returns_true() {
        assert!(store()
            .add_learned_path("fs_read", "src/**", "alice", EntrySource::Cli, None)
            .unwrap());
    }

    #[test]
    fn duplicate_is_idempotent() {
        let s = store();
        s.add_learned_path("fs_read", "src/**", "alice", EntrySource::Cli, None)
            .unwrap();
        assert!(!s
            .add_learned_path("fs_read", "src/**", "bob", EntrySource::Cli, None)
            .unwrap());
    }

    #[test]
    fn rejects_absolute() {
        assert!(store()
            .add_learned_path("fs_read", "/etc/passwd", "alice", EntrySource::Cli, None)
            .is_err());
    }

    #[test]
    fn rejects_traversal() {
        assert!(store()
            .add_learned_path("fs_read", "src/../../etc", "alice", EntrySource::Cli, None)
            .is_err());
    }

    #[test]
    fn rejects_null_byte() {
        assert!(store()
            .add_learned_path("fs_read", "src/\0evil", "alice", EntrySource::Cli, None)
            .is_err());
    }

    #[test]
    fn rejects_empty() {
        assert!(store()
            .add_learned_path("fs_read", "", "alice", EntrySource::Cli, None)
            .is_err());
    }

    #[test]
    fn allows_dotdot_in_segment_name() {
        // "a../foo" is NOT traversal — only ".." as a complete segment is.
        assert!(store()
            .add_learned_path("fs_read", "a../foo", "alice", EntrySource::Cli, None)
            .unwrap());
    }

    #[test]
    fn remove_deletes_and_returns_true() {
        let s = store();
        s.add_learned_path("fs_write", "tests/**", "alice", EntrySource::Cli, None)
            .unwrap();
        assert!(s.remove_learned_path("fs_write", "tests/**").unwrap());
        assert!(!s.is_path_learned("fs_write", "tests/**").unwrap());
    }

    #[test]
    fn remove_missing_returns_false() {
        assert!(!store().remove_learned_path("fs_write", "nope/**").unwrap());
    }

    #[test]
    fn list_all_and_filtered() {
        let s = store();
        s.add_learned_path("fs_read", "src/**", "alice", EntrySource::Cli, None)
            .unwrap();
        s.add_learned_path("fs_write", "docs/**", "bob", EntrySource::Cli, None)
            .unwrap();
        assert_eq!(s.list_learned_paths(None).unwrap().len(), 2);
        let filtered = s.list_learned_paths(Some("fs_read")).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].path_glob, "src/**");
    }

    #[test]
    fn get_for_action_returns_sorted() {
        let s = store();
        s.add_learned_path("fs_read", "z-dir/**", "alice", EntrySource::Cli, None)
            .unwrap();
        s.add_learned_path("fs_read", "a-dir/**", "alice", EntrySource::Cli, None)
            .unwrap();
        assert_eq!(
            s.get_learned_paths_for_action("fs_read").unwrap(),
            vec!["a-dir/**", "z-dir/**"]
        );
    }

    #[test]
    fn clear_for_action_scoped() {
        let s = store();
        s.add_learned_path("fs_read", "a/**", "alice", EntrySource::Cli, None)
            .unwrap();
        s.add_learned_path("fs_read", "b/**", "alice", EntrySource::Cli, None)
            .unwrap();
        s.add_learned_path("fs_write", "c/**", "alice", EntrySource::Cli, None)
            .unwrap();
        assert_eq!(s.clear_learned_paths_for_action("fs_read").unwrap(), 2);
        assert!(s
            .get_learned_paths_for_action("fs_read")
            .unwrap()
            .is_empty());
        assert_eq!(s.get_learned_paths_for_action("fs_write").unwrap().len(), 1);
    }

    #[test]
    fn audit_fields_roundtrip() {
        let s = store();
        s.add_learned_path(
            "fs_read",
            "src/**",
            "alice",
            EntrySource::Approval,
            Some("appr-42"),
        )
        .unwrap();
        let all = s.list_learned_paths(Some("fs_read")).unwrap();
        let entry = &all[0];
        assert_eq!(entry.action_id, "fs_read");
        assert_eq!(entry.path_glob, "src/**");
        assert_eq!(entry.added_by, "alice");
        assert_eq!(entry.source, "approval");
        assert_eq!(entry.approval_id.as_deref(), Some("appr-42"));
        assert!(!entry.added_at.is_empty());
    }

    #[test]
    fn does_not_affect_hash_chain() {
        let s = store();
        let cv = s.verify_chain().unwrap();
        assert!(cv.broken_at.is_none());
        s.add_learned_path("fs_read", "src/**", "alice", EntrySource::Cli, None)
            .unwrap();
        let cv = s.verify_chain().unwrap();
        assert!(cv.broken_at.is_none());
    }

    #[test]
    fn scoped_to_action() {
        let s = store();
        s.add_learned_path("fs_read", "shared/**", "alice", EntrySource::Cli, None)
            .unwrap();
        s.add_learned_path("fs_write", "shared/**", "alice", EntrySource::Cli, None)
            .unwrap();
        s.remove_learned_path("fs_read", "shared/**").unwrap();
        assert!(!s.is_path_learned("fs_read", "shared/**").unwrap());
        assert!(s.is_path_learned("fs_write", "shared/**").unwrap());
    }

    #[test]
    fn validate_path_glob_cases() {
        // Valid
        assert!(validate_path_glob("src/**").is_ok());
        assert!(validate_path_glob("*.json").is_ok());
        assert!(validate_path_glob("data/reports/*.csv").is_ok());
        assert!(validate_path_glob("a../foo").is_ok());
        assert!(validate_path_glob("docs/*").is_ok());

        // Invalid — structural
        assert!(validate_path_glob("").is_err());
        assert!(validate_path_glob("/etc/passwd").is_err());
        assert!(validate_path_glob("../foo").is_err());
        assert!(validate_path_glob("a/../../b").is_err());
        assert!(validate_path_glob("a/\0b").is_err());

        // Catch-all
        assert!(validate_path_glob("*").is_err());
        assert!(validate_path_glob("**").is_err());
        assert!(validate_path_glob("**/*").is_err());

        // Sensitive locations
        assert!(validate_path_glob(".env").is_err());
        assert!(validate_path_glob(".env.production").is_err());
        assert!(validate_path_glob(".ssh/**").is_err());
        assert!(validate_path_glob(".git/config").is_err());
        assert!(validate_path_glob(".aws/credentials").is_err());
        assert!(validate_path_glob(".latchgate/**").is_err());

        // Non-sensitive dot-dirs
        assert!(validate_path_glob(".github/**").is_ok());
        assert!(validate_path_glob(".vscode/**").is_ok());
    }
}
