//! Operator-approved egress domains persisted in the ledger.
//!
//! Learned domains augment the static manifest allowlist at runtime. They are
//! scoped per-action (`action_id`), persisted in SQLite, and cached in memory
//! to avoid `spawn_blocking` round-trips on every action execution.
//!
//! # Security properties
//!
//! - Per-action isolation: a domain approved for `slack_post` is NOT available
//!   to `gmail_send`.
//! - Full provenance: every entry records `added_by`, `added_at`, `source`,
//!   and optional `approval_id`.
//! - Writes do NOT participate in the hash-chain — they are mutable runtime
//!   authorization state, not immutable audit records.

use std::sync::Arc;

use tracing::instrument;

use crate::learned_allowlist::{self, EntrySource, DOMAINS};
use crate::store::{LedgerError, LedgerStore};

/// A domain that an operator approved for runtime use by a specific action.
///
/// SECURITY: scoped per-action. A domain approved for `slack_post` is NOT
/// available to `gmail_send`. Every entry records full provenance.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LearnedDomain {
    pub action_id: String,
    pub domain: String,
    pub added_by: String,
    pub added_at: String,
    pub source: String,
    pub approval_id: Option<String>,
}

impl From<learned_allowlist::EntryRow> for LearnedDomain {
    fn from(row: learned_allowlist::EntryRow) -> Self {
        Self {
            action_id: row.action_id,
            domain: row.value,
            added_by: row.added_by,
            added_at: row.added_at,
            source: row.source,
            approval_id: row.approval_id,
        }
    }
}

impl LedgerStore {
    /// Add a learned domain for an action. Idempotent (UNIQUE constraint).
    ///
    /// The domain is validated and normalized by
    /// [`latchgate_core::net::validate_domain_entry`] before insertion.
    /// Invalid entries (private IPs, localhost, malformed hostnames) are
    /// rejected. Wildcard entries (`*.suffix`) require `allow_unsafe_wildcard`
    /// when the suffix has fewer than 3 labels.
    ///
    /// Returns `true` if a new row was inserted, `false` if it already existed.
    #[instrument(
        name = "ledger.add_learned_domain",
        skip(self),
        fields(%action_id, %domain, %added_by),
    )]
    pub fn add_learned_domain(
        &self,
        action_id: &str,
        domain: &str,
        added_by: &str,
        source: EntrySource,
        approval_id: Option<&str>,
        allow_unsafe_wildcard: bool,
    ) -> Result<bool, LedgerError> {
        // SECURITY: validate and normalize before touching the database.
        // This is the single enforcement point — every write path (CLI,
        // API, approval flow) goes through this function.
        let normalized = latchgate_core::net::validate_domain_entry(domain, allow_unsafe_wildcard)
            .map_err(|e| {
                LedgerError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    e.to_string(),
                ))
            })?;

        learned_allowlist::insert_entry(
            &self.writer,
            &self.learned_cache,
            &DOMAINS,
            &learned_allowlist::InsertParams {
                action_id,
                value: &normalized,
                added_by,
                source: source.as_str(),
                approval_id,
                max_per_action: None,
            },
        )
    }

    /// Remove a learned domain. Returns `true` if a row was deleted.
    #[instrument(
        name = "ledger.remove_learned_domain",
        skip(self),
        fields(%action_id, %domain),
    )]
    pub fn remove_learned_domain(
        &self,
        action_id: &str,
        domain: &str,
    ) -> Result<bool, LedgerError> {
        learned_allowlist::delete_entry(
            &self.writer,
            &self.learned_cache,
            &DOMAINS,
            action_id,
            domain,
        )
    }

    /// List all learned domains, optionally filtered by action_id.
    pub fn list_learned_domains(
        &self,
        action_id: Option<&str>,
    ) -> Result<Vec<LearnedDomain>, LedgerError> {
        let rows = learned_allowlist::list_entries(&self.writer, &DOMAINS, action_id)?;
        Ok(rows.into_iter().map(LearnedDomain::from).collect())
    }

    /// Get all learned domains for a specific action as a `Vec<String>`.
    ///
    /// Hot path: used by the kernel to merge with manifest allowlists.
    pub fn get_learned_domains_for_action(
        &self,
        action_id: &str,
    ) -> Result<Vec<String>, LedgerError> {
        learned_allowlist::get_values_for_action(&self.writer, &DOMAINS, action_id)
    }

    /// Check whether a specific domain is learned for an action.
    pub fn is_domain_learned(&self, action_id: &str, domain: &str) -> Result<bool, LedgerError> {
        learned_allowlist::is_entry_present(&self.writer, &DOMAINS, action_id, domain)
    }

    /// Remove all learned domains for a given action. Returns count deleted.
    pub fn clear_learned_domains_for_action(&self, action_id: &str) -> Result<usize, LedgerError> {
        learned_allowlist::clear_for_action(&self.writer, &self.learned_cache, &DOMAINS, action_id)
    }

    /// Retrieve learned domains for an action, serving from cache when possible.
    ///
    /// Returns an `Arc<Vec<String>>` — callers pay a single atomic increment
    /// instead of cloning the entire vector on every hot-path cache hit.
    pub fn get_learned_domains_cached(
        &self,
        action_id: &str,
    ) -> Result<Arc<Vec<String>>, LedgerError> {
        learned_allowlist::get_cached(&self.writer, &self.learned_cache, &DOMAINS, action_id)
    }

    /// Invalidate the learned domains cache.
    pub fn invalidate_learned_cache(&self) {
        learned_allowlist::invalidate_cache(&self.learned_cache);
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
            .add_learned_domain(
                "slack_post",
                "hooks.slack.com",
                "alice",
                EntrySource::Cli,
                None,
                false
            )
            .unwrap());
    }

    #[test]
    fn duplicate_is_idempotent() {
        let s = store();
        s.add_learned_domain(
            "slack_post",
            "hooks.slack.com",
            "alice",
            EntrySource::Cli,
            None,
            false,
        )
        .unwrap();
        assert!(!s
            .add_learned_domain(
                "slack_post",
                "hooks.slack.com",
                "bob",
                EntrySource::Cli,
                None,
                false
            )
            .unwrap());
    }

    #[test]
    fn same_domain_different_actions_independent() {
        let s = store();
        assert!(s
            .add_learned_domain(
                "slack_post",
                "hooks.slack.com",
                "alice",
                EntrySource::Cli,
                None,
                false
            )
            .unwrap());
        assert!(s
            .add_learned_domain(
                "web_read",
                "hooks.slack.com",
                "alice",
                EntrySource::Cli,
                None,
                false
            )
            .unwrap());
    }

    #[test]
    fn remove_deletes_and_returns_true() {
        let s = store();
        s.add_learned_domain(
            "web_read",
            "example.com",
            "alice",
            EntrySource::Approval,
            Some("appr-1"),
            false,
        )
        .unwrap();
        assert!(s.remove_learned_domain("web_read", "example.com").unwrap());
        assert!(!s.is_domain_learned("web_read", "example.com").unwrap());
    }

    #[test]
    fn remove_nonexistent_returns_false() {
        assert!(!store()
            .remove_learned_domain("web_read", "nope.com")
            .unwrap());
    }

    #[test]
    fn list_all_and_filtered() {
        let s = store();
        s.add_learned_domain(
            "slack_post",
            "hooks.slack.com",
            "alice",
            EntrySource::Approval,
            Some("a"),
            false,
        )
        .unwrap();
        s.add_learned_domain(
            "web_read",
            "example.com",
            "bob",
            EntrySource::Cli,
            None,
            false,
        )
        .unwrap();
        assert_eq!(s.list_learned_domains(None).unwrap().len(), 2);
        let filtered = s.list_learned_domains(Some("web_read")).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].domain, "example.com");
    }

    #[test]
    fn get_for_action_returns_sorted() {
        let s = store();
        s.add_learned_domain(
            "web_read",
            "z-site.com",
            "alice",
            EntrySource::Cli,
            None,
            false,
        )
        .unwrap();
        s.add_learned_domain(
            "web_read",
            "a-site.com",
            "alice",
            EntrySource::Cli,
            None,
            false,
        )
        .unwrap();
        assert_eq!(
            s.get_learned_domains_for_action("web_read").unwrap(),
            vec!["a-site.com", "z-site.com"]
        );
    }

    #[test]
    fn is_learned_positive_and_negative() {
        let s = store();
        s.add_learned_domain(
            "web_read",
            "example.com",
            "alice",
            EntrySource::Cli,
            None,
            false,
        )
        .unwrap();
        assert!(s.is_domain_learned("web_read", "example.com").unwrap());
        assert!(!s.is_domain_learned("web_read", "other.com").unwrap());
        assert!(!s.is_domain_learned("slack_post", "example.com").unwrap());
    }

    #[test]
    fn clear_for_action_scoped() {
        let s = store();
        s.add_learned_domain("web_read", "a.com", "alice", EntrySource::Cli, None, false)
            .unwrap();
        s.add_learned_domain("web_read", "b.com", "alice", EntrySource::Cli, None, false)
            .unwrap();
        s.add_learned_domain(
            "slack_post",
            "c.com",
            "alice",
            EntrySource::Cli,
            None,
            false,
        )
        .unwrap();
        assert_eq!(s.clear_learned_domains_for_action("web_read").unwrap(), 2);
        assert!(s
            .get_learned_domains_for_action("web_read")
            .unwrap()
            .is_empty());
        assert_eq!(
            s.get_learned_domains_for_action("slack_post").unwrap(),
            vec!["c.com"]
        );
    }

    #[test]
    fn audit_fields_roundtrip() {
        let s = store();
        s.add_learned_domain(
            "web_read",
            "example.com",
            "alice",
            EntrySource::Approval,
            Some("appr-42"),
            false,
        )
        .unwrap();
        let all = s.list_learned_domains(Some("web_read")).unwrap();
        let d = &all[0];
        assert_eq!(d.action_id, "web_read");
        assert_eq!(d.domain, "example.com");
        assert_eq!(d.added_by, "alice");
        assert_eq!(d.source, "approval");
        assert_eq!(d.approval_id.as_deref(), Some("appr-42"));
        assert!(!d.added_at.is_empty());
    }

    #[test]
    fn survives_db_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("ledger.db");
        {
            let s = LedgerStore::open(&db_path, None).unwrap();
            s.add_learned_domain(
                "web_read",
                "persisted.com",
                "alice",
                EntrySource::Cli,
                None,
                false,
            )
            .unwrap();
        }
        let s = LedgerStore::open(&db_path, None).unwrap();
        assert!(s.is_domain_learned("web_read", "persisted.com").unwrap());
    }

    #[test]
    fn does_not_affect_hash_chain() {
        let s = store();
        let mut e1 =
            crate::events::AuditEventBuilder::new("t1", crate::events::EventType::ActionCall)
                .build();
        s.write_event(&mut e1).unwrap();
        s.add_learned_domain(
            "action",
            "example.com",
            "alice",
            EntrySource::Cli,
            None,
            false,
        )
        .unwrap();
        let mut e2 =
            crate::events::AuditEventBuilder::new("t2", crate::events::EventType::ActionCall)
                .build();
        s.write_event(&mut e2).unwrap();
        let chain = s.verify_chain().unwrap();
        assert!(chain.is_intact());
        assert_eq!(chain.total_events, 2);
    }

    #[test]
    fn all_sources_roundtrip() {
        let s = store();
        s.add_learned_domain("a", "cli.com", "alice", EntrySource::Cli, None, false)
            .unwrap();
        s.add_learned_domain(
            "a",
            "approval.com",
            "bob",
            EntrySource::Approval,
            Some("x"),
            false,
        )
        .unwrap();
        s.add_learned_domain("a", "import.com", "sys", EntrySource::Import, None, false)
            .unwrap();
        let sources: Vec<String> = s
            .list_learned_domains(Some("a"))
            .unwrap()
            .iter()
            .map(|d| d.source.clone())
            .collect();
        assert!(sources.contains(&"cli".to_string()));
        assert!(sources.contains(&"approval".to_string()));
        assert!(sources.contains(&"import".to_string()));
    }

    #[test]
    fn concurrent_add_remove_consistent() {
        use std::sync::Arc;
        let s = Arc::new(store());
        let handles: Vec<_> = (0..10)
            .map(|i| {
                let s = Arc::clone(&s);
                std::thread::spawn(move || {
                    s.add_learned_domain(
                        "web_read",
                        &format!("site-{i}.com"),
                        "alice",
                        EntrySource::Cli,
                        None,
                        false,
                    )
                    .unwrap();
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(
            s.get_learned_domains_for_action("web_read").unwrap().len(),
            10
        );

        let handles: Vec<_> = (0..5)
            .map(|i| {
                let s = Arc::clone(&s);
                std::thread::spawn(move || {
                    s.remove_learned_domain("web_read", &format!("site-{i}.com"))
                        .unwrap();
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(
            s.get_learned_domains_for_action("web_read").unwrap().len(),
            5
        );
    }

    // === Validation ===

    #[test]
    fn rejects_empty() {
        assert!(store()
            .add_learned_domain("a", "", "x", EntrySource::Cli, None, false)
            .is_err());
    }
    #[test]
    fn rejects_private_ip() {
        assert!(store()
            .add_learned_domain("a", "127.0.0.1", "x", EntrySource::Cli, None, false)
            .is_err());
    }
    #[test]
    fn rejects_localhost() {
        assert!(store()
            .add_learned_domain("a", "localhost", "x", EntrySource::Cli, None, false)
            .is_err());
    }
    #[test]
    fn rejects_wildcard() {
        assert!(store()
            .add_learned_domain("a", "*.example.com", "x", EntrySource::Cli, None, false)
            .is_err());
    }
    #[test]
    fn rejects_no_dot() {
        assert!(store()
            .add_learned_domain("a", "intranet", "x", EntrySource::Cli, None, false)
            .is_err());
    }

    #[test]
    fn normalizes_case() {
        let s = store();
        s.add_learned_domain("a", "API.GitHub.COM", "x", EntrySource::Cli, None, false)
            .unwrap();
        assert_eq!(
            s.get_learned_domains_for_action("a").unwrap(),
            vec!["api.github.com"]
        );
    }

    #[test]
    fn normalizes_trailing_dot() {
        let s = store();
        s.add_learned_domain("a", "example.com.", "x", EntrySource::Cli, None, false)
            .unwrap();
        assert_eq!(
            s.get_learned_domains_for_action("a").unwrap(),
            vec!["example.com"]
        );
    }

    #[test]
    fn normalized_dedup() {
        let s = store();
        assert!(s
            .add_learned_domain("a", "Example.COM", "x", EntrySource::Cli, None, false)
            .unwrap());
        assert!(!s
            .add_learned_domain("a", "example.com", "y", EntrySource::Cli, None, false)
            .unwrap());
    }
}
