//! Approval lifecycle store: atomic claim => execute => complete.
//!
//! # Lifecycle
//!
//! ```text
//! ┌─────────┐  claim_pending()   ┌─────────┐  complete_approved()  ┌──────────┐
//! │ Pending ├───────────────────>│ Claimed ├──────────────────────>│ Approved │
//! └────┬────┘                    └────┬────┘                       └──────────┘
//!      │                              │
//!      │  (Redis TTL)                 │   complete_denied()         ┌────────┐
//!      │                              ├────────────────────────────>│ Denied │
//!      │                              │                             └────────┘
//!      │                              │   complete_failed()         ┌────────┐
//!      │                              ├────────────────────────────>│ Failed │
//!      │                              │                             └────────┘
//!      │                              │   (claim TTL expires)
//!      │                              └────> re-claimable (state stays Claimed,
//!      │                                     but expired claim allows re-claim)
//!      ▼
//! ┌─────────┐
//! │ Expired │  (Redis TTL purges key — implicit)
//! └─────────┘
//! ```
//!
//! # Atomicity
//!
//! All state transitions are atomic:
//! - **Redis**: Lua scripts perform read-check-write in a single command.
//!   No `GET` + `SET` from Rust — all transitions happen inside Redis.
//! - **In-memory**: `RwLock` held for the entire transition.
//!
//! # Security properties
//!
//! - **One-shot execution**: `claim_pending` succeeds for at most one caller.
//!   Parallel approve requests: one wins, others get `AlreadyClaimed`.
//! - **Crash recovery**: if a process claims but crashes before completing,
//!   the claim expires after `claim_ttl` and the approval becomes re-claimable.
//!   The forensics record shows the incomplete attempt.
//! - **Forensic trail**: completed records stay in Redis for `forensics_ttl`
//!   (default 1 hour) before expiry. Operators can query status via GET.
//! - **Fail-closed**: Redis unavailable => `ApprovalError::Unavailable` => 503.

use std::sync::Arc;
use std::time::Duration;

use tracing::instrument;

use crate::approval_inmemory::InMemoryStore;
use crate::sqlite::SqliteStateDb;

pub use crate::approval_types::*;

// ApprovalStore

/// Default claim TTL: 120 seconds.
///
/// If a process claims but crashes, the claim expires after this duration
/// and the approval becomes re-claimable.
const DEFAULT_CLAIM_TTL_SECS: u64 = 120;

/// Default forensics TTL: 1 hour.
///
/// Completed records stay in Redis for this duration so operators can query
/// them via GET before they expire.
const DEFAULT_FORENSICS_TTL_SECS: u64 = 3600;

pub struct ApprovalStore {
    pub(crate) backend: ApprovalBackend,
    pub(crate) default_ttl: Duration,
    pub(crate) claim_ttl_secs: u64,
    pub(crate) forensics_ttl_secs: u64,
}

pub(crate) enum ApprovalBackend {
    Redis(redis::Client),
    Sqlite(Arc<SqliteStateDb>),
    InMemory(InMemoryStore),
}

impl std::fmt::Debug for ApprovalStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match &self.backend {
            ApprovalBackend::Redis(_) => "redis",
            ApprovalBackend::Sqlite(_) => "sqlite",
            ApprovalBackend::InMemory(_) => "in_memory",
        };
        f.debug_struct("ApprovalStore")
            .field("backend", &kind)
            .field("default_ttl", &self.default_ttl)
            .field("claim_ttl_secs", &self.claim_ttl_secs)
            .finish_non_exhaustive()
    }
}

impl ApprovalStore {
    /// Create a new `ApprovalStore` backed by Redis.
    pub fn new(redis_url: &str, default_ttl: Duration) -> Result<Self, ApprovalError> {
        let client =
            redis::Client::open(redis_url).map_err(|e| ApprovalError::InvalidUrl(e.to_string()))?;
        Ok(Self {
            backend: ApprovalBackend::Redis(client),
            default_ttl,
            claim_ttl_secs: DEFAULT_CLAIM_TTL_SECS,
            forensics_ttl_secs: DEFAULT_FORENSICS_TTL_SECS,
        })
    }

    /// Create an `ApprovalStore` backed by SQLite.
    ///
    /// Persistent across restarts. State machine transitions use
    /// `BEGIN IMMEDIATE` for single-writer atomicity.
    pub fn sqlite(db: Arc<SqliteStateDb>, default_ttl: Duration) -> Self {
        Self {
            backend: ApprovalBackend::Sqlite(db),
            default_ttl,
            claim_ttl_secs: DEFAULT_CLAIM_TTL_SECS,
            forensics_ttl_secs: DEFAULT_FORENSICS_TTL_SECS,
        }
    }

    /// Create an in-memory `ApprovalStore` for testing.
    ///
    /// TTL expiry is checked lazily. NOT suitable for production.
    #[doc(hidden)]
    pub fn in_memory_for_tests(default_ttl: Duration) -> Self {
        Self {
            backend: ApprovalBackend::InMemory(Arc::new(tokio::sync::RwLock::new(
                std::collections::HashMap::new(),
            ))),
            default_ttl,
            claim_ttl_secs: DEFAULT_CLAIM_TTL_SECS,
            forensics_ttl_secs: DEFAULT_FORENSICS_TTL_SECS,
        }
    }

    /// Default TTL for pending approvals.
    pub fn default_ttl(&self) -> Duration {
        self.default_ttl
    }

    /// Readiness check: verify the backend is reachable.
    ///
    /// Returns `true` if a Redis PING succeeds (or if in-memory backend).
    /// Used by `/readyz` to determine if the approval store can handle requests.
    pub async fn ping(&self) -> bool {
        match &self.backend {
            ApprovalBackend::Redis(client) => {
                let conn = client.get_multiplexed_async_connection().await;
                match conn {
                    Ok(mut c) => {
                        let result: Result<String, _> =
                            redis::cmd("PING").query_async(&mut c).await;
                        result.is_ok()
                    }
                    Err(_) => false,
                }
            }
            ApprovalBackend::Sqlite(_) => true,
            ApprovalBackend::InMemory(_) => true,
        }
    }

    // create_pending — insert new approval in Pending state

    /// Persist a new approval in `Pending` state with TTL.
    #[instrument(name = "approval.create", skip(self, pending), fields(approval_id = %pending.approval_id, action_id = %pending.action_id))]
    pub async fn create_pending(&self, pending: &PendingApproval) -> Result<(), ApprovalError> {
        let record = ApprovalRecord::new_pending(pending.clone());

        match &self.backend {
            ApprovalBackend::Redis(client) => self.redis_create(client, &record).await,
            ApprovalBackend::Sqlite(db) => self.sqlite_create(db, &record).await,
            ApprovalBackend::InMemory(store) => self.inmemory_create(store, &record).await,
        }
    }

    // get_pending — read-only access (for GET endpoint compatibility)

    /// Retrieve a pending approval payload. Returns `None` if expired, never
    /// created, or already in a terminal state.
    ///
    /// SECURITY: this is a read-only operation. It does NOT claim the approval.
    /// Use `claim_pending` for the approve/deny flow.
    #[instrument(name = "approval.get", skip(self), fields(%approval_id))]
    pub async fn get_pending(
        &self,
        approval_id: &str,
    ) -> Result<Option<PendingApproval>, ApprovalError> {
        match &self.backend {
            ApprovalBackend::Redis(client) => self.redis_get_pending(client, approval_id).await,
            ApprovalBackend::Sqlite(db) => self.sqlite_get_pending(db, approval_id).await,
            ApprovalBackend::InMemory(store) => self.inmemory_get_pending(store, approval_id).await,
        }
    }

    /// Retrieve the approval payload regardless of lifecycle state.
    ///
    /// Unlike [`get_pending`](Self::get_pending), this returns the payload
    /// even for `claimed`, `approved`, or `denied` approvals — as long as
    /// the record has not expired or been purged. Used by the operator detail
    /// endpoint where plan review fields must be visible throughout the
    /// approval lifecycle, not only while pending.
    ///
    /// SECURITY: read-only, no state mutation. The operator is already
    /// authenticated by the caller.
    #[instrument(name = "approval.get_payload", skip(self), fields(%approval_id))]
    pub async fn get_payload(
        &self,
        approval_id: &str,
    ) -> Result<Option<PendingApproval>, ApprovalError> {
        match &self.backend {
            ApprovalBackend::Redis(client) => self.redis_get_payload(client, approval_id).await,
            ApprovalBackend::Sqlite(db) => self.sqlite_get_payload(db, approval_id).await,
            // InMemory backend never filters by state — reuse get_pending.
            ApprovalBackend::InMemory(store) => self.inmemory_get_pending(store, approval_id).await,
        }
    }

    // get_status — full status for operator GET endpoint

    /// Retrieve the current status of an approval (any state).
    ///
    /// Returns `None` only if the key was never created or has been purged.
    /// Terminal records are visible until `forensics_ttl` expires.
    #[instrument(name = "approval.get_status", skip(self), fields(%approval_id))]
    pub async fn get_status(
        &self,
        approval_id: &str,
    ) -> Result<Option<ApprovalStatus>, ApprovalError> {
        let record = match &self.backend {
            ApprovalBackend::Redis(client) => self.redis_get_record(client, approval_id).await?,
            ApprovalBackend::Sqlite(db) => self.sqlite_get_record(db, approval_id).await?,
            ApprovalBackend::InMemory(store) => Self::inmemory_get_record(store, approval_id).await,
        };

        Ok(record.map(|r| r.to_status()))
    }

    // list_approvals — bounded listing with optional state filter

    /// List approvals matching an optional state filter.
    ///
    /// Returns up to `limit` summaries, sorted by `created_at` descending
    /// (newest first). Both pending and terminal records are listable —
    /// terminal records remain visible until their Redis TTL (or in-memory
    /// TTL) expires.
    ///
    /// SECURITY: this is a read-only operation. It never modifies state.
    /// The caller (API layer) is responsible for operator authentication.
    ///
    /// # Redis implementation
    ///
    /// Uses `SCAN` with a bounded iteration count to avoid blocking the
    /// server on large keyspaces. Each batch of keys is fetched via a
    /// pipelined `HGETALL`. Corrupted records are skipped with a warning.
    ///
    /// # Cardinality
    ///
    /// Pending approvals are bounded by TTL (`default_ttl`). Terminal
    /// records are bounded by `forensics_ttl`. Under normal operation
    /// the total key count is small (dozens to low hundreds).
    #[instrument(name = "approval.list", skip(self), fields(?state_filter, %limit))]
    pub async fn list_approvals(
        &self,
        state_filter: Option<ApprovalState>,
        limit: usize,
    ) -> Result<Vec<ApprovalSummary>, ApprovalError> {
        let limit = limit.min(1000); // hard cap to prevent abuse

        match &self.backend {
            ApprovalBackend::Redis(client) => {
                self.redis_list_approvals(client, state_filter, limit).await
            }
            ApprovalBackend::Sqlite(db) => self.sqlite_list(db, state_filter, limit).await,
            ApprovalBackend::InMemory(store) => {
                self.inmemory_list(store, state_filter, limit).await
            }
        }
    }

    // claim_pending — atomic Pending => Claimed

    /// Atomically claim a pending approval for execution.
    ///
    /// SECURITY: at most one caller succeeds. All others receive
    /// `AlreadyClaimed` or `AlreadyCompleted`. This prevents double execution.
    ///
    /// If a previous claim expired (process crashed), the approval can be
    /// re-claimed. The expired claim is visible in the record for forensics.
    #[instrument(name = "approval.claim", skip(self), fields(%approval_id, %operator_id))]
    pub async fn claim_pending(
        &self,
        approval_id: &str,
        operator_id: &str,
    ) -> Result<ClaimedApproval, ApprovalError> {
        let claim_token = {
            use rand::RngCore;
            let mut bytes = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            hex::encode(bytes)
        };
        let now = chrono::Utc::now();
        let now_unix = now.timestamp();
        let now_millis = now.timestamp_millis();
        let claimed_at = now.to_rfc3339();

        match &self.backend {
            ApprovalBackend::Redis(client) => {
                self.redis_claim(
                    client,
                    approval_id,
                    operator_id,
                    &claim_token,
                    self.claim_ttl_secs,
                    now_unix,
                    &claimed_at,
                )
                .await
            }
            ApprovalBackend::Sqlite(db) => {
                self.sqlite_claim(
                    db,
                    approval_id,
                    operator_id,
                    &claim_token,
                    now_unix,
                    &claimed_at,
                )
                .await
            }
            ApprovalBackend::InMemory(store) => {
                self.inmemory_claim(
                    store,
                    approval_id,
                    operator_id,
                    &claim_token,
                    now_millis,
                    &claimed_at,
                )
                .await
            }
        }
    }

    // complete_approved — atomic Claimed => Approved

    /// Atomically transition a claimed approval to terminal `Approved` state.
    ///
    /// SECURITY: `claim_token` must match the token returned by `claim_pending`.
    /// `receipt_id` is persisted for idempotent retry lookups.
    #[instrument(name = "approval.complete_approved", skip(self), fields(%approval_id))]
    pub async fn complete_approved(
        &self,
        approval_id: &str,
        claim_token: &str,
        trace_id: &str,
        receipt_id: &str,
    ) -> Result<(), ApprovalError> {
        self.complete(
            approval_id,
            claim_token,
            ApprovalState::Approved,
            trace_id,
            "receipt_id",
            receipt_id,
        )
        .await
    }

    // complete_denied — atomic Claimed => Denied

    /// Atomically transition a claimed approval to terminal `Denied` state.
    ///
    /// `reason` is persisted for forensic audit trail.
    #[instrument(name = "approval.complete_denied", skip(self), fields(%approval_id))]
    pub async fn complete_denied(
        &self,
        approval_id: &str,
        claim_token: &str,
        trace_id: &str,
        reason: &str,
    ) -> Result<(), ApprovalError> {
        self.complete(
            approval_id,
            claim_token,
            ApprovalState::Denied,
            trace_id,
            "deny_reason",
            reason,
        )
        .await
    }

    // complete_failed — atomic Claimed => Failed

    /// Atomically transition a claimed approval to terminal `Failed` state.
    ///
    /// SECURITY: called when execution fails after claim (provider error,
    /// timeout, etc.). Prevents the claim from expiring silently and
    /// allowing re-execution of non-idempotent side effects.
    /// `error_code` is persisted for forensic audit trail.
    #[instrument(name = "approval.complete_failed", skip(self), fields(%approval_id))]
    pub async fn complete_failed(
        &self,
        approval_id: &str,
        claim_token: &str,
        trace_id: &str,
        error_code: &str,
    ) -> Result<(), ApprovalError> {
        self.complete(
            approval_id,
            claim_token,
            ApprovalState::Failed,
            trace_id,
            "error_code",
            error_code,
        )
        .await
    }

    // write_outcome_marker — durable pre-completion marker (02)

    /// Write a durable outcome marker to the approval record.
    ///
    /// SECURITY (02): this method MUST be called AFTER the side effect
    /// occurs (approve => execute => marker) or AFTER the deny decision
    /// (deny => claim => marker), but BEFORE `complete_*()`. The marker
    /// permanently blocks re-claim via `LUA_CLAIM`'s outcome check,
    /// closing the window between side-effect execution and terminal
    /// state persistence.
    ///
    /// If both `write_outcome_marker()` and `complete_*()` fail (e.g.
    /// Redis goes down), the claim TTL still provides a bounded window
    /// before re-claim becomes possible. But if only `complete_*()` fails,
    /// the outcome marker alone is sufficient to prevent double execution.
    ///
    /// This method is **idempotent**: calling it twice with the same
    /// approval and claim token succeeds silently. Safe for retry.
    ///
    /// # Arguments
    ///
    /// * `outcome_kind` — one of `"approved"`, `"denied"`, `"failed"`.
    /// * `outcome_detail` — receipt_id, deny reason, or error code.
    #[instrument(name = "approval.write_outcome_marker", skip(self), fields(%approval_id, %outcome_kind))]
    pub async fn write_outcome_marker(
        &self,
        approval_id: &str,
        claim_token: &str,
        outcome_kind: &str,
        outcome_detail: &str,
    ) -> Result<(), ApprovalError> {
        let outcome_at = chrono::Utc::now().to_rfc3339();

        match &self.backend {
            ApprovalBackend::Redis(client) => {
                self.redis_write_outcome(
                    client,
                    approval_id,
                    claim_token,
                    outcome_kind,
                    outcome_detail,
                    &outcome_at,
                )
                .await
            }
            ApprovalBackend::Sqlite(db) => {
                self.sqlite_write_outcome(
                    db,
                    approval_id,
                    claim_token,
                    outcome_kind,
                    outcome_detail,
                    &outcome_at,
                )
                .await
            }
            ApprovalBackend::InMemory(store) => {
                self.inmemory_write_outcome(
                    store,
                    approval_id,
                    claim_token,
                    outcome_kind,
                    outcome_detail,
                    &outcome_at,
                )
                .await
            }
        }
    }

    // complete — shared implementation

    async fn complete(
        &self,
        approval_id: &str,
        claim_token: &str,
        terminal_state: ApprovalState,
        trace_id: &str,
        detail_key: &str,
        detail_value: &str,
    ) -> Result<(), ApprovalError> {
        let completed_at = chrono::Utc::now().to_rfc3339();
        if !terminal_state.is_terminal() {
            return Err(ApprovalError::DataCorrupted(
                "complete() called with non-terminal state".into(),
            ));
        }
        let state_str = terminal_state.as_str();

        match &self.backend {
            ApprovalBackend::Redis(client) => {
                self.redis_complete(
                    client,
                    approval_id,
                    claim_token,
                    state_str,
                    trace_id,
                    &completed_at,
                    self.forensics_ttl_secs,
                    detail_key,
                    detail_value,
                )
                .await
            }
            ApprovalBackend::Sqlite(db) => {
                self.sqlite_complete(
                    db,
                    approval_id,
                    claim_token,
                    state_str,
                    trace_id,
                    &completed_at,
                    detail_key,
                    detail_value,
                )
                .await
            }
            ApprovalBackend::InMemory(store) => {
                self.inmemory_complete(
                    store,
                    approval_id,
                    claim_token,
                    terminal_state,
                    trace_id,
                    &completed_at,
                    detail_key,
                    detail_value,
                )
                .await
            }
        }
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval_redis::approval_key;

    // Key formatting

    #[test]
    fn approval_key_has_correct_prefix() {
        assert_eq!(approval_key("abc-123"), "latch:approval:abc-123");
    }

    // ApprovalState

    #[test]
    fn terminal_states_are_terminal() {
        assert!(ApprovalState::Approved.is_terminal());
        assert!(ApprovalState::Denied.is_terminal());
        assert!(ApprovalState::Failed.is_terminal());
        assert!(!ApprovalState::Pending.is_terminal());
        assert!(!ApprovalState::Claimed.is_terminal());
    }

    // Construction

    #[test]
    fn new_with_valid_url_succeeds() {
        let store = ApprovalStore::new(&test_redis_url(), Duration::from_secs(300));
        assert!(store.is_ok());
    }

    #[test]
    fn new_with_invalid_url_returns_error() {
        let store = ApprovalStore::new("not-a-url", Duration::from_secs(300));
        assert!(store.is_err());
        assert!(matches!(store.unwrap_err(), ApprovalError::InvalidUrl(_)));
    }

    // Test helpers

    fn test_redis_url() -> String {
        std::env::var("LATCHGATE_REDIS_URL")
            .unwrap_or_else(|_| "redis://:changeme@127.0.0.1:6379".to_string())
    }

    /// Check if Redis is reachable — skip test gracefully if not.
    fn redis_available() -> bool {
        std::net::TcpStream::connect_timeout(
            &"127.0.0.1:6379".parse().unwrap(),
            std::time::Duration::from_millis(200),
        )
        .is_ok()
    }

    fn test_store() -> ApprovalStore {
        ApprovalStore::new(&test_redis_url(), Duration::from_secs(300)).unwrap()
    }

    fn test_plan() -> latchgate_core::ApprovedExecutionPlan {
        latchgate_core::ApprovedExecutionPlan::test_default()
    }

    fn test_pending() -> PendingApproval {
        PendingApproval {
            approval_id: uuid::Uuid::now_v7().to_string(),
            trace_id: uuid::Uuid::now_v7().to_string().into(),
            action_id: "http_fetch".into(),
            auth_context: StoredAuthContext {
                principal: "agent-1".into(),
                session_id: "sess-001".into(),
                lease_jti: "jti-abc".into(),
                sender_thumbprint: "thumb-abc".into(),
                owner: None,
            },
            request_hash: "sha256:deadbeef".into(),
            request_body: std::sync::Arc::new(serde_json::json!({"url": "https://example.com"})),
            policy_version: Some("v1.2.3".into()),
            created_at: chrono::Utc::now().to_rfc3339(),
            plan: test_plan(),
            unresolved_domains: vec![],
            unresolved_paths: vec![],
        }
    }

    // Basic lifecycle (Redis)

    #[tokio::test]
    async fn create_and_get_pending() {
        if !redis_available() {
            eprintln!("skipping create_and_get_pending: Redis not available on 127.0.0.1:6379");
            return;
        }
        let store = test_store();
        let pending = test_pending();
        let id = pending.approval_id.clone();

        store.create_pending(&pending).await.unwrap();

        let retrieved = store.get_pending(&id).await.unwrap().unwrap();
        assert_eq!(retrieved.approval_id, id);
        assert_eq!(&*retrieved.action_id, "http_fetch");
    }

    #[tokio::test]
    async fn get_nonexistent_returns_none() {
        if !redis_available() {
            eprintln!(
                "skipping get_nonexistent_returns_none: Redis not available on 127.0.0.1:6379"
            );
            return;
        }
        let store = test_store();
        let result = store.get_pending("nonexistent-id").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn pending_approval_roundtrips_with_full_plan() {
        if !redis_available() {
            eprintln!("skipping pending_approval_roundtrips_with_full_plan: Redis not available on 127.0.0.1:6379");
            return;
        }
        let store = test_store();
        let pending = test_pending();
        let id = pending.approval_id.clone();

        store.create_pending(&pending).await.unwrap();
        let retrieved = store.get_pending(&id).await.unwrap().unwrap();

        assert!(
            retrieved.plan.verify_hash(),
            "plan hash must verify after Redis roundtrip"
        );
        assert_eq!(retrieved.plan, pending.plan);
    }

    #[tokio::test]
    async fn unresolved_domains_survive_redis_roundtrip() {
        if !redis_available() {
            eprintln!("skipping unresolved_domains_survive_redis_roundtrip: Redis not available on 127.0.0.1:6379");
            return;
        }
        let store = test_store();
        let mut pending = test_pending();
        pending.unresolved_domains = vec!["newsite.com".into(), "api.other.dev".into()];
        let id = pending.approval_id.clone();

        store.create_pending(&pending).await.unwrap();
        let retrieved = store.get_pending(&id).await.unwrap().unwrap();

        assert_eq!(
            retrieved.unresolved_domains,
            vec!["newsite.com", "api.other.dev"],
            "unresolved_domains must survive Redis serialization roundtrip"
        );
    }

    // Claim lifecycle (Redis)

    #[tokio::test]
    async fn claim_and_complete_approved() {
        if !redis_available() {
            eprintln!(
                "skipping claim_and_complete_approved: Redis not available on 127.0.0.1:6379"
            );
            return;
        }
        let store = test_store();
        let pending = test_pending();
        let id = pending.approval_id.clone();

        store.create_pending(&pending).await.unwrap();

        let claimed = store.claim_pending(&id, "alice").await.unwrap();
        assert_eq!(claimed.pending.approval_id, id);
        assert!(!claimed.claim_token.is_empty());

        store
            .complete_approved(&id, &claimed.claim_token, "trace-001", "rcpt-001")
            .await
            .unwrap();

        // Status should show approved.
        let status = store.get_status(&id).await.unwrap().unwrap();
        assert_eq!(status.state, ApprovalState::Approved);
        assert_eq!(status.claimed_by.as_deref(), Some("alice"));
    }

    #[tokio::test]
    async fn claim_and_complete_denied() {
        if !redis_available() {
            eprintln!("skipping claim_and_complete_denied: Redis not available on 127.0.0.1:6379");
            return;
        }
        let store = test_store();
        let pending = test_pending();
        let id = pending.approval_id.clone();

        store.create_pending(&pending).await.unwrap();

        let claimed = store.claim_pending(&id, "bob").await.unwrap();

        store
            .complete_denied(&id, &claimed.claim_token, "trace-002", "operator_denied")
            .await
            .unwrap();

        let status = store.get_status(&id).await.unwrap().unwrap();
        assert_eq!(status.state, ApprovalState::Denied);
    }

    // Concurrency tests (in-memory — deterministic)

    #[tokio::test]
    async fn parallel_approve_only_one_claim_succeeds() {
        let store = Arc::new(ApprovalStore::in_memory_for_tests(Duration::from_secs(300)));
        let pending = test_pending();
        let id = pending.approval_id.clone();

        store.create_pending(&pending).await.unwrap();

        let mut handles = Vec::new();
        for i in 0..10 {
            let store = Arc::clone(&store);
            let id = id.clone();
            handles.push(tokio::spawn(async move {
                store.claim_pending(&id, &format!("op-{i}")).await
            }));
        }

        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.await.unwrap());
        }

        let successes: Vec<_> = results.iter().filter(|r| r.is_ok()).collect();
        let claimed_errors: Vec<_> = results
            .iter()
            .filter(|r| matches!(r, Err(ApprovalError::AlreadyClaimed { .. })))
            .collect();

        assert_eq!(successes.len(), 1, "exactly one claim must succeed");
        assert_eq!(
            claimed_errors.len(),
            9,
            "all others must get AlreadyClaimed"
        );
    }

    #[tokio::test]
    async fn parallel_deny_only_one_claim_succeeds() {
        let store = Arc::new(ApprovalStore::in_memory_for_tests(Duration::from_secs(300)));
        let pending = test_pending();
        let id = pending.approval_id.clone();

        store.create_pending(&pending).await.unwrap();

        let mut handles = Vec::new();
        for i in 0..10 {
            let store = Arc::clone(&store);
            let id = id.clone();
            handles.push(tokio::spawn(async move {
                store.claim_pending(&id, &format!("op-{i}")).await
            }));
        }

        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.await.unwrap());
        }

        let successes: Vec<_> = results.iter().filter(|r| r.is_ok()).collect();
        assert_eq!(successes.len(), 1);
    }

    #[tokio::test]
    async fn approve_and_deny_race_produces_single_terminal_outcome() {
        let store = Arc::new(ApprovalStore::in_memory_for_tests(Duration::from_secs(300)));
        let pending = test_pending();
        let id = pending.approval_id.clone();

        store.create_pending(&pending).await.unwrap();

        // Only one can claim.
        let claim1 = store.claim_pending(&id, "approver").await;
        let claim2 = store.claim_pending(&id, "denier").await;

        assert!(claim1.is_ok() || claim2.is_ok());
        assert!(claim1.is_err() || claim2.is_err());

        // The winner completes.
        if let Ok(claimed) = claim1 {
            store
                .complete_approved(&id, &claimed.claim_token, "t1", "rcpt-t1")
                .await
                .unwrap();
        } else if let Ok(claimed) = claim2 {
            store
                .complete_denied(&id, &claimed.claim_token, "t2", "operator_denied")
                .await
                .unwrap();
        }

        let status = store.get_status(&id).await.unwrap().unwrap();
        assert!(
            status.state.is_terminal(),
            "must reach exactly one terminal state"
        );
    }

    // Recovery: expired claim can be re-claimed

    #[tokio::test]
    async fn expired_claim_can_be_reclaimed() {
        // Store with 1-second claim TTL.
        let mut store = ApprovalStore::in_memory_for_tests(Duration::from_secs(300));
        store.claim_ttl_secs = 1;

        let pending = test_pending();
        let id = pending.approval_id.clone();

        store.create_pending(&pending).await.unwrap();

        let claim1 = store.claim_pending(&id, "op-1").await.unwrap();

        // Second claim should fail immediately.
        let claim2 = store.claim_pending(&id, "op-2").await;
        assert!(
            matches!(claim2, Err(ApprovalError::AlreadyClaimed { .. })),
            "concurrent claim must fail"
        );

        // Wait for claim to expire.
        // NOTE: must use std::thread::sleep (real wall-clock) because
        // claim_pending uses chrono::Utc::now() for expiry checks, not
        // tokio::time::Instant. tokio::time::sleep only advances tokio's
        // internal clock which chrono does not observe.
        // Margin: 3s sleep for 1s TTL — 2s headroom for CI load.
        std::thread::sleep(Duration::from_secs(3));

        // Now re-claim should succeed.
        let claim3 = store.claim_pending(&id, "op-3").await.unwrap();

        // Old token should not work.
        let complete_old = store
            .complete_approved(&id, &claim1.claim_token, "trace-old", "rcpt-old")
            .await;
        assert!(
            matches!(complete_old, Err(ApprovalError::TokenMismatch { .. })),
            "old claim token must be rejected"
        );

        // New token works.
        store
            .complete_approved(&id, &claim3.claim_token, "trace-new", "rcpt-new")
            .await
            .unwrap();
    }

    // Terminal state prevents further operations

    #[tokio::test]
    async fn same_approval_id_cannot_execute_twice() {
        let store = ApprovalStore::in_memory_for_tests(Duration::from_secs(300));
        let pending = test_pending();
        let id = pending.approval_id.clone();

        store.create_pending(&pending).await.unwrap();

        let claimed = store.claim_pending(&id, "alice").await.unwrap();
        store
            .complete_approved(&id, &claimed.claim_token, "trace-1", "rcpt-1")
            .await
            .unwrap();

        // Second claim after completion must fail.
        let claim2 = store.claim_pending(&id, "bob").await;
        assert!(
            matches!(claim2, Err(ApprovalError::AlreadyCompleted { .. })),
            "claim after terminal state must fail"
        );
    }

    #[tokio::test]
    async fn retry_after_terminal_returns_already_completed() {
        let store = ApprovalStore::in_memory_for_tests(Duration::from_secs(300));
        let pending = test_pending();
        let id = pending.approval_id.clone();

        store.create_pending(&pending).await.unwrap();

        let claimed = store.claim_pending(&id, "alice").await.unwrap();
        store
            .complete_denied(&id, &claimed.claim_token, "trace-1", "operator_denied")
            .await
            .unwrap();

        // Retry claim after deny.
        let err = store.claim_pending(&id, "alice").await.unwrap_err();
        assert!(matches!(err, ApprovalError::AlreadyCompleted { .. }));
    }

    // Forensics: completed record is visible

    #[tokio::test]
    async fn claimed_but_unfinished_record_is_visible_for_forensics() {
        let store = ApprovalStore::in_memory_for_tests(Duration::from_secs(300));
        let pending = test_pending();
        let id = pending.approval_id.clone();

        store.create_pending(&pending).await.unwrap();
        let _claimed = store.claim_pending(&id, "alice").await.unwrap();

        // Status should show claimed state.
        let status = store.get_status(&id).await.unwrap().unwrap();
        assert_eq!(status.state, ApprovalState::Claimed);
        assert_eq!(status.claimed_by.as_deref(), Some("alice"));
    }

    // Failed state: execution error produces terminal state

    #[tokio::test]
    async fn complete_failed_is_terminal() {
        let store = ApprovalStore::in_memory_for_tests(Duration::from_secs(300));
        let pending = test_pending();
        let id = pending.approval_id.clone();

        store.create_pending(&pending).await.unwrap();

        let claimed = store.claim_pending(&id, "alice").await.unwrap();
        store
            .complete_failed(&id, &claimed.claim_token, "trace-fail", "provider_error")
            .await
            .unwrap();

        let status = store.get_status(&id).await.unwrap().unwrap();
        assert_eq!(status.state, ApprovalState::Failed);
        assert!(
            status.state.is_terminal(),
            "Failed must be a terminal state"
        );
    }

    #[tokio::test]
    async fn failed_approval_cannot_be_reclaimed() {
        let store = ApprovalStore::in_memory_for_tests(Duration::from_secs(300));
        let pending = test_pending();
        let id = pending.approval_id.clone();

        store.create_pending(&pending).await.unwrap();

        let claimed = store.claim_pending(&id, "alice").await.unwrap();
        store
            .complete_failed(&id, &claimed.claim_token, "trace-fail", "provider_error")
            .await
            .unwrap();

        let err = store.claim_pending(&id, "bob").await.unwrap_err();
        assert!(
            matches!(err, ApprovalError::AlreadyCompleted { .. }),
            "Failed approval must not be re-claimable"
        );
    }

    // list_approvals (in-memory — deterministic)

    fn pending_with_action(action_id: &str, created_at: &str) -> PendingApproval {
        let mut plan = test_plan();
        plan.core.action_id = action_id.into();
        plan.finalize();
        PendingApproval {
            approval_id: uuid::Uuid::now_v7().to_string(),
            trace_id: uuid::Uuid::now_v7().to_string().into(),
            action_id: action_id.into(),
            auth_context: StoredAuthContext {
                principal: "agent-1".into(),
                session_id: "sess-001".into(),
                lease_jti: "jti-abc".into(),
                sender_thumbprint: "thumb-abc".into(),
                owner: None,
            },
            request_hash: "sha256:deadbeef".into(),
            request_body: std::sync::Arc::new(serde_json::json!({})),
            policy_version: Some("v1".into()),
            created_at: created_at.into(),
            plan,
            unresolved_domains: vec![],
            unresolved_paths: vec![],
        }
    }

    #[tokio::test]
    async fn list_returns_pending_approvals() {
        let store = ApprovalStore::in_memory_for_tests(Duration::from_secs(300));

        store
            .create_pending(&pending_with_action("action_a", "2025-01-01T00:00:01Z"))
            .await
            .unwrap();
        store
            .create_pending(&pending_with_action("action_b", "2025-01-01T00:00:02Z"))
            .await
            .unwrap();
        store
            .create_pending(&pending_with_action("action_c", "2025-01-01T00:00:03Z"))
            .await
            .unwrap();

        let results = store.list_approvals(None, 100).await.unwrap();
        assert_eq!(results.len(), 3, "all 3 pending approvals must be listed");
    }

    #[tokio::test]
    async fn list_returns_empty_when_no_approvals() {
        let store = ApprovalStore::in_memory_for_tests(Duration::from_secs(300));
        let results = store.list_approvals(None, 100).await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn list_filters_by_pending_state() {
        let store = ApprovalStore::in_memory_for_tests(Duration::from_secs(300));

        let p1 = pending_with_action("action_a", "2025-01-01T00:00:01Z");
        let p2 = pending_with_action("action_b", "2025-01-01T00:00:02Z");
        let id2 = p2.approval_id.clone();

        store.create_pending(&p1).await.unwrap();
        store.create_pending(&p2).await.unwrap();

        // Claim and complete p2 => terminal state.
        let claimed = store.claim_pending(&id2, "alice").await.unwrap();
        store
            .complete_approved(&id2, &claimed.claim_token, "trace-1", "rcpt-1")
            .await
            .unwrap();

        // Filter: only pending.
        let pending = store
            .list_approvals(Some(ApprovalState::Pending), 100)
            .await
            .unwrap();
        assert_eq!(pending.len(), 1, "only one should still be pending");
        assert_eq!(&*pending[0].action_id, "action_a");

        // Filter: only approved.
        let approved = store
            .list_approvals(Some(ApprovalState::Approved), 100)
            .await
            .unwrap();
        assert_eq!(approved.len(), 1);
        assert_eq!(&*approved[0].action_id, "action_b");
    }

    #[tokio::test]
    async fn list_excludes_expired_pending() {
        // Store with 1-second TTL.
        let store = ApprovalStore::in_memory_for_tests(Duration::from_secs(1));
        store
            .create_pending(&pending_with_action("action_a", "2025-01-01T00:00:01Z"))
            .await
            .unwrap();

        // Verify it's listed before expiry.
        let before = store.list_approvals(None, 100).await.unwrap();
        assert_eq!(before.len(), 1);

        // Wait for TTL to expire.
        std::thread::sleep(Duration::from_secs(2));

        let after = store.list_approvals(None, 100).await.unwrap();
        assert!(
            after.is_empty(),
            "expired pending approvals must not appear in list"
        );
    }

    #[tokio::test]
    async fn list_respects_limit() {
        let store = ApprovalStore::in_memory_for_tests(Duration::from_secs(300));

        for i in 0..5 {
            store
                .create_pending(&pending_with_action(
                    &format!("action_{i}"),
                    &format!("2025-01-01T00:00:0{i}Z"),
                ))
                .await
                .unwrap();
        }

        let results = store.list_approvals(None, 2).await.unwrap();
        assert_eq!(results.len(), 2, "must return at most `limit` results");
    }

    #[tokio::test]
    async fn list_sorted_newest_first() {
        let store = ApprovalStore::in_memory_for_tests(Duration::from_secs(300));

        // Insert in non-chronological order.
        store
            .create_pending(&pending_with_action("old", "2025-01-01T00:00:01Z"))
            .await
            .unwrap();
        store
            .create_pending(&pending_with_action("new", "2025-01-01T00:00:03Z"))
            .await
            .unwrap();
        store
            .create_pending(&pending_with_action("mid", "2025-01-01T00:00:02Z"))
            .await
            .unwrap();

        let results = store.list_approvals(None, 100).await.unwrap();
        assert_eq!(&*results[0].action_id, "new", "newest must be first");
        assert_eq!(&*results[1].action_id, "mid");
        assert_eq!(&*results[2].action_id, "old", "oldest must be last");
    }

    #[tokio::test]
    async fn list_includes_claimed_by() {
        let store = ApprovalStore::in_memory_for_tests(Duration::from_secs(300));
        let p = pending_with_action("action_a", "2025-01-01T00:00:01Z");
        let id = p.approval_id.clone();

        store.create_pending(&p).await.unwrap();
        let _claimed = store.claim_pending(&id, "alice").await.unwrap();

        let results = store.list_approvals(None, 100).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].claimed_by.as_deref(),
            Some("alice"),
            "claimed_by must be visible in list summary"
        );
        assert_eq!(results[0].state, ApprovalState::Claimed);
    }

    #[tokio::test]
    async fn list_summary_contains_plan_fields() {
        let store = ApprovalStore::in_memory_for_tests(Duration::from_secs(300));
        let p = pending_with_action("action_a", "2025-01-01T00:00:01Z");

        store.create_pending(&p).await.unwrap();

        let results = store.list_approvals(None, 100).await.unwrap();
        assert_eq!(results.len(), 1);

        let summary = &results[0];
        assert_eq!(&*summary.action_id, "action_a");
        assert_eq!(
            &*summary.action_version, "1.0.0",
            "action_version must come from plan"
        );
        assert_eq!(
            summary.risk_level,
            latchgate_core::RiskLevel::Low,
            "risk_level must come from plan"
        );
        assert!(
            !summary.expires_at.is_empty(),
            "expires_at must be populated from plan"
        );
        assert_eq!(&*summary.principal, "agent-1");
    }

    #[tokio::test]
    async fn summary_includes_owner_when_configured() {
        let store = ApprovalStore::in_memory_for_tests(Duration::from_secs(300));

        let mut p = pending_with_action("owned_action", "2025-01-01T00:00:01Z");
        p.auth_context.owner = Some("alice@company.com".into());
        store.create_pending(&p).await.unwrap();

        let results = store.list_approvals(None, 100).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].owner.as_deref(),
            Some("alice@company.com"),
            "ApprovalSummary must carry owner from StoredAuthContext — \
             Platform uses this for Slack/Teams notifications"
        );
    }

    #[tokio::test]
    async fn summary_owner_none_when_not_configured() {
        let store = ApprovalStore::in_memory_for_tests(Duration::from_secs(300));

        // pending_with_action sets owner: None by default.
        let p = pending_with_action("unowned_action", "2025-01-01T00:00:01Z");
        store.create_pending(&p).await.unwrap();

        let results = store.list_approvals(None, 100).await.unwrap();
        assert_eq!(results.len(), 1);
        assert!(
            results[0].owner.is_none(),
            "ApprovalSummary.owner must be None when StoredAuthContext has no owner"
        );
    }

    #[tokio::test]
    async fn list_no_filter_returns_all_states() {
        let store = ApprovalStore::in_memory_for_tests(Duration::from_secs(300));

        let p1 = pending_with_action("pending_action", "2025-01-01T00:00:01Z");
        let p2 = pending_with_action("denied_action", "2025-01-01T00:00:02Z");
        let id2 = p2.approval_id.clone();

        store.create_pending(&p1).await.unwrap();
        store.create_pending(&p2).await.unwrap();

        // Complete p2 as denied.
        let claimed = store.claim_pending(&id2, "alice").await.unwrap();
        store
            .complete_denied(&id2, &claimed.claim_token, "trace-1", "operator_denied")
            .await
            .unwrap();

        // No filter => both states visible.
        let all = store.list_approvals(None, 100).await.unwrap();
        assert_eq!(all.len(), 2, "no filter must return all states");

        let states: Vec<_> = all.iter().map(|s| s.state).collect();
        assert!(states.contains(&ApprovalState::Pending));
        assert!(states.contains(&ApprovalState::Denied));
    }

    // Fail-closed: Redis down

    #[tokio::test]
    async fn redis_down_returns_unavailable() {
        let store = ApprovalStore::new("redis://127.0.0.1:1", Duration::from_secs(300)).unwrap();

        let pending = test_pending();
        let err = store.create_pending(&pending).await.unwrap_err();
        assert!(matches!(err, ApprovalError::Unavailable(_)));

        let err = store.get_pending("any").await.unwrap_err();
        assert!(matches!(err, ApprovalError::Unavailable(_)));

        let err = store.list_approvals(None, 10).await.unwrap_err();
        assert!(
            matches!(err, ApprovalError::Unavailable(_)),
            "list must fail-closed when Redis is down"
        );
    }

    // Durable outcome marker (02) — double-execution prevention

    #[tokio::test]
    async fn outcome_marker_blocks_reclaim_after_approved_execution() {
        let store = ApprovalStore::in_memory_for_tests(Duration::from_secs(300));
        // Use short claim TTL so we can test expired-claim re-claim blocking.
        let store = ApprovalStore {
            claim_ttl_secs: 1,
            ..store
        };

        let p = test_pending();
        let id = p.approval_id.clone();
        store.create_pending(&p).await.unwrap();

        // Claim and write outcome marker (simulating: execute succeeded).
        let claimed = store.claim_pending(&id, "alice").await.unwrap();
        store
            .write_outcome_marker(&id, &claimed.claim_token, "approved", "rcpt-001")
            .await
            .unwrap();

        // Do NOT call complete_approved — simulate failure of terminal write.

        // Wait for claim TTL to expire.
        std::thread::sleep(Duration::from_secs(2));

        // Attempt re-claim: MUST fail even though claim TTL expired.
        let err = store.claim_pending(&id, "bob").await.unwrap_err();
        assert!(
            matches!(err, ApprovalError::AlreadyCompleted { .. }),
            "outcome marker must block re-claim after expired claim TTL: {err:?}"
        );
    }

    #[tokio::test]
    async fn outcome_marker_blocks_reclaim_after_denied() {
        let store = ApprovalStore::in_memory_for_tests(Duration::from_secs(300));
        let store = ApprovalStore {
            claim_ttl_secs: 1,
            ..store
        };

        let p = test_pending();
        let id = p.approval_id.clone();
        store.create_pending(&p).await.unwrap();

        let claimed = store.claim_pending(&id, "alice").await.unwrap();
        store
            .write_outcome_marker(&id, &claimed.claim_token, "denied", "operator_denied")
            .await
            .unwrap();

        // Simulate failed complete_denied — claim TTL expires.
        std::thread::sleep(Duration::from_secs(2));

        let err = store.claim_pending(&id, "bob").await.unwrap_err();
        assert!(
            matches!(err, ApprovalError::AlreadyCompleted { .. }),
            "deny outcome marker must block re-claim: {err:?}"
        );
    }

    #[tokio::test]
    async fn outcome_marker_blocks_reclaim_after_failed_execution() {
        let store = ApprovalStore::in_memory_for_tests(Duration::from_secs(300));
        let store = ApprovalStore {
            claim_ttl_secs: 1,
            ..store
        };

        let p = test_pending();
        let id = p.approval_id.clone();
        store.create_pending(&p).await.unwrap();

        let claimed = store.claim_pending(&id, "alice").await.unwrap();
        store
            .write_outcome_marker(&id, &claimed.claim_token, "failed", "provider_timeout")
            .await
            .unwrap();

        std::thread::sleep(Duration::from_secs(2));

        let err = store.claim_pending(&id, "bob").await.unwrap_err();
        assert!(
            matches!(err, ApprovalError::AlreadyCompleted { .. }),
            "failed outcome marker must block re-claim: {err:?}"
        );
    }

    #[tokio::test]
    async fn outcome_marker_is_idempotent() {
        let store = ApprovalStore::in_memory_for_tests(Duration::from_secs(300));
        let p = test_pending();
        let id = p.approval_id.clone();
        store.create_pending(&p).await.unwrap();

        let claimed = store.claim_pending(&id, "alice").await.unwrap();

        // Write same marker twice — must succeed both times.
        store
            .write_outcome_marker(&id, &claimed.claim_token, "approved", "rcpt-001")
            .await
            .unwrap();
        store
            .write_outcome_marker(&id, &claimed.claim_token, "approved", "rcpt-001")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn outcome_marker_rejects_wrong_claim_token() {
        let store = ApprovalStore::in_memory_for_tests(Duration::from_secs(300));
        let p = test_pending();
        let id = p.approval_id.clone();
        store.create_pending(&p).await.unwrap();

        let _claimed = store.claim_pending(&id, "alice").await.unwrap();

        let err = store
            .write_outcome_marker(&id, "wrong-token", "approved", "rcpt-001")
            .await
            .unwrap_err();
        assert!(
            matches!(err, ApprovalError::TokenMismatch { .. }),
            "wrong token must be rejected: {err:?}"
        );
    }

    #[tokio::test]
    async fn outcome_marker_rejects_unclaimed_approval() {
        let store = ApprovalStore::in_memory_for_tests(Duration::from_secs(300));
        let p = test_pending();
        let id = p.approval_id.clone();
        store.create_pending(&p).await.unwrap();

        let err = store
            .write_outcome_marker(&id, "any-token", "approved", "rcpt-001")
            .await
            .unwrap_err();
        assert!(
            matches!(err, ApprovalError::NotClaimed { .. }),
            "unclaimed approval must reject outcome marker: {err:?}"
        );
    }

    #[tokio::test]
    async fn get_status_synthesizes_state_from_outcome_marker() {
        let store = ApprovalStore::in_memory_for_tests(Duration::from_secs(300));
        let p = test_pending();
        let id = p.approval_id.clone();
        store.create_pending(&p).await.unwrap();

        let claimed = store.claim_pending(&id, "alice").await.unwrap();
        store
            .write_outcome_marker(&id, &claimed.claim_token, "approved", "rcpt-001")
            .await
            .unwrap();

        // Do NOT call complete_approved — state is still Claimed in Redis.
        // But get_status must return the effective terminal state.
        let status = store.get_status(&id).await.unwrap().unwrap();
        assert_eq!(
            status.state,
            ApprovalState::Approved,
            "get_status must synthesize effective state from outcome marker"
        );
        assert_eq!(
            status.receipt_id.as_deref(),
            Some("rcpt-001"),
            "receipt_id must be synthesized from outcome detail"
        );
    }

    #[tokio::test]
    async fn get_status_synthesizes_denied_from_outcome_marker() {
        let store = ApprovalStore::in_memory_for_tests(Duration::from_secs(300));
        let p = test_pending();
        let id = p.approval_id.clone();
        store.create_pending(&p).await.unwrap();

        let claimed = store.claim_pending(&id, "alice").await.unwrap();
        store
            .write_outcome_marker(&id, &claimed.claim_token, "denied", "too_risky")
            .await
            .unwrap();

        let status = store.get_status(&id).await.unwrap().unwrap();
        assert_eq!(status.state, ApprovalState::Denied);
        assert_eq!(status.deny_reason.as_deref(), Some("too_risky"));
    }

    #[tokio::test]
    async fn complete_after_outcome_marker_succeeds() {
        // Outcome marker + complete is the normal happy path.
        let store = ApprovalStore::in_memory_for_tests(Duration::from_secs(300));
        let p = test_pending();
        let id = p.approval_id.clone();
        store.create_pending(&p).await.unwrap();

        let claimed = store.claim_pending(&id, "alice").await.unwrap();
        store
            .write_outcome_marker(&id, &claimed.claim_token, "approved", "rcpt-001")
            .await
            .unwrap();

        // complete_approved MUST still work after outcome marker.
        store
            .complete_approved(&id, &claimed.claim_token, "trace-1", "rcpt-001")
            .await
            .unwrap();

        let status = store.get_status(&id).await.unwrap().unwrap();
        assert_eq!(status.state, ApprovalState::Approved);
        assert_eq!(status.receipt_id.as_deref(), Some("rcpt-001"));
    }

    #[tokio::test]
    async fn no_reclaim_after_outcome_marker_even_without_complete() {
        // The critical crash-recovery scenario:
        // 1. Claim succeeds
        // 2. Side effect executes
        // 3. Outcome marker written
        // 4. Process crashes before complete_approved
        // 5. Claim TTL expires
        // 6. Another operator tries to re-claim
        // 7. MUST fail — side effect already occurred
        let store = ApprovalStore::in_memory_for_tests(Duration::from_secs(300));
        let store = ApprovalStore {
            claim_ttl_secs: 1,
            ..store
        };

        let p = test_pending();
        let id = p.approval_id.clone();
        store.create_pending(&p).await.unwrap();

        // Step 1-3
        let claimed = store.claim_pending(&id, "alice").await.unwrap();
        store
            .write_outcome_marker(&id, &claimed.claim_token, "approved", "rcpt-crash")
            .await
            .unwrap();

        // Step 4-5: process crashes, claim expires
        std::thread::sleep(Duration::from_secs(2));

        // Step 6: another operator attempts re-claim
        let err = store.claim_pending(&id, "bob").await.unwrap_err();

        // Step 7: MUST fail
        assert!(
            matches!(err, ApprovalError::AlreadyCompleted { .. }),
            "CRITICAL: re-claim after outcome marker must be impossible: {err:?}"
        );
    }
}
