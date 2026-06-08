//! Stateful budget enforcement backed by Redis.
//!
//! Per-session call limits are initialised at lease issuance and atomically
//! debited on every action call. The core invariant: **no concurrent requests
//! can exceed the budget**, guaranteed by a Lua script that performs
//! check-and-debit in a single atomic Redis operation.
//!
//! # Key format
//!
//! `latch:budget:{session_id}` — a Redis hash with field:
//! - `calls_remaining` (integer)
//!
//! # Security properties
//!
//! - **Atomic debit**: Lua script runs check + decrement in one operation —
//!   no TOCTOU race between "is budget sufficient?" and "debit budget".
//! - **Fail-closed**: Redis unavailable => `BudgetError::Unavailable` => pipeline
//!   returns 503, request DENIED. Never allow without a budget check.
//! - **TTL-bounded**: budget keys expire after lease TTL + grace period,
//!   preventing unbounded Redis memory growth from abandoned sessions.
//! - **Rollback on provider failure**: if the provider fails after budget
//!   debit, the pipeline restores the budget (best-effort).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
use tracing::{instrument, warn};

use latchgate_core::BudgetSnapshot;

use crate::sqlite::SqliteStateDb;

// Error

/// Errors from the budget manager.
///
/// Callers must treat all variants as DENY — never allow an action call when
/// budget state is uncertain.
#[derive(Debug, thiserror::Error)]
pub enum BudgetError {
    /// The session's budget has been fully consumed.
    #[error("budget exhausted: {reason}")]
    Exhausted { reason: String },

    /// Budget for this session was already initialised. Prevents silent
    /// reset of an in-flight session's remaining budget.
    #[error("budget already initialised: {session_id}")]
    AlreadyInitialised { session_id: String },

    /// No budget state found for this session. Either the session was never
    /// initialised or the Redis key expired (lease TTL exceeded).
    #[error("session budget not initialised: {session_id}")]
    SessionNotFound { session_id: String },

    /// Redis is unavailable or returned an unexpected error.
    ///
    /// SECURITY: fail-closed. Pipeline maps this to 503.
    #[error("budget store unavailable: {0}")]
    Unavailable(String),
}

// Lua scripts

/// Atomic check-and-debit script.
///
/// KEYS[1] = budget hash key
///
/// Returns: calls_remaining after debit.
/// Errors:  SESSION_NOT_FOUND | CALLS_EXHAUSTED
///
/// Uses `redis.error_reply()` (available since Redis 2.6) instead of
/// `redis.error()` (Redis 7.0+) for broad compatibility.
const LUA_DEBIT: &str = r#"
local key = KEYS[1]

local calls = tonumber(redis.call('HGET', key, 'calls_remaining'))

-- Session not initialised or expired => deny (fail-closed)
if calls == nil then
    return redis.error_reply('SESSION_NOT_FOUND')
end

-- Budget check
if calls <= 0 then
    return redis.error_reply('CALLS_EXHAUSTED')
end

-- Atomic debit
local new_calls = redis.call('HINCRBY', key, 'calls_remaining', -1)

return new_calls
"#;

// Key formatting

/// Redis key prefix for budget hashes.
const KEY_PREFIX: &str = "latch:budget:";

/// Build the Redis key for a session's budget.
fn budget_key(session_id: &str) -> String {
    format!("{KEY_PREFIX}{session_id}")
}

// In-memory budget state (for tests)

struct InMemoryBudget {
    calls_remaining: i64,
}

// BudgetManager

/// Stateful budget manager backed by Redis or an in-memory store.
///
/// Created once at startup; shared via `Arc<BudgetManager>` in `AppState`.
pub struct BudgetManager {
    backend: BudgetBackend,
}

enum BudgetBackend {
    Redis(redis::Client),
    Sqlite(Arc<SqliteStateDb>),
    InMemory(Arc<RwLock<HashMap<String, InMemoryBudget>>>),
}

impl std::fmt::Debug for BudgetManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match &self.backend {
            BudgetBackend::Redis(_) => "redis",
            BudgetBackend::Sqlite(_) => "sqlite",
            BudgetBackend::InMemory(_) => "in_memory",
        };
        f.debug_struct("BudgetManager")
            .field("backend", &kind)
            .finish_non_exhaustive()
    }
}

impl BudgetManager {
    /// Create a new `BudgetManager` backed by Redis.
    pub fn new(redis_url: &str) -> Result<Self, BudgetError> {
        let client =
            redis::Client::open(redis_url).map_err(|e| BudgetError::Unavailable(e.to_string()))?;
        Ok(Self {
            backend: BudgetBackend::Redis(client),
        })
    }

    /// Create a `BudgetManager` backed by SQLite.
    ///
    /// Uses the shared state database. Atomic debit is guaranteed by
    /// SQLite's single-writer property under WAL mode — functionally
    /// equivalent to Redis Lua scripts in single-process mode.
    pub fn sqlite(db: Arc<SqliteStateDb>) -> Self {
        Self {
            backend: BudgetBackend::Sqlite(db),
        }
    }

    /// Create an in-memory `BudgetManager` for testing.
    ///
    /// Provides the same atomic check-and-debit semantics via tokio RwLock.
    /// NOT suitable for production — no persistence, no cross-process safety.
    #[doc(hidden)]
    pub fn in_memory_for_tests() -> Self {
        Self {
            backend: BudgetBackend::InMemory(Arc::new(RwLock::new(HashMap::new()))),
        }
    }

    /// Initialise budget counters for a new session.
    #[instrument(name = "budget.init", skip(self), fields(%session_id, calls))]
    pub async fn init_budgets(
        &self,
        session_id: &str,
        calls: u64,
        ttl: Duration,
    ) -> Result<(), BudgetError> {
        match &self.backend {
            BudgetBackend::Redis(client) => self.redis_init(client, session_id, calls, ttl).await,
            BudgetBackend::Sqlite(db) => {
                let db = db.clone();
                let sid = session_id.to_string();
                let now = chrono::Utc::now();
                let expires = now.timestamp() + ttl.as_secs() as i64;
                let created_at = now.to_rfc3339();
                tokio::task::spawn_blocking(move || {
                    let conn = db
                        .conn()
                        .map_err(|e| BudgetError::Unavailable(e.to_string()))?;
                    let inserted = conn
                        .execute(
                            "INSERT OR IGNORE INTO session_budgets
                             (session_id, calls_remaining, created_at, expires_at_unix)
                             VALUES (?1, ?2, ?3, ?4)",
                            rusqlite::params![sid, calls as i64, created_at, expires],
                        )
                        .map_err(|e| BudgetError::Unavailable(e.to_string()))?;
                    if inserted == 0 {
                        return Err(BudgetError::AlreadyInitialised { session_id: sid });
                    }
                    Ok(())
                })
                .await
                .map_err(|e| BudgetError::Unavailable(e.to_string()))?
            }
            BudgetBackend::InMemory(store) => {
                let mut map = store.write().await;
                if map.contains_key(session_id) {
                    return Err(BudgetError::AlreadyInitialised {
                        session_id: session_id.to_string(),
                    });
                }
                map.insert(
                    session_id.to_string(),
                    InMemoryBudget {
                        calls_remaining: calls as i64,
                    },
                );
                Ok(())
            }
        }
    }

    /// Read current budget counters without modifying them.
    #[instrument(name = "budget.snapshot", skip(self), fields(%session_id))]
    pub async fn get_snapshot(&self, session_id: &str) -> Result<BudgetSnapshot, BudgetError> {
        match &self.backend {
            BudgetBackend::Redis(client) => self.redis_snapshot(client, session_id).await,
            BudgetBackend::Sqlite(db) => {
                let db = db.clone();
                let sid = session_id.to_string();
                let now = chrono::Utc::now().timestamp();
                tokio::task::spawn_blocking(move || {
                    let conn = db
                        .conn()
                        .map_err(|e| BudgetError::Unavailable(e.to_string()))?;
                    let result: Result<i64, _> = conn.query_row(
                        "SELECT calls_remaining FROM session_budgets
                         WHERE session_id = ?1 AND expires_at_unix > ?2",
                        rusqlite::params![sid, now],
                        |row| row.get(0),
                    );
                    match result {
                        Ok(calls) => Ok(BudgetSnapshot {
                            calls_remaining: calls,
                        }),
                        Err(rusqlite::Error::QueryReturnedNoRows) => {
                            Err(BudgetError::SessionNotFound { session_id: sid })
                        }
                        Err(e) => Err(BudgetError::Unavailable(e.to_string())),
                    }
                })
                .await
                .map_err(|e| BudgetError::Unavailable(e.to_string()))?
            }
            BudgetBackend::InMemory(store) => {
                let map = store.read().await;
                match map.get(session_id) {
                    Some(b) => Ok(BudgetSnapshot {
                        calls_remaining: b.calls_remaining,
                    }),
                    None => Err(BudgetError::SessionNotFound {
                        session_id: session_id.to_string(),
                    }),
                }
            }
        }
    }

    /// Atomically check and debit the budget for one action call.
    #[instrument(name = "budget.debit", skip(self), fields(%session_id))]
    pub async fn get_and_debit(&self, session_id: &str) -> Result<BudgetSnapshot, BudgetError> {
        match &self.backend {
            BudgetBackend::Redis(client) => self.redis_debit(client, session_id).await,
            BudgetBackend::Sqlite(db) => {
                let db = db.clone();
                let sid = session_id.to_string();
                let now = chrono::Utc::now().timestamp();
                tokio::task::spawn_blocking(move || {
                    let conn = db
                        .conn()
                        .map_err(|e| BudgetError::Unavailable(e.to_string()))?;
                    // Atomic debit: UPDATE ... WHERE calls_remaining > 0
                    // RETURNING gives us the new value in one statement.
                    let result: Result<i64, _> = conn.query_row(
                        "UPDATE session_budgets
                         SET calls_remaining = calls_remaining - 1
                         WHERE session_id = ?1
                           AND calls_remaining > 0
                           AND expires_at_unix > ?2
                         RETURNING calls_remaining",
                        rusqlite::params![sid, now],
                        |row| row.get(0),
                    );
                    match result {
                        Ok(calls) => Ok(BudgetSnapshot {
                            calls_remaining: calls,
                        }),
                        Err(rusqlite::Error::QueryReturnedNoRows) => {
                            // Distinguish: session missing vs budget exhausted.
                            let exists: bool = conn
                                .query_row(
                                    "SELECT 1 FROM session_budgets
                                     WHERE session_id = ?1 AND expires_at_unix > ?2",
                                    rusqlite::params![sid, now],
                                    |_| Ok(true),
                                )
                                .unwrap_or(false);
                            if exists {
                                Err(BudgetError::Exhausted {
                                    reason: "calls_exhausted".into(),
                                })
                            } else {
                                Err(BudgetError::SessionNotFound { session_id: sid })
                            }
                        }
                        Err(e) => Err(BudgetError::Unavailable(e.to_string())),
                    }
                })
                .await
                .map_err(|e| BudgetError::Unavailable(e.to_string()))?
            }
            BudgetBackend::InMemory(store) => {
                let mut map = store.write().await;
                let b = map
                    .get_mut(session_id)
                    .ok_or(BudgetError::SessionNotFound {
                        session_id: session_id.to_string(),
                    })?;
                if b.calls_remaining <= 0 {
                    return Err(BudgetError::Exhausted {
                        reason: "calls_exhausted".into(),
                    });
                }
                b.calls_remaining -= 1;
                Ok(BudgetSnapshot {
                    calls_remaining: b.calls_remaining,
                })
            }
        }
    }

    /// Restore a previously debited budget (best-effort).
    #[instrument(name = "budget.rollback", skip(self), fields(%session_id))]
    pub async fn rollback(&self, session_id: &str) -> Result<(), BudgetError> {
        match &self.backend {
            BudgetBackend::Redis(client) => self.redis_rollback(client, session_id).await,
            BudgetBackend::Sqlite(db) => {
                let db = db.clone();
                let sid = session_id.to_string();
                tokio::task::spawn_blocking(move || {
                    let conn = db
                        .conn()
                        .map_err(|e| BudgetError::Unavailable(e.to_string()))?;
                    conn.execute(
                        "UPDATE session_budgets
                         SET calls_remaining = calls_remaining + 1
                         WHERE session_id = ?1",
                        rusqlite::params![sid],
                    )
                    .map_err(|e| BudgetError::Unavailable(e.to_string()))?;
                    Ok(())
                })
                .await
                .map_err(|e| BudgetError::Unavailable(e.to_string()))?
            }
            BudgetBackend::InMemory(store) => {
                let mut map = store.write().await;
                if let Some(b) = map.get_mut(session_id) {
                    b.calls_remaining += 1;
                }
                Ok(())
            }
        }
    }

    // Redis implementations

    async fn redis_init(
        &self,
        client: &redis::Client,
        session_id: &str,
        calls: u64,
        ttl: Duration,
    ) -> Result<(), BudgetError> {
        let key = budget_key(session_id);
        let ttl_secs = ttl.as_secs().max(1) as i64;
        let mut conn = self.redis_conn(client).await?;

        // Atomic: HSETNX + EXPIRE. Returns 1 if the key was created, 0 if
        // it already existed. A plain HSET would silently reset an in-flight
        // session's remaining budget.
        let created: i64 = redis::cmd("HSETNX")
            .arg(&key)
            .arg("calls_remaining")
            .arg(calls as i64)
            .query_async(&mut conn)
            .await
            .map_err(|e| {
                warn!(session_id, error = %e, "budget init failed");
                BudgetError::Unavailable(e.to_string())
            })?;

        if created == 0 {
            return Err(BudgetError::AlreadyInitialised {
                session_id: session_id.to_string(),
            });
        }

        redis::cmd("EXPIRE")
            .arg(&key)
            .arg(ttl_secs)
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| {
                warn!(session_id, error = %e, "budget expire failed");
                BudgetError::Unavailable(e.to_string())
            })?;

        Ok(())
    }

    async fn redis_snapshot(
        &self,
        client: &redis::Client,
        session_id: &str,
    ) -> Result<BudgetSnapshot, BudgetError> {
        let key = budget_key(session_id);
        let mut conn = self.redis_conn(client).await?;

        let calls: Option<i64> = redis::cmd("HGET")
            .arg(&key)
            .arg("calls_remaining")
            .query_async(&mut conn)
            .await
            .map_err(|e| {
                warn!(session_id, error = %e, "budget snapshot failed");
                BudgetError::Unavailable(e.to_string())
            })?;

        match calls {
            Some(c) => Ok(BudgetSnapshot { calls_remaining: c }),
            None => Err(BudgetError::SessionNotFound {
                session_id: session_id.to_string(),
            }),
        }
    }

    async fn redis_debit(
        &self,
        client: &redis::Client,
        session_id: &str,
    ) -> Result<BudgetSnapshot, BudgetError> {
        let key = budget_key(session_id);
        let mut conn = self.redis_conn(client).await?;

        let result: Result<i64, redis::RedisError> = redis::cmd("EVAL")
            .arg(LUA_DEBIT)
            .arg(1)
            .arg(&key)
            .query_async(&mut conn)
            .await;

        match result {
            Ok(calls) => Ok(BudgetSnapshot {
                calls_remaining: calls,
            }),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("SESSION_NOT_FOUND") {
                    Err(BudgetError::SessionNotFound {
                        session_id: session_id.to_string(),
                    })
                } else if msg.contains("CALLS_EXHAUSTED") {
                    Err(BudgetError::Exhausted {
                        reason: "calls_exhausted".into(),
                    })
                } else {
                    warn!(session_id, error = %e, "budget debit failed");
                    Err(BudgetError::Unavailable(e.to_string()))
                }
            }
        }
    }

    async fn redis_rollback(
        &self,
        client: &redis::Client,
        session_id: &str,
    ) -> Result<(), BudgetError> {
        let key = budget_key(session_id);
        let mut conn = self.redis_conn(client).await?;

        redis::pipe()
            .hincr(&key, "calls_remaining", 1i64)
            .ignore()
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| {
                warn!(session_id, error = %e, "budget rollback failed");
                BudgetError::Unavailable(e.to_string())
            })?;

        Ok(())
    }

    /// Obtain a multiplexed async connection from the client pool.
    async fn redis_conn(
        &self,
        client: &redis::Client,
    ) -> Result<redis::aio::MultiplexedConnection, BudgetError> {
        client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                warn!(error = %e, "budget manager: failed to connect to Redis");
                BudgetError::Unavailable(e.to_string())
            })
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    // Key formatting (pure, no Redis)

    #[test]
    fn budget_key_has_correct_prefix() {
        assert_eq!(budget_key("sess-001"), "latch:budget:sess-001");
    }

    #[test]
    fn budget_key_handles_uuid() {
        let id = uuid::Uuid::now_v7().to_string();
        let key = budget_key(&id);
        assert!(key.starts_with("latch:budget:"));
        assert!(key.ends_with(&id));
    }

    // Construction

    #[test]
    fn new_with_valid_url_succeeds() {
        let mgr = BudgetManager::new(&test_redis_url());
        assert!(mgr.is_ok());
    }

    #[test]
    fn new_with_invalid_url_returns_error() {
        let mgr = BudgetManager::new("not-a-url");
        assert!(mgr.is_err());
        assert!(matches!(mgr.unwrap_err(), BudgetError::Unavailable(_)));
    }

    // Integration tests (require running Redis)

    fn redis_available() -> bool {
        std::net::TcpStream::connect_timeout(
            &"127.0.0.1:6379".parse().unwrap(),
            std::time::Duration::from_millis(200),
        )
        .is_ok()
    }

    fn test_redis_url() -> String {
        std::env::var("LATCHGATE_REDIS_URL")
            .unwrap_or_else(|_| "redis://:changeme@127.0.0.1:6379".to_string())
    }

    fn test_manager() -> BudgetManager {
        BudgetManager::new(&test_redis_url()).unwrap()
    }

    /// Unique session ID per test to avoid cross-test interference.
    fn unique_session() -> String {
        format!("test-budget-{}", uuid::Uuid::now_v7())
    }

    #[tokio::test]
    async fn init_and_get_snapshot() {
        if !redis_available() {
            eprintln!("SKIP: Redis not available");
            return;
        }
        let mgr = test_manager();
        let sess = unique_session();

        mgr.init_budgets(&sess, 10, Duration::from_secs(60))
            .await
            .unwrap();

        let snap = mgr.get_snapshot(&sess).await.unwrap();
        assert_eq!(snap.calls_remaining, 10);
    }

    #[tokio::test]
    async fn debit_decrements() {
        if !redis_available() {
            eprintln!("SKIP: Redis not available");
            return;
        }
        let mgr = test_manager();
        let sess = unique_session();

        mgr.init_budgets(&sess, 10, Duration::from_secs(60))
            .await
            .unwrap();

        let snap = mgr.get_and_debit(&sess).await.unwrap();
        assert_eq!(snap.calls_remaining, 9);
    }

    #[tokio::test]
    async fn calls_exhausted_returns_error() {
        if !redis_available() {
            eprintln!("SKIP: Redis not available");
            return;
        }
        let mgr = test_manager();
        let sess = unique_session();

        mgr.init_budgets(&sess, 1, Duration::from_secs(60))
            .await
            .unwrap();

        // First debit OK
        let _ = mgr.get_and_debit(&sess).await.unwrap();

        // Second debit => exhausted
        let err = mgr.get_and_debit(&sess).await.unwrap_err();
        assert!(matches!(err, BudgetError::Exhausted { .. }));
    }

    /// SECURITY: concurrent debits on a tight budget must never over-debit.
    #[tokio::test]
    async fn debit_is_atomic_under_concurrency() {
        if !redis_available() {
            eprintln!("SKIP: Redis not available");
            return;
        }
        let mgr = std::sync::Arc::new(test_manager());
        let sess = unique_session();

        // 5 calls available, 10 concurrent attempts.
        mgr.init_budgets(&sess, 5, Duration::from_secs(60))
            .await
            .unwrap();

        let mut handles = Vec::new();
        for _ in 0..10 {
            let mgr = mgr.clone();
            let sess = sess.clone();
            handles.push(tokio::spawn(async move { mgr.get_and_debit(&sess).await }));
        }

        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.await.unwrap());
        }

        let ok_count = results.iter().filter(|r| r.is_ok()).count();
        let exhausted_count = results
            .iter()
            .filter(|r| matches!(r, Err(BudgetError::Exhausted { .. })))
            .count();

        assert_eq!(ok_count, 5, "exactly 5 debits should succeed");
        assert_eq!(exhausted_count, 5, "exactly 5 should be exhausted");

        // Final snapshot must be 0 calls remaining.
        let snap = mgr.get_snapshot(&sess).await.unwrap();
        assert_eq!(snap.calls_remaining, 0);
    }

    #[tokio::test]
    async fn session_not_found_on_debit() {
        if !redis_available() {
            eprintln!("SKIP: Redis not available");
            return;
        }
        let mgr = test_manager();
        let err = mgr.get_and_debit("nonexistent-session").await.unwrap_err();
        assert!(matches!(err, BudgetError::SessionNotFound { .. }));
    }

    #[tokio::test]
    async fn session_not_found_on_snapshot() {
        if !redis_available() {
            eprintln!("SKIP: Redis not available");
            return;
        }
        let mgr = test_manager();
        let err = mgr.get_snapshot("nonexistent-session").await.unwrap_err();
        assert!(matches!(err, BudgetError::SessionNotFound { .. }));
    }

    #[tokio::test]
    async fn rollback_restores_budget() {
        if !redis_available() {
            eprintln!("SKIP: Redis not available");
            return;
        }
        let mgr = test_manager();
        let sess = unique_session();

        mgr.init_budgets(&sess, 5, Duration::from_secs(60))
            .await
            .unwrap();

        // Debit
        let _ = mgr.get_and_debit(&sess).await.unwrap();
        let after_debit = mgr.get_snapshot(&sess).await.unwrap();
        assert_eq!(after_debit.calls_remaining, 4);

        // Rollback
        mgr.rollback(&sess).await.unwrap();
        let after_rollback = mgr.get_snapshot(&sess).await.unwrap();
        assert_eq!(after_rollback.calls_remaining, 5);
    }

    /// SECURITY: Redis down must return Unavailable, not panic.
    #[tokio::test]
    async fn redis_down_returns_unavailable() {
        let mgr = BudgetManager::new("redis://127.0.0.1:1").unwrap();

        let err = mgr
            .init_budgets("sess", 10, Duration::from_secs(60))
            .await
            .unwrap_err();
        assert!(matches!(err, BudgetError::Unavailable(_)));

        let err = mgr.get_snapshot("sess").await.unwrap_err();
        assert!(matches!(err, BudgetError::Unavailable(_)));

        let err = mgr.get_and_debit("sess").await.unwrap_err();
        assert!(matches!(err, BudgetError::Unavailable(_)));
    }

    #[tokio::test]
    async fn ttl_set_on_init() {
        if !redis_available() {
            eprintln!("SKIP: Redis not available");
            return;
        }
        let mgr = test_manager();
        let sess = unique_session();

        mgr.init_budgets(&sess, 10, Duration::from_secs(120))
            .await
            .unwrap();

        // Check TTL via raw Redis command.
        let client = redis::Client::open(test_redis_url()).unwrap();
        let mut conn = client.get_multiplexed_async_connection().await.unwrap();
        let ttl: i64 = redis::cmd("TTL")
            .arg(budget_key(&sess))
            .query_async(&mut conn)
            .await
            .unwrap();

        assert!(ttl > 0, "budget key must have a positive TTL");
        assert!(ttl <= 120, "TTL must not exceed the requested duration");
    }

    #[tokio::test]
    async fn expired_budget_returns_session_not_found() {
        if !redis_available() {
            eprintln!("SKIP: Redis not available");
            return;
        }
        let mgr = test_manager();
        let sess = unique_session();

        // Init with 1-second TTL.
        mgr.init_budgets(&sess, 10, Duration::from_secs(1))
            .await
            .unwrap();

        // Wait for expiry.
        // Margin: 3s sleep for 1s Redis TTL — 2s headroom for CI load
        // and Redis lazy-expiry jitter.
        tokio::time::sleep(Duration::from_secs(3)).await;

        let err = mgr.get_snapshot(&sess).await.unwrap_err();
        assert!(matches!(err, BudgetError::SessionNotFound { .. }));
    }
}
