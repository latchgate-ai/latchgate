//! Anti-replay cache for DPoP `jti` uniqueness (RFC 9449).
//!
//! Each DPoP proof carries a unique `jti`. The cache stores seen `jti` values
//! in Redis with a TTL, rejecting duplicates. This prevents token replay attacks
//! where an intercepted proof is re-submitted.
//!
//! # Security properties
//!
//! - **Atomic check-and-store**: `SET key 1 NX EX ttl` is a single Redis
//!   command — no TOCTOU race between "check if exists" and "store".
//! - **Fail-closed**: if Redis is unavailable, `check_and_store_jti` returns
//!   `CacheUnavailable`. Callers MUST deny the request — never allow without
//!   a replay check.
//! - **TTL-bounded**: entries expire after `replay_ttl_seconds`, keeping
//!   memory bounded. TTL should be ≥ `allowed_clock_skew + max_proof_age`.
//!
//! # Key format
//!
//! `{key_prefix}{jti}` where `key_prefix` is configured at construction time
//! (default `"latchgate:jti:"`). In multi-tenant deployments, each tenant gets
//! a unique prefix (e.g. `"latchgate:acme:jti:"`) for keyspace isolation.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, instrument, warn};

/// Rate-limits warn!-level log emission for events an attacker can trigger
/// at will (replay detection, cache-full). Without this, 1 k bad proofs/s
/// produces 1 k structured log records/s with attacker-chosen `jti` content,
/// which is a free DoS amplification vector against the logging pipeline.
///
/// Within each window the first `MAX_WARNS_PER_WINDOW` events log at warn!;
/// subsequent events log at debug!. At the window boundary the counter
/// resets and a summary of suppressed events is emitted if any were dropped.
struct WarnThrottle {
    count: AtomicU64,
    window_start_secs: AtomicU64,
}

impl WarnThrottle {
    const WINDOW_SECS: u64 = 60;
    const MAX_WARNS_PER_WINDOW: u64 = 10;

    const fn new() -> Self {
        Self {
            count: AtomicU64::new(0),
            window_start_secs: AtomicU64::new(0),
        }
    }

    /// Returns `true` if this event should be logged at warn! level.
    /// When `false`, the caller should use debug! instead.
    fn should_warn(&self) -> bool {
        let now = Self::now_secs();
        let start = self.window_start_secs.load(AtomicOrdering::Relaxed);

        if now.saturating_sub(start) >= Self::WINDOW_SECS {
            // New window — emit a summary of the old one if events were
            // suppressed, then reset.
            let prev_count = self.count.swap(1, AtomicOrdering::Relaxed);
            self.window_start_secs.store(now, AtomicOrdering::Relaxed);
            if prev_count > Self::MAX_WARNS_PER_WINDOW {
                let suppressed = prev_count - Self::MAX_WARNS_PER_WINDOW;
                warn!(
                    suppressed_count = suppressed,
                    window_secs = Self::WINDOW_SECS,
                    "replay cache: {suppressed} warn-level log entries suppressed in last window"
                );
            }
            true
        } else {
            let prev = self.count.fetch_add(1, AtomicOrdering::Relaxed);
            prev < Self::MAX_WARNS_PER_WINDOW
        }
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Errors from the anti-replay cache.
///
/// Callers must treat `CacheUnavailable` as a DENY — never fall through to
/// "allow without replay check". This is enforced in `gate::pipeline`.
#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    /// The `jti` has already been seen within the TTL window.
    /// This is a replay attack or a buggy client reusing proofs.
    #[error("jti already seen: {jti}")]
    AlreadySeen { jti: String },

    /// Redis is unavailable or returned an error.
    ///
    /// SECURITY: fail-closed. The request MUST be denied when this is returned.
    /// A missing replay check enables token reuse attacks.
    #[error("replay cache unavailable: {0}")]
    CacheUnavailable(String),
}

impl From<redis::RedisError> for ReplayError {
    fn from(e: redis::RedisError) -> Self {
        ReplayError::CacheUnavailable(e.to_string())
    }
}

/// Anti-replay cache backed by Redis or an in-memory store.
///
/// Created once at startup; shared via `Arc<ReplayCache>` in `AppState`.
/// The in-memory variant is suitable for tests; production must use Redis.
///
/// `key_prefix` is the full Redis key prefix (e.g. `"latchgate:jti:"` or
/// `"latchgate:acme:jti:"`). Keys are `{key_prefix}{jti}`.
pub struct ReplayCache {
    backend: Backend,
    ttl: Duration,
    key_prefix: String,
    max_in_memory_entries: usize,
    /// Throttles warn!-level logs for attacker-controllable events
    /// (replay detection, cache-full). See [`WarnThrottle`].
    replay_warn_throttle: WarnThrottle,
}

enum Backend {
    Redis(redis::Client),
    InMemory {
        map: Arc<dashmap::DashMap<String, Instant>>,
        entry_count: Arc<AtomicUsize>,
    },
}

impl std::fmt::Debug for ReplayCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match &self.backend {
            Backend::Redis(_) => "redis",
            Backend::InMemory { .. } => "in_memory",
        };
        f.debug_struct("ReplayCache")
            .field("backend", &kind)
            .field("ttl", &self.ttl)
            .field("key_prefix", &self.key_prefix)
            .finish_non_exhaustive()
    }
}

impl ReplayCache {
    /// Create a new `ReplayCache` backed by Redis.
    ///
    /// `key_prefix` is the full prefix prepended to every jti key in Redis.
    /// For multi-tenant deployments, each tenant gets a unique prefix
    /// (e.g. `"latchgate:acme:jti:"`) to isolate anti-replay keyspaces.
    ///
    /// Parses the Redis URL and validates it. Does NOT eagerly connect —
    /// the first `check_and_store_jti` call will establish the connection.
    /// This keeps startup fast and lets the health check surface Redis issues.
    pub fn new(redis_url: &str, ttl: Duration, key_prefix: &str) -> Result<Self, ReplayError> {
        if !key_prefix.ends_with(':') {
            warn!(
                key_prefix = %key_prefix,
                "redis_key_prefix does not end with ':' — keys may collide with other namespaces"
            );
        }
        let client = redis::Client::open(redis_url)
            .map_err(|e| ReplayError::CacheUnavailable(e.to_string()))?;
        Ok(Self {
            backend: Backend::Redis(client),
            ttl,
            key_prefix: key_prefix.to_string(),
            max_in_memory_entries: 100_000,
            replay_warn_throttle: WarnThrottle::new(),
        })
    }

    /// In-memory `ReplayCache` for testing. Same semantics as Redis but no external infra.
    pub fn in_memory(ttl: Duration) -> Self {
        Self {
            backend: Backend::InMemory {
                map: Arc::new(dashmap::DashMap::new()),
                entry_count: Arc::new(AtomicUsize::new(0)),
            },
            ttl,
            key_prefix: "latchgate:jti:".to_string(),
            max_in_memory_entries: 100_000,
            replay_warn_throttle: WarnThrottle::new(),
        }
    }

    /// Bounded in-memory `ReplayCache` for single-process production mode.
    ///
    /// Fail-closed on hard cap: requests are denied when the cap is hit.
    pub fn in_memory_bounded(ttl: Duration, max_entries: usize) -> Self {
        Self {
            backend: Backend::InMemory {
                map: Arc::new(dashmap::DashMap::new()),
                entry_count: Arc::new(AtomicUsize::new(0)),
            },
            ttl,
            key_prefix: String::new(), // not used for in-memory
            max_in_memory_entries: max_entries,
            replay_warn_throttle: WarnThrottle::new(),
        }
    }

    /// Check if `jti` has been seen; if not, store it with TTL.
    ///
    /// SECURITY: callers MUST deny the request on any `Err` variant.
    #[instrument(name = "replay.check_jti", skip(self), fields(%jti))]
    pub async fn check_and_store_jti(&self, jti: &str) -> Result<(), ReplayError> {
        match &self.backend {
            Backend::Redis(client) => self.redis_check_and_store(client, jti).await,
            Backend::InMemory { map, entry_count } => {
                self.memory_check_and_store(map, entry_count, jti)
            }
        }
    }

    /// Readiness check: verify the backend is reachable.
    ///
    /// Returns `true` if a Redis PING succeeds (or if in-memory backend).
    /// Used by `/readyz` to determine if the Gate can handle requests.
    pub async fn ping(&self) -> bool {
        match &self.backend {
            Backend::Redis(client) => {
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
            Backend::InMemory { .. } => true,
        }
    }

    async fn redis_check_and_store(
        &self,
        client: &redis::Client,
        jti: &str,
    ) -> Result<(), ReplayError> {
        let key = format!("{}{jti}", self.key_prefix);
        let ttl_secs = self.ttl.as_secs().max(1);

        let mut conn = client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                warn!(error = %e, "replay cache: failed to connect to Redis");
                ReplayError::CacheUnavailable(e.to_string())
            })?;

        let result: Option<String> = redis::cmd("SET")
            .arg(&key)
            .arg(1)
            .arg("NX")
            .arg("EX")
            .arg(ttl_secs)
            .query_async(&mut conn)
            .await
            .map_err(|e| {
                warn!(error = %e, jti = %jti, "replay cache: SET NX EX failed");
                ReplayError::CacheUnavailable(e.to_string())
            })?;

        match result {
            Some(_) => Ok(()),
            None => {
                if self.replay_warn_throttle.should_warn() {
                    warn!(jti = %jti, "replay detected: jti already seen");
                } else {
                    debug!(jti = %jti, "replay detected: jti already seen (throttled)");
                }
                Err(ReplayError::AlreadySeen {
                    jti: jti.to_string(),
                })
            }
        }
    }

    fn memory_check_and_store(
        &self,
        map: &dashmap::DashMap<String, Instant>,
        entry_count: &AtomicUsize,
        jti: &str,
    ) -> Result<(), ReplayError> {
        let max_entries = self.max_in_memory_entries;
        let now = Instant::now();
        let ttl = self.ttl;

        use dashmap::mapref::entry::Entry;

        match map.entry(jti.to_string()) {
            Entry::Occupied(mut e) => {
                // Key exists — check if it's expired.
                if now.duration_since(*e.get()) < ttl {
                    if self.replay_warn_throttle.should_warn() {
                        warn!(jti = %jti, "replay detected: jti already seen (in-memory)");
                    } else {
                        debug!(jti = %jti, "replay detected: jti already seen (in-memory, throttled)");
                    }
                    return Err(ReplayError::AlreadySeen {
                        jti: jti.to_string(),
                    });
                }
                // Expired — overwrite with fresh timestamp. No net new entry.
                e.insert(now);
                Ok(())
            }
            Entry::Vacant(e) => {
                // New JTI — enforce hard cap before inserting.
                //
                // Optimistic reservation: increment first, check second.
                // If over cap, decrement and deny. The counter may briefly
                // overcount by the number of concurrent insert paths; this
                // is acceptable because the cap is a memory-safety bound,
                // not a security invariant. The per-key replay detection
                // (above) is the security boundary.
                let current = entry_count.fetch_add(1, AtomicOrdering::Relaxed);
                if current >= max_entries {
                    entry_count.fetch_sub(1, AtomicOrdering::Relaxed);
                    if self.replay_warn_throttle.should_warn() {
                        warn!(
                            entries = current,
                            max_entries,
                            "in-memory replay cache full — denying request (fail-closed)"
                        );
                    } else {
                        debug!(
                            entries = current,
                            max_entries, "in-memory replay cache full — denying (throttled)"
                        );
                    }
                    return Err(ReplayError::CacheUnavailable(
                        "replay cache at capacity".to_string(),
                    ));
                }
                e.insert(now);
                Ok(())
            }
        }
    }

    /// TTL configured for this cache. Useful for diagnostics / health checks.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Evict expired entries from the in-memory backend.
    ///
    /// Called by the background sweep task every 30 seconds. No-op for
    /// the Redis backend (Redis handles its own TTL expiry).
    pub async fn evict_expired(&self) -> usize {
        match &self.backend {
            Backend::Redis(_) => 0,
            Backend::InMemory { map, entry_count } => {
                let now = Instant::now();
                let ttl = self.ttl;
                let before = map.len();
                map.retain(|_, inserted| now.duration_since(*inserted) < ttl);
                let after = map.len();
                let evicted = before.saturating_sub(after);
                // Reconcile the atomic counter with the actual map size.
                // This is the authoritative correction point — any drift
                // from concurrent insert/cap races is corrected here.
                entry_count.store(after, AtomicOrdering::Relaxed);
                evicted
            }
        }
    }

    /// Full key prefix used for Redis keys. Useful for diagnostics.
    pub fn key_prefix(&self) -> &str {
        &self.key_prefix
    }

    /// Create an in-memory cache with a custom entry cap (test only).
    #[cfg(test)]
    fn in_memory_with_cap(ttl: Duration, max_entries: usize) -> Self {
        Self {
            backend: Backend::InMemory {
                map: Arc::new(dashmap::DashMap::new()),
                entry_count: Arc::new(AtomicUsize::new(0)),
            },
            ttl,
            key_prefix: "latchgate:jti:".to_string(),
            max_in_memory_entries: max_entries,
            replay_warn_throttle: WarnThrottle::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Mutex;

    #[test]
    fn key_prefix_stored_verbatim() {
        let cache = ReplayCache::new(
            &test_redis_url(),
            Duration::from_secs(60),
            "latchgate:acme:jti:",
        )
        .unwrap();
        assert_eq!(cache.key_prefix(), "latchgate:acme:jti:");
    }

    #[test]
    fn in_memory_uses_default_prefix() {
        let cache = ReplayCache::in_memory(Duration::from_secs(60));
        assert_eq!(cache.key_prefix(), "latchgate:jti:");
    }

    #[test]
    fn new_with_valid_url_succeeds() {
        // Does not connect — just parses the URL.
        let cache = ReplayCache::new(
            &test_redis_url(),
            Duration::from_secs(180),
            "latchgate:jti:",
        );
        assert!(cache.is_ok());
    }

    #[test]
    fn new_with_invalid_url_returns_error() {
        let cache = ReplayCache::new("not-a-url", Duration::from_secs(180), "latchgate:jti:");
        assert!(
            cache.is_err(),
            "invalid Redis URL must return CacheUnavailable"
        );
        assert!(matches!(
            cache.unwrap_err(),
            ReplayError::CacheUnavailable(_)
        ));
    }

    #[test]
    fn ttl_accessor_returns_configured_value() {
        let cache = ReplayCache::new(
            &test_redis_url(),
            Duration::from_secs(300),
            "latchgate:jti:",
        )
        .unwrap();
        assert_eq!(cache.ttl(), Duration::from_secs(300));
    }
    //
    // These tests verify the replay detection *contract* using an in-memory
    // implementation. The production `ReplayCache` achieves the same semantics
    // via Redis SETNX. Integration tests with real Redis are below
    // (auto-skip when Redis is not reachable).

    /// Minimal in-memory replay cache for contract testing.
    ///
    /// Not used in production — only verifies the "first ok, second denied"
    /// contract without requiring a Redis server.
    struct InMemoryReplayCache {
        seen: Mutex<HashSet<String>>,
    }

    impl InMemoryReplayCache {
        fn new() -> Self {
            Self {
                seen: Mutex::new(HashSet::new()),
            }
        }

        fn check_and_store_jti(&self, jti: &str) -> Result<(), ReplayError> {
            let mut seen = self.seen.lock().unwrap();
            if seen.contains(jti) {
                Err(ReplayError::AlreadySeen {
                    jti: jti.to_string(),
                })
            } else {
                seen.insert(jti.to_string());
                Ok(())
            }
        }
    }

    #[test]
    fn first_jti_is_accepted() {
        let cache = InMemoryReplayCache::new();
        assert!(cache.check_and_store_jti("jti-001").is_ok());
    }

    #[test]
    fn same_jti_twice_is_rejected() {
        let cache = InMemoryReplayCache::new();
        cache.check_and_store_jti("jti-replay").unwrap();
        let result = cache.check_and_store_jti("jti-replay");
        assert!(matches!(
            result,
            Err(ReplayError::AlreadySeen { ref jti }) if jti == "jti-replay"
        ));
    }

    #[test]
    fn different_jtis_are_accepted() {
        let cache = InMemoryReplayCache::new();
        assert!(cache.check_and_store_jti("jti-a").is_ok());
        assert!(cache.check_and_store_jti("jti-b").is_ok());
        assert!(cache.check_and_store_jti("jti-c").is_ok());
    }

    #[test]
    fn replay_after_multiple_unique_jtis() {
        let cache = InMemoryReplayCache::new();
        cache.check_and_store_jti("jti-1").unwrap();
        cache.check_and_store_jti("jti-2").unwrap();
        cache.check_and_store_jti("jti-3").unwrap();

        // Replay of jti-2
        assert!(matches!(
            cache.check_and_store_jti("jti-2"),
            Err(ReplayError::AlreadySeen { ref jti }) if jti == "jti-2"
        ));
    }

    /// The in-memory backend must not grow unbounded. After reaching the
    /// hard cap, new requests are denied (fail-closed). Expired entries are
    /// cleaned by the background sweep, not inline.
    #[tokio::test]
    async fn in_memory_cache_denies_when_full() {
        // Small cap so the test completes in milliseconds, not minutes.
        let cap = 200;
        let cache = ReplayCache::in_memory_with_cap(Duration::from_secs(3600), cap);

        // Fill to the cap.
        for i in 0..cap {
            let jti = format!("evict-test-{i:06}");
            cache.check_and_store_jti(&jti).await.unwrap();
        }

        // Next request must be denied (fail-closed).
        let result = cache.check_and_store_jti("should-be-denied").await;
        assert!(
            matches!(result, Err(ReplayError::CacheUnavailable(_))),
            "cache at capacity must deny new entries (fail-closed)"
        );
    }

    /// An expired JTI must be re-accepted without waiting for the
    /// background sweep. The per-entry TTL check in
    /// `memory_check_and_store` handles this in O(1).
    #[tokio::test]
    async fn in_memory_expired_jti_is_reaccepted() {
        let cache = ReplayCache::in_memory_with_cap(Duration::from_millis(50), 1000);
        cache.check_and_store_jti("jti-ttl").await.unwrap();

        // Immediately: replay detected.
        assert!(matches!(
            cache.check_and_store_jti("jti-ttl").await,
            Err(ReplayError::AlreadySeen { .. })
        ));

        // Wait for TTL to expire (real wall-clock sleep — Instant is
        // monotonic, not mockable via tokio::time).
        std::thread::sleep(Duration::from_millis(80));

        // After expiry: re-accepted (entry overwritten with fresh timestamp).
        assert!(
            cache.check_and_store_jti("jti-ttl").await.is_ok(),
            "expired in-memory JTI must be re-accepted"
        );
    }
    //
    // These tests auto-skip when Redis is not reachable (e.g. `make dev` not
    // running). Start Redis with `make dev` to execute them.

    /// Returns true if Redis is reachable AND authenticated on the test URL.
    ///
    /// A TCP-only check is insufficient: if Redis is running with a different
    /// password (e.g. from a prior compose session), the tests would pass the
    /// availability gate but fail on every authenticated command. Verifying
    /// PING through the full client catches both connectivity and auth issues,
    /// so the tests skip cleanly instead of panicking.
    fn redis_available() -> bool {
        let url = test_redis_url();
        let client = match redis::Client::open(url.as_str()) {
            Ok(c) => c,
            Err(_) => return false,
        };
        let mut conn =
            match client.get_connection_with_timeout(std::time::Duration::from_millis(500)) {
                Ok(c) => c,
                Err(_) => return false,
            };
        redis::cmd("PING").query::<String>(&mut conn).is_ok()
    }

    fn test_redis_url() -> String {
        std::env::var("LATCHGATE_REDIS_URL")
            .unwrap_or_else(|_| "redis://:changeme@127.0.0.1:6379".to_string())
    }

    #[tokio::test]
    async fn redis_first_jti_accepted() {
        if !redis_available() {
            eprintln!("skipping redis_first_jti_accepted: Redis not available on 127.0.0.1:6379");
            return;
        }
        let cache =
            ReplayCache::new(&test_redis_url(), Duration::from_secs(60), "latchgate:jti:").unwrap();
        let jti = format!("test-{}", uuid::Uuid::now_v7());
        assert!(cache.check_and_store_jti(&jti).await.is_ok());
    }

    #[tokio::test]
    async fn redis_replay_jti_rejected() {
        if !redis_available() {
            eprintln!("skipping redis_replay_jti_rejected: Redis not available");
            return;
        }
        let cache =
            ReplayCache::new(&test_redis_url(), Duration::from_secs(60), "latchgate:jti:").unwrap();
        let jti = format!("test-{}", uuid::Uuid::now_v7());

        cache.check_and_store_jti(&jti).await.unwrap();
        let result = cache.check_and_store_jti(&jti).await;
        assert!(matches!(result, Err(ReplayError::AlreadySeen { .. })));
    }

    #[tokio::test]
    async fn redis_different_jtis_accepted() {
        if !redis_available() {
            eprintln!("skipping redis_different_jtis_accepted: Redis not available");
            return;
        }
        let cache =
            ReplayCache::new(&test_redis_url(), Duration::from_secs(60), "latchgate:jti:").unwrap();
        let jti_a = format!("test-a-{}", uuid::Uuid::now_v7());
        let jti_b = format!("test-b-{}", uuid::Uuid::now_v7());

        assert!(cache.check_and_store_jti(&jti_a).await.is_ok());
        assert!(cache.check_and_store_jti(&jti_b).await.is_ok());
    }

    /// SECURITY: Redis down must return CacheUnavailable, not panic or allow.
    #[tokio::test]
    async fn redis_unavailable_returns_cache_error() {
        // Connect to a port where nothing is listening.
        let cache = ReplayCache::new(
            "redis://127.0.0.1:1",
            Duration::from_secs(60),
            "latchgate:jti:",
        )
        .unwrap();
        let result = cache.check_and_store_jti("jti-should-fail").await;
        assert!(
            matches!(result, Err(ReplayError::CacheUnavailable(_))),
            "Redis down must return CacheUnavailable, not panic or allow"
        );
    }

    /// SECURITY: TTL must be set so entries expire (bounded memory, cache window).
    #[tokio::test]
    async fn redis_jti_expires_after_ttl() {
        if !redis_available() {
            eprintln!("skipping redis_jti_expires_after_ttl: Redis not available");
            return;
        }
        let short_ttl = Duration::from_secs(1);
        let cache = ReplayCache::new(&test_redis_url(), short_ttl, "latchgate:jti:").unwrap();
        let jti = format!("test-ttl-{}", uuid::Uuid::now_v7());

        cache.check_and_store_jti(&jti).await.unwrap();

        // Should be rejected immediately.
        assert!(matches!(
            cache.check_and_store_jti(&jti).await,
            Err(ReplayError::AlreadySeen { .. })
        ));

        // Wait beyond TTL to account for Redis timing variance.
        // NOTE: must use std::thread::sleep (real wall-clock) because Redis
        // TTL expiry is based on server-side real time, not tokio's clock.
        // Margin: 3s sleep for 1s TTL — 2s headroom for CI load and
        // Redis lazy-expiry jitter.
        std::thread::sleep(Duration::from_secs(3));

        // Should be accepted again after expiry.
        assert!(
            cache.check_and_store_jti(&jti).await.is_ok(),
            "jti must be accepted after TTL expiry"
        );
    }

    /// SECURITY: different key prefixes must isolate keyspaces — a jti stored
    /// under one prefix must not collide with the same jti under another.
    #[tokio::test]
    async fn redis_different_prefixes_are_isolated() {
        if !redis_available() {
            eprintln!("skipping redis_different_prefixes_are_isolated: Redis not available");
            return;
        }
        let cache_a = ReplayCache::new(
            &test_redis_url(),
            Duration::from_secs(60),
            "latchgate:tenant-a:jti:",
        )
        .unwrap();
        let cache_b = ReplayCache::new(
            &test_redis_url(),
            Duration::from_secs(60),
            "latchgate:tenant-b:jti:",
        )
        .unwrap();

        let jti = format!("iso-{}", uuid::Uuid::now_v7());

        // Store in tenant-a
        cache_a.check_and_store_jti(&jti).await.unwrap();

        // Same jti must succeed in tenant-b (different keyspace)
        assert!(
            cache_b.check_and_store_jti(&jti).await.is_ok(),
            "same jti under a different prefix must not collide"
        );

        // But replay within tenant-a is still detected
        assert!(matches!(
            cache_a.check_and_store_jti(&jti).await,
            Err(ReplayError::AlreadySeen { .. })
        ));
    }
}
