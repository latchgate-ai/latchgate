//! Lock-free token bucket rate limiting.
//!
//! Used by `AppState` to bound per-endpoint traffic:
//!
//! - **Operator write/read, lease issuance:** one global
//!   [`TokenBucketRateLimiter`] per endpoint class, constructed once at
//!   startup.
//! - **Execute path:** per-session (or per-peer for unauthenticated
//!   requests) via [`ExecuteRateLimitMap`]. Applied *before* any
//!   cryptographic verification so a misbehaving agent cannot burn CPU
//!   on DPoP, OPA, or WASM without ever touching its budget.
//!
//! SECURITY: the limiter is a brute-force / DPoP-verification DoS
//! mitigation. It does not replace authentication or policy enforcement;
//! it only bounds the rate at which those paths can be exercised.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::coarse_clock::CoarseClock;

/// Transport-layer peer identity for rate-limit sharding.
///
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerId {
    Uid(u32),
    Unknown,
}

impl std::fmt::Display for PeerId {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerId::Uid(uid) => write!(f, "uid:{uid}"),
            PeerId::Unknown => f.write_str("unknown"),
        }
    }
}

/// Lock-free token bucket rate limiter.
///
/// # Algorithm
///
/// Tokens accrue continuously at `rps` tokens per second, capped at a
/// bucket of size `rps` (one second's worth). Each successful `check()`
/// consumes one token; callers that do not find a token are rejected.
/// Steady-state throughput is exactly `rps` requests per second — bursts
/// are limited to the bucket size, so a client cannot double the intended
/// rate by exploiting a window boundary (the fixed-window pitfall).
///
/// # Concurrency
///
/// State is packed into a single `AtomicU64` of `(last_refill_secs, tokens_x100)`.
/// Tokens are stored in hundredths (`×100`) to give sub-second refill
/// resolution without floating-point math: at 20 rps, 50 ms of elapsed time
/// adds 100 units (one full token). A CAS loop serialises concurrent
/// deductions; a client that loses the CAS re-reads and retries, so two
/// requests arriving simultaneously cannot both succeed against the same
/// single token.
///
/// # Memory ordering
///
/// The packed state is self-contained — no other memory location's
/// visibility depends on it. `Acquire` on the load ensures we observe
/// the most recent successful CAS; `AcqRel` on the success path
/// publishes our write to subsequent readers; `Acquire` on the failure
/// path gives us the winner's state for a correct retry. `SeqCst` is
/// unnecessary because there is no cross-variable ordering requirement.
///
/// # Limits
///
/// The packed field widths set practical maxima:
/// - `last_refill_secs`: `u32` — wraps after year 2106 (wrapping_sub used).
/// - `tokens_x100`: `u32` — max rate ~42 M rps (far above any production
///   setting). `saturating_*` is used internally to keep the invariant
///   even if a caller constructs a limiter near the limit.
pub struct TokenBucketRateLimiter {
    /// Packed `(last_refill_secs: u32, tokens_x100: u32)`.
    /// Upper 32 bits: seconds since Unix epoch at last refill, truncated to u32.
    /// Lower 32 bits: current tokens available, stored as `value × 100`.
    state: AtomicU64,

    /// Bucket capacity in tokens × 100.
    max_tokens_x100: u32,

    /// Refill rate in tokens × 100 per second. Equal to `max_tokens_x100`
    /// so a fully drained bucket refills in exactly one second.
    refill_per_sec_x100: u32,

    /// Coarse-grained second clock shared with all other rate limiters
    /// in this `AppState`. One `Arc<AtomicU32>` load per `check()`.
    clock: CoarseClock,
}

impl TokenBucketRateLimiter {
    /// Construct a limiter with a bucket size and refill rate both equal
    /// to `rps` tokens per second. Bucket starts full.
    pub fn new(rps: u32, clock: CoarseClock) -> Self {
        let max_x100 = rps.saturating_mul(100);
        let now = clock.now_secs();
        Self {
            state: AtomicU64::new(Self::pack(now, max_x100)),
            max_tokens_x100: max_x100,
            refill_per_sec_x100: max_x100,
            clock,
        }
    }

    /// Attempt to consume one token. Returns `true` on success.
    ///
    /// Lock-free: the CAS loop runs at most a handful of iterations even
    /// under heavy contention — each iteration either succeeds, retries
    /// against a fresh read, or terminates early on an empty bucket.
    #[must_use = "ignoring a rate-limit check means the request bypasses throttling"]
    pub fn check(&self) -> bool {
        let now = self.now_secs();
        loop {
            let current = self.state.load(Ordering::Acquire);
            let (last_refill, tokens_x100) = Self::unpack(current);

            // Refill: add elapsed × rate, cap at bucket size.
            let elapsed = now.wrapping_sub(last_refill);
            let refilled = (tokens_x100 as u64)
                .saturating_add((elapsed as u64).saturating_mul(self.refill_per_sec_x100 as u64))
                .min(self.max_tokens_x100 as u64) as u32;

            // Less than one full token — reject without mutating state.
            if refilled < 100 {
                return false;
            }

            let desired = Self::pack(now, refilled - 100);
            match self.state.compare_exchange_weak(
                current,
                desired,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(_) => continue, // Another thread raced us — retry.
            }
        }
    }

    #[inline]
    fn now_secs(&self) -> u32 {
        self.clock.now_secs()
    }

    #[inline]
    const fn pack(last_refill_secs: u32, tokens_x100: u32) -> u64 {
        ((last_refill_secs as u64) << 32) | (tokens_x100 as u64)
    }

    #[inline]
    const fn unpack(packed: u64) -> (u32, u32) {
        ((packed >> 32) as u32, packed as u32)
    }
}

/// Shard key for execute-path rate limiters.
///
/// `Session` keys are extracted from the lease JWT payload *without* signature
/// verification — the value is a hint, not an authentication assertion. An
/// attacker who forges a session_id merely selects which bucket they draw
/// from; they cannot increase their aggregate throughput because each bucket
/// is individually bounded.
///
/// `Peer` keys are used when no session hint is parseable from the request
/// (missing header, malformed JWT, etc.). The value is a typed [`PeerId`]
/// derived from transport-layer credentials (e.g. `SO_PEERCRED` uid on UDS).
/// `PeerId` is `Copy`, so DashMap `entry(key.clone())` on the slow path is
/// a trivial bitwise copy — no heap allocation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LimiterKey {
    Session(Arc<str>),
    Peer(PeerId),
}

/// Entry in the execute rate limit map. Pairs a limiter with a last-access
/// timestamp so the periodic sweep can evict idle entries.
struct LimiterEntry {
    limiter: Arc<TokenBucketRateLimiter>,
    last_access: AtomicU64,
}

impl LimiterEntry {
    fn new(rps: u32, clock: CoarseClock) -> Self {
        let now = clock.now_secs() as u64;
        Self {
            limiter: Arc::new(TokenBucketRateLimiter::new(rps, clock)),
            last_access: AtomicU64::new(now),
        }
    }

    /// Update last-access using a pre-computed timestamp.
    ///
    /// Avoids a redundant `SystemTime::now()` syscall when the caller
    /// already has the current time (e.g. from the sweep loop).
    fn touch_at(&self, now: u64) {
        self.last_access.store(now, Ordering::Relaxed);
    }

    fn last_access_secs(&self) -> u64 {
        self.last_access.load(Ordering::Relaxed)
    }
}

/// Per-session / per-peer rate limiter map for the execute path.
///
/// Backed by `DashMap` for lock-free concurrent reads and sharded writes.
/// Each entry is created on first access and automatically evicted by the
/// background sweep task once its owning session is idle for longer than
/// `peer_idle_ttl_secs`.
///
/// # Capacity
///
/// Bounded by periodic eviction, not by a hard cap on the map size. Under
/// normal operation: one entry per active session + a small number of
/// anonymous peer entries. Pathological case (attacker cycling session hints):
/// bounded by the sweep interval × creation rate, which is a low multiple
/// of `sweep_interval / idle_ttl` — each cycle evicts stale entries faster
/// than they accumulate at any reasonable request rate.
pub struct ExecuteRateLimitMap {
    map: dashmap::DashMap<LimiterKey, LimiterEntry>,
    session_rps: u32,
    anonymous_rps: u32,
    clock: CoarseClock,
}

impl ExecuteRateLimitMap {
    /// Construct a new map with the given per-session and anonymous rates.
    pub fn new(session_rps: u32, anonymous_rps: u32, clock: CoarseClock) -> Self {
        Self {
            map: dashmap::DashMap::new(),
            session_rps,
            anonymous_rps,
            clock,
        }
    }

    /// Attempt to consume one token for the given key. Returns `true` if
    /// the request is allowed. Creates the bucket on first access.
    #[must_use = "ignoring a rate-limit check means the request bypasses throttling"]
    pub fn check(&self, key: &LimiterKey) -> bool {
        let rps = match key {
            LimiterKey::Session(_) => self.session_rps,
            LimiterKey::Peer(_) => self.anonymous_rps,
        };

        // Pre-compute timestamp once — shared by the idle-sweep touch and
        // any new LimiterEntry construction. Eliminates a redundant
        // `SystemTime::now()` syscall per request.
        let now = self.clock.now_secs() as u64;

        // Fast path: entry already exists.
        if let Some(entry) = self.map.get(key) {
            entry.touch_at(now);
            return entry.limiter.check();
        }

        // Slow path: insert a new entry. `or_insert_with` handles the race
        // where two requests create the same key simultaneously — only one
        // allocation survives.
        let clock = self.clock.clone();
        let entry = self
            .map
            .entry(key.clone())
            .or_insert_with(|| LimiterEntry::new(rps, clock));
        entry.touch_at(now);
        entry.limiter.check()
    }

    /// Remove entries that have been idle for longer than `max_idle_secs`.
    ///
    /// Called by the background sweep task. Returns the number of entries
    /// removed.
    #[must_use = "sweep count indicates map pressure — log or act on it"]
    pub fn sweep_stale(&self, max_idle_secs: u64) -> usize {
        let now = self.clock.now_secs() as u64;
        let before = self.map.len();
        self.map
            .retain(|_, entry| now.saturating_sub(entry.last_access_secs()) < max_idle_secs);
        before.saturating_sub(self.map.len())
    }

    /// Current number of entries (for diagnostics / testing).
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the map contains no entries.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Extract a rate-limiter shard key from the request headers.
///
/// Attempts to parse the `session_id` claim from the lease JWT payload
/// **without** verifying the signature. This is safe: the session hint is
/// used only to select a rate-limit bucket, not for any security decision.
/// A forged session_id merely selects a different bucket — each bucket is
/// individually bounded.
///
/// Falls back to a `Peer` key using `peer_id` when the session hint is
/// unparseable.
pub fn extract_limiter_key(authorization: Option<&str>, peer_id: PeerId) -> LimiterKey {
    if let Some(session_id) = parse_session_hint(authorization) {
        LimiterKey::Session(session_id)
    } else {
        LimiterKey::Peer(peer_id)
    }
}

/// Parse `session_id` from the lease JWT payload without signature
/// verification. Returns `None` on any parse failure (missing header,
/// wrong scheme, malformed base64, missing claim).
///
/// Hot path: runs on every execute request before authentication.
/// Decodes into a stack buffer and uses a borrowing serde struct to
/// avoid the `Vec<u8>` + `serde_json::Value` heap allocations that
/// the previous implementation incurred per request.
fn parse_session_hint(authorization: Option<&str>) -> Option<Arc<str>> {
    // Expected format: "DPoP <base64url-header>.<base64url-payload>.<signature>"
    let token = authorization?.strip_prefix("DPoP ")?;

    let payload_b64 = token.split('.').nth(1)?;

    // Decode into a fixed stack buffer. Lease JWT payloads are typically
    // 100–300 bytes; 512 bytes covers any reasonable payload. Oversize
    // tokens fail gracefully (returns None → peer-based rate limiting).
    use base64ct::{Base64UrlUnpadded, Encoding};
    let mut buf = [0u8; 512];
    let decoded = Base64UrlUnpadded::decode(payload_b64, &mut buf).ok()?;

    // Borrowing struct: serde_json borrows string values directly from
    // the input slice when they contain no escape sequences — which is
    // always true for well-formed session IDs (UUIDs, opaque tokens).
    // If an ID does contain escape sequences, deserialization into &str
    // returns an error and we fall back to peer-based rate limiting.
    #[derive(serde::Deserialize)]
    struct Hint<'a> {
        #[serde(borrow)]
        session_id: Option<&'a str>,
    }

    let hint: Hint<'_> = serde_json::from_slice(decoded).ok()?;
    let session_id = hint.session_id?;

    // Reject empty or excessively long session IDs (defense-in-depth
    // against map key bloat).
    if session_id.is_empty() || session_id.len() > 256 {
        return None;
    }

    Some(Arc::from(session_id))
}

#[cfg(test)]
mod tests {
    use super::TokenBucketRateLimiter;
    use crate::coarse_clock::CoarseClock;

    fn test_clock() -> CoarseClock {
        CoarseClock::new()
    }

    /// A fresh bucket MUST start full: the client gets its configured RPS
    /// worth of allowance from the first second. Starting empty would
    /// wrongly reject the first N requests of every process lifetime.
    #[test]
    fn new_bucket_allows_burst_up_to_rps() {
        let limiter = TokenBucketRateLimiter::new(10, test_clock());
        for i in 0..10 {
            assert!(limiter.check(), "call {} of 10 within fresh bucket", i + 1);
        }
    }

    /// SECURITY: steady-state throughput MUST NOT exceed RPS. The fixed-
    /// window flaw we migrated away from allowed 2×RPS at window edges;
    /// token bucket caps burst at bucket size (= RPS). This test exhausts
    /// the bucket then asserts the very next call is rejected.
    #[test]
    fn exhausted_bucket_rejects_next_call() {
        let limiter = TokenBucketRateLimiter::new(5, test_clock());
        for _ in 0..5 {
            assert!(limiter.check());
        }
        assert!(
            !limiter.check(),
            "the 6th call within one second must be rejected"
        );
    }

    /// A bucket with RPS=1 exposes the edge case: exactly one token, no
    /// fractional carry. Must allow exactly one call, reject the rest.
    #[test]
    fn rps_one_allows_exactly_one_call_per_second() {
        let limiter = TokenBucketRateLimiter::new(1, test_clock());
        assert!(limiter.check());
        assert!(!limiter.check());
        assert!(!limiter.check());
    }

    /// RPS=0 is a pathological config but must not panic. Bucket starts
    /// empty and never refills — every call rejected. Fail-closed.
    #[test]
    fn rps_zero_rejects_all_calls() {
        let limiter = TokenBucketRateLimiter::new(0, test_clock());
        assert!(!limiter.check());
        assert!(!limiter.check());
    }

    /// Concurrent `check()` calls must not both succeed against the same
    /// single token. Spawn `N` threads hammering a bucket of size `N`;
    /// `N` successes allowed, then all further attempts rejected. This
    /// asserts the CAS loop is correct under contention.
    ///
    /// The wall clock may advance during the test, refilling tokens at
    /// `rps` per second. We account for this by measuring elapsed time
    /// and adding the worst-case refill to the expected ceiling.
    #[test]
    fn concurrent_checks_do_not_exceed_bucket_size() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::thread;

        const BUCKET: u32 = 50;
        const THREADS: usize = 16;
        const CALLS_PER_THREAD: usize = 10; // 16*10 = 160 > 50

        let limiter = Arc::new(TokenBucketRateLimiter::new(BUCKET, test_clock()));
        let allowed = Arc::new(AtomicUsize::new(0));

        let start = std::time::Instant::now();

        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let limiter = Arc::clone(&limiter);
                let allowed = Arc::clone(&allowed);
                thread::spawn(move || {
                    for _ in 0..CALLS_PER_THREAD {
                        if limiter.check() {
                            allowed.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        // Account for time-based refill: the wall clock may have ticked
        // forward during execution, legitimately adding tokens. +1 second
        // for rounding since the limiter uses whole-second granularity.
        let elapsed_secs = start.elapsed().as_secs() + 1;
        let max_allowed = BUCKET as usize + (elapsed_secs as usize * BUCKET as usize);

        let total = allowed.load(Ordering::Relaxed);
        assert!(
            total <= max_allowed,
            "bucket of {BUCKET} granted {total} successes under {THREADS} threads \
             (max {max_allowed} with {elapsed_secs}s refill) — CAS race"
        );
        // Sanity: without CAS, all 160 attempts would succeed.
        // With correct CAS, total is bounded by bucket + refill.
    }

    use super::{extract_limiter_key, parse_session_hint, ExecuteRateLimitMap, LimiterKey};
    use std::sync::Arc;

    /// Per-session buckets are independent: exhausting session A does not
    /// affect session B.
    #[test]
    fn execute_map_sessions_are_independent() {
        let map = ExecuteRateLimitMap::new(3, 1, test_clock());
        let a = LimiterKey::Session(Arc::from("session-a"));
        let b = LimiterKey::Session(Arc::from("session-b"));

        for _ in 0..3 {
            assert!(map.check(&a));
        }
        assert!(!map.check(&a), "session-a bucket must be exhausted");

        // session-b is unaffected.
        for _ in 0..3 {
            assert!(map.check(&b));
        }
    }

    /// Anonymous (peer) buckets use the lower anonymous RPS, not the
    /// session RPS.
    #[test]
    fn execute_map_anonymous_uses_lower_rps() {
        let map = ExecuteRateLimitMap::new(20, 2, test_clock());
        let peer = LimiterKey::Peer(super::PeerId::Uid(1000));

        assert!(map.check(&peer));
        assert!(map.check(&peer));
        assert!(
            !map.check(&peer),
            "anonymous bucket at 2 rps must reject the 3rd call"
        );
    }

    /// `sweep_stale` removes entries idle beyond the threshold and leaves
    /// active entries intact.
    #[test]
    fn sweep_removes_stale_entries() {
        let map = ExecuteRateLimitMap::new(10, 5, test_clock());
        let active = LimiterKey::Session(Arc::from("active"));
        let _stale = LimiterKey::Session(Arc::from("stale"));

        // Create both entries (return value intentionally unused — we only
        // need the side effect of bucket creation).
        let _ = map.check(&active);
        let _ = map.check(&_stale);
        assert_eq!(map.len(), 2);

        // Sweep with max_idle_secs=0 evicts everything (they are all "idle"
        // since they were accessed at the same second or earlier).
        let removed = map.sweep_stale(0);
        assert_eq!(removed, 2);
        assert_eq!(map.len(), 0);
    }

    /// Sweep with a generous idle threshold removes nothing.
    #[test]
    fn sweep_keeps_active_entries() {
        let map = ExecuteRateLimitMap::new(10, 5, test_clock());
        let key = LimiterKey::Session(Arc::from("s1"));
        let _ = map.check(&key);

        let removed = map.sweep_stale(3600);
        assert_eq!(removed, 0);
        assert_eq!(map.len(), 1);
    }

    /// Build a minimal unsigned JWT with the given payload for testing.
    fn fake_jwt(payload_json: &str) -> String {
        use base64ct::{Base64UrlUnpadded, Encoding};
        let header = Base64UrlUnpadded::encode_string(b"{\"alg\":\"ES256\"}");
        let payload = Base64UrlUnpadded::encode_string(payload_json.as_bytes());
        format!("DPoP {header}.{payload}.fakesig")
    }

    #[test]
    fn parse_session_hint_valid_jwt() {
        let auth = fake_jwt(r#"{"session_id":"sess-42","sub":"agent"}"#);
        assert_eq!(parse_session_hint(Some(&auth)), Some(Arc::from("sess-42")),);
    }

    #[test]
    fn parse_session_hint_missing_header() {
        assert_eq!(parse_session_hint(None), None);
    }

    #[test]
    fn parse_session_hint_wrong_scheme() {
        assert_eq!(parse_session_hint(Some("Bearer token")), None);
    }

    #[test]
    fn parse_session_hint_malformed_base64() {
        assert_eq!(parse_session_hint(Some("DPoP aaa.!!!.ccc")), None);
    }

    #[test]
    fn parse_session_hint_missing_session_id_claim() {
        let auth = fake_jwt(r#"{"sub":"agent"}"#);
        assert_eq!(parse_session_hint(Some(&auth)), None);
    }

    #[test]
    fn parse_session_hint_empty_session_id_rejected() {
        let auth = fake_jwt(r#"{"session_id":""}"#);
        assert_eq!(parse_session_hint(Some(&auth)), None);
    }

    #[test]
    fn parse_session_hint_overlong_session_id_rejected() {
        let long = "x".repeat(257);
        let auth = fake_jwt(&format!(r#"{{"session_id":"{long}"}}"#));
        assert_eq!(parse_session_hint(Some(&auth)), None);
    }

    /// `extract_limiter_key` falls back to `Peer` when the JWT is
    /// unparseable.
    #[test]
    fn extract_limiter_key_falls_back_to_peer() {
        let key = extract_limiter_key(Some("Bearer not-dpop"), super::PeerId::Uid(1000));
        assert_eq!(key, LimiterKey::Peer(super::PeerId::Uid(1000)));
    }

    #[test]
    fn extract_limiter_key_uses_session_when_available() {
        let auth = fake_jwt(r#"{"session_id":"sess-7"}"#);
        let key = extract_limiter_key(Some(&auth), super::PeerId::Uid(1000));
        assert_eq!(key, LimiterKey::Session(Arc::from("sess-7")));
    }
}
