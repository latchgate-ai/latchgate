//! Bounded per-process LRU cache of parsed P-256 verifying keys.
//!
//! Keyed by JWK thumbprint (`cnf.jkt`), this cache eliminates redundant
//! JWK parsing, base64url decoding, EC point decompression, and thumbprint
//! computation on repeat requests from the same agent.
//!
//! # Security properties
//!
//! - **Signature verification is never cached.** Every request still requires
//!   a full ECDSA signature check against the (cached or freshly parsed) key.
//!   This preserves the per-request proof freshness guarantee of RFC 9449.
//!
//! - **Cache keys are trusted input.** `cnf.jkt` is extracted from the
//!   already-verified Lease JWT, not from the (untrusted) DPoP proof header.
//!   An attacker cannot influence which cache entry is selected.
//!
//! - **Insertion requires prior verification.** A verifying key is only
//!   inserted after the caller has confirmed that
//!   `compute_jwk_thumbprint(x, y) == cnf_jkt` and the ECDSA signature
//!   verifies against the key. Cache poisoning therefore requires a
//!   SHA-256 second-preimage.
//!
//! - **Per-process, not shared.** The cache lives in a single process and
//!   is never serialized or transmitted, eliminating cross-node poisoning.
//!
//! - **Bounded capacity, LRU eviction.** Memory is O(capacity). Concurrent
//!   sessions are naturally bounded by lease capacity, so a small cache
//!   (default 256) covers the working set.

use std::fmt;
use std::num::NonZeroUsize;
use std::sync::Mutex;

use lru::LruCache;

/// Default cache capacity (number of distinct DPoP keys).
///
/// 256 covers typical concurrent-session counts with headroom. Each entry
/// is ~96 bytes (43-byte thumbprint string + 33-byte compressed EC point +
/// struct overhead), so 256 entries ≈ 25 KiB — negligible.
const DEFAULT_CAPACITY: usize = 256;

/// Bounded LRU cache mapping JWK thumbprints to parsed P-256 verifying keys.
///
/// Thread-safe via [`Mutex`]. The critical section is a single hash-map
/// lookup or insert (nanoseconds), which is negligible compared to the
/// ECDSA signature verification (~60 µs) that follows every cache access.
/// Contention is not a concern even under high concurrency.
///
/// # Mutex poisoning
///
/// If a thread panics while holding the lock, subsequent accesses recover
/// via [`Mutex::lock`]'s `PoisonError::into_inner`. The cache is a
/// performance optimisation — a temporarily inconsistent state simply
/// causes cache misses until the entry is re-inserted. No security
/// property depends on cache consistency.
pub struct DPoPKeyCache {
    inner: Mutex<LruCache<String, [u8; 65]>>,
}

// Compile-time assertion: the cache must be shareable across async tasks
// and OS threads (e.g. via `Arc<DPoPKeyCache>` in server state).
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    #[allow(unused)]
    const fn check() {
        assert_send_sync::<DPoPKeyCache>();
    }
};

impl DPoPKeyCache {
    /// Create a new cache with the default capacity ([`DEFAULT_CAPACITY`] = 256).
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Create a new cache with the specified maximum capacity.
    ///
    /// A `capacity` of 0 is clamped to 1 (a zero-entry cache is pointless).
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        // `capacity.max(1)` guarantees >= 1, so `NonZeroUsize::new` always
        // returns `Some`. The `unwrap_or` is a defensive fallback that
        // satisfies `clippy::unwrap_used` without introducing a panic path.
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap_or(NonZeroUsize::MIN);
        Self {
            inner: Mutex::new(LruCache::new(cap)),
        }
    }

    /// Look up a cached verifying key by JWK thumbprint.
    ///
    /// Returns `Some(key)` on hit, `None` on miss. On hit the entry is
    /// promoted to most-recently-used, reducing its eviction priority.
    ///
    /// The returned key is a clone — the lock is released before return.
    pub fn get(&self, thumbprint: &str) -> Option<[u8; 65]> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(thumbprint)
            .cloned()
    }

    /// Insert a verified (thumbprint → key) binding into the cache.
    ///
    /// If the cache is at capacity, the least-recently-used entry is evicted.
    /// If `thumbprint` already exists, the value is updated and the entry
    /// is promoted to most-recently-used.
    ///
    /// # Security contract
    ///
    /// Callers **must** only invoke this after confirming:
    ///
    /// 1. The key was successfully constructed from the JWK `x`/`y`
    ///    coordinates (valid EC point).
    /// 2. `compute_jwk_thumbprint(x, y)` matches the provided `thumbprint`.
    /// 3. The ECDSA signature verified against this key.
    ///
    /// Violating this contract allows cache poisoning: a bad key cached
    /// under a valid thumbprint would cause all subsequent signature
    /// verifications for that session to fail (denial of service).
    pub fn insert(&self, thumbprint: String, key: [u8; 65]) {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .put(thumbprint, key);
    }

    /// Number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    /// Returns `true` if the cache contains no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Remove all entries from the cache.
    pub fn clear(&self) {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }
}

impl Default for DPoPKeyCache {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for DPoPKeyCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.inner.lock() {
            Ok(cache) => f
                .debug_struct("DPoPKeyCache")
                .field("len", &cache.len())
                .field("capacity", &cache.cap())
                .finish(),
            Err(_) => f
                .debug_struct("DPoPKeyCache")
                .field("status", &"poisoned")
                .finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate distinct SEC1 public-key byte arrays for cache tests.
    use std::sync::atomic::{AtomicU8, Ordering};

    fn random_vk() -> [u8; 65] {
        static COUNTER: AtomicU8 = AtomicU8::new(1);

        let mut key = [0u8; 65];
        key[0] = 0x04;
        key[1] = COUNTER.fetch_add(1, Ordering::Relaxed);
        key
    }

    #[test]
    fn cache_hit_returns_correct_key() {
        let cache = DPoPKeyCache::with_capacity(16);
        let vk = random_vk();
        cache.insert("jkt-alpha".into(), vk);

        let cached = cache.get("jkt-alpha").expect("expected cache hit");
        assert_eq!(cached, vk, "cached key must match the inserted key");
    }

    #[test]
    fn cache_miss_returns_none() {
        let cache = DPoPKeyCache::new();
        assert!(
            cache.get("nonexistent-jkt").is_none(),
            "lookup for absent key must return None"
        );
    }

    #[test]
    fn lru_eviction_drops_oldest_entry() {
        let cache = DPoPKeyCache::with_capacity(2);
        let vk_a = random_vk();
        let vk_b = random_vk();
        let vk_c = random_vk();

        cache.insert("a".into(), vk_a);
        cache.insert("b".into(), vk_b);
        // Cache is full (capacity=2). Inserting "c" must evict "a" (LRU).
        cache.insert("c".into(), vk_c);

        assert!(cache.get("a").is_none(), "evicted entry must not be found");
        assert_eq!(cache.get("b").unwrap(), vk_b);
        assert_eq!(cache.get("c").unwrap(), vk_c);
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn access_promotes_entry_and_shifts_eviction() {
        let cache = DPoPKeyCache::with_capacity(2);
        let vk_a = random_vk();
        let vk_b = random_vk();
        let vk_c = random_vk();

        cache.insert("a".into(), vk_a);
        cache.insert("b".into(), vk_b);

        // Access "a" to promote it — "b" becomes the LRU candidate.
        let _ = cache.get("a");

        // Insert "c"; "b" should be evicted (now LRU), not "a".
        cache.insert("c".into(), vk_c);

        assert_eq!(cache.get("a").unwrap(), vk_a, "promoted entry must survive");
        assert!(cache.get("b").is_none(), "LRU entry must be evicted");
        assert_eq!(cache.get("c").unwrap(), vk_c);
    }

    #[test]
    fn insert_same_thumbprint_updates_value() {
        let cache = DPoPKeyCache::with_capacity(16);
        let vk_old = random_vk();
        let vk_new = random_vk();

        cache.insert("jkt-same".into(), vk_old);
        cache.insert("jkt-same".into(), vk_new);

        let cached = cache.get("jkt-same").expect("expected cache hit");
        assert_eq!(cached, vk_new, "value must reflect the latest insert");
        assert_eq!(cache.len(), 1, "duplicate insert must not grow the cache");
    }

    #[test]
    fn distinct_thumbprints_coexist() {
        let cache = DPoPKeyCache::with_capacity(16);
        let vk_1 = random_vk();
        let vk_2 = random_vk();

        cache.insert("jkt-1".into(), vk_1);
        cache.insert("jkt-2".into(), vk_2);

        assert_eq!(cache.get("jkt-1").unwrap(), vk_1);
        assert_eq!(cache.get("jkt-2").unwrap(), vk_2);
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn zero_capacity_is_clamped_to_one() {
        let cache = DPoPKeyCache::with_capacity(0);
        let vk = random_vk();
        cache.insert("a".into(), vk);
        assert_eq!(
            cache.get("a").unwrap(),
            vk,
            "capacity-1 cache must still function"
        );
    }

    #[test]
    fn default_creates_standard_capacity() {
        let cache = DPoPKeyCache::default();
        assert!(cache.is_empty());
        // Insert up to DEFAULT_CAPACITY entries and verify none are evicted.
        for i in 0..DEFAULT_CAPACITY {
            cache.insert(format!("jkt-{i}"), random_vk());
        }
        assert_eq!(cache.len(), DEFAULT_CAPACITY);
    }

    #[test]
    fn clear_removes_all_entries() {
        let cache = DPoPKeyCache::with_capacity(16);
        cache.insert("a".into(), random_vk());
        cache.insert("b".into(), random_vk());
        assert_eq!(cache.len(), 2);

        cache.clear();

        assert!(cache.is_empty());
        assert!(cache.get("a").is_none());
        assert!(cache.get("b").is_none());
    }

    #[test]
    fn debug_output_includes_len_and_capacity() {
        let cache = DPoPKeyCache::with_capacity(8);
        cache.insert("x".into(), random_vk());
        let dbg = format!("{cache:?}");
        assert!(dbg.contains("DPoPKeyCache"), "debug must name the type");
        assert!(dbg.contains("len"), "debug must include current length");
        assert!(dbg.contains("capacity"), "debug must include capacity");
    }
}
