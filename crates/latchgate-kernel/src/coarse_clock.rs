//! Coarse-grained second clock for rate limiting.
//!
//! Replaces per-request `SystemTime::now()` reads with a single atomic load
//! from a cached clock that a background task refreshes once per second.
//!
//! # Initialisation and fallback
//!
//! Call [`CoarseClock::start`] once from the server's async runtime. Before
//! `start` is called (unit tests, standalone tools), [`CoarseClock::now_secs`]
//! transparently seeds the cache from the wall clock on first use, so it never
//! returns a stale or sentinel value.
//!
//! # Liveness
//!
//! If the background ticker ever stops advancing the cache (a stalled runtime
//! timer driver), the rate limiter degrades fail-closed: `elapsed` stays `0`,
//! buckets stop refilling, and requests are throttled rather than admitted —
//! never the reverse. To make that state observable rather than silent, the
//! ticker publishes the cached second to the `latchgate_coarse_clock_unix_seconds`
//! gauge on every tick. Monitoring compares this gauge against scrape time; a
//! gauge that stops advancing is a stalled clock and should alert.
//!
//! # Test isolation
//!
//! Each `CoarseClock` instance owns its own `AtomicU32` via `Arc`, so tests
//! that construct separate `AppState` values receive independent clocks. No
//! global mutable state is shared across `#[tokio::test]` harnesses.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use latchgate_ledger::Metrics;

/// Injectable coarse-grained second clock.
///
/// Wraps an `Arc<AtomicU32>` so cloning is a refcount bump. Passed into
/// rate limiters at construction time, eliminating the previous global
/// `static AtomicU32`.
#[derive(Clone, Debug)]
pub struct CoarseClock {
    /// Cached current second (Unix epoch, truncated to `u32`).
    ///
    /// `0` is the uninitialised sentinel. It is never a legitimate cached
    /// value: the wall clock is always far past the epoch, and
    /// [`now_secs`](Self::now_secs) seeds the cache on first read if
    /// `start` has not run. The `u32` width matches the token bucket's
    /// packed `(last_refill_secs: u32, tokens_x100: u32)` state; it wraps
    /// after year 2106, which the bucket handles via `wrapping_sub`.
    secs: Arc<AtomicU32>,
}

impl Default for CoarseClock {
    fn default() -> Self {
        Self::new()
    }
}

impl CoarseClock {
    /// Create a new clock with an uninitialised cache.
    ///
    /// The first call to [`now_secs`](Self::now_secs) (or [`start`](Self::start))
    /// seeds the cache from the wall clock.
    pub fn new() -> Self {
        Self {
            secs: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Read the current second (Unix epoch, truncated to `u32`).
    ///
    /// After [`start`](Self::start) (or the first call) this is a single
    /// relaxed atomic load with no clock read. If the cache is still
    /// uninitialised, it is seeded from the wall clock so callers never
    /// observe the `0` sentinel.
    #[inline]
    #[must_use]
    pub fn now_secs(&self) -> u32 {
        let cached = self.secs.load(Ordering::Relaxed);
        if cached != 0 {
            return cached;
        }

        // Uninitialised: `start` has not run yet (tests, standalone tools),
        // or this is the first read. Seed the cache so subsequent reads are
        // fast and never see `0`. A racing seeder is harmless — both write
        // the same second.
        let now = wallclock_secs();
        let _ = self
            .secs
            .compare_exchange(0, now, Ordering::Relaxed, Ordering::Relaxed);
        now
    }

    /// Spawn the 1 Hz background ticker that keeps the cache fresh.
    ///
    /// Must be called once from the server's async runtime (alongside the
    /// other background sweep tasks). Calling it more than once is harmless
    /// — each extra ticker writes the same value.
    ///
    /// The cache is seeded synchronously before the task is spawned so
    /// [`now_secs`](Self::now_secs) returns a valid value immediately after
    /// `start` returns. Each tick also publishes the cached second to a
    /// gauge so a stalled ticker is observable.
    pub fn start(&self, metrics: Arc<Metrics>) {
        // Seed immediately so callers between start() and the first tick
        // read a fresh value rather than seeding individually.
        let seeded = wallclock_secs();
        self.secs.store(seeded, Ordering::Relaxed);
        metrics.set_coarse_clock_unix_seconds(i64::from(seeded));

        let secs = Arc::clone(&self.secs);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let now = wallclock_secs();
                secs.store(now, Ordering::Relaxed);
                // Liveness heartbeat: a gauge that stops advancing means the
                // ticker (and therefore rate-limit refill) has stalled.
                metrics.set_coarse_clock_unix_seconds(i64::from(now));
            }
        });
    }
}

/// Read `SystemTime::now()` as whole Unix seconds, truncated to `u32`.
#[inline]
fn wallclock_secs() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_secs_returns_plausible_value() {
        let clock = CoarseClock::new();
        let secs = clock.now_secs();
        // Should be after 2024-01-01 (1_704_067_200).
        assert!(secs > 1_704_067_200, "clock returned implausible {secs}");
    }

    #[test]
    fn now_secs_never_returns_zero_sentinel() {
        // Even without start(), a read must seed and return a real second.
        let clock = CoarseClock::new();
        let secs = clock.now_secs();
        assert_ne!(
            secs, 0,
            "now_secs must never expose the uninitialised sentinel"
        );
    }

    #[test]
    fn seeded_read_matches_wallclock() {
        let clock = CoarseClock::new();
        let a = clock.now_secs();
        let b = wallclock_secs();
        // Allow 1 second of skew in either direction — the second boundary
        // can tick between the two reads regardless of ordering.
        let diff = (a as i64 - b as i64).unsigned_abs();
        assert!(diff <= 1, "seeded read diverged: {a} vs {b}");
    }

    #[test]
    fn independent_clocks_do_not_share_state() {
        let c1 = CoarseClock::new();
        let c2 = CoarseClock::new();
        // Both must return plausible values independently.
        let s1 = c1.now_secs();
        let s2 = c2.now_secs();
        assert!(s1 > 1_704_067_200);
        assert!(s2 > 1_704_067_200);
        // Internal arcs must be distinct allocations.
        assert!(!Arc::ptr_eq(&c1.secs, &c2.secs));
    }
}
