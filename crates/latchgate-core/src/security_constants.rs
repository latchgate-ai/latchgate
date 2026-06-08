//! Security constants promoted from configurable `Config` fields.
//!
//! Each value was a configurable field whose **only safe value is the
//! default**. Exposing them invited misconfiguration with no legitimate
//! upside. Pre-public release: we harden by removing the knobs.
//!
//! If a future deployment genuinely requires a different value, the
//! constant can be moved back to `Config` with a documented security
//! justification and a corresponding test.

/// Anti-replay cache TTL in seconds.
///
/// Tied to `allowed_clock_skew + max_proof_age`. Shorter reopens the
/// replay window; longer wastes memory. 180 s covers ±60 s skew + proof
/// lifetime.
pub const REPLAY_TTL_SECS: u64 = 180;

/// OPA policy evaluation timeout in milliseconds.
///
/// Timeout fires => DENY (fail-closed). 1000 ms is generous for a local
/// sidecar. If OPA consistently exceeds this, investigate bundle size or
/// network latency — do NOT raise the timeout.
pub const OPA_TIMEOUT_MS: u64 = 1000;

/// Hard ceiling on Lease lifetime in seconds.
///
/// Even misconfigured `lease_ttl_seconds` cannot exceed this. A hard
/// ceiling that config can lift is not a ceiling.
pub const MAX_LEASE_TTL_SECS: u64 = 3600;

/// Redis key prefix for all keys written by this instance.
///
/// Scopes the keyspace. Multi-tenant Platform deployments that need
/// per-tenant isolation build their own binary with a different constant.
pub const REDIS_KEY_PREFIX: &str = "latchgate:jti:";

/// TTL for pending approval requests in seconds.
///
/// After expiry, unapproved requests are auto-denied. Short window
/// limits exposure of stored request bodies.
pub const APPROVAL_TTL_SECS: u64 = 300;

/// Maximum concurrent WASM provider executions.
///
/// Limits parallelism to prevent resource exhaustion on the host.
pub const MAX_CONCURRENT_EXECUTIONS: usize = 4;

/// Maximum HTTP request body size in bytes (1 MB).
///
/// Enforced at the transport layer before any buffering. Without this,
/// concurrent oversized bodies exhaust gate memory before per-action
/// `max_request_bytes` fires. Defense-in-depth against memory DoS.
pub const MAX_REQUEST_BODY_BYTES: usize = 1_048_576;

/// Path to the SOPS binary.
pub const SOPS_BIN: &str = "sops";

/// SOPS decryption cache TTL in seconds.
///
/// Caches decrypted secrets in memory keyed by file mtime + inode.
/// Secret rotation takes effect within this window.
pub const SOPS_CACHE_TTL_SECS: u64 = 30;

/// Paths that are never valid as a per-session filesystem root,
/// regardless of `fs_root_allowed_prefixes`.
///
/// These are system directories whose contents should never be
/// exposed as a project root. The allowlist is the primary control;
/// this blocklist is defense-in-depth for misconfigured allowlists.
///
/// SECURITY: exact-match only. `/home` is blocked (all users' dirs)
/// but `/home/alice` can pass the allowlist. Canonical paths are
/// compared via `Path::eq`, so symlinks don't bypass this.
pub const FS_ROOT_BLOCKED_PATHS: &[&str] = &[
    "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/media", "/mnt", "/opt",
    "/proc", "/root", "/run", "/sbin", "/snap", "/srv", "/sys", "/tmp", "/usr", "/var",
];

/// Grace period added to lease TTL for session fs_root eviction.
///
/// Ensures in-flight executions at lease expiry are not disrupted.
/// Matches the budget TTL grace period in `leases.rs`.
pub const SESSION_FS_ROOT_EVICTION_GRACE_SECS: u64 = 60;
