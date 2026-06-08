//! Host-mediated I/O layer for WASM provider modules.
//!
//! Every I/O call from a .wasm provider module goes through the host I/O
//! layer. The host validates the target against allowed_sinks, injects
//! credentials from the secrets manager, executes the I/O operation, and
//! tracks the call against the per-execution I/O budget.
//!
//! SECURITY: providers never see credentials. Sink validation is enforced
//! at the host layer before every outbound call.

use std::cell::Cell;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use url::Url;
use zeroize::Zeroizing;

pub use latchgate_core::host_observed::HostObservedEffect;

pub struct HostState {
    /// Sinks approved by policy for this execution.
    pub allowed_sinks: Vec<Arc<str>>,

    allowed_sinks_lower: Vec<String>,

    /// Secret names approved for injection into host I/O calls.
    pub approved_secrets: HashSet<Arc<str>>,

    /// Decrypted secret values, keyed by secret name.
    /// SECURITY: never exposed to the WASM sandbox. Used by host I/O
    /// handlers to inject credentials into outbound requests.
    /// Wrapped in `Zeroizing` to overwrite plaintext on drop.
    decrypted_secrets: HashMap<String, Zeroizing<String>>,

    /// Trace ID for correlation. `Arc<str>` so clones into log spans and
    /// error paths are O(1) refcount bumps rather than heap allocations.
    pub trace_id: Arc<str>,

    /// I/O calls made so far.
    ///
    /// Uses `Cell` rather than `AtomicU32` because WASM execution is
    /// single-threaded per Store — atomics are unnecessary overhead.
    io_calls_made: Cell<u32>,

    /// Maximum I/O calls allowed for this execution.
    max_io_calls: u32,

    /// Maximum response body size in bytes for a single host I/O call.
    /// SECURITY: prevents OOM from unbounded upstream responses.
    pub max_host_response_bytes: usize,

    /// Host I/O interfaces declared in the action manifest.
    ///
    /// SECURITY: this is the runtime enforcement of import gating. Even
    /// though all interfaces are registered in the linker (a wasmtime
    /// constraint — the linker is built once at startup), a provider that
    /// calls an interface it did not declare in `required_imports` is
    /// rejected here before any I/O is performed. Each host handler calls
    /// `check_import_allowed` as its first step.
    ///
    /// Example: a provider that declared only `latchgate:io/smtp` cannot
    /// call `latchgate:io/http` — the handler returns an error immediately,
    /// the I/O budget is not consumed, and the execution fails with
    /// `ImportNotDeclared`.
    allowed_imports: Vec<Arc<str>>,

    /// Database configuration from the action manifest (if this is a database action).
    ///
    /// SECURITY: the host uses this to enforce database mode rules
    /// (strict/parameterized/hybrid) and validate every database request
    /// before any SQL reaches the database. The provider cannot influence
    /// these rules.
    pub database_config: Option<crate::database::DatabaseConfig>,

    /// Forward proxy URL for defense-in-depth egress control.
    /// When set, outbound HTTP is routed through this proxy.
    pub egress_proxy_url: Option<Arc<str>>,

    /// Log calls emitted so far by the provider.
    ///
    /// SECURITY: `latchgate:io/log` is now gated like any other import —
    /// providers must declare it in `required_imports`. Rate limiting and
    /// secret redaction provide defense-in-depth against data exfiltration
    /// through log messages even for declared providers.
    log_calls_made: Cell<u32>,

    /// Maximum log calls allowed per execution.
    max_log_calls: u32,

    /// Maximum bytes per individual log message. Messages exceeding this
    /// are truncated with a `[truncated]` suffix.
    max_log_message_bytes: usize,

    /// Effects independently observed by the host during I/O execution.
    /// Passed to the verifier for cross-checking against provider output.
    observed_effects: RefCell<Vec<HostObservedEffect>>,

    /// Filesystem provider configuration for this execution. `None` when
    /// the action is not an `fs` action. Set from the manifest's `FsConfig`
    /// and the operator-configured root fd.
    pub fs_config: Option<Arc<crate::fs_io::FsHostConfig>>,
}

/// Configuration for constructing a [`HostState`].
///
/// Groups all per-execution parameters into a single struct to prevent
/// positional argument mistakes in a security-critical constructor.
pub struct HostStateConfig {
    pub allowed_sinks: Vec<Arc<str>>,
    pub approved_secrets: Vec<Arc<str>>,
    pub decrypted_secrets: HashMap<String, Zeroizing<String>>,
    pub trace_id: Arc<str>,
    pub max_io_calls: u32,
    pub max_host_response_bytes: usize,
    pub allowed_imports: Vec<Arc<str>>,
    pub database_config: Option<crate::database::DatabaseConfig>,
    pub egress_proxy_url: Option<Arc<str>>,
    /// Maximum log calls per execution (default: 256).
    pub max_log_calls: Option<u32>,
    /// Maximum bytes per log message (default: 4096).
    pub max_log_message_bytes: Option<usize>,
    /// Filesystem provider configuration. `None` for non-fs actions.
    pub fs_config: Option<Arc<crate::fs_io::FsHostConfig>>,
}

impl HostState {
    /// Create a new HostState for a single execution.
    pub fn new(config: HostStateConfig) -> Self {
        let allowed_sinks_lower: Vec<String> = config
            .allowed_sinks
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        let approved_secrets: HashSet<Arc<str>> = config.approved_secrets.into_iter().collect();
        Self {
            allowed_sinks: config.allowed_sinks,
            allowed_sinks_lower,
            approved_secrets,
            decrypted_secrets: config.decrypted_secrets,
            trace_id: config.trace_id,
            io_calls_made: Cell::new(0),
            max_io_calls: config.max_io_calls,
            max_host_response_bytes: config.max_host_response_bytes,
            allowed_imports: config.allowed_imports,
            database_config: config.database_config,
            egress_proxy_url: config.egress_proxy_url,
            log_calls_made: Cell::new(0),
            max_log_calls: config.max_log_calls.unwrap_or(256),
            max_log_message_bytes: config.max_log_message_bytes.unwrap_or(4096),
            observed_effects: RefCell::new(Vec::new()),
            fs_config: config.fs_config,
        }
    }

    /// Look up a decrypted secret by name.
    ///
    /// SECURITY: only returns secrets that are both:
    ///   1. present in `decrypted_secrets` (decrypted by the pipeline), AND
    ///   2. listed in `approved_secrets` (declared in the action manifest).
    ///
    /// A secret that was decrypted but not declared in the manifest is not
    /// accessible — least-privilege secret release. This prevents a provider
    /// from reading secrets it did not declare even if the SOPS file contains
    /// them (e.g. a database password when only an API key was approved).
    ///
    /// Approval lookup is O(1) via `HashSet` — get_secret is called multiple
    /// times per HTTP request on the hot path.
    pub fn get_secret(&self, name: &str) -> Option<&str> {
        if !self.approved_secrets.contains(name) {
            return None;
        }
        self.decrypted_secrets.get(name).map(|s| s.as_str())
    }

    /// Returns `true` if any credential-bearing secret will be injected
    /// into outbound HTTP requests by the host layer.
    ///
    /// SECURITY: the host HTTP handler uses this to enforce HTTPS before
    /// secret injection. Checked once per outbound request; O(k) where
    /// k = |CREDENTIAL_SECRET_NAMES| (currently 3).
    pub fn has_credential_secrets(&self) -> bool {
        /// Secret names the host injects as HTTP credentials.
        const CREDENTIAL_SECRET_NAMES: [&str; 3] = ["AUTHORIZATION", "BEARER_TOKEN", "API_KEY"];
        CREDENTIAL_SECRET_NAMES
            .iter()
            .any(|name| self.get_secret(name).is_some())
    }

    /// Check and consume one I/O call from the budget.
    ///
    /// Returns `Err` if the budget is exhausted.
    pub fn consume_io_call(&self) -> Result<u32, IoError> {
        let current = self.io_calls_made.get();
        if current >= self.max_io_calls {
            return Err(IoError::BudgetExhausted {
                max: self.max_io_calls,
            });
        }
        self.io_calls_made.set(current + 1);
        Ok(current + 1)
    }

    /// Check that the given host interface was declared in the action manifest.
    ///
    /// SECURITY: called as the first step in every host I/O handler. A provider
    /// that calls an interface it did not declare in `required_imports` is
    /// rejected before any I/O is attempted. This enforces the capability model
    /// at runtime, compensating for the fact that the linker is built once with
    /// all interfaces registered (a wasmtime architectural constraint).
    ///
    /// `interface` must be the canonical WIT interface name, e.g.
    /// `"latchgate:io/http"`. Logging (`latchgate:io/log`) follows the same
    /// gate — providers must declare it in `required_imports` to use it.
    /// All shipped manifests declare it; the gate prevents future undeclared
    /// providers from using log as an unaudited egress channel.
    pub fn check_import_allowed(&self, interface: &str) -> Result<(), IoError> {
        if self.allowed_imports.iter().any(|i| i.as_ref() == interface) {
            Ok(())
        } else {
            Err(IoError::ImportNotAllowed {
                interface: interface.to_string(),
                declared: self.allowed_imports.clone(),
            })
        }
    }

    /// Validate that the target is in the allowed sinks list.
    ///
    /// Extracts the host from the target (URL, email, or bare identifier) and
    /// checks it against allowed sinks using exact or subdomain matching.
    ///
    /// SECURITY: fail-closed. If the target is not in the list, reject.
    /// Subdomain matching requires a literal `.` boundary: a sink of
    /// `"api.com"` matches `"api.com"` and `"foo.api.com"` but NOT
    /// `"evil-api.com"`. The shared matcher in `host_matches_allowlist_lower`
    /// is the single source of truth for this boundary rule.
    pub fn validate_sink(&self, target: &str) -> Result<(), IoError> {
        let host = extract_host(target);
        if host_matches_allowlist_lower(host, &self.allowed_sinks_lower) {
            Ok(())
        } else {
            Err(IoError::SinkNotAllowed {
                safe_target: safe_url_for_log(target).to_string(),
                target: target.to_string(),
            })
        }
    }

    /// Total I/O calls made during this execution.
    pub fn io_calls_count(&self) -> u32 {
        self.io_calls_made.get()
    }

    /// Record a host-observed effect for later verification cross-checking.
    pub fn record_observed_effect(&self, effect: HostObservedEffect) {
        self.observed_effects.borrow_mut().push(effect);
    }

    /// Take all recorded observations, leaving the internal vec empty.
    pub fn take_observed_effects(&self) -> Vec<HostObservedEffect> {
        self.observed_effects.borrow_mut().drain(..).collect()
    }

    /// Consume one log call from the log budget. Returns the sanitized
    /// message if the budget allows, or `None` if exhausted.
    ///
    /// SECURITY: truncates messages exceeding `max_log_message_bytes` and
    /// redacts any decrypted secret values that appear in the message.
    pub fn consume_log_call(&self, raw_message: &str) -> Option<String> {
        let current = self.log_calls_made.get();
        if current >= self.max_log_calls {
            return None;
        }
        self.log_calls_made.set(current + 1);

        // Truncate oversized messages.
        let truncated = if raw_message.len() > self.max_log_message_bytes {
            let safe_end = truncate_at_char_boundary(raw_message, self.max_log_message_bytes);
            format!("{}[truncated]", &raw_message[..safe_end])
        } else {
            raw_message.to_string()
        };

        // Redact any decrypted secret values that appear in the message.
        let mut message = truncated;
        for value in self.decrypted_secrets.values() {
            if !value.is_empty() && message.contains(value.as_str()) {
                message = message.replace(value.as_str(), "***REDACTED***");
            }
        }

        Some(message)
    }
}

/// Errors from host I/O operations.
#[derive(Debug, thiserror::Error)]
pub enum IoError {
    #[error("I/O budget exhausted (max {max} calls)")]
    BudgetExhausted { max: u32 },

    #[error("sink not in allowed list: {safe_target}")]
    SinkNotAllowed {
        /// Full target, preserved for programmatic callers that need exact
        /// sink identity (e.g. to suggest the correct allowlist entry).
        target: String,
        /// Redacted for Display/logs: scheme + host + redacted path, no
        /// query/fragment/userinfo.
        safe_target: String,
    },

    #[error("secret not approved: {name}")]
    SecretNotApproved { name: String },

    #[error("I/O operation failed: {reason}")]
    OperationFailed { reason: String },

    /// SECURITY (S1): DNS resolution resolved to a private/reserved IP address.
    /// This blocks SSRF attacks where an allowed domain redirects or resolves
    /// to internal infrastructure (cloud metadata, localhost, RFC 1918, etc.).
    #[error("SSRF blocked: {reason}")]
    SsrfBlocked { reason: String },

    /// SECURITY: provider attempted to use a host interface it did not declare
    /// in its action manifest `required_imports`. This is an import gating
    /// violation — the execution is terminated before any I/O is performed.
    #[error(
        "import not allowed: '{interface}' was not declared in required_imports (declared: {declared:?})"
    )]
    ImportNotAllowed {
        interface: String,
        declared: Vec<Arc<str>>,
    },
}

// Host extraction

/// Extract the host/domain from a target string.
///
/// Handles three forms:
/// 1. URL (`https://api.github.com/repos`) => `api.github.com`
/// 2. Email (`user@example.com`) => `example.com`
/// 3. Bare identifier (`my-bucket`) => `my-bucket` (returned as-is)
///
/// Port numbers are stripped: `api.com:8443` => `api.com`.
fn extract_host(target: &str) -> &str {
    // 1. Try URL parse (covers http://, https://, etc.)
    if let Ok(parsed) = Url::parse(target) {
        if let Some(host) = parsed.host_str() {
            // Return a slice from the original string to avoid allocation.
            // Url::parse guarantees host_str is a substring of the input.
            if let Some(start) = target.find(host) {
                return &target[start..start + host.len()];
            }
        }
    }

    // 2. Try email: take domain after the last '@'.
    if let Some(at_pos) = target.rfind('@') {
        let domain = &target[at_pos + 1..];
        // Strip port if present (user@host:587).
        return domain.split(':').next().unwrap_or(domain);
    }

    // 3. Bare identifier: strip port if present.
    target.split(':').next().unwrap_or(target)
}

// Host allowlist matching — shared matcher

/// Test whether `host` matches any entry in `allowlist_lower` by exact or
/// subdomain match, with a literal `.` boundary.
///
/// `allowlist_lower` MUST already be ASCII-lowercased — the matcher does
/// not re-lower entries on every call. Callers that hold a static allowlist
/// (e.g. [`HostState::allowed_sinks_lower`]) pre-lower once; callers with a
/// dynamic allowlist pass it through [`latchgate_core::net::lowercase_allowlist`] at their
/// boundary.
///
/// # Boundary rule
///
/// - Exact match: `"api.github.com"` matches `"api.github.com"`.
/// - Subdomain match: `"github.com"` matches `"api.github.com"` because
///   the character immediately preceding the suffix is a literal `.`.
/// - NOT a match: `"api.com"` does NOT match `"evil-api.com"` — the byte
///   before the suffix is `-`, not `.`.
///
/// # SECURITY
///
/// Check whether `host` matches any entry in a pre-lowercased allowlist.
///
/// Delegates to [`latchgate_core::net::host_matches_allowlist_lower`] —
/// the single source of truth for host allowlist matching.
pub fn host_matches_allowlist_lower(host: &str, allowlist_lower: &[String]) -> bool {
    latchgate_core::net::host_matches_allowlist_lower(host, allowlist_lower)
}

// Log message truncation

/// Find the largest byte offset ≤ `max_bytes` that is a valid UTF-8 char
/// boundary. Avoids splitting multi-byte characters.
fn truncate_at_char_boundary(s: &str, max_bytes: usize) -> usize {
    if max_bytes >= s.len() {
        return s.len();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    end
}

// URL redaction for logs / errors / audit

/// Produce a log-safe representation of a URL: `scheme://host[:port]/…`.
///
/// Strips query string, fragment, and userinfo (all of which may contain
/// tokens, passwords, or signed parameters). The path is replaced with
/// `/…` to avoid leaking internal API routes or object IDs in logs.
///
/// Non-URL targets (emails, bare identifiers) are returned as-is — they
/// do not carry query/userinfo components.
pub(crate) fn safe_url_for_log(target: &str) -> std::borrow::Cow<'_, str> {
    if let Ok(parsed) = Url::parse(target) {
        let host = parsed.host_str().unwrap_or("?");
        let port_suffix = match parsed.port() {
            Some(p) => format!(":{p}"),
            None => String::new(),
        };
        std::borrow::Cow::Owned(format!("{}://{}{}/…", parsed.scheme(), host, port_suffix))
    } else {
        // Not a URL (email address, bare identifier, etc.) — return as-is.
        std::borrow::Cow::Borrowed(target)
    }
}

// Credential header blocklist

/// Headers that only the host layer may set. Provider-supplied values for
/// these headers are stripped before the request is built, and host-injected
/// credentials are added afterwards. This prevents a provider from
/// overriding, duplicating, or exfiltrating credentials via the header map.
const CREDENTIAL_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-amz-security-token",
    "x-amz-session-token",
];

/// Return `true` if the given header name (case-insensitive) is in the
/// credential blocklist and must not be set by providers.
pub(crate) fn is_credential_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    CREDENTIAL_HEADERS.iter().any(|&h| h == lower)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consume_io_call_within_budget() {
        let state = HostState::new(HostStateConfig {
            allowed_sinks: vec![],
            approved_secrets: vec![],
            decrypted_secrets: HashMap::new(),
            trace_id: "t".into(),
            max_io_calls: 3,
            max_host_response_bytes: 10 * 1024 * 1024,
            allowed_imports: vec![],
            database_config: None,
            egress_proxy_url: None,
            max_log_calls: None,
            max_log_message_bytes: None,
            fs_config: None,
        });
        assert_eq!(state.consume_io_call().unwrap(), 1);
        assert_eq!(state.consume_io_call().unwrap(), 2);
        assert_eq!(state.consume_io_call().unwrap(), 3);
        assert!(state.consume_io_call().is_err());
        assert_eq!(state.io_calls_count(), 3);
    }

    // -- URL-based sink validation ----------------------------------------

    #[test]
    fn validate_sink_allows_exact_domain_in_url() {
        let state = HostState::new(HostStateConfig {
            allowed_sinks: vec!["api.github.com".into(), "httpbin.org".into()],
            approved_secrets: vec![],
            decrypted_secrets: HashMap::new(),
            trace_id: "t".into(),
            max_io_calls: 10,
            max_host_response_bytes: 10 * 1024 * 1024,
            allowed_imports: vec![],
            database_config: None,
            egress_proxy_url: None,
            max_log_calls: None,
            max_log_message_bytes: None,
            fs_config: None,
        });
        assert!(state.validate_sink("https://api.github.com/repos").is_ok());
        assert!(state.validate_sink("https://httpbin.org/get").is_ok());
    }

    #[test]
    fn validate_sink_allows_subdomain_match() {
        let state = HostState::new(HostStateConfig {
            allowed_sinks: vec!["github.com".into()],
            approved_secrets: vec![],
            decrypted_secrets: HashMap::new(),
            trace_id: "t".into(),
            max_io_calls: 10,
            max_host_response_bytes: 10 * 1024 * 1024,
            allowed_imports: vec![],
            database_config: None,
            egress_proxy_url: None,
            max_log_calls: None,
            max_log_message_bytes: None,
            fs_config: None,
        });
        assert!(state.validate_sink("https://api.github.com/repos").is_ok());
        assert!(state.validate_sink("https://raw.github.com/file").is_ok());
        assert!(state.validate_sink("https://github.com/org/repo").is_ok());
    }

    #[test]
    fn validate_sink_rejects_unknown() {
        let state = HostState::new(HostStateConfig {
            allowed_sinks: vec!["api.github.com".into()],
            approved_secrets: vec![],
            decrypted_secrets: HashMap::new(),
            trace_id: "t".into(),
            max_io_calls: 10,
            max_host_response_bytes: 10 * 1024 * 1024,
            allowed_imports: vec![],
            database_config: None,
            egress_proxy_url: None,
            max_log_calls: None,
            max_log_message_bytes: None,
            fs_config: None,
        });
        assert!(state.validate_sink("https://evil.com/steal").is_err());
    }

    /// SECURITY: The old substring-contains approach allowed `evil-api.com`
    /// to match an allowed sink of `api.com`. Domain matching prevents this.
    #[test]
    fn validate_sink_rejects_substring_spoof() {
        let state = HostState::new(HostStateConfig {
            allowed_sinks: vec!["api.com".into()],
            approved_secrets: vec![],
            decrypted_secrets: HashMap::new(),
            trace_id: "t".into(),
            max_io_calls: 10,
            max_host_response_bytes: 10 * 1024 * 1024,
            allowed_imports: vec![],
            database_config: None,
            egress_proxy_url: None,
            max_log_calls: None,
            max_log_message_bytes: None,
            fs_config: None,
        });
        // "evil-api.com" contains "api.com" but is NOT a subdomain of api.com.
        assert!(
            state.validate_sink("https://evil-api.com/steal").is_err(),
            "substring spoof must be rejected"
        );
        // "notapi.com" also contains "api.com" as a substring.
        assert!(
            state.validate_sink("https://notapi.com/data").is_err(),
            "prefix-glued domain must be rejected"
        );
        // Legitimate subdomain still works.
        assert!(state.validate_sink("https://sub.api.com/ok").is_ok());
    }

    #[test]
    fn validate_sink_case_insensitive() {
        let state = HostState::new(HostStateConfig {
            allowed_sinks: vec!["API.GitHub.COM".into()],
            approved_secrets: vec![],
            decrypted_secrets: HashMap::new(),
            trace_id: "t".into(),
            max_io_calls: 10,
            max_host_response_bytes: 10 * 1024 * 1024,
            allowed_imports: vec![],
            database_config: None,
            egress_proxy_url: None,
            max_log_calls: None,
            max_log_message_bytes: None,
            fs_config: None,
        });
        assert!(state.validate_sink("https://api.github.com/repos").is_ok());
    }

    // -- host_matches_allowlist_lower: direct matcher contract -----------

    #[test]
    fn matcher_exact_match() {
        let list = vec!["api.github.com".to_string()];
        assert!(super::host_matches_allowlist_lower("api.github.com", &list));
    }

    #[test]
    fn matcher_subdomain_match_with_dot_boundary() {
        let list = vec!["github.com".to_string()];
        assert!(super::host_matches_allowlist_lower("api.github.com", &list));
        assert!(super::host_matches_allowlist_lower(
            "raw.githubusercontent.github.com",
            &list
        ));
    }

    /// SECURITY: substring-spoof guard. The old matcher allowed
    /// `evil-api.com` to satisfy `api.com`; the dot-boundary rule rules it
    /// out. Pinned here so any refactor that breaks it fails this test
    /// before it can reach the pre-check or runtime paths.
    #[test]
    fn matcher_rejects_substring_spoof() {
        let list = vec!["api.com".to_string()];
        assert!(!super::host_matches_allowlist_lower("evil-api.com", &list));
        assert!(!super::host_matches_allowlist_lower("notapi.com", &list));
    }

    #[test]
    fn matcher_is_ascii_case_insensitive_on_host_side() {
        // Allowlist is pre-lowered by contract; caller's responsibility.
        // The matcher lowers the host input on every call.
        let list = vec!["github.com".to_string()];
        assert!(super::host_matches_allowlist_lower("API.GitHub.COM", &list));
    }

    #[test]
    fn matcher_rejects_on_empty_allowlist() {
        assert!(!super::host_matches_allowlist_lower("anything.com", &[]));
    }

    #[test]
    fn matcher_rejects_empty_host() {
        let list = vec!["api.github.com".to_string()];
        assert!(!super::host_matches_allowlist_lower("", &list));
    }

    /// SECURITY: an empty string slipping into the allowlist (e.g. via a
    /// malformed manifest or a migration bug) must not match every host.
    /// Regression guard on the subdomain boundary arithmetic.
    #[test]
    fn matcher_rejects_empty_entry() {
        let list = vec!["".to_string()];
        assert!(!super::host_matches_allowlist_lower("example.com", &list));
    }

    // -- Email-based sink validation --------------------------------------

    #[test]
    fn validate_sink_email_domain_match() {
        let state = HostState::new(HostStateConfig {
            allowed_sinks: vec!["example.com".into()],
            approved_secrets: vec![],
            decrypted_secrets: HashMap::new(),
            trace_id: "t".into(),
            max_io_calls: 10,
            max_host_response_bytes: 10 * 1024 * 1024,
            allowed_imports: vec![],
            database_config: None,
            egress_proxy_url: None,
            max_log_calls: None,
            max_log_message_bytes: None,
            fs_config: None,
        });
        assert!(state.validate_sink("user@example.com").is_ok());
        assert!(state.validate_sink("user@mail.example.com").is_ok());
        assert!(state.validate_sink("user@evil-example.com").is_err());
    }

    // -- Bare identifier sink validation ----------------------------------

    #[test]
    fn validate_sink_bare_identifier_exact() {
        let state = HostState::new(HostStateConfig {
            allowed_sinks: vec!["my-bucket".into(), "order-events".into()],
            approved_secrets: vec![],
            decrypted_secrets: HashMap::new(),
            trace_id: "t".into(),
            max_io_calls: 10,
            max_host_response_bytes: 10 * 1024 * 1024,
            allowed_imports: vec![],
            database_config: None,
            egress_proxy_url: None,
            max_log_calls: None,
            max_log_message_bytes: None,
            fs_config: None,
        });
        assert!(state.validate_sink("my-bucket").is_ok());
        assert!(state.validate_sink("order-events").is_ok());
        assert!(state.validate_sink("other-bucket").is_err());
    }

    // -- extract_host unit tests ------------------------------------------

    #[test]
    fn extract_host_from_url() {
        assert_eq!(
            extract_host("https://api.github.com/repos"),
            "api.github.com"
        );
        assert_eq!(extract_host("http://localhost:8080/path"), "localhost");
        assert_eq!(extract_host("https://example.com"), "example.com");
    }

    #[test]
    fn extract_host_from_email() {
        assert_eq!(extract_host("user@example.com"), "example.com");
        assert_eq!(extract_host("admin@mail.corp.co"), "mail.corp.co");
    }

    #[test]
    fn extract_host_bare_identifier() {
        assert_eq!(extract_host("my-bucket"), "my-bucket");
        assert_eq!(extract_host("order-events"), "order-events");
    }

    // -- Import gating -------------------------------------------------------

    #[test]
    fn check_import_allowed_permits_declared_interface() {
        let state = HostState::new(HostStateConfig {
            allowed_sinks: vec![],
            approved_secrets: vec![],
            decrypted_secrets: HashMap::new(),
            trace_id: "t".into(),
            max_io_calls: 10,
            max_host_response_bytes: 10 * 1024 * 1024,
            allowed_imports: vec!["latchgate:io/http".into(), "latchgate:io/smtp".into()],
            database_config: None,
            egress_proxy_url: None,
            max_log_calls: None,
            max_log_message_bytes: None,
            fs_config: None,
        });
        assert!(state.check_import_allowed("latchgate:io/http").is_ok());
        assert!(state.check_import_allowed("latchgate:io/smtp").is_ok());
    }

    #[test]
    fn check_import_allowed_rejects_undeclared_interface() {
        let state = HostState::new(HostStateConfig {
            allowed_sinks: vec![],
            approved_secrets: vec![],
            decrypted_secrets: HashMap::new(),
            trace_id: "t".into(),
            max_io_calls: 10,
            max_host_response_bytes: 10 * 1024 * 1024,
            allowed_imports: vec!["latchgate:io/smtp".into()],
            database_config: None,
            egress_proxy_url: None,
            max_log_calls: None,
            max_log_message_bytes: None,
            fs_config: None,
        });
        // Provider declared smtp but not http — cannot use http.
        let err = state.check_import_allowed("latchgate:io/http");
        assert!(err.is_err());
        let msg = err.unwrap_err().to_string();
        assert!(msg.contains("latchgate:io/http"));
        assert!(msg.contains("not declared"));
    }

    #[test]
    fn check_import_log_rejected_when_not_declared() {
        // Log is gated like any other import — undeclared providers cannot
        // use it as an unaudited egress channel.
        let state = HostState::new(HostStateConfig {
            allowed_sinks: vec![],
            approved_secrets: vec![],
            decrypted_secrets: HashMap::new(),
            trace_id: "t".into(),
            max_io_calls: 10,
            max_host_response_bytes: 10 * 1024 * 1024,
            allowed_imports: vec![],
            database_config: None,
            egress_proxy_url: None,
            max_log_calls: None,
            max_log_message_bytes: None,
            fs_config: None,
        });
        assert!(
            state.check_import_allowed("latchgate:io/log").is_err(),
            "log must be rejected when not in allowed_imports"
        );
    }

    #[test]
    fn check_import_log_allowed_when_declared() {
        let state = HostState::new(HostStateConfig {
            allowed_sinks: vec![],
            approved_secrets: vec![],
            decrypted_secrets: HashMap::new(),
            trace_id: "t".into(),
            max_io_calls: 10,
            max_host_response_bytes: 10 * 1024 * 1024,
            allowed_imports: vec!["latchgate:io/log".into()],
            database_config: None,
            egress_proxy_url: None,
            max_log_calls: None,
            max_log_message_bytes: None,
            fs_config: None,
        });
        assert!(
            state.check_import_allowed("latchgate:io/log").is_ok(),
            "log must be allowed when declared in required_imports"
        );
    }

    #[test]
    fn check_import_rejects_all_when_no_imports_declared() {
        let state = HostState::new(HostStateConfig {
            allowed_sinks: vec![],
            approved_secrets: vec![],
            decrypted_secrets: HashMap::new(),
            trace_id: "t".into(),
            max_io_calls: 10,
            max_host_response_bytes: 10 * 1024 * 1024,
            allowed_imports: vec![],
            database_config: None,
            egress_proxy_url: None,
            max_log_calls: None,
            max_log_message_bytes: None,
            fs_config: None,
        });
        for iface in &[
            "latchgate:io/http",
            "latchgate:io/smtp",
            "latchgate:io/database",
            "latchgate:io/queue",
            "latchgate:io/storage",
        ] {
            assert!(
                state.check_import_allowed(iface).is_err(),
                "{iface} must be rejected when required_imports is empty"
            );
        }
    }

    // -- Empty sinks list (deny-all) --------------------------------------

    #[test]
    fn validate_sink_empty_sinks_rejects_all() {
        let state = HostState::new(HostStateConfig {
            allowed_sinks: vec![],
            approved_secrets: vec![],
            decrypted_secrets: HashMap::new(),
            trace_id: "t".into(),
            max_io_calls: 10,
            max_host_response_bytes: 10 * 1024 * 1024,
            allowed_imports: vec![],
            database_config: None,
            egress_proxy_url: None,
            max_log_calls: None,
            max_log_message_bytes: None,
            fs_config: None,
        });
        assert!(state.validate_sink("https://anything.com").is_err());
    }

    // Host I/O conformance — import gating, sink validation, budget, secrets

    fn conformance_state(sinks: Vec<&str>, imports: Vec<&str>) -> HostState {
        HostState::new(HostStateConfig {
            allowed_sinks: sinks.into_iter().map(Arc::from).collect(),
            approved_secrets: vec![],
            decrypted_secrets: HashMap::new(),
            trace_id: "conformance-test".into(),
            max_io_calls: 10,
            max_host_response_bytes: 10 * 1024 * 1024,
            allowed_imports: imports.into_iter().map(Arc::from).collect(),
            database_config: None,
            egress_proxy_url: None,
            max_log_calls: None,
            max_log_message_bytes: None,
            fs_config: None,
        })
    }

    fn conformance_state_with_secrets(
        sinks: Vec<&str>,
        imports: Vec<&str>,
        approved: Vec<&str>,
        secrets: Vec<(&str, &str)>,
    ) -> HostState {
        let decrypted: HashMap<String, Zeroizing<String>> = secrets
            .into_iter()
            .map(|(k, v)| (k.to_string(), Zeroizing::new(v.to_string())))
            .collect();
        HostState::new(HostStateConfig {
            allowed_sinks: sinks.into_iter().map(Arc::from).collect(),
            approved_secrets: approved.into_iter().map(Arc::from).collect(),
            decrypted_secrets: decrypted,
            trace_id: "conformance-test".into(),
            max_io_calls: 10,
            max_host_response_bytes: 10 * 1024 * 1024,
            allowed_imports: imports.into_iter().map(Arc::from).collect(),
            database_config: None,
            egress_proxy_url: None,
            max_log_calls: None,
            max_log_message_bytes: None,
            fs_config: None,
        })
    }

    // -- Import gating --

    #[test]
    fn http_import_gated_when_not_declared() {
        let s = conformance_state(vec!["api.example.com"], vec![]);
        let err = s.check_import_allowed("latchgate:io/http").unwrap_err();
        assert!(
            err.to_string().contains("latchgate:io/http"),
            "error must name the interface: {err}"
        );
    }

    #[test]
    fn http_import_allowed_when_declared() {
        let s = conformance_state(vec![], vec!["latchgate:io/http"]);
        assert!(s.check_import_allowed("latchgate:io/http").is_ok());
    }

    #[test]
    fn smtp_import_gated_when_not_declared() {
        let s = conformance_state(vec![], vec![]);
        assert!(s.check_import_allowed("latchgate:io/smtp").is_err());
    }

    #[test]
    fn smtp_import_allowed_when_declared() {
        let s = conformance_state(vec![], vec!["latchgate:io/smtp"]);
        assert!(s.check_import_allowed("latchgate:io/smtp").is_ok());
    }

    #[test]
    fn database_import_gated_when_not_declared() {
        let s = conformance_state(vec![], vec![]);
        assert!(s.check_import_allowed("latchgate:io/database").is_err());
    }

    #[test]
    fn database_import_allowed_when_declared() {
        let s = conformance_state(vec![], vec!["latchgate:io/database"]);
        assert!(s.check_import_allowed("latchgate:io/database").is_ok());
    }

    #[test]
    fn queue_import_gated_when_not_declared() {
        let s = conformance_state(vec![], vec![]);
        assert!(s.check_import_allowed("latchgate:io/queue").is_err());
    }

    #[test]
    fn queue_import_allowed_when_declared() {
        let s = conformance_state(vec![], vec!["latchgate:io/queue"]);
        assert!(s.check_import_allowed("latchgate:io/queue").is_ok());
    }

    #[test]
    fn storage_import_gated_when_not_declared() {
        let s = conformance_state(vec![], vec![]);
        assert!(s.check_import_allowed("latchgate:io/storage").is_err());
    }

    #[test]
    fn storage_import_allowed_when_declared() {
        let s = conformance_state(vec![], vec!["latchgate:io/storage"]);
        assert!(s.check_import_allowed("latchgate:io/storage").is_ok());
    }

    #[test]
    fn log_import_rejected_when_not_declared() {
        let s = conformance_state(vec![], vec![]);
        assert!(
            s.check_import_allowed("latchgate:io/log").is_err(),
            "latchgate:io/log must be rejected when not in allowed_imports"
        );
    }

    #[test]
    fn log_import_allowed_when_declared() {
        let s = conformance_state(vec![], vec!["latchgate:io/log"]);
        assert!(
            s.check_import_allowed("latchgate:io/log").is_ok(),
            "latchgate:io/log must be allowed when declared"
        );
    }

    #[test]
    fn import_grants_are_independent() {
        let s = conformance_state(vec![], vec!["latchgate:io/http"]);
        assert!(s.check_import_allowed("latchgate:io/http").is_ok());
        assert!(s.check_import_allowed("latchgate:io/smtp").is_err());
        assert!(s.check_import_allowed("latchgate:io/database").is_err());
        assert!(s.check_import_allowed("latchgate:io/queue").is_err());
        assert!(s.check_import_allowed("latchgate:io/storage").is_err());
    }

    // -- Sink validation (per interface) --

    #[test]
    fn http_sink_validation_allows_declared_host() {
        let s = conformance_state(vec!["api.example.com"], vec!["latchgate:io/http"]);
        assert!(s.validate_sink("https://api.example.com/v1/orders").is_ok());
    }

    #[test]
    fn http_sink_validation_rejects_undeclared_host() {
        let s = conformance_state(vec!["api.example.com"], vec!["latchgate:io/http"]);
        assert!(s.validate_sink("https://evil.com/exfiltrate").is_err());
    }

    #[test]
    fn http_sink_validation_allows_subdomain_of_declared() {
        let s = conformance_state(vec!["example.com"], vec!["latchgate:io/http"]);
        assert!(s.validate_sink("https://api.example.com/path").is_ok());
        assert!(s.validate_sink("https://v2.api.example.com/path").is_ok());
    }

    #[test]
    fn http_sink_validation_rejects_substring_match() {
        let s = conformance_state(vec!["example.com"], vec!["latchgate:io/http"]);
        assert!(s.validate_sink("https://notexample.com/path").is_err());
    }

    #[test]
    fn smtp_sink_validation_allows_declared_domain() {
        let s = conformance_state(vec!["example.com"], vec!["latchgate:io/smtp"]);
        assert!(s.validate_sink("user@example.com").is_ok());
    }

    #[test]
    fn smtp_sink_validation_rejects_undeclared_domain() {
        let s = conformance_state(vec!["example.com"], vec!["latchgate:io/smtp"]);
        assert!(s.validate_sink("attacker@evil.com").is_err());
    }

    #[test]
    fn queue_sink_validation_allows_declared_queue() {
        let s = conformance_state(vec!["order-events"], vec!["latchgate:io/queue"]);
        assert!(s.validate_sink("order-events").is_ok());
    }

    #[test]
    fn queue_sink_validation_rejects_undeclared_queue() {
        let s = conformance_state(vec!["order-events"], vec!["latchgate:io/queue"]);
        assert!(s.validate_sink("all-secrets-queue").is_err());
    }

    #[test]
    fn storage_sink_validation_allows_declared_bucket() {
        let s = conformance_state(vec!["artifacts-prod"], vec!["latchgate:io/storage"]);
        assert!(s.validate_sink("artifacts-prod").is_ok());
    }

    #[test]
    fn storage_sink_validation_rejects_undeclared_bucket() {
        let s = conformance_state(vec!["artifacts-prod"], vec!["latchgate:io/storage"]);
        assert!(s.validate_sink("exfil-bucket").is_err());
    }

    #[test]
    fn empty_sinks_denies_all() {
        let s = conformance_state(vec![], vec!["latchgate:io/http"]);
        assert!(s.validate_sink("https://anywhere.com").is_err());
    }

    // -- Budget enforcement --

    #[test]
    fn io_budget_exhaustion_denies_further_calls() {
        let s = HostState::new(HostStateConfig {
            allowed_sinks: vec![],
            approved_secrets: vec![],
            decrypted_secrets: HashMap::new(),
            trace_id: "budget-test".into(),
            max_io_calls: 2,
            max_host_response_bytes: 10 * 1024 * 1024,
            allowed_imports: vec![],
            database_config: None,
            egress_proxy_url: None,
            max_log_calls: None,
            max_log_message_bytes: None,
            fs_config: None,
        });
        assert!(s.consume_io_call().is_ok());
        assert!(s.consume_io_call().is_ok());
        assert!(s.consume_io_call().is_err());
        assert_eq!(s.io_calls_count(), 2);
    }

    #[test]
    fn io_budget_zero_denies_immediately() {
        let s = HostState::new(HostStateConfig {
            allowed_sinks: vec![],
            approved_secrets: vec![],
            decrypted_secrets: HashMap::new(),
            trace_id: "zero-budget".into(),
            max_io_calls: 0,
            max_host_response_bytes: 10 * 1024 * 1024,
            allowed_imports: vec![],
            database_config: None,
            egress_proxy_url: None,
            max_log_calls: None,
            max_log_message_bytes: None,
            fs_config: None,
        });
        assert!(
            s.consume_io_call().is_err(),
            "zero budget must deny the first call"
        );
        assert_eq!(s.io_calls_count(), 0);
    }

    #[test]
    fn io_budget_count_increments_on_each_call() {
        let s = HostState::new(HostStateConfig {
            allowed_sinks: vec![],
            approved_secrets: vec![],
            decrypted_secrets: HashMap::new(),
            trace_id: "count-test".into(),
            max_io_calls: 5,
            max_host_response_bytes: 10 * 1024 * 1024,
            allowed_imports: vec![],
            database_config: None,
            egress_proxy_url: None,
            max_log_calls: None,
            max_log_message_bytes: None,
            fs_config: None,
        });
        for expected in 1..=5u32 {
            assert!(s.consume_io_call().is_ok());
            assert_eq!(s.io_calls_count(), expected);
        }
    }

    // -- Credential gate --

    #[test]
    fn secret_not_in_approved_list_returns_none() {
        let s = conformance_state_with_secrets(
            vec![],
            vec![],
            vec!["API_KEY"],
            vec![("DB_PASS", "s3cr3t"), ("API_KEY", "tok_123")],
        );
        assert_eq!(s.get_secret("API_KEY"), Some("tok_123"));
        assert_eq!(
            s.get_secret("DB_PASS"),
            None,
            "unapproved secret must not be readable even if present in decrypted map"
        );
    }

    #[test]
    fn secret_absent_from_decrypted_map_returns_none() {
        let s = conformance_state_with_secrets(vec![], vec![], vec!["MISSING_KEY"], vec![]);
        assert_eq!(s.get_secret("MISSING_KEY"), None);
    }

    #[test]
    fn empty_approved_list_blocks_all_secrets() {
        let s = conformance_state_with_secrets(
            vec![],
            vec![],
            vec![],
            vec![("SMTP_PASS", "hunter2"), ("AWS_SECRET", "aws_key")],
        );
        assert_eq!(s.get_secret("SMTP_PASS"), None);
        assert_eq!(s.get_secret("AWS_SECRET"), None);
    }

    #[test]
    fn multiple_approved_secrets_all_accessible() {
        let s = conformance_state_with_secrets(
            vec![],
            vec![],
            vec!["KEY_A", "KEY_B", "KEY_C"],
            vec![("KEY_A", "val_a"), ("KEY_B", "val_b"), ("KEY_C", "val_c")],
        );
        assert_eq!(s.get_secret("KEY_A"), Some("val_a"));
        assert_eq!(s.get_secret("KEY_B"), Some("val_b"));
        assert_eq!(s.get_secret("KEY_C"), Some("val_c"));
    }

    // -- Immutable sink validation --

    #[test]
    fn sink_validation_is_immutable_after_construction() {
        let s = conformance_state(vec!["safe.example.com"], vec!["latchgate:io/http"]);
        assert!(s.validate_sink("https://safe.example.com/api").is_ok());
        assert!(s.validate_sink("https://evil.com/exfil").is_err());
        assert!(s.validate_sink("https://safe.example.com/other").is_ok());
        assert!(s.validate_sink("https://evil.com/exfil").is_err());
    }

    #[test]
    fn no_sinks_blocks_all_interfaces() {
        for iface in [
            "latchgate:io/http",
            "latchgate:io/smtp",
            "latchgate:io/database",
            "latchgate:io/queue",
            "latchgate:io/storage",
        ] {
            let s = conformance_state(vec![], vec![iface]);
            assert!(
                s.validate_sink("anything").is_err(),
                "empty sinks must block all targets for {iface}"
            );
        }
    }

    #[test]
    fn secret_access_only_through_gated_getter() {
        let s = conformance_state_with_secrets(
            vec![],
            vec![],
            vec!["ONLY_THIS"],
            vec![
                ("ONLY_THIS", "allowed_value"),
                ("HIDDEN_A", "secret_a"),
                ("HIDDEN_B", "secret_b"),
            ],
        );
        assert_eq!(s.get_secret("ONLY_THIS"), Some("allowed_value"));
        assert_eq!(s.get_secret("HIDDEN_A"), None);
        assert_eq!(s.get_secret("HIDDEN_B"), None);
        assert_eq!(s.get_secret("NONEXISTENT"), None);
    }

    #[test]
    fn approved_but_undecrypted_secret_returns_none() {
        let s = conformance_state_with_secrets(
            vec![],
            vec![],
            vec!["APPROVED_BUT_MISSING"],
            vec![("OTHER_KEY", "val")],
        );
        assert_eq!(
            s.get_secret("APPROVED_BUT_MISSING"),
            None,
            "approved but undecrypted secret must return None"
        );
    }

    #[test]
    fn all_three_gates_enforced_independently() {
        let s = HostState::new(HostStateConfig {
            allowed_sinks: vec!["safe.com".into()],
            approved_secrets: vec![],
            decrypted_secrets: HashMap::new(),
            trace_id: "triple-gate".into(),
            max_io_calls: 1,
            max_host_response_bytes: 10 * 1024 * 1024,
            allowed_imports: vec!["latchgate:io/http".into()],
            database_config: None,
            egress_proxy_url: None,
            max_log_calls: None,
            max_log_message_bytes: None,
            fs_config: None,
        });
        assert!(s.check_import_allowed("latchgate:io/http").is_ok());
        assert!(s.validate_sink("https://evil.com").is_err());
        assert!(s.validate_sink("https://safe.com/api").is_ok());
        assert!(s.consume_io_call().is_ok());
        assert!(s.consume_io_call().is_err());
    }

    // safe_url_for_log — URL redaction

    #[test]
    fn safe_url_strips_query_and_fragment() {
        let redacted = safe_url_for_log("https://api.example.com/v1/users?token=SECRET#frag");
        assert_eq!(redacted, "https://api.example.com/…");
    }

    #[test]
    fn safe_url_strips_userinfo() {
        let redacted = safe_url_for_log("https://user:pass@api.example.com/path");
        assert_eq!(redacted, "https://api.example.com/…");
    }

    #[test]
    fn safe_url_preserves_non_default_port() {
        let redacted = safe_url_for_log("https://api.example.com:8443/v1?key=SECRET");
        assert_eq!(redacted, "https://api.example.com:8443/…");
    }

    #[test]
    fn safe_url_passes_through_non_url_targets() {
        assert_eq!(safe_url_for_log("user@example.com"), "user@example.com");
        assert_eq!(safe_url_for_log("my-bucket"), "my-bucket");
    }

    #[test]
    fn safe_url_does_not_leak_signed_url_params() {
        let signed = "https://storage.example.com/obj?X-Amz-Credential=AKIA&X-Amz-Signature=abc";
        let redacted = safe_url_for_log(signed);
        assert!(
            !redacted.contains("AKIA"),
            "signed URL credential leaked: {redacted}"
        );
        assert!(
            !redacted.contains("Signature"),
            "signed URL signature leaked: {redacted}"
        );
    }

    // is_credential_header — blocklist

    #[test]
    fn credential_headers_detected_case_insensitive() {
        assert!(is_credential_header("Authorization"));
        assert!(is_credential_header("AUTHORIZATION"));
        assert!(is_credential_header("authorization"));
        assert!(is_credential_header("Cookie"));
        assert!(is_credential_header("Proxy-Authorization"));
        assert!(is_credential_header("X-Api-Key"));
        assert!(is_credential_header("X-Amz-Security-Token"));
        assert!(is_credential_header("X-Amz-Session-Token"));
    }

    #[test]
    fn non_credential_headers_allowed() {
        assert!(!is_credential_header("Content-Type"));
        assert!(!is_credential_header("Accept"));
        assert!(!is_credential_header("User-Agent"));
        assert!(!is_credential_header("X-Request-Id"));
    }

    // extract_host — boundary cases

    #[test]
    fn extract_host_strips_port_from_bare_host() {
        assert_eq!(extract_host("api.example.com:8443"), "api.example.com");
    }

    #[test]
    fn extract_host_url_with_explicit_port() {
        assert_eq!(
            extract_host("https://api.example.com:8443/path"),
            "api.example.com"
        );
    }

    #[test]
    fn extract_host_ipv6_url() {
        assert_eq!(extract_host("https://[::1]:443/path"), "[::1]");
    }

    #[test]
    fn extract_host_email_with_port() {
        assert_eq!(
            extract_host("user@smtp.example.com:587"),
            "smtp.example.com"
        );
    }

    #[test]
    fn extract_host_empty_string() {
        assert_eq!(extract_host(""), "");
    }

    // host_matches_allowlist_lower — boundary hardening

    #[test]
    fn matcher_trailing_dot_does_not_bypass() {
        // DNS trailing dot must not fool the matcher into accepting
        // a host that isn't in the allowlist.
        let list = vec!["api.com".to_string()];
        assert!(!host_matches_allowlist_lower("api.com.", &list));
    }

    #[test]
    fn matcher_single_label_host_no_false_positive() {
        // "com" in allowlist must not match "example.com".
        let list = vec!["com".to_string()];
        // "example.com" ends with "com" and the byte before is '.',
        // so this WOULD match the subdomain rule. This is intentional:
        // putting a TLD in the allowlist permits all subdomains of that
        // TLD. Operators should never allowlist bare TLDs.
        assert!(host_matches_allowlist_lower("example.com", &list));
    }

    #[test]
    fn matcher_host_equals_entry_length_plus_one() {
        // Boundary: host is exactly 1 char longer than entry.
        // "x.a" vs allowlist "a" — the byte before "a" is '.', match.
        let list = vec!["a".to_string()];
        assert!(host_matches_allowlist_lower("x.a", &list));
    }

    #[test]
    fn matcher_host_one_char_shorter_than_entry_no_panic() {
        let list = vec!["long-domain.example.com".to_string()];
        assert!(!host_matches_allowlist_lower("x.com", &list));
    }

    // safe_url_for_log — additional edge cases

    #[test]
    fn safe_url_ipv6_host() {
        let redacted = safe_url_for_log("https://[2001:db8::1]:443/secret");
        assert_eq!(redacted, "https://[2001:db8::1]/…");
    }

    #[test]
    fn safe_url_http_scheme() {
        let redacted = safe_url_for_log("http://api.example.com/data?key=val");
        assert_eq!(redacted, "http://api.example.com/…");
    }

    // -- has_credential_secrets ---------------------------------------------

    #[test]
    fn has_credential_secrets_true_when_bearer_present() {
        let state = HostState::new(HostStateConfig {
            allowed_sinks: vec![],
            approved_secrets: vec!["BEARER_TOKEN".into()],
            decrypted_secrets: HashMap::from([(
                "BEARER_TOKEN".to_string(),
                Zeroizing::new("tok-123".to_string()),
            )]),
            trace_id: "t".into(),
            max_io_calls: 10,
            max_host_response_bytes: 1_000_000,
            allowed_imports: vec![],
            database_config: None,
            egress_proxy_url: None,
            max_log_calls: None,
            max_log_message_bytes: None,
            fs_config: None,
        });
        assert!(state.has_credential_secrets());
    }

    #[test]
    fn has_credential_secrets_true_when_api_key_present() {
        let state = HostState::new(HostStateConfig {
            allowed_sinks: vec![],
            approved_secrets: vec!["API_KEY".into()],
            decrypted_secrets: HashMap::from([(
                "API_KEY".to_string(),
                Zeroizing::new("key-abc".to_string()),
            )]),
            trace_id: "t".into(),
            max_io_calls: 10,
            max_host_response_bytes: 1_000_000,
            allowed_imports: vec![],
            database_config: None,
            egress_proxy_url: None,
            max_log_calls: None,
            max_log_message_bytes: None,
            fs_config: None,
        });
        assert!(state.has_credential_secrets());
    }

    #[test]
    fn has_credential_secrets_false_when_no_secrets() {
        let state = HostState::new(HostStateConfig {
            allowed_sinks: vec![],
            approved_secrets: vec![],
            decrypted_secrets: HashMap::new(),
            trace_id: "t".into(),
            max_io_calls: 10,
            max_host_response_bytes: 1_000_000,
            allowed_imports: vec![],
            database_config: None,
            egress_proxy_url: None,
            max_log_calls: None,
            max_log_message_bytes: None,
            fs_config: None,
        });
        assert!(!state.has_credential_secrets());
    }

    #[test]
    fn has_credential_secrets_false_when_only_non_credential_secrets() {
        let state = HostState::new(HostStateConfig {
            allowed_sinks: vec![],
            approved_secrets: vec!["DATABASE_URL".into()],
            decrypted_secrets: HashMap::from([(
                "DATABASE_URL".to_string(),
                Zeroizing::new("postgres://...".to_string()),
            )]),
            trace_id: "t".into(),
            max_io_calls: 10,
            max_host_response_bytes: 1_000_000,
            allowed_imports: vec![],
            database_config: None,
            egress_proxy_url: None,
            max_log_calls: None,
            max_log_message_bytes: None,
            fs_config: None,
        });
        assert!(!state.has_credential_secrets());
    }

    #[test]
    fn has_credential_secrets_false_when_approved_but_not_decrypted() {
        // Secret declared in manifest but not present in SOPS file.
        let state = HostState::new(HostStateConfig {
            allowed_sinks: vec![],
            approved_secrets: vec!["BEARER_TOKEN".into()],
            decrypted_secrets: HashMap::new(),
            trace_id: "t".into(),
            max_io_calls: 10,
            max_host_response_bytes: 1_000_000,
            allowed_imports: vec![],
            database_config: None,
            egress_proxy_url: None,
            max_log_calls: None,
            max_log_message_bytes: None,
            fs_config: None,
        });
        assert!(!state.has_credential_secrets());
    }
}
