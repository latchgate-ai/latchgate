//! Domain entry validation and normalization.
//!
//! Validates domain strings for use in learned allowlists (CLI, API,
//! approval flow) and manifest `allowed_domains` lists. Shared by all
//! domain write paths — the ledger calls [`validate_domain_entry`]
//! unconditionally so no path can bypass validation.
//!
//! # Wildcard support
//!
//! Leading `*.suffix` wildcards are supported with configurable breadth
//! gating. Mid-string and trailing wildcards are rejected.

use super::ip::is_private_ip;

/// Errors from validating a domain string for use as a learned allowlist entry.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DomainValidationError {
    #[error("domain must not be empty or whitespace-only")]
    Empty,

    #[error("domain contains whitespace")]
    ContainsWhitespace,

    #[error("'{0}' is a private/reserved IP address — learned domains must be public")]
    PrivateIp(String),

    #[error("'localhost' is not permitted as a learned domain")]
    Localhost,

    #[error("domain must contain at least one dot (got '{0}')")]
    NoDot(String),

    #[error("invalid wildcard: {reason}")]
    WildcardInvalid { reason: String },

    #[error("wildcard suffix too short: '{0}' — suffix after '*.' must contain at least one dot (e.g. '*.example.com', not '*.com')")]
    WildcardSuffixTooShort(String),

    #[error("wildcard '{0}' has a broad suffix (fewer than 3 labels) — use --force on the CLI to accept this risk")]
    WildcardSuffixUnsafe(String),

    #[error("domain contains invalid character '{0}' — only ASCII alphanumerics, hyphens, and dots are allowed")]
    InvalidCharacter(char),

    #[error(
        "domain label must not be empty (double dot or leading/trailing dot after normalization)"
    )]
    EmptyLabel,

    #[error("domain label '{0}' exceeds 63 characters")]
    LabelTooLong(String),

    #[error("domain exceeds 253 characters")]
    TooLong,
}

/// Check whether a wildcard suffix is safe to accept without explicit
/// operator confirmation.
///
/// "Safe" means the suffix contains at least 3 labels (≥ 2 dots), which
/// limits the blast radius. For example:
///
/// - `s3.eu-west-1.amazonaws.com` => 3 dots, safe.
/// - `s3.amazonaws.com` => 2 dots, safe.
/// - `example.com` => 1 dot, **unsafe** (covers all subdomains of a
///   registrable domain — needs `--force`).
/// - `com` => 0 dots, rejected unconditionally.
///
/// This is a heuristic, not a public-suffix lookup. A proper PSL check
/// can replace it later without changing the calling convention.
#[must_use]
pub fn is_safe_wildcard_suffix(suffix: &str) -> bool {
    suffix.chars().filter(|c| *c == '.').count() >= 2
}

/// Validate and normalize a domain string for use as a learned allowlist entry.
///
/// Returns the normalized domain (lowercased, trailing dot stripped) on
/// success. The caller MUST persist the returned value, not the original
/// input, to ensure consistent matching at runtime.
///
/// # Wildcard support
///
/// Entries of the form `*.suffix` are accepted when the suffix passes
/// safety checks. Only leading `*.` is allowed — mid-string wildcards
/// (`foo.*.com`) and trailing wildcards (`example.*`) are rejected.
///
/// When `allow_unsafe_wildcard` is `false`, the suffix must contain at
/// least 2 dots (≥ 3 labels). Broader wildcards like `*.example.com`
/// require `allow_unsafe_wildcard` to be `true` (CLI `--force` flag).
/// Extremely short suffixes with zero dots (`*.com`) are always rejected.
///
/// # Validation rules
///
/// 1. Reject empty, whitespace-only, or whitespace-containing strings.
/// 2. Reject bare IP addresses in private/reserved ranges (see
///    [`is_private_ip`]). Public IPs are allowed — runtime SSRF checks
///    provide defense-in-depth.
/// 3. Reject `localhost` (any case).
/// 4. Validate wildcard entries (`*.suffix`) with suffix safety checks.
///    Reject all other forms containing `*`.
/// 5. Reject strings without a dot (single-label hostnames are not
///    meaningful in an egress allowlist).
/// 6. Enforce DNS label constraints: ≤63 bytes per label, ≤253 bytes
///    total, ASCII alphanumeric + hyphen only.
/// 7. Normalize: ASCII lowercase, strip single trailing dot.
///
/// # Security
///
/// This function is the single validation gate for all domain write paths
/// (CLI `domains add`, API `POST /v1/admin/domains`, approval `learn_domain`).
/// The ledger's `add_learned_domain` calls it unconditionally so that no
/// write path can bypass validation.
#[must_use = "discarding the result skips domain validation"]
pub fn validate_domain_entry(
    domain: &str,
    allow_unsafe_wildcard: bool,
) -> Result<String, DomainValidationError> {
    let (normalized, is_wildcard) = normalize_and_validate_syntax(domain)?;

    if is_wildcard {
        // Safety gate: require ≥ 2 dots in the suffix (≥ 3 labels) unless
        // the caller explicitly opts in to broader wildcards.
        if let Some(suffix) = normalized.strip_prefix("*.") {
            if !is_safe_wildcard_suffix(suffix) && !allow_unsafe_wildcard {
                return Err(DomainValidationError::WildcardSuffixUnsafe(normalized));
            }
        }
        return Ok(normalized);
    }

    // Reject localhost.
    if normalized == "localhost" {
        return Err(DomainValidationError::Localhost);
    }

    // Check for IP address literals. Brackets are stripped for
    // IPv6 (`[::1]` => `::1`).
    let ip_candidate = normalized
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(&normalized);
    if let Ok(ip) = ip_candidate.parse::<std::net::IpAddr>() {
        if is_private_ip(ip) {
            return Err(DomainValidationError::PrivateIp(normalized));
        }
        return Ok(normalized);
    }

    // Require at least one dot (single-label hostnames are not meaningful
    // in an egress allowlist).
    if !normalized.contains('.') {
        return Err(DomainValidationError::NoDot(normalized));
    }

    validate_domain_labels(&normalized)?;

    Ok(normalized)
}

/// Validate DNS label constraints on a domain string.
///
/// Shared between regular domain entries and wildcard suffixes. Checks
/// total length (≤ 253), per-label length (≤ 63), no empty labels, and
/// ASCII alphanumeric + hyphen character set.
fn validate_domain_labels(domain: &str) -> Result<(), DomainValidationError> {
    if domain.len() > 253 {
        return Err(DomainValidationError::TooLong);
    }
    for label in domain.split('.') {
        if label.is_empty() {
            return Err(DomainValidationError::EmptyLabel);
        }
        if label.len() > 63 {
            return Err(DomainValidationError::LabelTooLong(label.to_string()));
        }
        for ch in label.chars() {
            if !ch.is_ascii_alphanumeric() && ch != '-' {
                return Err(DomainValidationError::InvalidCharacter(ch));
            }
        }
    }
    Ok(())
}

/// Normalize a domain string and validate its structural syntax.
///
/// Shared prefix for [`validate_domain_entry`] (learned domains) and
/// [`validate_manifest_domain_entry`] (manifest domains). Handles:
///
/// - Trim, reject empty/whitespace.
/// - ASCII-lowercase, strip trailing dot.
/// - Wildcard syntax: only leading `*.` with a multi-label suffix.
/// - DNS label validation on wildcard suffixes.
/// - Reject bare, trailing, and mid-string `*`.
///
/// Returns `(normalized, is_wildcard)`. Callers apply their own policy
/// gates (localhost, private IP, wildcard breadth, single-label).
fn normalize_and_validate_syntax(domain: &str) -> Result<(String, bool), DomainValidationError> {
    let trimmed = domain.trim();
    if trimmed.is_empty() {
        return Err(DomainValidationError::Empty);
    }
    if trimmed.contains(char::is_whitespace) {
        return Err(DomainValidationError::ContainsWhitespace);
    }

    let mut normalized = trimmed.to_ascii_lowercase();
    if normalized.ends_with('.') {
        normalized.pop();
    }
    if normalized.is_empty() {
        return Err(DomainValidationError::Empty);
    }

    // Wildcard syntax validation.
    if let Some(suffix) = normalized.strip_prefix("*.") {
        // Only leading "*." is allowed. Reject mid-string wildcards in the
        // suffix (e.g. "*.foo.*.com").
        if suffix.contains('*') {
            return Err(DomainValidationError::WildcardInvalid {
                reason: "only a leading '*.' is permitted; mid-string wildcards are not supported"
                    .into(),
            });
        }
        // Suffix must not be empty (bare "*." after normalization).
        if suffix.is_empty() {
            return Err(DomainValidationError::WildcardInvalid {
                reason: "wildcard '*.' must be followed by a domain suffix".into(),
            });
        }
        // Suffix must contain at least one dot — "*.com" would match every
        // .com domain.
        if !suffix.contains('.') {
            return Err(DomainValidationError::WildcardSuffixTooShort(normalized));
        }
        // Validate the suffix labels with standard DNS rules.
        validate_domain_labels(suffix)?;
        return Ok((normalized, true));
    }

    // Reject any remaining wildcard characters: bare "*", trailing
    // wildcards ("example.*"), and mid-string wildcards ("foo.*.com").
    if normalized.contains('*') {
        return Err(DomainValidationError::WildcardInvalid {
            reason: "only '*.suffix' form is supported; bare '*' and mid-string wildcards are not"
                .into(),
        });
    }

    Ok((normalized, false))
}

/// Validate and normalize a domain entry from a manifest `allowed_domains` list.
///
/// Manifests are operator-authored, code-reviewed artifacts. This validator
/// enforces structural correctness (well-formed labels, valid wildcard
/// syntax, no `*.com`) but intentionally does NOT reject:
///
/// - `localhost` — legitimate for local-service integrations (e.g. Obsidian).
/// - Private/reserved IPs — runtime SSRF checks ([`resolve_and_check_ssrf`])
///   provide defense-in-depth.
/// - Broad wildcards (`*.example.com`) — the code review is the gate.
/// - Single-label hostnames — `localhost` is the canonical example.
///
/// For the stricter validator used by learned-domain write paths (CLI, API,
/// approval flow), see [`validate_domain_entry`].
#[must_use = "discarding the result skips domain validation"]
pub fn validate_manifest_domain_entry(domain: &str) -> Result<String, DomainValidationError> {
    let (normalized, is_wildcard) = normalize_and_validate_syntax(domain)?;

    if is_wildcard {
        // Manifests are code-reviewed — no breadth restriction on wildcards.
        return Ok(normalized);
    }

    // Skip localhost / private-IP / single-label checks — manifests are
    // trusted operator config and runtime enforcement handles SSRF.

    // IP literals are accepted as-is (already lowered).
    let ip_candidate = normalized
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(&normalized);
    if ip_candidate.parse::<std::net::IpAddr>().is_ok() {
        return Ok(normalized);
    }

    // Label validation for non-IP, non-wildcard entries.
    // Single-label hostnames like "localhost" are accepted.
    if normalized.contains('.') {
        validate_domain_labels(&normalized)?;
    }

    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    // =======================================================================
    // validate_domain_entry — reject cases
    // =======================================================================

    #[test]
    fn validate_rejects_empty() {
        assert!(matches!(
            validate_domain_entry("", false),
            Err(DomainValidationError::Empty)
        ));
        assert!(matches!(
            validate_domain_entry("   ", false),
            Err(DomainValidationError::Empty)
        ));
        assert!(matches!(
            validate_domain_entry("\t", false),
            Err(DomainValidationError::Empty)
        ));
    }

    #[test]
    fn validate_rejects_whitespace() {
        assert!(matches!(
            validate_domain_entry("hello world.com", false),
            Err(DomainValidationError::ContainsWhitespace)
        ));
        assert!(matches!(
            validate_domain_entry("foo\tbar.com", false),
            Err(DomainValidationError::ContainsWhitespace)
        ));
    }

    #[test]
    fn validate_rejects_private_ips() {
        assert!(matches!(
            validate_domain_entry("127.0.0.1", false),
            Err(DomainValidationError::PrivateIp(_))
        ));
        assert!(matches!(
            validate_domain_entry("10.0.0.1", false),
            Err(DomainValidationError::PrivateIp(_))
        ));
        assert!(matches!(
            validate_domain_entry("172.16.0.1", false),
            Err(DomainValidationError::PrivateIp(_))
        ));
        assert!(matches!(
            validate_domain_entry("192.168.1.1", false),
            Err(DomainValidationError::PrivateIp(_))
        ));
        assert!(matches!(
            validate_domain_entry("169.254.169.254", false),
            Err(DomainValidationError::PrivateIp(_))
        ));
    }

    #[test]
    fn validate_rejects_ipv6_private() {
        assert!(matches!(
            validate_domain_entry("[::1]", false),
            Err(DomainValidationError::PrivateIp(_))
        ));
        assert!(matches!(
            validate_domain_entry("[fc00::1]", false),
            Err(DomainValidationError::PrivateIp(_))
        ));
        assert!(matches!(
            validate_domain_entry("[fe80::1]", false),
            Err(DomainValidationError::PrivateIp(_))
        ));
    }

    #[test]
    fn validate_rejects_localhost() {
        assert!(matches!(
            validate_domain_entry("localhost", false),
            Err(DomainValidationError::Localhost)
        ));
        assert!(matches!(
            validate_domain_entry("LOCALHOST", false),
            Err(DomainValidationError::Localhost)
        ));
        assert!(matches!(
            validate_domain_entry("LocalHost", false),
            Err(DomainValidationError::Localhost)
        ));
    }

    #[test]
    fn validate_rejects_no_dot() {
        assert!(matches!(
            validate_domain_entry("intranet", false),
            Err(DomainValidationError::NoDot(_))
        ));
        assert!(matches!(
            validate_domain_entry("singleword", false),
            Err(DomainValidationError::NoDot(_))
        ));
    }

    #[test]
    fn validate_rejects_bare_wildcard() {
        assert!(matches!(
            validate_domain_entry("*", false),
            Err(DomainValidationError::WildcardInvalid { .. })
        ));
    }

    #[test]
    fn validate_rejects_wildcard_tld() {
        // *.com — suffix has 0 dots, always rejected even with force.
        assert!(matches!(
            validate_domain_entry("*.com", false),
            Err(DomainValidationError::WildcardSuffixTooShort(_))
        ));
        assert!(matches!(
            validate_domain_entry("*.com", true),
            Err(DomainValidationError::WildcardSuffixTooShort(_))
        ));
    }

    #[test]
    fn validate_rejects_unsafe_wildcard_without_force() {
        // *.example.com — suffix has 1 dot, needs force.
        assert!(matches!(
            validate_domain_entry("*.example.com", false),
            Err(DomainValidationError::WildcardSuffixUnsafe(_))
        ));
    }

    #[test]
    fn validate_accepts_unsafe_wildcard_with_force() {
        assert_eq!(
            validate_domain_entry("*.example.com", true).unwrap(),
            "*.example.com"
        );
    }

    #[test]
    fn validate_accepts_safe_wildcard() {
        // *.s3.amazonaws.com — suffix has 2 dots, safe without force.
        assert_eq!(
            validate_domain_entry("*.s3.amazonaws.com", false).unwrap(),
            "*.s3.amazonaws.com"
        );
        assert_eq!(
            validate_domain_entry("*.s3.eu-west-1.amazonaws.com", false).unwrap(),
            "*.s3.eu-west-1.amazonaws.com"
        );
        assert_eq!(
            validate_domain_entry("*.execute-api.us-east-1.amazonaws.com", false).unwrap(),
            "*.execute-api.us-east-1.amazonaws.com"
        );
    }

    #[test]
    fn validate_wildcard_normalizes_case() {
        assert_eq!(
            validate_domain_entry("*.S3.AMAZONAWS.COM", false).unwrap(),
            "*.s3.amazonaws.com"
        );
    }

    #[test]
    fn validate_wildcard_strips_trailing_dot() {
        assert_eq!(
            validate_domain_entry("*.s3.amazonaws.com.", false).unwrap(),
            "*.s3.amazonaws.com"
        );
    }

    #[test]
    fn validate_rejects_mid_wildcard() {
        assert!(matches!(
            validate_domain_entry("foo.*.com", false),
            Err(DomainValidationError::WildcardInvalid { .. })
        ));
    }

    #[test]
    fn validate_rejects_trailing_wildcard() {
        assert!(matches!(
            validate_domain_entry("example.*", false),
            Err(DomainValidationError::WildcardInvalid { .. })
        ));
    }

    #[test]
    fn validate_rejects_double_wildcard() {
        assert!(matches!(
            validate_domain_entry("*.*.example.com", false),
            Err(DomainValidationError::WildcardInvalid { .. })
        ));
    }

    #[test]
    fn validate_rejects_bare_star_dot() {
        assert!(matches!(
            validate_domain_entry("*.", false),
            Err(DomainValidationError::WildcardInvalid { .. })
        ));
    }

    #[test]
    fn validate_wildcard_suffix_labels_validated() {
        // Invalid character in suffix label.
        assert!(matches!(
            validate_domain_entry("*.foo_bar.example.com", false),
            Err(DomainValidationError::InvalidCharacter('_'))
        ));
        // Empty label in suffix (double dot).
        assert!(matches!(
            validate_domain_entry("*.foo..example.com", false),
            Err(DomainValidationError::EmptyLabel)
        ));
    }

    #[test]
    fn validate_rejects_invalid_chars() {
        assert!(matches!(
            validate_domain_entry("foo_bar.com", false),
            Err(DomainValidationError::InvalidCharacter('_'))
        ));
        assert!(matches!(
            validate_domain_entry("foo@bar.com", false),
            Err(DomainValidationError::InvalidCharacter('@'))
        ));
        assert!(matches!(
            validate_domain_entry("foo/bar.com", false),
            Err(DomainValidationError::InvalidCharacter('/'))
        ));
    }

    #[test]
    fn validate_rejects_empty_labels() {
        assert!(matches!(
            validate_domain_entry("foo..bar.com", false),
            Err(DomainValidationError::EmptyLabel)
        ));
        // Leading dot after trim produces empty first label.
        assert!(matches!(
            validate_domain_entry(".example.com", false),
            Err(DomainValidationError::EmptyLabel)
        ));
    }

    #[test]
    fn validate_rejects_label_too_long() {
        let long_label = "a".repeat(64);
        let domain = format!("{long_label}.com");
        assert!(matches!(
            validate_domain_entry(&domain, false),
            Err(DomainValidationError::LabelTooLong(_))
        ));
    }

    #[test]
    fn validate_rejects_domain_too_long() {
        // 4 labels of 63 chars + 3 dots + ".com" = 256 + 4 = 260 chars.
        let domain = format!(
            "{}.{}.{}.{}.com",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(63),
        );
        assert!(domain.len() > 253);
        assert!(matches!(
            validate_domain_entry(&domain, false),
            Err(DomainValidationError::TooLong)
        ));
    }

    // =======================================================================
    // validate_domain_entry — accept + normalization cases
    // =======================================================================

    #[test]
    fn validate_accepts_normal_domain() {
        assert_eq!(
            validate_domain_entry("example.com", false).unwrap(),
            "example.com"
        );
        assert_eq!(
            validate_domain_entry("api.github.com", false).unwrap(),
            "api.github.com"
        );
        assert_eq!(
            validate_domain_entry("sub.api.github.com", false).unwrap(),
            "sub.api.github.com"
        );
    }

    #[test]
    fn validate_normalizes_case() {
        assert_eq!(
            validate_domain_entry("API.GitHub.COM", false).unwrap(),
            "api.github.com"
        );
        assert_eq!(
            validate_domain_entry("HOOKS.SLACK.COM", false).unwrap(),
            "hooks.slack.com"
        );
    }

    #[test]
    fn validate_strips_trailing_dot() {
        assert_eq!(
            validate_domain_entry("example.com.", false).unwrap(),
            "example.com"
        );
    }

    #[test]
    fn validate_trims_surrounding_whitespace() {
        assert_eq!(
            validate_domain_entry("  example.com  ", false).unwrap(),
            "example.com"
        );
    }

    #[test]
    fn validate_accepts_hyphenated_labels() {
        assert_eq!(
            validate_domain_entry("my-service.example.com", false).unwrap(),
            "my-service.example.com"
        );
    }

    #[test]
    fn validate_accepts_public_ip() {
        assert_eq!(validate_domain_entry("8.8.8.8", false).unwrap(), "8.8.8.8");
        assert_eq!(validate_domain_entry("1.1.1.1", false).unwrap(), "1.1.1.1");
    }

    #[test]
    fn validate_accepts_long_but_valid_domain() {
        let domain = format!("{}.{}.com", "a".repeat(63), "b".repeat(63));
        assert!(validate_domain_entry(&domain, false).is_ok());
    }

    #[test]
    fn validate_dot_only_is_empty_after_strip() {
        assert!(matches!(
            validate_domain_entry(".", false),
            Err(DomainValidationError::Empty)
        ));
    }

    // =======================================================================
    // is_safe_wildcard_suffix
    // =======================================================================

    #[test]
    fn safe_wildcard_suffix_requires_two_dots() {
        // 0 dots => not safe.
        assert!(!is_safe_wildcard_suffix("com"));
        // 1 dot => not safe.
        assert!(!is_safe_wildcard_suffix("example.com"));
        assert!(!is_safe_wildcard_suffix("amazonaws.com"));
        // 2 dots => safe.
        assert!(is_safe_wildcard_suffix("s3.amazonaws.com"));
        assert!(is_safe_wildcard_suffix(
            "execute-api.us-east-1.amazonaws.com"
        ));
        // 3+ dots => safe.
        assert!(is_safe_wildcard_suffix("a.b.c.d"));
    }

    #[test]
    fn safe_wildcard_suffix_empty_is_not_safe() {
        assert!(!is_safe_wildcard_suffix(""));
    }

    // =======================================================================
    // validate_manifest_domain_entry
    // =======================================================================

    #[test]
    fn manifest_accepts_localhost() {
        assert_eq!(
            validate_manifest_domain_entry("localhost").unwrap(),
            "localhost"
        );
    }

    #[test]
    fn manifest_accepts_private_ip() {
        assert_eq!(
            validate_manifest_domain_entry("127.0.0.1").unwrap(),
            "127.0.0.1"
        );
        assert_eq!(
            validate_manifest_domain_entry("10.0.0.1").unwrap(),
            "10.0.0.1"
        );
    }

    #[test]
    fn manifest_accepts_broad_wildcard() {
        assert_eq!(
            validate_manifest_domain_entry("*.atlassian.net").unwrap(),
            "*.atlassian.net"
        );
        assert_eq!(
            validate_manifest_domain_entry("*.example.com").unwrap(),
            "*.example.com"
        );
    }

    #[test]
    fn manifest_accepts_safe_wildcard() {
        assert_eq!(
            validate_manifest_domain_entry("*.s3.amazonaws.com").unwrap(),
            "*.s3.amazonaws.com"
        );
    }

    #[test]
    fn manifest_rejects_wildcard_tld() {
        assert!(matches!(
            validate_manifest_domain_entry("*.com"),
            Err(DomainValidationError::WildcardSuffixTooShort(_))
        ));
    }

    #[test]
    fn manifest_rejects_mid_wildcard() {
        assert!(matches!(
            validate_manifest_domain_entry("foo.*.com"),
            Err(DomainValidationError::WildcardInvalid { .. })
        ));
    }

    #[test]
    fn manifest_rejects_empty() {
        assert!(matches!(
            validate_manifest_domain_entry(""),
            Err(DomainValidationError::Empty)
        ));
    }

    #[test]
    fn manifest_validates_labels() {
        assert!(matches!(
            validate_manifest_domain_entry("foo_bar.com"),
            Err(DomainValidationError::InvalidCharacter('_'))
        ));
    }

    #[test]
    fn manifest_normalizes_case_and_trailing_dot() {
        assert_eq!(
            validate_manifest_domain_entry("API.GitHub.COM.").unwrap(),
            "api.github.com"
        );
    }
}
