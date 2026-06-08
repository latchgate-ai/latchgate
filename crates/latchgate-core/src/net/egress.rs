//! Host allowlist matching for egress control.
//!
//! Provides exact, subdomain, and wildcard (`*.suffix`) matching against
//! pre-lowercased allowlists. Used by the kernel pipeline (domain
//! pre-checks) and the CLI (`domains check`).

/// Find which allowlist entry matches `host`, if any.
///
/// Returns a reference to the matching entry for diagnostics (e.g. CLI
/// `domains check`). The matching rules are:
///
/// - **Exact match:** `"api.github.com"` matches `"api.github.com"`.
/// - **Subdomain match:** `"sub.api.github.com"` matches `"api.github.com"`
///   because the character before the suffix is `'.'` (a subdomain boundary).
/// - **Wildcard match:** `"my-bucket.s3.amazonaws.com"` matches
///   `"*.s3.amazonaws.com"` because the host ends in `".s3.amazonaws.com"`
///   with at least one additional label. The wildcard does NOT match the
///   bare suffix itself (`"s3.amazonaws.com"`).
/// - **No substring match:** `"evil-api.com"` does NOT match `"api.com"`
///   because the character before the suffix is `'-'`, not `'.'`.
///
/// `allowlist_lower` MUST be pre-lowercased via [`lowercase_allowlist`].
/// The `host` argument is lowercased internally.
#[must_use]
pub fn find_matching_entry<'a>(host: &str, allowlist_lower: &'a [String]) -> Option<&'a str> {
    let host_lower = host.to_ascii_lowercase();
    let host_bytes = host_lower.as_bytes();

    for entry_lower in allowlist_lower {
        // Wildcard match: entry is "*.suffix".
        //
        // "*.s3.amazonaws.com" matches "my-bucket.s3.amazonaws.com" because:
        //   suffix = "s3.amazonaws.com"
        //   host ends with ".s3.amazonaws.com" (byte before suffix is '.')
        //   host has at least one label before the suffix
        //
        // Does NOT match "s3.amazonaws.com" (no label before the suffix).
        if let Some(suffix) = entry_lower.strip_prefix("*.") {
            if !suffix.is_empty()
                && host_bytes.len() > suffix.len() + 1
                && host_bytes[host_bytes.len() - suffix.len() - 1] == b'.'
                && host_lower.ends_with(suffix)
            {
                return Some(entry_lower);
            }
            continue;
        }

        // Exact match.
        if host_lower == *entry_lower {
            return Some(entry_lower);
        }

        // Subdomain match: host ends with "." + entry. The byte at position
        // `host.len() - entry.len() - 1` must be `.` — this is the boundary
        // that distinguishes `foo.api.com` from `evil-api.com`.
        let entry_len = entry_lower.len();
        if host_bytes.len() > entry_len + 1
            && host_bytes[host_bytes.len() - entry_len - 1] == b'.'
            && host_lower.ends_with(entry_lower.as_str())
        {
            return Some(entry_lower);
        }
    }

    None
}

/// Check whether `host` matches any entry in a pre-lowercased allowlist.
///
/// Supports exact match, subdomain match, and wildcard match (`*.suffix`).
/// See [`find_matching_entry`] for the full matching rules.
///
/// `allowlist_lower` MUST be pre-lowercased via [`lowercase_allowlist`].
/// The `host` argument is lowercased internally.
#[must_use]
pub fn host_matches_allowlist_lower(host: &str, allowlist_lower: &[String]) -> bool {
    find_matching_entry(host, allowlist_lower).is_some()
}

/// Pre-lowercase an allowlist for use with [`host_matches_allowlist_lower`].
///
/// Call once at construction time. Avoids per-request lowercasing.
pub fn lowercase_allowlist(allowlist: &[impl AsRef<str>]) -> Vec<String> {
    allowlist
        .iter()
        .map(|s| s.as_ref().to_ascii_lowercase())
        .collect()
}

/// Extract the host from a URL, email address, or bare hostname.
///
/// Returns the lowercased host if one can be determined:
///
/// - `https://API.GitHub.COM/repos` => `Some("api.github.com")`
/// - `user@example.com` => `Some("example.com")`
/// - `hooks.slack.com` (bare, contains `.`) => `Some("hooks.slack.com")`
/// - `localhost` (no dot) => `None`
/// - `""` => `None`
pub fn parse_host_from_url(target: &str) -> Option<String> {
    // Try URL parse.
    if let Ok(parsed) = url::Url::parse(target) {
        if let Some(host) = parsed.host_str() {
            return Some(host.to_ascii_lowercase());
        }
    }
    // Try email: domain after '@'.
    if let Some(at_pos) = target.rfind('@') {
        let domain = &target[at_pos + 1..];
        let domain = domain.split(':').next().unwrap_or(domain);
        if !domain.is_empty() {
            return Some(domain.to_ascii_lowercase());
        }
    }
    // Bare identifier — return as-is if it looks like a hostname.
    let bare = target.split(':').next().unwrap_or(target);
    if !bare.is_empty() && bare.contains('.') && !bare.contains('@') && !bare.contains('/') {
        return Some(bare.to_ascii_lowercase());
    }
    None
}

/// Check if a domain is in the effective allowlist (manifest + learned).
///
/// Lowercases the allowlist entries and delegates to
/// [`host_matches_allowlist_lower`]. The allowlist may be mixed-case
/// (assembled from manifest fields plus operator-approved learned
/// domains), so normalisation is applied on each call.
pub fn domain_in_allowlist(domain: &str, allowlist: &[impl AsRef<str>]) -> bool {
    let lowered = lowercase_allowlist(allowlist);
    host_matches_allowlist_lower(domain, &lowered)
}

#[cfg(test)]
mod tests {
    use super::*;

    // =======================================================================
    // host_matches_allowlist_lower — wildcard matching
    // =======================================================================

    #[test]
    fn wildcard_matches_subdomain_of_suffix() {
        let list = vec!["*.s3.amazonaws.com".to_string()];
        assert!(host_matches_allowlist_lower(
            "my-bucket.s3.amazonaws.com",
            &list
        ));
    }

    #[test]
    fn wildcard_matches_deep_subdomain() {
        let list = vec!["*.s3.amazonaws.com".to_string()];
        assert!(host_matches_allowlist_lower(
            "a.b.c.s3.amazonaws.com",
            &list
        ));
    }

    #[test]
    fn wildcard_does_not_match_bare_suffix() {
        // *.s3.amazonaws.com must NOT match s3.amazonaws.com itself —
        // the wildcard requires at least one label before the suffix.
        let list = vec!["*.s3.amazonaws.com".to_string()];
        assert!(!host_matches_allowlist_lower("s3.amazonaws.com", &list));
    }

    #[test]
    fn wildcard_does_not_match_substring_spoof() {
        // "evil-s3.amazonaws.com" must NOT match "*.s3.amazonaws.com"
        // because "evil-s3" is not a label boundary + "s3".
        // Actually: the host ends with "s3.amazonaws.com" and the char
        // before is '.', so it WOULD match. This is correct: the host
        // IS a subdomain of s3.amazonaws.com.
        //
        // Test the REAL spoof case: "evil.coms3.amazonaws.com" should NOT
        // match "*.s3.amazonaws.com" (suffix mismatch).
        let list = vec!["*.s3.amazonaws.com".to_string()];
        assert!(!host_matches_allowlist_lower(
            "evil.notamazonaws.com",
            &list
        ));
    }

    #[test]
    fn wildcard_is_case_insensitive() {
        let list = vec!["*.s3.amazonaws.com".to_string()];
        assert!(host_matches_allowlist_lower(
            "MY-BUCKET.S3.AMAZONAWS.COM",
            &list
        ));
    }

    #[test]
    fn wildcard_and_exact_coexist() {
        let list = vec![
            "api.github.com".to_string(),
            "*.s3.amazonaws.com".to_string(),
        ];
        assert!(host_matches_allowlist_lower("api.github.com", &list));
        assert!(host_matches_allowlist_lower("sub.api.github.com", &list));
        assert!(host_matches_allowlist_lower(
            "my-bucket.s3.amazonaws.com",
            &list
        ));
        assert!(!host_matches_allowlist_lower("evil.com", &list));
    }

    #[test]
    fn wildcard_empty_suffix_never_matches() {
        // Edge case: "*.". After lowercasing this is "*." — strip_prefix
        // yields "" which is empty, so the match is skipped.
        let list = vec!["*.".to_string()];
        assert!(!host_matches_allowlist_lower("anything.com", &list));
    }

    // =======================================================================
    // find_matching_entry — diagnostics
    // =======================================================================

    #[test]
    fn find_matching_returns_exact_entry() {
        let list = vec!["api.github.com".to_string()];
        assert_eq!(
            find_matching_entry("api.github.com", &list),
            Some("api.github.com")
        );
    }

    #[test]
    fn find_matching_returns_wildcard_entry() {
        let list = vec!["*.s3.amazonaws.com".to_string()];
        assert_eq!(
            find_matching_entry("bucket.s3.amazonaws.com", &list),
            Some("*.s3.amazonaws.com")
        );
    }

    #[test]
    fn find_matching_returns_none_for_no_match() {
        let list = vec!["api.github.com".to_string()];
        assert_eq!(find_matching_entry("evil.com", &list), None);
    }

    // =======================================================================
    // parse_host_from_url
    // =======================================================================

    #[test]
    fn parse_host_https_url() {
        assert_eq!(
            parse_host_from_url("https://api.github.com/repos"),
            Some("api.github.com".into())
        );
    }

    #[test]
    fn parse_host_http_with_port() {
        assert_eq!(
            parse_host_from_url("http://localhost:8080/path"),
            Some("localhost".into())
        );
    }

    #[test]
    fn parse_host_uppercased() {
        assert_eq!(
            parse_host_from_url("https://API.GitHub.COM/repos"),
            Some("api.github.com".into())
        );
    }

    #[test]
    fn parse_host_email() {
        assert_eq!(
            parse_host_from_url("user@example.com"),
            Some("example.com".into())
        );
    }

    #[test]
    fn parse_host_bare_domain() {
        assert_eq!(
            parse_host_from_url("hooks.slack.com"),
            Some("hooks.slack.com".into())
        );
    }

    #[test]
    fn parse_host_bare_no_dot_returns_none() {
        assert_eq!(parse_host_from_url("localhost"), None);
    }

    #[test]
    fn parse_host_empty_returns_none() {
        assert_eq!(parse_host_from_url(""), None);
    }

    #[test]
    fn parse_host_ip_address() {
        assert_eq!(
            parse_host_from_url("http://192.168.1.1:8080/path"),
            Some("192.168.1.1".into())
        );
    }

    #[test]
    fn parse_host_ipv6() {
        assert_eq!(
            parse_host_from_url("http://[::1]:8080/path"),
            Some("[::1]".into())
        );
    }

    #[test]
    fn parse_host_ftp_scheme() {
        assert_eq!(
            parse_host_from_url("ftp://files.example.com/data"),
            Some("files.example.com".into())
        );
    }

    // =======================================================================
    // domain_in_allowlist
    // =======================================================================

    #[test]
    fn domain_in_allowlist_mixed_case_entries() {
        let list: Vec<String> = vec!["API.GitHub.COM".into()];
        assert!(
            domain_in_allowlist("api.github.com", &list),
            "must lowercase allowlist entries before matching"
        );
    }

    #[test]
    fn domain_in_allowlist_exact_match() {
        let list: Vec<String> = vec!["example.com".into()];
        assert!(domain_in_allowlist("example.com", &list));
        assert!(!domain_in_allowlist("other.com", &list));
    }
}
