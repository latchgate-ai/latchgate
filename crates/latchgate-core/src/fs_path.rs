//! Filesystem path evaluation against glob allowlists and denylists.
//!
//! Shared between Layer 1 (host import path validation) and Layer 2
//! (provider filesystem I/O). Both layers use the same function with different
//! inputs: Layer 1 evaluates against the grant's manifest-derived
//! allowlist; Layer 2 evaluates against the OPA-derived policy.
//!
//! Deny overrides allow. A path matching any denied pattern is rejected
//! regardless of whether it also matches an allowed pattern.

use std::path::Path;

// `FsOperation` is the canonical filesystem operation enum, defined in
// `crate::host_observed`. It is used both for manifest-declared allowed
// operations and for host-observed evidence recording.

/// Result of evaluating a path against allow/deny glob patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathDecision {
    /// Path matches an allowed pattern and no denied pattern.
    Allowed,
    /// Path matches a denied pattern (deny overrides allow).
    Denied,
    /// Path does not match any allowed pattern.
    NotMatched,
}

/// Evaluate a path against allowed and denied glob patterns.
///
/// Inputs must be canonical paths (no `..`, no symlinks). Layer 1
/// canonicalizes via `O_NOFOLLOW` + `/proc/self/fd/{n}`. Layer 2
/// reads from `/proc/self/fd/{event.fd}`.
///
/// # Deny-overrides-allow
///
/// A path matching **any** denied pattern is rejected even if it also
/// matches an allowed pattern. This is the single enforcement rule —
/// there is no priority ordering within the deny set or the allow set.
#[must_use]
pub fn evaluate_path(path: &Path, allowed: &[GlobPattern], denied: &[GlobPattern]) -> PathDecision {
    let path_str = path.to_string_lossy();

    if denied.iter().any(|g| g.matches(&path_str)) {
        return PathDecision::Denied;
    }
    if allowed.iter().any(|g| g.matches(&path_str)) {
        return PathDecision::Allowed;
    }
    PathDecision::NotMatched
}

/// Result of a detailed path evaluation, including the matching pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetailedPathDecision {
    Allowed { pattern: String },
    Denied { pattern: String },
    NotMatched,
}

/// Like [`evaluate_path`], but returns the first matching pattern string.
///
/// Used by the host I/O layer so that deny-list hits include the triggering
/// pattern in error messages and audit events.
pub fn evaluate_path_detailed(
    path: &Path,
    allowed: &[GlobPattern],
    denied: &[GlobPattern],
) -> DetailedPathDecision {
    let path_str = path.to_string_lossy();

    if let Some(g) = denied.iter().find(|g| g.matches(&path_str)) {
        return DetailedPathDecision::Denied {
            pattern: g.raw.clone(),
        };
    }
    if let Some(g) = allowed.iter().find(|g| g.matches(&path_str)) {
        return DetailedPathDecision::Allowed {
            pattern: g.raw.clone(),
        };
    }
    DetailedPathDecision::NotMatched
}

/// Compiled glob pattern for path matching.
///
/// Wraps `globset::GlobMatcher` for efficient repeated matching. Patterns
/// are compiled once at manifest load (or when learned paths are added)
/// and reused for every request.
#[derive(Debug, Clone)]
pub struct GlobPattern {
    raw: String,
    matcher: globset::GlobMatcher,
}

impl GlobPattern {
    /// Compile a glob pattern string.
    ///
    /// Returns `Err` if the pattern is syntactically invalid.
    pub fn new(pattern: &str) -> Result<Self, GlobPatternError> {
        let glob = globset::GlobBuilder::new(pattern)
            .literal_separator(true)
            .build()
            .map_err(|e| GlobPatternError {
                pattern: pattern.to_string(),
                reason: e.to_string(),
            })?;
        Ok(Self {
            raw: pattern.to_string(),
            matcher: glob.compile_matcher(),
        })
    }

    /// Test whether a path string matches this pattern.
    pub fn matches(&self, path: &str) -> bool {
        self.matcher.is_match(path)
    }

    /// The original pattern string.
    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

impl std::fmt::Display for GlobPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.raw)
    }
}

/// Error from compiling a glob pattern.
#[derive(Debug, Clone, thiserror::Error)]
#[error("invalid glob pattern '{pattern}': {reason}")]
pub struct GlobPatternError {
    pub pattern: String,
    pub reason: String,
}

/// Compile a list of pattern strings into [`GlobPattern`]s.
///
/// Accepts any iterable of string-like items (`&[String]`, `&[&str]`,
/// chained iterators, etc.) so callers can compile from multiple sources
/// without first collecting into a single `Vec<String>`.
///
/// Returns the first compilation error.
#[must_use = "discarding compiled patterns skips path enforcement"]
pub fn compile_patterns<I, S>(patterns: I) -> Result<Vec<GlobPattern>, GlobPatternError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    patterns
        .into_iter()
        .map(|p| GlobPattern::new(p.as_ref()))
        .collect()
}

/// Errors from validating a glob string for use as a learned allowlist entry.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PathGlobValidationError {
    #[error("path glob must not be empty or whitespace-only")]
    Empty,

    #[error("path glob must be relative (no leading '/')")]
    Absolute,

    #[error("catch-all pattern '{0}' is too broad — use a scoped pattern like 'src/**' instead")]
    CatchAll(String),

    #[error("null byte at position {0}")]
    NullByte(usize),

    #[error("control character 0x{0:02x} at position {1}")]
    ControlCharacter(u8, usize),

    #[error("parent traversal ('..') is not allowed in learned paths")]
    ParentTraversal,

    #[error("glob targets sensitive location '{0}' — these are covered by the runtime deny list and must not be learned as allow patterns")]
    SensitiveTarget(String),
}

/// Sensitive path prefixes that must never be learned as allow patterns.
///
/// These locations are protected by the runtime deny-overrides-allow
/// mechanism, but allowing them in the learned allowlist creates false
/// confidence and muddies operator review.
const SENSITIVE_PATH_SEGMENTS: &[&str] = &[
    ".env",
    ".ssh",
    ".git",
    ".latchgate",
    ".aws",
    ".gnupg",
    ".pgpass",
    ".netrc",
    ".docker",
    ".kube",
    ".config/latchgate",
];

/// Validate a glob string for use as a learned path allowlist entry.
///
/// This is the single validation gate for all learned-path write paths.
/// The ledger's `add_learned_path` calls it unconditionally.
///
/// # Validation rules
///
/// 1. Reject empty or whitespace-only strings.
/// 2. Reject absolute paths (leading `/`).
/// 3. Reject catch-all patterns (`*`, `**`, `**/*`).
/// 4. Reject null bytes and control characters.
/// 5. Reject parent traversal (`..` as a complete path segment).
/// 6. Reject globs that target known sensitive locations (`.env`, `.ssh`,
///    `.git`, `.latchgate`, etc.) — these are covered by the runtime deny
///    list and must not be learned as allow patterns.
#[must_use = "discarding the result skips path validation"]
pub fn validate_path_glob_entry(glob: &str) -> Result<(), PathGlobValidationError> {
    // 1. Empty / whitespace-only.
    let trimmed = glob.trim();
    if trimmed.is_empty() {
        return Err(PathGlobValidationError::Empty);
    }

    // Operate on the original (untrimmed) input — whitespace in a glob is
    // suspicious but not necessarily wrong. The empty-after-trim check above
    // catches the degenerate case.

    // 2. Absolute paths.
    if glob.starts_with('/') {
        return Err(PathGlobValidationError::Absolute);
    }

    // 3. Catch-all patterns.
    let normalized = glob.trim_matches('/');
    if matches!(normalized, "*" | "**" | "**/*") {
        return Err(PathGlobValidationError::CatchAll(glob.to_string()));
    }

    // 4. Null bytes and control characters.
    for (i, b) in glob.bytes().enumerate() {
        if b == 0 {
            return Err(PathGlobValidationError::NullByte(i));
        }
        // Allow tab (0x09) but reject all other control characters.
        if b < 0x20 && b != b'\t' {
            return Err(PathGlobValidationError::ControlCharacter(b, i));
        }
    }

    // 5. Parent traversal — `..` as a complete segment.
    for segment in glob.split('/') {
        if segment == ".." {
            return Err(PathGlobValidationError::ParentTraversal);
        }
    }

    // 6. Sensitive locations — check if the first segment (or the entire
    //    glob) targets a known sensitive path.
    if let Some(target) = targets_sensitive_location(glob) {
        return Err(PathGlobValidationError::SensitiveTarget(target.to_string()));
    }

    Ok(())
}

/// Check whether a glob primarily targets a sensitive location.
///
/// Returns the matched sensitive prefix if the glob's leading segment
/// names a known sensitive directory or file.
fn targets_sensitive_location(glob: &str) -> Option<&'static str> {
    let first_segment = glob.split('/').next().unwrap_or(glob);

    for sensitive in SENSITIVE_PATH_SEGMENTS {
        // Direct match: ".env", ".ssh/**", ".git/config"
        if first_segment == *sensitive {
            return Some(sensitive);
        }
        // Glob suffix match: ".env.*", ".env.local", ".env.production"
        if first_segment.starts_with(sensitive)
            && first_segment
                .as_bytes()
                .get(sensitive.len())
                .is_some_and(|&b| b == b'.' || b == b'*')
        {
            return Some(sensitive);
        }
        // Multi-segment sensitive: ".config/latchgate"
        if sensitive.contains('/') && glob.starts_with(sensitive) {
            let next_byte = glob.as_bytes().get(sensitive.len());
            if next_byte.is_none() || next_byte == Some(&b'/') || next_byte == Some(&b'*') {
                return Some(sensitive);
            }
        }
    }
    None
}

/// Relativize an absolute path against a session's filesystem root.
///
/// Used by the approval learn-path flow to convert the agent's absolute
/// file path into a relative glob entry suitable for `validate_path_glob_entry`
/// and `add_learned_path`.
///
/// Returns:
/// - `Some(relative)` if `path` is absolute and starts with `root`.
/// - `Some(path)` unchanged if `path` is already relative.
/// - `None` if `path` is absolute but not under `root` (security boundary
///   violation — the caller must reject the request).
///
/// SECURITY: this function MUST NOT silently accept paths outside `root`.
/// An absolute path that doesn't start with the session's fs_root is an
/// attempt (intentional or accidental) to learn a glob outside the agent's
/// containment boundary.
pub fn relativize_to_root(path: &str, root: &Path) -> Option<String> {
    let p = Path::new(path);
    if !p.is_absolute() {
        // Already relative — pass through unchanged.
        return Some(path.to_owned());
    }
    let relative = p.strip_prefix(root).ok()?;
    // `strip_prefix` on an exact match returns "" — not a valid glob target.
    let s = relative.to_str()?;
    if s.is_empty() {
        return None;
    }
    Some(s.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn pat(s: &str) -> GlobPattern {
        GlobPattern::new(s).unwrap()
    }

    fn allowed(patterns: &[&str]) -> Vec<GlobPattern> {
        patterns.iter().map(|p| pat(p)).collect()
    }

    // -- PathDecision basics --

    #[test]
    fn allowed_path_matches() {
        let allow = allowed(&["src/**"]);
        let deny = vec![];
        assert_eq!(
            evaluate_path(&PathBuf::from("src/main.rs"), &allow, &deny),
            PathDecision::Allowed,
        );
    }

    #[test]
    fn not_matched_when_no_allow() {
        let allow = allowed(&["src/**"]);
        let deny = vec![];
        assert_eq!(
            evaluate_path(&PathBuf::from("configs/app.toml"), &allow, &deny),
            PathDecision::NotMatched,
        );
    }

    #[test]
    fn deny_overrides_allow() {
        let allow = allowed(&["src/**"]);
        let deny = allowed(&["src/.env"]);
        assert_eq!(
            evaluate_path(&PathBuf::from("src/.env"), &allow, &deny),
            PathDecision::Denied,
        );
    }

    #[test]
    fn deny_with_double_star() {
        let allow = allowed(&["src/**"]);
        let deny = allowed(&["**/.env"]);
        assert_eq!(
            evaluate_path(&PathBuf::from("src/deep/.env"), &allow, &deny),
            PathDecision::Denied,
        );
    }

    #[test]
    fn deny_wins_even_with_multiple_allow_matches() {
        let allow = allowed(&["**/*.rs", "src/**"]);
        let deny = allowed(&["**/secrets/**"]);
        assert_eq!(
            evaluate_path(&PathBuf::from("src/secrets/key.rs"), &allow, &deny),
            PathDecision::Denied,
        );
    }

    // -- Glob pattern edge cases --

    #[test]
    fn star_matches_single_level() {
        let allow = allowed(&["*.md"]);
        let deny = vec![];
        assert_eq!(
            evaluate_path(&PathBuf::from("README.md"), &allow, &deny),
            PathDecision::Allowed,
        );
        // *.md should NOT match nested paths
        assert_eq!(
            evaluate_path(&PathBuf::from("docs/guide.md"), &allow, &deny),
            PathDecision::NotMatched,
        );
    }

    #[test]
    fn double_star_matches_nested() {
        let allow = allowed(&["**/*.toml"]);
        let deny = vec![];
        assert_eq!(
            evaluate_path(&PathBuf::from("configs/deploy.toml"), &allow, &deny),
            PathDecision::Allowed,
        );
        assert_eq!(
            evaluate_path(
                &PathBuf::from("deep/nested/path/config.toml"),
                &allow,
                &deny
            ),
            PathDecision::Allowed,
        );
    }

    #[test]
    fn exact_file_deny() {
        let allow = allowed(&["src/**"]);
        let deny = allowed(&["Cargo.lock"]);
        assert_eq!(
            evaluate_path(&PathBuf::from("Cargo.lock"), &allow, &deny),
            PathDecision::Denied,
        );
        assert_eq!(
            evaluate_path(&PathBuf::from("src/lib.rs"), &allow, &deny),
            PathDecision::Allowed,
        );
    }

    #[test]
    fn empty_allow_denies_everything() {
        let allow: Vec<GlobPattern> = vec![];
        let deny = vec![];
        assert_eq!(
            evaluate_path(&PathBuf::from("anything.rs"), &allow, &deny),
            PathDecision::NotMatched,
        );
    }

    // -- compile_patterns --

    #[test]
    fn compile_valid_patterns() {
        let patterns: Vec<String> = vec!["src/**".into(), "*.md".into()];
        let compiled = compile_patterns(&patterns).unwrap();
        assert_eq!(compiled.len(), 2);
        assert_eq!(compiled[0].as_str(), "src/**");
    }

    #[test]
    fn compile_invalid_pattern_errors() {
        let patterns: Vec<String> = vec!["[invalid".into()];
        assert!(compile_patterns(&patterns).is_err());
    }

    // -- Manifest-realistic scenarios (from fs_read.yaml / fs_write.yaml) --

    #[test]
    fn fs_read_manifest_patterns() {
        let allow = allowed(&["src/**", "docs/**", "*.md", "*.toml"]);
        let deny = allowed(&[
            "**/.env",
            "**/.env.*",
            "**/secrets/**",
            "**/.git/config",
            "**/.ssh/**",
            "**/.aws/credentials",
        ]);

        assert_eq!(
            evaluate_path(&PathBuf::from("src/main.rs"), &allow, &deny),
            PathDecision::Allowed
        );
        assert_eq!(
            evaluate_path(&PathBuf::from("docs/guide.md"), &allow, &deny),
            PathDecision::Allowed
        );
        assert_eq!(
            evaluate_path(&PathBuf::from("README.md"), &allow, &deny),
            PathDecision::Allowed
        );
        assert_eq!(
            evaluate_path(&PathBuf::from("Cargo.toml"), &allow, &deny),
            PathDecision::Allowed
        );
        assert_eq!(
            evaluate_path(&PathBuf::from("src/.env"), &allow, &deny),
            PathDecision::Denied
        );
        assert_eq!(
            evaluate_path(&PathBuf::from("src/.env.production"), &allow, &deny),
            PathDecision::Denied
        );
        assert_eq!(
            evaluate_path(&PathBuf::from("src/secrets/api_key"), &allow, &deny),
            PathDecision::Denied
        );
        assert_eq!(
            evaluate_path(&PathBuf::from(".ssh/id_rsa"), &allow, &deny),
            PathDecision::Denied
        );
        assert_eq!(
            evaluate_path(&PathBuf::from(".aws/credentials"), &allow, &deny),
            PathDecision::Denied
        );
        assert_eq!(
            evaluate_path(&PathBuf::from("random/file.txt"), &allow, &deny),
            PathDecision::NotMatched
        );
    }

    // -- evaluate_path_detailed --

    #[test]
    fn detailed_returns_deny_pattern() {
        let allow = allowed(&["src/**"]);
        let deny = allowed(&["**/.env", "**/secrets/**"]);
        match evaluate_path_detailed(&PathBuf::from("src/.env"), &allow, &deny) {
            DetailedPathDecision::Denied { pattern } => {
                assert_eq!(pattern, "**/.env");
            }
            other => panic!("expected Denied, got: {other:?}"),
        }
    }

    #[test]
    fn detailed_returns_allow_pattern() {
        let allow = allowed(&["src/**", "docs/**"]);
        let deny = vec![];
        match evaluate_path_detailed(&PathBuf::from("docs/guide.md"), &allow, &deny) {
            DetailedPathDecision::Allowed { pattern } => {
                assert_eq!(pattern, "docs/**");
            }
            other => panic!("expected Allowed, got: {other:?}"),
        }
    }

    #[test]
    fn detailed_not_matched() {
        let allow = allowed(&["src/**"]);
        let deny = vec![];
        assert_eq!(
            evaluate_path_detailed(&PathBuf::from("other.txt"), &allow, &deny),
            DetailedPathDecision::NotMatched,
        );
    }

    // =======================================================================
    // validate_path_glob_entry — reject cases
    // =======================================================================

    #[test]
    fn validate_glob_rejects_empty() {
        assert!(matches!(
            validate_path_glob_entry(""),
            Err(PathGlobValidationError::Empty)
        ));
        assert!(matches!(
            validate_path_glob_entry("   "),
            Err(PathGlobValidationError::Empty)
        ));
    }

    #[test]
    fn validate_glob_rejects_absolute() {
        assert!(matches!(
            validate_path_glob_entry("/etc/passwd"),
            Err(PathGlobValidationError::Absolute)
        ));
        assert!(matches!(
            validate_path_glob_entry("/root/**"),
            Err(PathGlobValidationError::Absolute)
        ));
    }

    #[test]
    fn validate_glob_rejects_catch_all() {
        assert!(matches!(
            validate_path_glob_entry("*"),
            Err(PathGlobValidationError::CatchAll(_))
        ));
        assert!(matches!(
            validate_path_glob_entry("**"),
            Err(PathGlobValidationError::CatchAll(_))
        ));
        assert!(matches!(
            validate_path_glob_entry("**/*"),
            Err(PathGlobValidationError::CatchAll(_))
        ));
    }

    #[test]
    fn validate_glob_rejects_null_byte() {
        assert!(matches!(
            validate_path_glob_entry("src/\0evil"),
            Err(PathGlobValidationError::NullByte(4))
        ));
    }

    #[test]
    fn validate_glob_rejects_control_chars() {
        assert!(matches!(
            validate_path_glob_entry("src/\x01evil"),
            Err(PathGlobValidationError::ControlCharacter(1, 4))
        ));
    }

    #[test]
    fn validate_glob_rejects_traversal() {
        assert!(matches!(
            validate_path_glob_entry("../foo"),
            Err(PathGlobValidationError::ParentTraversal)
        ));
        assert!(matches!(
            validate_path_glob_entry("src/../../etc"),
            Err(PathGlobValidationError::ParentTraversal)
        ));
    }

    #[test]
    fn validate_glob_allows_dotdot_in_segment_name() {
        assert!(validate_path_glob_entry("a../foo").is_ok());
    }

    #[test]
    fn validate_glob_rejects_sensitive_env() {
        assert!(matches!(
            validate_path_glob_entry(".env"),
            Err(PathGlobValidationError::SensitiveTarget(_))
        ));
        assert!(matches!(
            validate_path_glob_entry(".env.production"),
            Err(PathGlobValidationError::SensitiveTarget(_))
        ));
        assert!(matches!(
            validate_path_glob_entry(".env.*"),
            Err(PathGlobValidationError::SensitiveTarget(_))
        ));
    }

    #[test]
    fn validate_glob_rejects_sensitive_dirs() {
        assert!(matches!(
            validate_path_glob_entry(".ssh/**"),
            Err(PathGlobValidationError::SensitiveTarget(_))
        ));
        assert!(matches!(
            validate_path_glob_entry(".git/config"),
            Err(PathGlobValidationError::SensitiveTarget(_))
        ));
        assert!(matches!(
            validate_path_glob_entry(".aws/credentials"),
            Err(PathGlobValidationError::SensitiveTarget(_))
        ));
        assert!(matches!(
            validate_path_glob_entry(".latchgate/**"),
            Err(PathGlobValidationError::SensitiveTarget(_))
        ));
        assert!(matches!(
            validate_path_glob_entry(".gnupg/**"),
            Err(PathGlobValidationError::SensitiveTarget(_))
        ));
        assert!(matches!(
            validate_path_glob_entry(".config/latchgate"),
            Err(PathGlobValidationError::SensitiveTarget(_))
        ));
    }

    // =======================================================================
    // validate_path_glob_entry — accept cases
    // =======================================================================

    #[test]
    fn validate_glob_accepts_normal_patterns() {
        assert!(validate_path_glob_entry("src/**").is_ok());
        assert!(validate_path_glob_entry("docs/**").is_ok());
        assert!(validate_path_glob_entry("*.json").is_ok());
        assert!(validate_path_glob_entry("data/reports/*.csv").is_ok());
        assert!(validate_path_glob_entry("docs/report.md").is_ok());
        assert!(validate_path_glob_entry("docs/*").is_ok());
    }

    #[test]
    fn validate_glob_allows_env_in_subdirectory() {
        // "src/.env" is not a sensitive-target match because the first
        // segment is "src", not ".env". Runtime deny list handles it.
        assert!(validate_path_glob_entry("src/.env").is_ok());
    }

    #[test]
    fn validate_glob_allows_non_sensitive_dot_dirs() {
        assert!(validate_path_glob_entry(".github/**").is_ok());
        assert!(validate_path_glob_entry(".vscode/**").is_ok());
        assert!(validate_path_glob_entry(".cargo/**").is_ok());
    }

    // =======================================================================
    // targets_sensitive_location — edge cases
    // =======================================================================

    #[test]
    fn sensitive_no_false_positive_on_prefix_overlap() {
        // ".environment" should NOT match ".env" — the next char is 'i', not '.' or '*'.
        assert!(targets_sensitive_location(".environment").is_none());
        // ".gitter" should NOT match ".git".
        assert!(targets_sensitive_location(".gitter").is_none());
        // ".sshconfig" should NOT match ".ssh".
        assert!(targets_sensitive_location(".sshconfig").is_none());
    }

    #[test]
    fn sensitive_matches_exact_and_glob() {
        assert!(targets_sensitive_location(".env").is_some());
        assert!(targets_sensitive_location(".env.local").is_some());
        assert!(targets_sensitive_location(".env*").is_some());
        assert!(targets_sensitive_location(".ssh/id_rsa").is_some());
        assert!(targets_sensitive_location(".git/**").is_some());
    }

    // =======================================================================
    // relativize_to_root
    // =======================================================================

    #[test]
    fn relativize_strips_root_prefix() {
        let root = PathBuf::from("/home/user");
        assert_eq!(
            relativize_to_root("/home/user/projects/foo.rs", &root),
            Some("projects/foo.rs".into()),
        );
    }

    #[test]
    fn relativize_nested_subpath() {
        let root = PathBuf::from("/home/user");
        assert_eq!(
            relativize_to_root("/home/user/a/b/c/d.txt", &root),
            Some("a/b/c/d.txt".into()),
        );
    }

    #[test]
    fn relativize_passes_through_relative_paths() {
        let root = PathBuf::from("/home/user");
        assert_eq!(
            relativize_to_root("src/main.rs", &root),
            Some("src/main.rs".into()),
        );
    }

    #[test]
    fn relativize_rejects_outside_root() {
        let root = PathBuf::from("/home/user");
        assert_eq!(relativize_to_root("/etc/passwd", &root), None);
    }

    #[test]
    fn relativize_rejects_sibling_directory() {
        let root = PathBuf::from("/home/user");
        assert_eq!(relativize_to_root("/home/other/file.txt", &root), None);
    }

    #[test]
    fn relativize_rejects_exact_root() {
        // Path == root itself is not a valid glob target.
        let root = PathBuf::from("/home/user");
        assert_eq!(relativize_to_root("/home/user", &root), None);
    }

    #[test]
    fn relativize_rejects_root_with_trailing_slash() {
        let root = PathBuf::from("/home/user");
        // Path::strip_prefix normalises this — "/home/user/" strip "/home/user" = "".
        assert_eq!(relativize_to_root("/home/user/", &root), None);
    }
}
