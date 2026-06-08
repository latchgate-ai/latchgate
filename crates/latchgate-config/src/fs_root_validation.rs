//! Per-session filesystem root validation.
//!
//! Called at lease issuance time to validate a client-requested `fs_root`.
//! This is a pure function of (requested path, config) → Result<canonical>.
//!
//! # Security properties
//!
//! - Rejects relative paths (ambiguous — depends on gate CWD, not client CWD)
//! - Rejects non-existent or non-directory paths
//! - Canonicalizes (resolves symlinks) before all checks
//! - Rejects system directories via hardcoded blocklist
//! - Rejects paths outside operator-configured allowed prefixes
//! - Returns the canonical path for downstream storage and enforcement

use std::path::{Path, PathBuf};

use latchgate_core::security_constants::FS_ROOT_BLOCKED_PATHS;

/// Errors from per-session `fs_root` validation.
///
/// Each variant maps to a specific HTTP status code in the API layer.
#[derive(Debug, thiserror::Error)]
pub enum FsRootError {
    /// 400: structurally invalid (relative, non-existent, not a directory).
    #[error("invalid fs_root: {reason}")]
    Invalid { reason: String },

    /// 403: valid path but policy-denied (outside prefixes or blocklisted).
    #[error("fs_root denied: {reason}")]
    Denied { reason: String },
}

/// Validate a client-requested per-session filesystem root.
///
/// Returns the canonicalized path on success.
///
/// # Steps
///
/// 1. Reject empty / relative paths
/// 2. `stat()` — must exist and be a directory
/// 3. `canonicalize()` — resolve all symlinks
/// 4. Blocklist — reject known system directories
/// 5. Allowlist — canonical path must start with an allowed prefix
pub fn validate_session_fs_root(
    requested: &str,
    allowed_prefixes: &[PathBuf],
) -> Result<PathBuf, FsRootError> {
    // Step 1: reject empty and relative paths.
    if requested.is_empty() {
        return Err(FsRootError::Invalid {
            reason: "empty path".into(),
        });
    }

    let path = Path::new(requested);

    if !path.is_absolute() {
        return Err(FsRootError::Invalid {
            reason: format!("must be absolute, got: {requested}"),
        });
    }

    // Step 2: must exist and be a directory.
    let metadata = std::fs::metadata(path).map_err(|e| FsRootError::Invalid {
        reason: format!("does not exist or not accessible: {e}"),
    })?;

    if !metadata.is_dir() {
        return Err(FsRootError::Invalid {
            reason: format!("not a directory: {requested}"),
        });
    }

    // Step 3: canonicalize (resolve symlinks).
    let canonical = path.canonicalize().map_err(|e| FsRootError::Invalid {
        reason: format!("canonicalization failed: {e}"),
    })?;

    // Step 4: blocklist — exact match against canonical path.
    for blocked in FS_ROOT_BLOCKED_PATHS {
        if canonical == Path::new(blocked) {
            return Err(FsRootError::Denied {
                reason: format!("system directory: {}", canonical.display()),
            });
        }
    }

    // Step 5: allowlist — canonical must start with at least one prefix.
    if allowed_prefixes.is_empty() {
        return Err(FsRootError::Denied {
            reason: "per-session fs_root is disabled \
                     (fs_root_allowed_prefixes is empty)"
                .into(),
        });
    }

    let allowed = allowed_prefixes
        .iter()
        .any(|prefix| canonical.starts_with(prefix));

    if !allowed {
        return Err(FsRootError::Denied {
            reason: format!("outside allowed prefixes: {}", canonical.display()),
        });
    }

    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// Helper: create a temporary directory under `parent` and return its path.
    fn make_dir(parent: &Path, name: &str) -> PathBuf {
        let dir = parent.join(name);
        std::fs::create_dir_all(&dir).expect("create test dir");
        dir
    }

    /// Helper: create a regular file under `parent`.
    fn make_file(parent: &Path, name: &str) -> PathBuf {
        let file = parent.join(name);
        std::fs::write(&file, b"").expect("create test file");
        file
    }

    // --- Structural validation (step 1–2) ---

    #[test]
    fn rejects_empty_path() {
        let err = validate_session_fs_root("", &[]).unwrap_err();
        assert!(matches!(err, FsRootError::Invalid { .. }));
    }

    #[test]
    fn rejects_relative_path() {
        let err = validate_session_fs_root("./foo", &[]).unwrap_err();
        assert!(matches!(err, FsRootError::Invalid { .. }));

        let err = validate_session_fs_root("foo/bar", &[]).unwrap_err();
        assert!(matches!(err, FsRootError::Invalid { .. }));
    }

    #[test]
    fn rejects_nonexistent_path() {
        let err = validate_session_fs_root("/nonexistent_path_that_does_not_exist_abc123", &[])
            .unwrap_err();
        assert!(matches!(err, FsRootError::Invalid { .. }));
    }

    #[test]
    fn rejects_file_not_directory() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let file = make_file(tmp.path(), "regular.txt");
        let prefixes = vec![tmp.path().canonicalize().unwrap()];

        let err = validate_session_fs_root(file.to_str().unwrap(), &prefixes).unwrap_err();
        assert!(
            matches!(err, FsRootError::Invalid { ref reason } if reason.contains("not a directory")),
            "got: {err}"
        );
    }

    // --- Blocklist (step 4) ---

    #[test]
    fn rejects_system_directories() {
        // Use /tmp as the most reliably existing system directory across CI.
        // It's in the blocklist, so even if we add it to allowed prefixes,
        // the blocklist takes precedence.
        let prefixes = vec![PathBuf::from("/")];
        for path in &["/", "/etc", "/proc", "/tmp", "/var", "/usr"] {
            if Path::new(path).exists() {
                let err = validate_session_fs_root(path, &prefixes).unwrap_err();
                assert!(
                    matches!(err, FsRootError::Denied { .. }),
                    "{path} should be denied, got: {err}"
                );
            }
        }
    }

    #[test]
    fn blocked_path_overrides_allowlist() {
        // /tmp is blocked even if it falls under an allowed prefix.
        let prefixes = vec![PathBuf::from("/")];
        if Path::new("/tmp").exists() {
            let err = validate_session_fs_root("/tmp", &prefixes).unwrap_err();
            assert!(matches!(err, FsRootError::Denied { .. }));
        }
    }

    // --- Allowlist (step 5) ---

    #[test]
    fn rejects_empty_prefix_list() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = make_dir(tmp.path(), "project");

        let err = validate_session_fs_root(dir.to_str().unwrap(), &[]).unwrap_err();
        assert!(
            matches!(err, FsRootError::Denied { ref reason } if reason.contains("disabled")),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_outside_prefixes() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let inside = make_dir(tmp.path(), "allowed/project");
        let outside = make_dir(tmp.path(), "other/project");

        let prefixes = vec![inside.parent().unwrap().canonicalize().unwrap()];

        let err = validate_session_fs_root(outside.to_str().unwrap(), &prefixes).unwrap_err();
        assert!(matches!(err, FsRootError::Denied { .. }));
    }

    // --- Happy path ---

    #[test]
    fn accepts_valid_path_under_prefix() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let project = make_dir(tmp.path(), "projects/my-app");
        let prefixes = vec![tmp.path().canonicalize().unwrap()];

        let canonical = validate_session_fs_root(project.to_str().unwrap(), &prefixes)
            .expect("should accept valid path");
        assert!(canonical.is_absolute());
        assert!(canonical.ends_with("my-app"));
    }

    // --- Symlink handling (step 3) ---

    #[test]
    fn canonicalizes_symlink_in_requested_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let real = make_dir(tmp.path(), "real-project");
        let link = tmp.path().join("link-project");
        symlink(&real, &link).expect("create symlink");

        let prefixes = vec![tmp.path().canonicalize().unwrap()];

        let canonical = validate_session_fs_root(link.to_str().unwrap(), &prefixes)
            .expect("should accept symlinked path");
        // Must return the real path, not the symlink.
        assert_eq!(canonical, real.canonicalize().unwrap());
    }

    #[test]
    fn prefix_check_uses_canonical_not_raw() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let real = make_dir(tmp.path(), "real/project");

        // Create a symlink at a sibling location pointing to `real/`.
        let link_parent = tmp.path().join("link-to-real");
        symlink(tmp.path().join("real"), &link_parent).expect("create symlink");

        // Prefix is the real parent — the symlinked request should still
        // match after canonicalization.
        let prefixes = vec![tmp.path().join("real").canonicalize().unwrap()];
        let request = link_parent.join("project");

        let canonical = validate_session_fs_root(request.to_str().unwrap(), &prefixes)
            .expect("symlinked request should match canonical prefix");
        assert_eq!(canonical, real.canonicalize().unwrap());
    }

    // --- Multiple prefixes ---

    #[test]
    fn accepts_path_matching_any_prefix() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let a = make_dir(tmp.path(), "workspace-a/proj");
        let b = make_dir(tmp.path(), "workspace-b/proj");
        let prefixes = vec![
            tmp.path().join("workspace-a").canonicalize().unwrap(),
            tmp.path().join("workspace-b").canonicalize().unwrap(),
        ];

        assert!(validate_session_fs_root(a.to_str().unwrap(), &prefixes).is_ok());
        assert!(validate_session_fs_root(b.to_str().unwrap(), &prefixes).is_ok());
    }
}
