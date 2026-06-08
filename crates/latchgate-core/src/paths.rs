//! Platform-aware path resolution for LatchGate install locations.
//!
//! Three canonical locations with explicit precedence:
//!
//! 1. `--config <path>` / `$LATCHGATE_CONFIG` (explicit override)
//! 2. `$PWD/.latchgate/latchgate.toml` (project-local)
//! 3. `$XDG_CONFIG_HOME/latchgate/latchgate.toml` (user-global)
//!
//! Data, cache, and runtime directories follow XDG conventions on Linux
//! and platform-native conventions on macOS.

use std::path::{Path, PathBuf};

/// Project-local install directory (`.latchgate/` under a project root).
#[derive(Debug, Clone)]
pub struct ProjectDirs {
    root: PathBuf,
}

impl ProjectDirs {
    pub fn from_cwd() -> Result<Self, PathError> {
        let cwd = std::env::current_dir().map_err(PathError::Io)?;
        Ok(Self::from_root(cwd))
    }

    pub fn from_root(project_root: PathBuf) -> Self {
        Self { root: project_root }
    }

    pub fn install_dir(&self) -> PathBuf {
        self.root.join(".latchgate")
    }

    pub fn config_file(&self) -> PathBuf {
        self.install_dir().join("latchgate.toml")
    }

    pub fn manifests_dir(&self) -> PathBuf {
        self.install_dir().join("manifests")
    }

    pub fn policies_dir(&self) -> PathBuf {
        self.install_dir().join("policies")
    }

    pub fn providers_dir(&self) -> PathBuf {
        self.install_dir().join("providers")
    }

    pub fn operators_dir(&self) -> PathBuf {
        self.install_dir().join("operators")
    }

    pub fn data_dir(&self) -> PathBuf {
        self.install_dir().join("data")
    }

    pub fn keys_dir(&self) -> PathBuf {
        self.operators_dir().join("keys")
    }
}

/// LatchGate source repo detected at CWD.
///
/// Resources resolve to the repo layout (`definitions/manifests/`, `target/providers/`,
/// `policies/opa/`) so developers never need `.latchgate/` or `~/.config/latchgate/`.
#[derive(Debug, Clone)]
pub struct DevWorkspace {
    root: PathBuf,
}

impl DevWorkspace {
    /// Detect a latchgate workspace at `dir`.
    ///
    /// Positive when `Cargo.toml` exists and `crates/` contains at least one
    /// entry starting with `latchgate-`.
    pub fn detect(dir: &Path) -> Option<Self> {
        if !dir.join("Cargo.toml").is_file() {
            return None;
        }
        let crates_dir = dir.join("crates");
        let has_latchgate_crate = crates_dir.read_dir().ok()?.any(|entry| {
            entry
                .ok()
                .and_then(|e| e.file_name().to_str().map(|n| n.starts_with("latchgate-")))
                .unwrap_or(false)
        });
        if has_latchgate_crate {
            Some(Self {
                root: dir.to_path_buf(),
            })
        } else {
            None
        }
    }

    /// Detect from CWD.
    pub fn detect_cwd() -> Option<Self> {
        let cwd = std::env::current_dir().ok()?;
        Self::detect(&cwd)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn manifests_dir(&self) -> PathBuf {
        self.root.join("definitions/manifests")
    }

    pub fn policies_dir(&self) -> PathBuf {
        self.root.join("definitions/policies/opa")
    }

    pub fn providers_dir(&self) -> PathBuf {
        self.root.join("target/providers")
    }

    pub fn data_dir(&self) -> PathBuf {
        self.root.join(".latchgate/data")
    }
}

/// Linux: `$XDG_RUNTIME_DIR/latchgate/`
/// macOS / fallback: `/tmp/latchgate-<uid>/`
///
/// Both the CLI (`latchgate up`, `latchgate init`) and the SDKs (Python,
/// TypeScript) must use the same algorithm. If you change this, update
/// `sdk/python/latchgate/_client.py` and `sdk/typescript/src/client.ts`.
pub fn resolve_runtime_dir() -> Result<PathBuf, PathError> {
    let xdg = std::env::var("XDG_RUNTIME_DIR").ok();
    resolve_runtime_dir_inner(xdg.as_deref())
}

/// Inner implementation that accepts the XDG value directly.
/// Testable without mutating the process environment.
fn resolve_runtime_dir_inner(xdg_runtime_dir: Option<&str>) -> Result<PathBuf, PathError> {
    if let Some(xdg_rt) = xdg_runtime_dir {
        if !xdg_rt.is_empty() {
            return Ok(PathBuf::from(xdg_rt).join("latchgate"));
        }
    }

    #[cfg(unix)]
    {
        let uid = rustix::process::getuid().as_raw();
        return Ok(PathBuf::from(format!("/tmp/latchgate-{uid}")));
    }

    #[allow(unreachable_code)]
    Ok(std::env::temp_dir().join("latchgate"))
}

/// Default path for the client UDS socket.
///
/// Resolves to `{runtime_dir}/gate.sock` where `runtime_dir` is determined
/// by [`resolve_runtime_dir`].
pub fn default_uds_path() -> PathBuf {
    resolve_runtime_dir()
        .unwrap_or_else(|_| PathBuf::from("/tmp/latchgate"))
        .join("gate.sock")
}

/// Default path for the admin UDS socket.
///
/// Resolves to `{runtime_dir}/gate-admin.sock` where `runtime_dir` is
/// determined by [`resolve_runtime_dir`].
pub fn default_admin_uds_path() -> PathBuf {
    resolve_runtime_dir()
        .unwrap_or_else(|_| PathBuf::from("/tmp/latchgate"))
        .join("gate-admin.sock")
}

#[derive(Debug, thiserror::Error)]
pub enum PathError {
    #[error(
        "cannot determine home directory — is $HOME set? \
         LatchGate refuses to start without a known home directory"
    )]
    HomeNotFound,

    #[error("path traversal rejected: {path} escapes root {root}")]
    Traversal { path: PathBuf, root: PathBuf },

    #[error("path resolution failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Verify that `path` resolves to within `root` after symlink resolution.
///
/// Both paths are canonicalized (symlinks followed, `..` resolved) before
/// comparison. Returns the canonical path on success.
///
/// Rejects symlinks or relative components that escape the merge root —
/// a manifest in `manifests/` must not resolve to `/etc/shadow` via a
/// symlink, and a schema path like `../../secrets.json` must not escape
/// the manifest directory.
#[must_use = "discarding the result skips path traversal protection"]
pub fn ensure_contained(root: &Path, path: &Path) -> Result<PathBuf, PathError> {
    let canonical_root = root.canonicalize().map_err(PathError::Io)?;
    let canonical_path = path.canonicalize().map_err(PathError::Io)?;

    if !canonical_path.starts_with(&canonical_root) {
        return Err(PathError::Traversal {
            path: canonical_path,
            root: canonical_root,
        });
    }

    Ok(canonical_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_dirs_layout() {
        let pd = ProjectDirs::from_root(PathBuf::from("/srv/myproject"));
        assert_eq!(
            pd.config_file(),
            PathBuf::from("/srv/myproject/.latchgate/latchgate.toml")
        );
        assert_eq!(
            pd.manifests_dir(),
            PathBuf::from("/srv/myproject/.latchgate/manifests")
        );
        assert_eq!(
            pd.data_dir(),
            PathBuf::from("/srv/myproject/.latchgate/data")
        );
        assert_eq!(
            pd.operators_dir(),
            PathBuf::from("/srv/myproject/.latchgate/operators")
        );
        assert_eq!(
            pd.keys_dir(),
            PathBuf::from("/srv/myproject/.latchgate/operators/keys")
        );
    }

    #[cfg(unix)]
    #[test]
    fn runtime_dir_respects_xdg() {
        let dir = super::resolve_runtime_dir_inner(Some("/run/user/1000")).unwrap();
        assert_eq!(dir, PathBuf::from("/run/user/1000/latchgate"));
    }

    #[cfg(unix)]
    #[test]
    fn runtime_dir_ignores_empty_xdg() {
        let dir = super::resolve_runtime_dir_inner(Some("")).unwrap();
        // Must fall through to /tmp/latchgate-{uid}, not produce "/latchgate".
        assert!(
            !dir.starts_with("/latchgate"),
            "empty XDG_RUNTIME_DIR should be ignored, got: {}",
            dir.display()
        );
    }

    #[cfg(unix)]
    #[test]
    fn default_uds_path_uses_xdg() {
        let dir = super::resolve_runtime_dir_inner(Some("/run/user/1000")).unwrap();
        let path = dir.join("gate.sock");
        assert_eq!(path, PathBuf::from("/run/user/1000/latchgate/gate.sock"));

        let admin = dir.join("gate-admin.sock");
        assert_eq!(
            admin,
            PathBuf::from("/run/user/1000/latchgate/gate-admin.sock")
        );
    }

    #[cfg(unix)]
    #[test]
    fn default_uds_path_falls_back_to_tmp() {
        let dir = super::resolve_runtime_dir_inner(None).unwrap();
        let path = dir.join("gate.sock");
        let uid = rustix::process::getuid().as_raw();
        assert_eq!(
            path,
            PathBuf::from(format!("/tmp/latchgate-{uid}/gate.sock"))
        );
    }

    #[test]
    fn ensure_contained_accepts_child() {
        let dir = tempfile::tempdir().unwrap();
        let child = dir.path().join("inner.txt");
        std::fs::write(&child, "ok").unwrap();

        let result = ensure_contained(dir.path(), &child);
        assert!(result.is_ok());
    }

    #[test]
    fn ensure_contained_accepts_nested_child() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        let child = sub.join("deep.txt");
        std::fs::write(&child, "ok").unwrap();

        let result = ensure_contained(dir.path(), &child);
        assert!(result.is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn ensure_contained_rejects_symlink_escape() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("secret.txt");
        std::fs::write(&target, "secret").unwrap();

        let link = root.path().join("escape.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let result = ensure_contained(root.path(), &link);
        assert!(matches!(result, Err(PathError::Traversal { .. })));
    }

    #[test]
    fn ensure_contained_rejects_nonexistent() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.txt");
        let result = ensure_contained(dir.path(), &missing);
        assert!(matches!(result, Err(PathError::Io(_))));
    }

    #[test]
    fn dev_workspace_detects_latchgate_repo() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "[workspace]").unwrap();
        let crates = tmp.path().join("crates/latchgate-core");
        std::fs::create_dir_all(&crates).unwrap();

        let ws = DevWorkspace::detect(tmp.path());
        assert!(ws.is_some());
        let ws = ws.unwrap();
        assert_eq!(ws.manifests_dir(), tmp.path().join("definitions/manifests"));
        assert_eq!(ws.providers_dir(), tmp.path().join("target/providers"));
        assert_eq!(
            ws.policies_dir(),
            tmp.path().join("definitions/policies/opa")
        );
    }

    #[test]
    fn dev_workspace_rejects_non_latchgate_repo() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "[workspace]").unwrap();
        let crates = tmp.path().join("crates/some-other-crate");
        std::fs::create_dir_all(&crates).unwrap();

        assert!(DevWorkspace::detect(tmp.path()).is_none());
    }

    #[test]
    fn dev_workspace_rejects_no_cargo_toml() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(DevWorkspace::detect(tmp.path()).is_none());
    }
}
