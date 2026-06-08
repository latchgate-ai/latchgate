//! Platform-aware directory resolution for LatchGate installs.
//!
//! `UserDirs` resolves XDG / platform-native directories using the
//! `directories` crate. `ConfigSource` tracks where the active config
//! was loaded from and determines how relative paths are resolved.
//!
//! These types live in the config crate (not core) because they depend
//! on `directories` for platform detection — a dependency the leaf core
//! crate should not carry.

use std::path::{Path, PathBuf};

use latchgate_core::paths::{DevWorkspace, PathError, ProjectDirs};

/// Resolved platform directories for a user-global LatchGate install.
///
/// All paths are absolute. Construction fails if the platform cannot
/// determine a home directory (e.g. `$HOME` unset in a container).
#[derive(Debug, Clone)]
pub struct UserDirs {
    config: PathBuf,
    data: PathBuf,
    cache: PathBuf,
    runtime: PathBuf,
}

impl UserDirs {
    /// Resolve user-global directories from the platform.
    ///
    /// Fails with [`PathError::HomeNotFound`] when the home directory
    /// cannot be determined. This is intentional: silent fallback to
    /// `/tmp` or CWD would violate data-path separation.
    pub fn resolve() -> Result<Self, PathError> {
        let dirs =
            directories::ProjectDirs::from("", "", "latchgate").ok_or(PathError::HomeNotFound)?;

        Ok(Self {
            config: dirs.config_dir().to_path_buf(),
            data: dirs.data_dir().to_path_buf(),
            cache: dirs.cache_dir().to_path_buf(),
            runtime: latchgate_core::paths::resolve_runtime_dir()?,
        })
    }

    pub fn config_dir(&self) -> &Path {
        &self.config
    }

    pub fn data_dir(&self) -> &Path {
        &self.data
    }

    pub fn cache_dir(&self) -> &Path {
        &self.cache
    }

    pub fn runtime_dir(&self) -> &Path {
        &self.runtime
    }

    pub fn config_file(&self) -> PathBuf {
        self.config.join("latchgate.toml")
    }
}

/// Origin of the active configuration file.
///
/// Determines how unset path fields (`manifests_dir`, `wasm_providers_dir`,
/// `ledger_db_path`) are resolved to absolute paths at load time.
#[derive(Debug, Clone, Default)]
pub enum ConfigSource {
    /// `--config <path>` or `$LATCHGATE_CONFIG`.
    Explicit(PathBuf),
    /// LatchGate source repo detected at CWD.
    DevWorkspace(DevWorkspace),
    /// `$PWD/.latchgate/latchgate.toml`.
    Project(ProjectDirs),
    /// `$XDG_CONFIG_HOME/latchgate/latchgate.toml`.
    UserGlobal(UserDirs),
    /// No config file found; compiled defaults only.
    #[default]
    Defaults,
}

impl std::fmt::Display for ConfigSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Explicit(p) => write!(f, "explicit ({})", p.display()),
            Self::DevWorkspace(w) => write!(f, "dev-workspace ({})", w.root().display()),
            Self::Project(p) => write!(f, "project ({})", p.config_file().display()),
            Self::UserGlobal(u) => write!(f, "user-global ({})", u.config_file().display()),
            Self::Defaults => write!(f, "defaults (no config file)"),
        }
    }
}

impl ConfigSource {
    /// Config file path, if one was loaded.
    pub fn config_file(&self) -> Option<PathBuf> {
        match self {
            Self::Explicit(p) => Some(p.clone()),
            Self::DevWorkspace(_) => None,
            Self::Project(p) => Some(p.config_file()),
            Self::UserGlobal(u) => Some(u.config_file()),
            Self::Defaults => None,
        }
    }

    /// Base directory for install-relative path resolution.
    fn install_base(&self) -> PathBuf {
        match self {
            Self::DevWorkspace(w) => w.root().to_path_buf(),
            Self::Project(p) => p.install_dir(),
            Self::Explicit(path) => path.parent().unwrap_or(Path::new(".")).to_path_buf(),
            Self::UserGlobal(_) => unreachable!("user-global uses dedicated resolution"),
            Self::Defaults => std::env::current_dir()
                .map(|cwd| cwd.join(".latchgate"))
                .unwrap_or_else(|_| PathBuf::from(".latchgate")),
        }
    }

    /// Default `manifests_dir` for this install context.
    pub fn default_manifests_dir(&self) -> PathBuf {
        match self {
            Self::DevWorkspace(w) => w.manifests_dir(),
            Self::UserGlobal(u) => u.config_dir().join("manifests"),
            _ => self.install_base().join("manifests"),
        }
    }

    /// Default `wasm_providers_dir` for this install context.
    pub fn default_providers_dir(&self) -> PathBuf {
        match self {
            Self::DevWorkspace(w) => w.providers_dir(),
            Self::UserGlobal(u) => u.config_dir().join("providers"),
            _ => self.install_base().join("providers"),
        }
    }

    /// Default `ledger_db_path` for this install context.
    pub fn default_ledger_db_path(&self) -> PathBuf {
        match self {
            Self::DevWorkspace(w) => w.data_dir().join("audit.db"),
            Self::UserGlobal(u) => u.data_dir().join("audit.db"),
            _ => self.install_base().join("data").join("audit.db"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_dirs_resolve_does_not_panic() {
        let _ = UserDirs::resolve();
    }

    #[test]
    fn config_source_project_paths() {
        let pd = ProjectDirs::from_root(PathBuf::from("/srv/app"));
        let src = ConfigSource::Project(pd);
        assert_eq!(
            src.default_manifests_dir(),
            PathBuf::from("/srv/app/.latchgate/manifests")
        );
        assert_eq!(
            src.default_providers_dir(),
            PathBuf::from("/srv/app/.latchgate/providers")
        );
        assert_eq!(
            src.default_ledger_db_path(),
            PathBuf::from("/srv/app/.latchgate/data/audit.db")
        );
    }

    #[test]
    fn config_source_explicit_paths() {
        let src = ConfigSource::Explicit(PathBuf::from("/opt/latchgate/latchgate.toml"));
        assert_eq!(
            src.default_manifests_dir(),
            PathBuf::from("/opt/latchgate/manifests")
        );
        assert_eq!(
            src.default_providers_dir(),
            PathBuf::from("/opt/latchgate/providers")
        );
        assert_eq!(
            src.default_ledger_db_path(),
            PathBuf::from("/opt/latchgate/data/audit.db")
        );
    }

    #[test]
    fn config_source_display() {
        assert_eq!(
            format!("{}", ConfigSource::Defaults),
            "defaults (no config file)"
        );
        let src = ConfigSource::Explicit(PathBuf::from("/etc/latchgate.toml"));
        assert!(format!("{src}").contains("/etc/latchgate.toml"));
    }

    #[test]
    fn config_source_config_file() {
        assert!(ConfigSource::Defaults.config_file().is_none());
        assert_eq!(
            ConfigSource::Explicit(PathBuf::from("/a/b.toml")).config_file(),
            Some(PathBuf::from("/a/b.toml"))
        );
    }

    #[test]
    fn config_source_dev_workspace_paths() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "[workspace]").unwrap();
        std::fs::create_dir_all(tmp.path().join("crates/latchgate-cli")).unwrap();
        let ws = DevWorkspace::detect(tmp.path()).unwrap();
        let src = ConfigSource::DevWorkspace(ws);
        assert!(src.config_file().is_none());
        assert_eq!(
            src.default_manifests_dir(),
            tmp.path().join("definitions/manifests")
        );
        assert_eq!(
            src.default_providers_dir(),
            tmp.path().join("target/providers")
        );
        assert_eq!(
            src.default_ledger_db_path(),
            tmp.path().join(".latchgate/data/audit.db")
        );
    }
}
