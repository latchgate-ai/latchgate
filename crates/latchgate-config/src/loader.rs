//! Configuration loading and path resolution.
//!
//! Discovery chain: `$LATCHGATE_CONFIG` → dev workspace → project-local →
//! user-global (XDG) → compiled defaults. Environment variable overrides
//! are applied after TOML parsing at every discovery level.

use std::path::{Path, PathBuf};

use super::error::ConfigError;
use super::Config;

/// Process-wide cached result of the unsafe-dev double gate.
static UNSAFE_DEV_RESOLVED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

pub(crate) fn is_unsafe_dev() -> bool {
    *UNSAFE_DEV_RESOLVED.get_or_init(|| {
        #[cfg(feature = "unsafe-dev")]
        {
            let active = matches!(
                std::env::var("LATCHGATE_UNSAFE_DEV").ok().as_deref(),
                Some(v) if v.eq_ignore_ascii_case("true") || v == "1"
            );
            if active {
                tracing::error!(
                    "UNSAFE DEV MODE ACTIVE — auth bypass enabled, sandbox relaxed. \
                     This binary was compiled with the `unsafe-dev` feature. \
                     Never deploy this build."
                );
            }
            active
        }
        #[cfg(not(feature = "unsafe-dev"))]
        {
            false
        }
    })
}

impl Config {
    /// Deserialize from TOML file, apply env overrides. No path resolution.
    fn parse_file(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        let mut config: Self =
            toml::from_str(&contents).map_err(|e| ConfigError::Parse { source: e })?;
        config.apply_env_overrides()?;
        Ok(config)
    }

    /// Load from an explicit file path.
    ///
    /// Precedence (highest wins): env vars > TOML file > compiled defaults.
    /// Empty path fields are resolved relative to the config file's parent.
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let mut config = Self::parse_file(path)?;
        config.source = crate::ConfigSource::Explicit(path.to_path_buf());
        config.resolve_default_paths();
        config.canonicalize_fs_root_prefixes();
        Ok(config)
    }

    /// Load config with automatic discovery.
    ///
    /// Discovery order (first existing match wins):
    ///   1. `$LATCHGATE_CONFIG` environment variable
    ///   2. Dev workspace — CWD is latchgate source repo (auto `dev_mode`)
    ///   3. `$PWD/.latchgate/latchgate.toml` (project-local)
    ///   4. `$XDG_CONFIG_HOME/latchgate/latchgate.toml` (user-global)
    ///   5. Built-in defaults with paths resolved from install context
    pub fn load() -> Result<Self, ConfigError> {
        // 1. Explicit override.
        if let Ok(path) = std::env::var("LATCHGATE_CONFIG") {
            return Self::from_file(Path::new(&path));
        }

        // 2. Dev workspace — CWD is the latchgate source repo.
        if let Some(ws) = latchgate_core::paths::DevWorkspace::detect_cwd() {
            let project_config = ws.root().join(".latchgate/latchgate.toml");
            let mut config = if project_config.exists() {
                let mut parsed = Self::parse_file(&project_config)?;
                parsed.manifests_dir = String::new();
                parsed.wasm_providers_dir = String::new();
                parsed.storage.ledger_db_path = String::new();
                parsed.source = crate::ConfigSource::DevWorkspace(ws);
                parsed
            } else {
                Self {
                    source: crate::ConfigSource::DevWorkspace(ws),
                    ..Self::default()
                }
            };
            config.resolve_default_paths();
            config.apply_env_overrides()?;
            config.canonicalize_fs_root_prefixes();
            return Ok(config);
        }

        // 3. Project-local.
        if let Ok(project) = latchgate_core::paths::ProjectDirs::from_cwd() {
            let project_config = project.config_file();
            if project_config.exists() {
                let mut config = Self::parse_file(&project_config)?;
                config.source = crate::ConfigSource::Project(project);
                config.resolve_default_paths();
                config.canonicalize_fs_root_prefixes();
                return Ok(config);
            }
        }

        // 4. User-global (XDG).
        if let Ok(user) = crate::UserDirs::resolve() {
            let user_config = user.config_file();
            if user_config.exists() {
                let mut config = Self::parse_file(&user_config)?;
                config.source = crate::ConfigSource::UserGlobal(user);
                config.resolve_default_paths();
                config.canonicalize_fs_root_prefixes();
                return Ok(config);
            }
        }

        // 5. Defaults with resolved paths.
        let mut config = Self::default();
        config.resolve_default_paths();
        config.apply_env_overrides()?;
        config.canonicalize_fs_root_prefixes();
        Ok(config)
    }

    /// Fill in empty path fields from the install context.
    fn resolve_default_paths(&mut self) {
        if self.manifests_dir.is_empty() {
            self.manifests_dir = self.source.default_manifests_dir().display().to_string();
        }
        if self.wasm_providers_dir.is_empty() {
            self.wasm_providers_dir = self.source.default_providers_dir().display().to_string();
        }
        if self.storage.ledger_db_path.is_empty() {
            self.storage.ledger_db_path =
                self.source.default_ledger_db_path().display().to_string();
        }
    }

    /// Ordered manifest directories for registry merge.
    pub fn manifest_dirs(&self) -> Vec<PathBuf> {
        let mut dirs = Vec::new();
        if matches!(&self.source, crate::ConfigSource::Project(_)) {
            if let Ok(user) = crate::UserDirs::resolve() {
                let user_dir = user.config_dir().join("manifests");
                let primary = PathBuf::from(&self.manifests_dir);
                if user_dir != primary {
                    dirs.push(user_dir);
                }
            }
        }
        dirs.push(PathBuf::from(&self.manifests_dir));
        dirs
    }

    /// Ordered provider directories for WASM module merge.
    pub fn provider_dirs(&self) -> Vec<PathBuf> {
        let mut dirs = Vec::new();
        if matches!(&self.source, crate::ConfigSource::Project(_)) {
            if let Ok(user) = crate::UserDirs::resolve() {
                let user_dir = user.config_dir().join("providers");
                let primary = PathBuf::from(&self.wasm_providers_dir);
                if user_dir != primary {
                    dirs.push(user_dir);
                }
            }
        }
        dirs.push(PathBuf::from(&self.wasm_providers_dir));
        dirs
    }
}
