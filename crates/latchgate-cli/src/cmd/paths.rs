//! Config file and socket path resolution.

use std::path::PathBuf;

/// Resolve the config file path for editing.
///
/// Discovery mirrors `Config::load()`: explicit arg => `$LATCHGATE_CONFIG`
/// => `.latchgate/latchgate.toml` => XDG user config.
pub fn resolve_config_path(explicit: Option<&str>) -> Result<PathBuf, String> {
    if let Some(p) = explicit {
        let path = PathBuf::from(p);
        if !path.exists() {
            return Err(format!("{} does not exist", path.display()));
        }
        return Ok(path);
    }

    if let Ok(env_path) = std::env::var("LATCHGATE_CONFIG") {
        let path = PathBuf::from(&env_path);
        if !path.exists() {
            return Err(format!(
                "LATCHGATE_CONFIG={env_path} but file does not exist"
            ));
        }
        return Ok(path);
    }

    // Project-local.
    if let Ok(project) = latchgate_core::paths::ProjectDirs::from_cwd() {
        let path = project.config_file();
        if path.exists() {
            return Ok(path);
        }
    }

    // User-global (XDG).
    if let Ok(user) = latchgate_config::UserDirs::resolve() {
        let path = user.config_file();
        if path.exists() {
            return Ok(path);
        }
    }

    Err("no config found — run 'latchgate init' first, or use --config <PATH>".to_string())
}

/// Default path for the client UDS socket.
///
/// Delegates to [`latchgate_core::paths::default_uds_path`] — the single
/// source of truth shared by the CLI, MCP server, and SDKs.
pub fn default_uds_path() -> PathBuf {
    latchgate_core::paths::default_uds_path()
}

/// Default path for the admin UDS socket.
pub fn default_admin_uds_path() -> PathBuf {
    latchgate_core::paths::default_admin_uds_path()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_config_path_explicit() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("custom.toml");
        std::fs::write(&path, "").unwrap();
        let resolved = resolve_config_path(Some(path.to_str().unwrap())).unwrap();
        assert_eq!(resolved, path);
    }

    #[test]
    fn resolve_config_path_missing_errors() {
        let result = resolve_config_path(Some("/nonexistent/path.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn default_uds_path_ends_with_gate_sock() {
        let path = default_uds_path();
        assert!(
            path.ends_with("gate.sock"),
            "expected gate.sock suffix, got: {}",
            path.display()
        );
    }

    #[test]
    fn default_admin_uds_path_ends_with_gate_admin_sock() {
        let path = default_admin_uds_path();
        assert!(
            path.ends_with("gate-admin.sock"),
            "expected gate-admin.sock suffix, got: {}",
            path.display()
        );
    }
}
