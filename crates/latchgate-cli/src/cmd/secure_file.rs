//! Atomic and permission-restricted filesystem operations for sensitive data.

use std::path::Path;

/// Write a file atomically: tmp => fsync => rename.
///
/// Ensures readers never see a partial write. If the process crashes between
/// create and rename, only the `.tmp` file is left (not the target).
pub fn atomic_write(path: &Path, content: &str) -> std::io::Result<()> {
    latchgate_core::atomic_write_str(path, content)
}

/// Write content with 0o600 permissions (owner read/write only).
///
/// Used for private keys, age key files, and any other sensitive material.
/// On non-Unix platforms, writes normally (no permission enforcement).
pub fn write_private_file(path: &Path, content: &str) -> std::io::Result<()> {
    std::fs::write(path, content)?;
    set_file_mode_0600(path)?;
    Ok(())
}

/// Set file permissions to 0o600 on Unix. No-op on other platforms.
pub fn set_file_mode_0600(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_creates_file_and_cleans_tmp() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("test.toml");
        atomic_write(&path, "key = \"value\"\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "key = \"value\"\n");
        assert!(
            !tmp.path().join("test.tmp").exists(),
            ".tmp residue must not remain"
        );
    }

    #[test]
    fn atomic_write_overwrites_existing() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("test.toml");
        std::fs::write(&path, "old").unwrap();
        atomic_write(&path, "new").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
    }

    #[test]
    fn write_private_file_sets_0600() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("secret.key");
        write_private_file(&path, "secret").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "secret");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "expected 0600, got {mode:o}");
        }
    }
}
