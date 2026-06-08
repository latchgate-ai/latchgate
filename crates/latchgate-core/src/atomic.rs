//! Atomic filesystem write: tmp => fsync => rename.
//!
//! Single source of truth for durable file writes. Every file mutation in
//! LatchGate (policy data, egress allowlists, embedded manifests, config)
//! MUST go through this function to guarantee readers never observe partial
//! content.

use std::io::Write;
use std::path::Path;

/// Write `contents` to `path` atomically.
///
/// Creates a temporary file at `{path}.tmp`, writes all bytes, fsyncs,
/// then renames over the target. If the process crashes between create
/// and rename, only the `.tmp` file is left — never a partial target.
pub fn atomic_write(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(contents)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Write a string atomically. Convenience wrapper over [`atomic_write`].
pub fn atomic_write_str(path: &Path, content: &str) -> std::io::Result<()> {
    atomic_write(path, content.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_file_and_cleans_tmp() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("test.toml");
        atomic_write_str(&path, "key = \"value\"\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "key = \"value\"\n");
        assert!(
            !tmp.path().join("test.tmp").exists(),
            ".tmp residue must not remain after successful write"
        );
    }

    #[test]
    fn overwrites_existing() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("test.toml");
        std::fs::write(&path, "old").unwrap();
        atomic_write_str(&path, "new").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
    }

    #[test]
    fn binary_content_roundtrips() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("data.bin");
        let bytes: Vec<u8> = (0..=255).collect();
        atomic_write(&path, &bytes).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
}
