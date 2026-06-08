//! Compile-time embedded action manifests.
//!
//! Binary installs (brew, cargo-binstall) do not ship `definitions/manifests/`.
//! This module embeds the manifest directory at compile time so that
//! `latchgate init` can extract a working set of manifests without the
//! source tree.
//!
//! # Security notes
//!
//! - Every manifest is validated through [`ActionSpec::from_yaml`] before
//!   extraction. Corrupt or invalid manifests are rejected, not silently
//!   skipped — this is a security project.
//! - File writes use atomic write-then-sync to avoid partial manifests on
//!   crash.

use std::path::Path;

use include_dir::{include_dir, Dir};
use latchgate_registry::manifest::{ActionSpec, ManifestError};

/// The `definitions/manifests/` directory, embedded at compile time.
///
/// Path is relative to `crates/latchgate-cli/Cargo.toml`.
///
/// Only top-level files are included. Subdirectories (e.g. `_experimental/`)
/// are embedded by `include_dir!` but excluded by [`iter_yaml`],
/// [`list_available`], and [`extract_manifests`], which iterate with
/// `Dir::files()` (non-recursive). Experimental provider manifests live in
/// `_experimental/` and are not shipped in v0.1.x
static MANIFESTS_DIR: Dir = include_dir!("$CARGO_MANIFEST_DIR/../../definitions/manifests");

// Public API

#[derive(Debug, Clone)]
pub struct EmbeddedManifest {
    pub action_id: String,
    pub filename: String,
}

/// Iterate over embedded manifest YAML texts for direct registry loading.
pub fn iter_yaml() -> impl Iterator<Item = (&'static str, &'static str)> {
    MANIFESTS_DIR.files().filter_map(|file| {
        let filename = file.path().file_name()?.to_str()?;
        let contents = std::str::from_utf8(file.contents()).ok()?;
        Some((filename, contents))
    })
}

/// List all valid embedded manifests.
///
/// Manifests that fail validation are **not** silently dropped — this
/// function returns an error if any embedded manifest is corrupt. A broken
/// manifest in the binary is a build-time bug that must be caught.
pub fn list_available() -> Result<Vec<EmbeddedManifest>, EmbeddedManifestError> {
    let mut result = Vec::new();
    for file in MANIFESTS_DIR.files() {
        let filename = file
            .path()
            .file_name()
            .ok_or_else(|| EmbeddedManifestError::BadFilename(file.path().display().to_string()))?
            .to_string_lossy()
            .into_owned();

        let contents = std::str::from_utf8(file.contents())
            .map_err(|_| EmbeddedManifestError::InvalidUtf8(filename.clone()))?;

        let spec = ActionSpec::from_yaml(contents).map_err(|e| {
            EmbeddedManifestError::InvalidManifest {
                filename: filename.clone(),
                source: e,
            }
        })?;

        result.push(EmbeddedManifest {
            action_id: spec.action_id,
            filename,
        });
    }
    result.sort_by(|a, b| a.action_id.cmp(&b.action_id));
    Ok(result)
}

#[derive(Debug, Clone)]
pub enum ManifestFilter<'a> {
    All,
    None,
    Tag(&'a str),
    Listed(&'a [String]),
}

/// Extract manifests matching `filter` to `dest`.
pub fn extract_manifests(
    filter: ManifestFilter<'_>,
    dest: &Path,
) -> Result<Vec<EmbeddedManifest>, EmbeddedManifestError> {
    // Phase 1: validate everything before writing anything.
    // Security: no partial extraction if a manifest is corrupt.
    let mut to_write: Vec<(EmbeddedManifest, &[u8])> = Vec::new();

    for file in MANIFESTS_DIR.files() {
        let filename = file
            .path()
            .file_name()
            .ok_or_else(|| EmbeddedManifestError::BadFilename(file.path().display().to_string()))?
            .to_string_lossy()
            .into_owned();

        let contents = std::str::from_utf8(file.contents())
            .map_err(|_| EmbeddedManifestError::InvalidUtf8(filename.clone()))?;

        let spec = ActionSpec::from_yaml(contents).map_err(|e| {
            EmbeddedManifestError::InvalidManifest {
                filename: filename.clone(),
                source: e,
            }
        })?;

        let dominated = match &filter {
            ManifestFilter::All => true,
            ManifestFilter::None => false,
            ManifestFilter::Tag(tag) => spec.tags.iter().any(|t| t == tag),
            ManifestFilter::Listed(ids) => ids.iter().any(|id| id == &spec.action_id),
        };

        if dominated {
            to_write.push((
                EmbeddedManifest {
                    action_id: spec.action_id,
                    filename,
                },
                file.contents(),
            ));
        }
    }

    // Phase 2: write validated manifests to disk.
    std::fs::create_dir_all(dest).map_err(|e| EmbeddedManifestError::Io {
        path: dest.display().to_string(),
        source: e,
    })?;

    for (meta, raw_bytes) in &to_write {
        let target = dest.join(&meta.filename);
        atomic_write(&target, raw_bytes)?;
    }

    Ok(to_write.into_iter().map(|(meta, _)| meta).collect())
}

// Error

#[derive(Debug, thiserror::Error)]
pub enum EmbeddedManifestError {
    #[error("embedded manifest has no filename: {0}")]
    BadFilename(String),

    #[error("embedded manifest is not valid UTF-8: {0}")]
    InvalidUtf8(String),

    #[error("embedded manifest '{filename}' failed validation: {source}")]
    InvalidManifest {
        filename: String,
        source: ManifestError,
    },

    #[error("I/O error at '{path}': {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
}

// Internal

fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), EmbeddedManifestError> {
    latchgate_core::atomic_write(path, contents).map_err(|e| EmbeddedManifestError::Io {
        path: path.display().to_string(),
        source: e,
    })
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    /// All embedded manifests must parse and validate.
    /// This catches broken manifests at test time, not in production.
    #[test]
    fn all_embedded_manifests_are_valid() {
        let manifests = list_available().expect("all embedded manifests must be valid");
        // definitions/manifests/ is non-empty — if this fails the embed path is wrong.
        assert!(
            !manifests.is_empty(),
            "no manifests embedded — check include_dir path"
        );
    }

    /// action_ids are unique across all embedded manifests.
    #[test]
    fn no_duplicate_action_ids() {
        let manifests = list_available().unwrap();
        let mut seen = std::collections::HashSet::new();
        for m in &manifests {
            assert!(
                seen.insert(&m.action_id),
                "duplicate action_id '{}' in embedded manifests",
                m.action_id
            );
        }
    }

    /// Extract with All produces all manifests.
    #[test]
    fn extract_all_matches_list() {
        let available = list_available().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let extracted = extract_manifests(ManifestFilter::All, tmp.path()).unwrap();
        assert_eq!(
            extracted.len(),
            available.len(),
            "All extraction count must match list_available count"
        );
        // Every file must exist on disk and re-parse cleanly.
        for m in &extracted {
            let path = tmp.path().join(&m.filename);
            assert!(path.exists(), "extracted file missing: {}", m.filename);
            let contents = std::fs::read_to_string(&path).unwrap();
            ActionSpec::from_yaml(&contents)
                .expect("extracted manifest must re-validate from disk");
        }
    }

    /// Tag-based extraction only writes matching manifests.
    #[test]
    fn extract_by_tag() {
        let all = list_available().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let extracted = extract_manifests(ManifestFilter::Tag("agent"), tmp.path()).unwrap();
        assert!(
            !extracted.is_empty(),
            "expected at least one tagged manifest"
        );
        assert!(
            extracted.len() < all.len(),
            "tag filter must be a strict subset"
        );

        let files: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(files.len(), extracted.len());
    }

    /// Non-existent tag extracts nothing, no error.
    #[test]
    fn extract_nonexistent_tag_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let extracted =
            extract_manifests(ManifestFilter::Tag("__no_such_tag__"), tmp.path()).unwrap();
        assert!(extracted.is_empty());
    }

    /// No .tmp files left behind after successful extraction.
    #[test]
    fn no_tmp_files_after_extract() {
        let tmp = tempfile::tempdir().unwrap();
        extract_manifests(ManifestFilter::All, tmp.path()).unwrap();
        for entry in std::fs::read_dir(tmp.path()).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            assert!(
                !name.ends_with(".tmp"),
                "temporary file left behind: {name}"
            );
        }
    }
}
