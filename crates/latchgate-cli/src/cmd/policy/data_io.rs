//! data.json I/O — resolution, read/write, ACL structure helpers.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::cmd::secure_file;

/// Find `data.json` in the expected locations.
pub(crate) fn resolve_data_json() -> Option<PathBuf> {
    let candidates = [
        PathBuf::from(".latchgate/policies/data.json"),
        PathBuf::from("policies/data.json"),
        PathBuf::from("policies/opa/data.json"),
    ];
    candidates.into_iter().find(|p| p.is_file())
}

/// Find the manifests directory.
pub(crate) fn resolve_manifests_dir(config_value: &str) -> Option<PathBuf> {
    let candidates = [
        PathBuf::from(".latchgate/manifests"),
        PathBuf::from("manifests"),
        PathBuf::from(config_value),
    ];
    candidates.into_iter().find(|p| p.is_dir())
}

pub(crate) fn read_data_json(path: &Path) -> Result<Value, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    serde_json::from_str(&content).map_err(|e| format!("invalid JSON in {}: {e}", path.display()))
}

pub(crate) fn write_data_json(path: &Path, doc: &Value) -> Result<(), String> {
    let content = serde_json::to_string_pretty(doc)
        .map_err(|e| format!("cannot serialize data.json: {e}"))?;
    secure_file::atomic_write(path, &content)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// Get or create the `acl` object in the document.
pub(crate) fn ensure_acl_object(doc: &mut Value) -> Result<&mut Map<String, Value>, String> {
    latchgate_core::ensure_acl_object(doc).map_err(|e| e.to_string())
}

/// Increment or set `policy_version`.
pub(crate) fn increment_version(doc: &mut Value) -> Result<(), String> {
    latchgate_core::increment_version(doc).map_err(|e| e.to_string())
}
