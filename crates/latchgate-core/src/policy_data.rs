//! OPA policy `data.json` structure helpers.
//!
//! Shared between `latchgate-api` (admin HTTP endpoints) and `latchgate-cli`
//! (`latchgate policy grant/revoke`). Previously duplicated in both crates
//! with bare `unwrap()` calls on `as_object_mut()`.
//!
//! # Security
//!
//! These functions manipulate the policy ACL document that controls which
//! principals may invoke which actions. A panic here is a potential denial
//! of service — or worse, a bypass if the panic occurs after a partial
//! mutation. All operations return `Result` so callers can fail cleanly.

use serde_json::{json, Map, Value};
use thiserror::Error;

/// Errors from policy data structure operations.
#[derive(Debug, Error)]
pub enum PolicyDataError {
    #[error("policy document root is not a JSON object")]
    RootNotObject,

    #[error("policy document 'acl' field is not a JSON object")]
    AclNotObject,
}

/// Get or create the `acl` object in the policy data document.
///
/// If `acl` is missing or not an object, inserts a fresh empty object.
/// Returns a mutable reference to the `acl` map.
///
/// # Errors
///
/// Returns [`PolicyDataError::RootNotObject`] if `doc` is not a JSON object.
pub fn ensure_acl_object(doc: &mut Value) -> Result<&mut Map<String, Value>, PolicyDataError> {
    let root = doc.as_object_mut().ok_or(PolicyDataError::RootNotObject)?;
    if !root.get("acl").is_some_and(|v| v.is_object()) {
        root.insert("acl".into(), json!({}));
    }
    root.get_mut("acl")
        .and_then(|v| v.as_object_mut())
        .ok_or(PolicyDataError::AclNotObject)
}

/// Increment or set `policy_version` in the policy data document.
///
/// Version format: `"v1"` => `"v1-1"` => `"v1-2"` => ... Appends `-1` to
/// non-numeric suffixes. Sets `"v1"` if the field is missing or empty.
///
/// # Errors
///
/// Returns [`PolicyDataError::RootNotObject`] if `doc` is not a JSON object.
pub fn increment_version(doc: &mut Value) -> Result<(), PolicyDataError> {
    let obj = doc.as_object_mut().ok_or(PolicyDataError::RootNotObject)?;
    let current = obj
        .get("policy_version")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let new_version = if let Some(pos) = current.rfind('-') {
        let (prefix, suffix) = current.split_at(pos + 1);
        if let Ok(n) = suffix.parse::<u64>() {
            format!("{prefix}{}", n + 1)
        } else {
            format!("{current}-1")
        }
    } else if current.is_empty() {
        "v1".to_string()
    } else {
        format!("{current}-1")
    };

    obj.insert("policy_version".into(), json!(new_version));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ensure_acl_creates_missing() {
        let mut doc = json!({});
        let acl = ensure_acl_object(&mut doc).unwrap();
        assert!(acl.is_empty());
    }

    #[test]
    fn ensure_acl_preserves_existing() {
        let mut doc = json!({ "acl": { "agent-a": { "allowed_actions": ["foo"] } } });
        let acl = ensure_acl_object(&mut doc).unwrap();
        assert!(acl.contains_key("agent-a"));
    }

    #[test]
    fn ensure_acl_replaces_non_object() {
        let mut doc = json!({ "acl": "invalid" });
        let acl = ensure_acl_object(&mut doc).unwrap();
        assert!(acl.is_empty());
    }

    #[test]
    fn ensure_acl_rejects_non_object_root() {
        let mut doc = json!([1, 2, 3]);
        assert!(ensure_acl_object(&mut doc).is_err());
    }

    #[test]
    fn increment_version_from_empty() {
        let mut doc = json!({});
        increment_version(&mut doc).unwrap();
        assert_eq!(doc["policy_version"], "v1");
    }

    #[test]
    fn increment_version_numeric_suffix() {
        let mut doc = json!({ "policy_version": "v1-3" });
        increment_version(&mut doc).unwrap();
        assert_eq!(doc["policy_version"], "v1-4");
    }

    #[test]
    fn increment_version_no_suffix() {
        let mut doc = json!({ "policy_version": "v1" });
        increment_version(&mut doc).unwrap();
        assert_eq!(doc["policy_version"], "v1-1");
    }

    #[test]
    fn increment_version_rejects_non_object_root() {
        let mut doc = json!("not an object");
        assert!(increment_version(&mut doc).is_err());
    }
}
