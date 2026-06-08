//! `config unset` — remove a config field via CLI.
//!
//! Uses `toml_edit` to remove the key while preserving surrounding comments
//! and formatting. The resulting config is validated before writing — if
//! removal makes the config invalid, the change is rejected (not written).

use serde_json::json;

use crate::cmd::{output, paths, secure_file};
use crate::output::{print_json, Printer};

use super::validate_toml_as_config;

/// Remove a configuration field by dotted key.
///
/// Idempotent: unsetting an absent key is a no-op with exit 0.
/// Validates the resulting config — required fields cannot be removed.
pub fn run_unset(config_path: Option<&str>, key: &str, pr: &Printer, json_mode: bool) -> i32 {
    // Validate key syntax before touching any files.
    let segments: Vec<&str> = key.split('.').collect();
    if segments.is_empty() || segments.iter().any(|s| s.is_empty()) {
        return output::emit_error(pr, &format!("invalid key: {key:?}"));
    }

    let path = match paths::resolve_config_path(config_path) {
        Ok(p) => p,
        Err(msg) => return output::emit_error(pr, &msg),
    };

    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            return output::emit_error(pr, &format!("cannot read {}: {e}", path.display()));
        }
    };

    let mut doc: toml_edit::DocumentMut = match raw.parse() {
        Ok(d) => d,
        Err(e) => {
            return output::emit_error(pr, &format!("{} is not valid TOML: {e}", path.display()));
        }
    };

    // Check whether the key exists before attempting removal.
    if !key_exists(doc.as_item(), &segments) {
        // Idempotent: absent key is a no-op.
        if json_mode {
            print_json(&json!({
                "ok": true,
                "key": key,
                "removed": false,
                "detail": "key not present in config",
            }));
        } else {
            pr.blank();
            pr.info(&format!("{key} is not set — nothing to remove"));
            pr.blank();
        }
        return 0;
    }

    // Remove the key from the document.
    if let Err(msg) = remove_key(&mut doc, &segments) {
        return output::emit_error(pr, &msg);
    }

    // Validate: deserialize the modified TOML into Config and run checks.
    let modified_toml = doc.to_string();
    if let Err(msg) = validate_toml_as_config(&modified_toml) {
        return output::emit_error(
            pr,
            &format!(
                "cannot unset '{key}' — the resulting config is invalid: {msg}\n\
                 \n  This field may be required. The config file was not modified."
            ),
        );
    }

    // Atomic write.
    if let Err(e) = secure_file::atomic_write(&path, &modified_toml) {
        return output::emit_error(pr, &format!("cannot write {}: {e}", path.display()));
    }

    if json_mode {
        print_json(&json!({
            "ok": true,
            "key": key,
            "removed": true,
            "path": path.to_string_lossy(),
        }));
    } else {
        pr.blank();
        pr.success(&format!("Removed {key} from {}", path.display()));
        pr.blank();
    }
    0
}

/// Check whether a dotted key path exists in the document.
fn key_exists(root: &toml_edit::Item, segments: &[&str]) -> bool {
    let mut current = root;
    for seg in segments {
        match current.get(seg) {
            Some(next) => current = next,
            None => return false,
        }
    }
    true
}

/// Remove a key from the TOML document.
///
/// For nested keys (`a.b.c`), navigates to the parent table and removes
/// the leaf. If removing the leaf leaves an empty parent table, the parent
/// is also removed (recursive cleanup).
fn remove_key(doc: &mut toml_edit::DocumentMut, segments: &[&str]) -> Result<(), String> {
    debug_assert!(!segments.is_empty());

    if segments.len() == 1 {
        // Top-level key.
        doc.remove(segments[0]);
        return Ok(());
    }

    // Navigate to the parent of the leaf.
    let (parents, leaf) = segments.split_at(segments.len() - 1);
    let leaf_key = leaf[0];

    let mut table: &mut toml_edit::Item = doc.as_item_mut();
    for &seg in parents {
        table = match table.get_mut(seg) {
            Some(t) if t.is_table() || t.is_table_like() => t,
            _ => {
                return Err(format!(
                    "'{seg}' in key '{}' is not a table",
                    segments.join(".")
                ));
            }
        };
    }

    // Remove the leaf from its parent table.
    if let Some(t) = table.as_table_mut() {
        t.remove(leaf_key);
    } else if let Some(t) = table.as_inline_table_mut() {
        t.remove(leaf_key);
    }

    // Prune empty ancestor tables (bottom-up).
    prune_empty_parents(doc, parents);

    Ok(())
}

/// Remove ancestor tables that became empty after a leaf removal.
///
/// Walks the parent chain from deepest to shallowest. Stops at the first
/// non-empty table — we never prune tables that still have other keys.
fn prune_empty_parents(doc: &mut toml_edit::DocumentMut, parents: &[&str]) {
    for depth in (0..parents.len()).rev() {
        let chain = &parents[..=depth];
        let target_key = chain
            .last()
            .expect("chain is non-empty: parents[..=depth] has at least one element");

        // Navigate to the parent of this level.
        let mut current: &toml_edit::Item = doc.as_item();
        for &seg in &chain[..chain.len() - 1] {
            current = match current.get(seg) {
                Some(c) => c,
                None => return, // Already removed upstream.
            };
        }

        let is_empty = current
            .get(target_key)
            .and_then(|t| t.as_table())
            .is_some_and(|t| t.is_empty());

        if is_empty {
            // Remove via mutable access — re-navigate from root.
            let mut mutable: &mut toml_edit::Item = doc.as_item_mut();
            for &seg in &chain[..chain.len() - 1] {
                // SAFETY: immutable traversal above confirmed this path exists.
                mutable = mutable
                    .get_mut(seg)
                    .expect("path verified by immutable traversal above");
            }
            if let Some(t) = mutable.as_table_mut() {
                t.remove(target_key);
            }
        } else {
            break; // Parent is non-empty; stop pruning.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_fixtures::*;
    use crate::output::Printer;

    #[test]
    fn unset_existing_optional_field() {
        // `log_level` has a default — removing it should succeed.
        // Use PROD_TOML (passes production validation) with log_level prepended.
        let toml = format!("log_level = \"debug\"\n{PROD_TOML}");
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), &toml);

        let pr = Printer::new(false);
        let code = run_unset(Some(path.to_str().unwrap()), "log_level", &pr, false);
        assert_eq!(code, 0);

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            !content.contains("log_level"),
            "log_level should have been removed"
        );
    }

    #[test]
    fn unset_absent_key_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), DEV_TOML);

        let pr = Printer::new(false);
        let code = run_unset(
            Some(path.to_str().unwrap()),
            "nonexistent_field",
            &pr,
            false,
        );
        assert_eq!(code, 0, "absent key should exit 0 (idempotent)");
    }

    #[test]
    fn unset_nested_key() {
        // PROD_TOML has [sandbox] mode = "strict". Insert strict_for_actions
        // into that section by replacing the mode line.
        let toml = PROD_TOML.replace(
            "mode = \"strict\"",
            "mode = \"strict\"\nstrict_for_actions = false",
        );
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), &toml);

        let pr = Printer::new(false);
        let code = run_unset(
            Some(path.to_str().unwrap()),
            "sandbox.strict_for_actions",
            &pr,
            false,
        );
        assert_eq!(code, 0);

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            !content.contains("strict_for_actions"),
            "nested key should have been removed"
        );
    }

    #[test]
    fn unset_invalid_key_syntax() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), DEV_TOML);

        let pr = Printer::new(false);
        assert_eq!(
            run_unset(Some(path.to_str().unwrap()), "", &pr, false),
            1,
            "empty key should be rejected"
        );
        assert_eq!(
            run_unset(Some(path.to_str().unwrap()), "a..b", &pr, false),
            1,
            "double-dot key should be rejected"
        );
    }

    #[test]
    fn unset_json_mode_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), DEV_TOML);

        let pr = Printer::new(true);
        let code = run_unset(Some(path.to_str().unwrap()), "nonexistent_field", &pr, true);
        assert_eq!(code, 0);
    }

    // -- key_exists unit tests ----------------------------------------------

    #[test]
    fn key_exists_positive() {
        let doc: toml_edit::DocumentMut = "[a]\nb = 1\n".parse().unwrap();
        assert!(key_exists(doc.as_item(), &["a", "b"]));
    }

    #[test]
    fn key_exists_negative() {
        let doc: toml_edit::DocumentMut = "[a]\nb = 1\n".parse().unwrap();
        assert!(!key_exists(doc.as_item(), &["a", "c"]));
    }

    // -- remove_key unit tests ----------------------------------------------

    #[test]
    fn remove_key_top_level() {
        let mut doc: toml_edit::DocumentMut = "x = 1\ny = 2\n".parse().unwrap();
        remove_key(&mut doc, &["x"]).unwrap();
        assert!(doc.get("x").is_none());
        assert!(doc.get("y").is_some());
    }

    #[test]
    fn remove_key_prunes_empty_parent() {
        let mut doc: toml_edit::DocumentMut = "[a]\nb = 1\n".parse().unwrap();
        remove_key(&mut doc, &["a", "b"]).unwrap();
        // Table [a] should be pruned since it's now empty.
        assert!(
            doc.get("a").is_none(),
            "empty parent table should be pruned"
        );
    }

    #[test]
    fn remove_key_preserves_nonempty_parent() {
        let mut doc: toml_edit::DocumentMut = "[a]\nb = 1\nc = 2\n".parse().unwrap();
        remove_key(&mut doc, &["a", "b"]).unwrap();
        assert!(doc.get("a").is_some(), "non-empty parent should be kept");
        assert!(doc["a"].get("c").is_some());
    }
}
