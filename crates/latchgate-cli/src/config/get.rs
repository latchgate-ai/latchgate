//! `config get` — type-aware config value query.
//!
//! Symmetric with `config set`. Reads from the raw TOML file (not the
//! deserialized `Config`) so the output matches what `config set` wrote.

use serde_json::json;

use crate::cmd::{output, paths};
use crate::output::{print_json, Printer};

/// Query a single configuration value by dotted key, or dump the entire file.
///
/// Behaviour contract: if `config set foo.bar X` succeeded, `config get foo.bar`
/// returns `X` byte-for-byte (strings) or value-equivalent (typed fields).
pub fn run_get(config_path: Option<&str>, key: Option<&str>, pr: &Printer, json_mode: bool) -> i32 {
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

    let doc: toml_edit::DocumentMut = match raw.parse() {
        Ok(d) => d,
        Err(e) => {
            return output::emit_error(pr, &format!("{} is not valid TOML: {e}", path.display()));
        }
    };

    // No key => dump the entire config.
    let Some(key) = key else {
        return dump_all(&doc, &path, json_mode);
    };

    // Navigate the dotted key path.
    let item = match resolve_key(doc.as_item(), key) {
        Ok(item) => item,
        Err(msg) => {
            let top_keys = list_top_level_keys(&doc);
            if json_mode {
                print_json(&json!({
                    "ok": false,
                    "error": "not_found",
                    "key": key,
                    "available_keys": top_keys,
                }));
            } else {
                pr.blank();
                pr.error(&msg);
                if !top_keys.is_empty() {
                    pr.hint("Available top-level keys:");
                    for k in &top_keys {
                        pr.hint(&format!("  {k}"));
                    }
                }
                pr.blank();
            }
            return 2; // exit 2 = not found
        }
    };

    emit_value(item, key, pr, json_mode)
}

/// Walk a dotted key path through a TOML document, returning the terminal item.
fn resolve_key<'a>(root: &'a toml_edit::Item, key: &str) -> Result<&'a toml_edit::Item, String> {
    let segments: Vec<&str> = key.split('.').collect();
    if segments.is_empty() || segments.iter().any(|s| s.is_empty()) {
        return Err(format!("invalid key: {key:?}"));
    }

    let mut current = root;
    for (i, seg) in segments.iter().enumerate() {
        match current.get(seg) {
            Some(next) => current = next,
            None => {
                let partial = segments[..=i].join(".");
                return Err(format!("key '{partial}' not found in config"));
            }
        }
    }
    Ok(current)
}

/// Collect top-level key names for hint output on missing-key errors.
fn list_top_level_keys(doc: &toml_edit::DocumentMut) -> Vec<String> {
    doc.as_table().iter().map(|(k, _)| k.to_string()).collect()
}

/// Emit a resolved TOML item with type-aware formatting.
fn emit_value(item: &toml_edit::Item, key: &str, pr: &Printer, json_mode: bool) -> i32 {
    if json_mode {
        print_json(&json!({
            "ok": true,
            "key": key,
            "value": item_to_json(item),
        }));
        return 0;
    }

    match item {
        // Scalar values — print directly.
        toml_edit::Item::Value(v) => {
            print_scalar(v);
        }
        // Table — pretty-print as TOML fragment.
        toml_edit::Item::Table(t) => {
            // Serialise the table subtree back to TOML for readable output.
            let mut sub = toml_edit::DocumentMut::new();
            for (k, v) in t.iter() {
                sub[k] = v.clone();
            }
            print!("{sub}");
        }
        // Array of tables — render each inline.
        toml_edit::Item::ArrayOfTables(arr) => {
            for table in arr.iter() {
                let mut sub = toml_edit::DocumentMut::new();
                for (k, v) in table.iter() {
                    sub[k] = v.clone();
                }
                print!("{sub}");
                println!();
            }
        }
        toml_edit::Item::None => {
            // Should not reach here after resolve_key, but handle gracefully.
            pr.blank();
            pr.error(&format!("key '{key}' has no value"));
            pr.blank();
            return 2;
        }
    }
    0
}

/// Print a TOML scalar with type-appropriate formatting.
///
/// Strings: unquoted (bare). Integers, floats, booleans: as-is.
/// Arrays: one element per line (newline-separated).
fn print_scalar(v: &toml_edit::Value) {
    match v {
        toml_edit::Value::String(s) => {
            println!("{}", s.value());
        }
        toml_edit::Value::Integer(i) => {
            println!("{}", i.value());
        }
        toml_edit::Value::Float(f) => {
            println!("{}", f.value());
        }
        toml_edit::Value::Boolean(b) => {
            println!("{}", b.value());
        }
        toml_edit::Value::Datetime(dt) => {
            println!("{}", dt.value());
        }
        toml_edit::Value::Array(arr) => {
            for elem in arr.iter() {
                // Recurse for each element, but arrays of tables are uncommon
                // in inline TOML. Print the decorated repr for fidelity.
                print_scalar(elem);
            }
        }
        toml_edit::Value::InlineTable(t) => {
            // Re-serialise the inline table as TOML.
            for (k, v) in t.iter() {
                print!("{k} = ");
                print_scalar(v);
            }
        }
    }
}

/// Convert a TOML item to a `serde_json::Value` for `--json` output.
fn item_to_json(item: &toml_edit::Item) -> serde_json::Value {
    match item {
        toml_edit::Item::Value(v) => value_to_json(v),
        toml_edit::Item::Table(t) => {
            let mut map = serde_json::Map::new();
            for (k, v) in t.iter() {
                map.insert(k.to_string(), item_to_json(v));
            }
            serde_json::Value::Object(map)
        }
        toml_edit::Item::ArrayOfTables(arr) => {
            let items: Vec<serde_json::Value> = arr
                .iter()
                .map(|t| {
                    let mut map = serde_json::Map::new();
                    for (k, v) in t.iter() {
                        map.insert(k.to_string(), item_to_json(v));
                    }
                    serde_json::Value::Object(map)
                })
                .collect();
            serde_json::Value::Array(items)
        }
        toml_edit::Item::None => serde_json::Value::Null,
    }
}

/// Convert a single TOML value to JSON.
fn value_to_json(v: &toml_edit::Value) -> serde_json::Value {
    match v {
        toml_edit::Value::String(s) => json!(s.value()),
        toml_edit::Value::Integer(i) => json!(i.value()),
        toml_edit::Value::Float(f) => json!(f.value()),
        toml_edit::Value::Boolean(b) => json!(b.value()),
        toml_edit::Value::Datetime(dt) => json!(dt.value().to_string()),
        toml_edit::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(value_to_json).collect())
        }
        toml_edit::Value::InlineTable(t) => {
            let mut map = serde_json::Map::new();
            for (k, v) in t.iter() {
                map.insert(k.to_string(), value_to_json(v));
            }
            serde_json::Value::Object(map)
        }
    }
}

/// Dump the entire config file.
fn dump_all(doc: &toml_edit::DocumentMut, path: &std::path::Path, json_mode: bool) -> i32 {
    if json_mode {
        // Convert the full document to JSON.
        let mut map = serde_json::Map::new();
        for (k, v) in doc.as_table().iter() {
            map.insert(k.to_string(), item_to_json(v));
        }
        print_json(&json!({
            "ok": true,
            "path": path.to_string_lossy(),
            "config": serde_json::Value::Object(map),
        }));
    } else {
        // Print the raw TOML — preserving comments and formatting.
        print!("{doc}");
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_fixtures::*;
    use crate::output::Printer;

    #[test]
    fn get_scalar_string() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), DEV_TOML);
        let pr = Printer::new(false);
        let code = run_get(Some(path.to_str().unwrap()), Some("redis_url"), &pr, false);
        assert_eq!(code, 0);
    }

    #[test]
    fn get_nested_key() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), DEV_TOML);
        let pr = Printer::new(false);
        let code = run_get(
            Some(path.to_str().unwrap()),
            Some("sandbox.mode"),
            &pr,
            false,
        );
        assert_eq!(code, 0);
    }

    #[test]
    fn get_missing_key_returns_2() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), DEV_TOML);
        let pr = Printer::new(false);
        let code = run_get(
            Some(path.to_str().unwrap()),
            Some("nonexistent_key"),
            &pr,
            false,
        );
        assert_eq!(code, 2);
    }

    #[test]
    fn get_table_section() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), DEV_TOML);
        let pr = Printer::new(false);
        let code = run_get(Some(path.to_str().unwrap()), Some("sandbox"), &pr, false);
        assert_eq!(code, 0);
    }

    #[test]
    fn get_no_key_dumps_all() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), DEV_TOML);
        let pr = Printer::new(false);
        let code = run_get(Some(path.to_str().unwrap()), None, &pr, false);
        assert_eq!(code, 0);
    }

    #[test]
    fn get_json_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), DEV_TOML);
        let pr = Printer::new(true);
        let code = run_get(Some(path.to_str().unwrap()), Some("redis_url"), &pr, true);
        assert_eq!(code, 0);
    }

    #[test]
    fn get_invalid_key_path() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), DEV_TOML);
        let pr = Printer::new(false);
        let code = run_get(Some(path.to_str().unwrap()), Some(""), &pr, false);
        assert_eq!(code, 2);
    }

    #[test]
    fn get_partial_nested_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), DEV_TOML);
        let pr = Printer::new(false);
        let code = run_get(
            Some(path.to_str().unwrap()),
            Some("sandbox.nonexistent"),
            &pr,
            false,
        );
        assert_eq!(code, 2);
    }

    // -- resolve_key unit tests ---------------------------------------------

    #[test]
    fn resolve_key_rejects_trailing_dot() {
        let doc: toml_edit::DocumentMut = "a = 1\n".parse().unwrap();
        assert!(resolve_key(doc.as_item(), "a.").is_err());
    }

    #[test]
    fn resolve_key_rejects_empty_segments() {
        let doc: toml_edit::DocumentMut = "a = 1\n".parse().unwrap();
        assert!(resolve_key(doc.as_item(), "a..b").is_err());
    }

    // -- item_to_json -------------------------------------------------------

    #[test]
    fn json_conversion_preserves_types() {
        let doc: toml_edit::DocumentMut = "s = \"hello\"\nn = 42\nb = true\n".parse().unwrap();

        let s = item_to_json(&doc["s"]);
        assert_eq!(s, json!("hello"));

        let n = item_to_json(&doc["n"]);
        assert_eq!(n, json!(42));

        let b = item_to_json(&doc["b"]);
        assert_eq!(b, json!(true));
    }
}
