//! `config set` — type-preserving scalar config editing.

use serde_json::json;
use toml_edit;

use crate::cmd::{output, paths, secure_file};
use crate::output::{print_json, Printer};

use super::{set_value_in_document, validate_toml_as_config};

/// Set a single configuration value with type preservation and validation.
///
/// Resolves the config file path the same way `Config::load()` does, edits
/// the raw TOML with `toml_edit` (preserving comments/formatting), validates
/// the result by deserializing to `Config`, and writes atomically on success.
pub fn run_set(
    config_path: Option<&str>,
    key: &str,
    value: &str,
    pr: &Printer,
    json_mode: bool,
) -> i32 {
    let path = match paths::resolve_config_path(config_path) {
        Ok(p) => p,
        Err(msg) => return output::emit_error(pr, &msg),
    };

    // Read existing TOML (file must exist — run `latchgate init` first).
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

    // Navigate to the target key, creating intermediate tables as needed.
    if let Err(msg) = set_value_in_document(&mut doc, key, value) {
        return output::emit_error(pr, &msg);
    }

    // Validate: deserialize the modified TOML into Config and run checks.
    let modified_toml = doc.to_string();
    if let Err(msg) = validate_toml_as_config(&modified_toml) {
        return output::emit_error(pr, &format!("Invalid: {key} — {msg}"));
    }

    // Atomic write.
    if let Err(e) = secure_file::atomic_write(&path, &modified_toml) {
        return output::emit_error(pr, &format!("cannot write {}: {e}", path.display()));
    }

    if json_mode {
        print_json(&json!({
            "ok": true,
            "key": key,
            "value": value,
            "path": path.to_string_lossy(),
        }));
    } else {
        pr.blank();
        pr.success(&format!("{key} = {value:?}"));
        pr.blank();
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_fixtures::*;

    // ── set_value_in_document ────────────────────────────────────────

    #[test]
    fn set_preserves_integer_type() {
        let mut doc: toml_edit::DocumentMut = "port = 3000\n".parse().unwrap();
        set_value_in_document(&mut doc, "port", "4000").unwrap();
        let item = doc.get("port").unwrap();
        assert!(item.is_integer(), "expected integer, got: {item:?}");
        assert_eq!(item.as_integer().unwrap(), 4000);
    }

    #[test]
    fn set_preserves_boolean_type() {
        let mut doc: toml_edit::DocumentMut = "unsafe_expose_http = false\n".parse().unwrap();
        set_value_in_document(&mut doc, "unsafe_expose_http", "true").unwrap();
        assert!(doc["unsafe_expose_http"].as_bool().unwrap());
    }

    #[test]
    fn set_integer_rejects_non_numeric() {
        let mut doc: toml_edit::DocumentMut = "port = 3000\n".parse().unwrap();
        let err = set_value_in_document(&mut doc, "port", "abc").unwrap_err();
        assert!(err.contains("expected integer"), "got: {err}");
    }

    #[test]
    fn set_creates_nested_table() {
        let mut doc: toml_edit::DocumentMut = "".parse().unwrap();
        set_value_in_document(&mut doc, "sandbox.mode", "strict").unwrap();
        let mode = doc["sandbox"]["mode"].as_str().unwrap();
        assert_eq!(mode, "strict");
    }

    #[test]
    fn set_new_field_defaults_to_string() {
        let mut doc: toml_edit::DocumentMut = "".parse().unwrap();
        set_value_in_document(&mut doc, "new_field", "42").unwrap();
        // New field => string, not auto-parsed as int.
        assert!(doc["new_field"].as_str().is_some());
        assert_eq!(doc["new_field"].as_str().unwrap(), "42");
    }

    #[test]
    fn set_preserves_comments() {
        let input = "# Important comment\nredis_url = \"redis://old:6379\"\n";
        let mut doc: toml_edit::DocumentMut = input.parse().unwrap();
        set_value_in_document(&mut doc, "redis_url", "redis://new:6379").unwrap();
        let output = doc.to_string();
        assert!(output.contains("# Important comment"), "comment lost");
        assert!(output.contains("redis://new:6379"));
    }

    #[test]
    fn set_rejects_empty_key() {
        let mut doc: toml_edit::DocumentMut = "".parse().unwrap();
        assert!(set_value_in_document(&mut doc, "", "val").is_err());
    }

    #[test]
    fn set_rejects_trailing_dot() {
        let mut doc: toml_edit::DocumentMut = "".parse().unwrap();
        assert!(set_value_in_document(&mut doc, "foo.", "val").is_err());
    }

    // ── validate_toml_as_config ─────────────────────────────────────

    #[test]
    fn validate_accepts_valid_config() {
        let result = validate_toml_as_config(PROD_TOML);
        assert!(result.is_ok(), "validation failed: {:?}", result.err());
    }

    #[test]
    fn validate_rejects_malformed_toml() {
        let result = validate_toml_as_config("not = [valid toml");
        assert!(result.is_err());
    }

    // ── run_set end-to-end ──────────────────────────────────────────

    /// Production-valid TOML for end-to-end tests (no env var dependency).
    const PROD_TOML: &str = r#"
listen_uds_path = "/tmp/lg-test.sock"
listen_admin_uds_path = "/tmp/lg-test-admin.sock"
redis_url = "redis://127.0.0.1:6379"
opa_url = "http://127.0.0.1:8181"
receipt_signing_key_path = "./keys/receipt.key"
grant_signing_key_path = "./keys/grant.key"
receipt_keys_jwks_path = "./keys/receipt.jwks"
response_schema_enforcement = "deny"

[sandbox]
mode = "strict"

[identity]
provider = "peercred"

[identity.peercred]
allow_unmapped = false

[identity.peercred.principals.1000]
principal = "agent"
scopes = ["tools:call"]

[operator_credentials.admin]
api_key = "key-admin-test"
dpop_jkt = "test-thumbprint-sha256"
"#;

    #[test]
    fn run_set_modifies_value_on_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), PROD_TOML);

        let pr = Printer::new(false);
        let code = run_set(
            Some(path.to_str().unwrap()),
            "redis_url",
            "redis://new:6379",
            &pr,
            false,
        );

        assert_eq!(code, 0, "run_set failed");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("redis://new:6379"));
    }

    #[test]
    fn run_set_rejects_invalid_value() {
        let tmp = tempfile::tempdir().unwrap();
        // Use config set to add listen_http_addr at top level, then verify
        // a subsequent set fails validation because unsafe_expose_http is missing.
        let path = write_test_config(tmp.path(), PROD_TOML);

        // First: set listen_http_addr (this goes to top-level via set_value_in_document).
        let pr = Printer::new(false);
        let code = run_set(
            Some(path.to_str().unwrap()),
            "listen_http_addr",
            "127.0.0.1:3000",
            &pr,
            false,
        );
        // This set itself should fail — the validation fires before writing.
        assert_ne!(
            code, 0,
            "expected validation failure for http_addr without unsafe flag"
        );
        // File should NOT contain the invalid value.
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            !content.contains("127.0.0.1:3000"),
            "file was written despite validation failure"
        );
    }
}
