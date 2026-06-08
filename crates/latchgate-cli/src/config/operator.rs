//! `config add-operator` / `config remove-operator` — DPoP credential management.

use std::path::Path;

use latchgate_auth::dpop::generate_dpop_keypair;
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use serde_json::json;
use toml_edit;

use crate::cmd::{credential, output, secure_file};
use crate::output::{print_json, Printer};

use super::edit_config_doc;

/// Generate a DPoP keypair and add an operator credential to latchgate.toml.
///
/// 1. Generate P-256 keypair + compute JWK thumbprint.
/// 2. Generate API key (if not provided).
/// 3. Write PEM to `<key_dir>/<name>.pem` (mode 0600).
/// 4. Add `[operator_credentials.<name>]` section to TOML.
/// 5. Validate the modified config.
/// 6. Atomic write on success.
pub fn run_add_operator(
    config_path: Option<&str>,
    name: &str,
    explicit_api_key: Option<&str>,
    key_dir: &Path,
    pr: &Printer,
    json_mode: bool,
) -> i32 {
    // Validate operator name (used as TOML key).
    if name.is_empty() || name.contains(|c: char| c.is_whitespace() || c == '.' || c == '"') {
        return output::emit_error(
            pr,
            &format!(
                "invalid operator name: {name:?} — must be non-empty, no whitespace/dots/quotes"
            ),
        );
    }

    // Generate keypair.
    let (signing_key, _pub_key) = match generate_dpop_keypair() {
        Ok(pair) => pair,
        Err(e) => return output::emit_error(pr, &format!("key generation failed: {e}")),
    };

    let thumbprint = match signing_key.thumbprint() {
        Ok(t) => t,
        Err(e) => return output::emit_error(pr, &format!("thumbprint computation failed: {e}")),
    };

    let pem_doc = match signing_key.as_inner().to_pkcs8_pem(LineEnding::LF) {
        Ok(doc) => doc,
        Err(e) => return output::emit_error(pr, &format!("PEM serialization failed: {e}")),
    };

    // Generate or use explicit API key.
    let api_key = explicit_api_key
        .map(|s| s.to_string())
        .unwrap_or_else(|| credential::generate_api_key(name));

    // Write PEM to key_dir.
    if let Err(e) = std::fs::create_dir_all(key_dir) {
        return output::emit_error(pr, &format!("cannot create {}: {e}", key_dir.display()));
    }

    let pem_path = key_dir.join(format!("{name}.pem"));
    if pem_path.exists() {
        return output::emit_error(
            pr,
            &format!("{} already exists — will not overwrite", pem_path.display()),
        );
    }

    if let Err(e) = secure_file::write_private_file(&pem_path, pem_doc.as_ref()) {
        return output::emit_error(pr, &format!("cannot write {}: {e}", pem_path.display()));
    }

    // Mutate config (resolve → read → parse → edit → validate → atomic write).
    let result = edit_config_doc(pr, config_path, |doc| {
        if let Some(creds) = doc.get("operator_credentials") {
            if creds.get(name).is_some() {
                return Err(format!("operator '{name}' already exists in config"));
            }
        }

        let creds = doc
            .entry("operator_credentials")
            .or_insert(toml_edit::Item::Table(toml_edit::Table::new()));
        let mut op_table = toml_edit::Table::new();
        op_table.insert("api_key", toml_edit::value(&api_key));
        op_table.insert("dpop_jkt", toml_edit::value(&thumbprint));
        creds[name] = toml_edit::Item::Table(op_table);

        Ok(())
    });

    if let Err(code) = result {
        // Cleanup: remove the PEM we already wrote.
        let _ = std::fs::remove_file(&pem_path);
        return code;
    }

    if json_mode {
        print_json(&json!({
            "ok": true,
            "operator": name,
            "api_key": api_key,
            "dpop_jkt": thumbprint,
            "private_key_path": pem_path.to_string_lossy(),
        }));
    } else {
        pr.blank();
        pr.success(&format!("Operator '{name}' added"));
        pr.blank();
        println!("  {}  {}", pr.dim("api_key:    "), api_key);
        println!("  {}  {}", pr.dim("private_key:"), pem_path.display());
        println!("  {}  {}", pr.dim("dpop_jkt:   "), pr.cyan(&thumbprint));
        pr.blank();
        pr.warn("api_key shown once — save it now");
        pr.blank();
    }
    0
}

/// Remove an operator credential from latchgate.toml.
///
/// Does NOT delete the PEM file (operator may want a backup).
pub fn run_remove_operator(
    config_path: Option<&str>,
    name: &str,
    pr: &Printer,
    json_mode: bool,
) -> i32 {
    let result = edit_config_doc(pr, config_path, |doc| {
        let exists = doc
            .get("operator_credentials")
            .and_then(|c| c.get(name))
            .is_some();
        if !exists {
            return Err(format!("operator '{name}' not found in config"));
        }

        doc["operator_credentials"]
            .as_table_mut()
            .expect("operator_credentials is a table")
            .remove(name);

        Ok(())
    });

    if let Err(code) = result {
        return code;
    }

    if json_mode {
        print_json(&json!({ "ok": true, "operator": name, "removed": true }));
    } else {
        pr.blank();
        pr.success(&format!("Operator '{name}' removed from config"));
        pr.info("PEM file not deleted — remove manually if no longer needed");
        pr.blank();
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_fixtures::*;

    // ── add_operator / remove_operator ──────────────────────────────

    #[test]
    fn add_operator_creates_credential_and_pem() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), PROD_TOML);
        let key_dir = tmp.path().join(".latchgate");

        let pr = Printer::new(false);
        let code = run_add_operator(
            Some(path.to_str().unwrap()),
            "bob",
            None,
            &key_dir,
            &pr,
            false,
        );
        assert_eq!(code, 0, "add_operator failed");

        // Config has the new operator.
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("[operator_credentials.bob]"));
        assert!(content.contains("dpop_jkt"));

        // PEM exists with restricted permissions.
        let pem = key_dir.join("bob.pem");
        assert!(pem.exists(), "PEM file not created");
        let pem_content = std::fs::read_to_string(&pem).unwrap();
        assert!(pem_content.contains("BEGIN PRIVATE KEY"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&pem).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "PEM should be 0600, got {mode:o}");
        }
    }

    #[test]
    fn add_operator_with_explicit_api_key() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), PROD_TOML);
        let key_dir = tmp.path().join(".latchgate");

        let pr = Printer::new(false);
        let code = run_add_operator(
            Some(path.to_str().unwrap()),
            "carol",
            Some("my-custom-key-123"),
            &key_dir,
            &pr,
            false,
        );
        assert_eq!(code, 0);

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("my-custom-key-123"));
    }

    #[test]
    fn add_operator_rejects_duplicate() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), PROD_TOML);
        let key_dir = tmp.path().join(".latchgate");

        let pr = Printer::new(false);
        // "admin" already exists in PROD_TOML.
        let code = run_add_operator(
            Some(path.to_str().unwrap()),
            "admin",
            None,
            &key_dir,
            &pr,
            false,
        );
        assert_ne!(code, 0, "should reject duplicate operator");
    }

    #[test]
    fn add_operator_rejects_invalid_name() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), PROD_TOML);
        let key_dir = tmp.path().join(".latchgate");

        let pr = Printer::new(false);
        for bad_name in &["", "has space", "has.dot", "has\"quote"] {
            let code = run_add_operator(
                Some(path.to_str().unwrap()),
                bad_name,
                None,
                &key_dir,
                &pr,
                false,
            );
            assert_ne!(code, 0, "should reject name: {bad_name:?}");
        }
    }

    #[test]
    fn remove_operator_removes_section() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), PROD_TOML);
        let key_dir = tmp.path().join(".latchgate");

        // First add a second operator so removal of one still leaves valid config.
        let pr = Printer::new(false);
        let code = run_add_operator(
            Some(path.to_str().unwrap()),
            "temp",
            None,
            &key_dir,
            &pr,
            false,
        );
        assert_eq!(code, 0);

        // Now remove it.
        let code = run_remove_operator(Some(path.to_str().unwrap()), "temp", &pr, false);
        assert_eq!(code, 0, "remove_operator failed");

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(!content.contains("[operator_credentials.temp]"));
        // Original operator untouched.
        assert!(content.contains("[operator_credentials.admin]"));
    }

    #[test]
    fn remove_operator_nonexistent_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), PROD_TOML);

        let pr = Printer::new(false);
        let code = run_remove_operator(Some(path.to_str().unwrap()), "nonexistent", &pr, false);
        assert_ne!(code, 0);
    }

    #[test]
    fn add_operator_cleans_up_pem_on_validation_failure() {
        let tmp = tempfile::tempdir().unwrap();
        // Insert listen_http_addr at top level so it actually triggers validation.
        let broken_toml = PROD_TOML.replacen(
            "listen_uds_path",
            "listen_http_addr = \"127.0.0.1:3000\"\nlisten_uds_path",
            1,
        );
        let path = write_test_config(tmp.path(), &broken_toml);
        let key_dir = tmp.path().join(".latchgate");

        let pr = Printer::new(false);
        let code = run_add_operator(
            Some(path.to_str().unwrap()),
            "doomed",
            None,
            &key_dir,
            &pr,
            false,
        );
        assert_ne!(code, 0, "should fail validation");

        // PEM must not be left behind.
        assert!(
            !key_dir.join("doomed.pem").exists(),
            "PEM file should be cleaned up on validation failure"
        );
    }
}
