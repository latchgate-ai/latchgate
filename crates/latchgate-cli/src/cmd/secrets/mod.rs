//! `latchgate secrets` — SOPS-encrypted credential management.
//!
//! Wraps `age-keygen` (key generation) and `sops` (encrypt/decrypt) so that
//! the operator never leaves the CLI. All decrypted material is held in
//! temporary files with 0o600 permissions (via `tempfile::NamedTempFile`,
//! auto-cleaned on drop) and never emitted to tracing spans.
//!

pub(crate) mod sops;
pub(crate) mod yaml;

use sops::{
    check_binary, extract_age_public_key, resolve_sops_paths, set_file_mode_0600,
    sops_decrypt_yaml, sops_encrypt_in_place, write_and_encrypt,
};

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use latchgate_config::Config;
use latchgate_registry::manifest::ActionSpec;
use serde_json::json;

use crate::output::{print_json, Printer};
use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub enum SecretsCommand {
    /// Initialize SOPS encryption: generate age keypair + encrypted secrets file.
    ///
    /// Creates `.latchgate/sops-age.key` (mode 0600) and `.latchgate/secrets.enc.yaml`,
    /// then sets `sops_secrets_file` and `sops_key_file` in latchgate.toml.
    Init {
        /// Overwrite existing key and secrets files.
        #[arg(long)]
        force: bool,
    },

    /// Set a secret value (encrypt and store).
    ///
    /// Key names must be UPPER_SNAKE_CASE (e.g. GITHUB_TOKEN).
    /// The value is encrypted at rest and never logged.
    Set {
        /// Secret name (e.g. GITHUB_TOKEN).
        #[arg(value_name = "KEY")]
        key: String,
        /// Secret value. Never logged or included in --json output.
        #[arg(value_name = "VALUE")]
        value: String,
    },

    /// Print a secret value to stdout (no --json wrapper for security).
    Get {
        /// Secret name.
        #[arg(value_name = "KEY")]
        key: String,
    },

    /// List secrets with status (set / missing / required by action).
    List,

    /// Remove a secret from the encrypted store.
    Remove {
        /// Secret name to remove.
        #[arg(value_name = "KEY")]
        key: String,
    },
}

use crate::config;

pub fn run(cfg: &Config, sub: &SecretsCommand, pr: &Printer, json_mode: bool) -> i32 {
    match sub {
        SecretsCommand::Init { force } => run_init(cfg, *force, pr, json_mode),
        SecretsCommand::Set { key, value } => run_set(cfg, key, value, pr, json_mode),
        SecretsCommand::Get { key } => run_get(cfg, key, pr),
        SecretsCommand::List => run_list(cfg, pr, json_mode),
        SecretsCommand::Remove { key } => run_remove(cfg, key, pr, json_mode),
    }
}

fn run_init(_cfg: &Config, force: bool, pr: &Printer, json_mode: bool) -> i32 {
    // Pre-flight: required binaries.
    if let Err(msg) = check_binary("age-keygen", "https://github.com/FiloSottile/age") {
        return emit_error(&msg, pr, json_mode);
    }
    if let Err(msg) = check_binary(
        latchgate_core::security_constants::SOPS_BIN,
        "https://github.com/getsops/sops",
    ) {
        return emit_error(&msg, pr, json_mode);
    }

    let key_dir = PathBuf::from(".latchgate");
    let key_path = key_dir.join("sops-age.key");
    let secrets_path = key_dir.join("secrets.enc.yaml");

    // Guard against accidental overwrite.
    if !force {
        if key_path.exists() {
            return emit_error(
                &format!(
                    "{} already exists — use --force to overwrite",
                    key_path.display()
                ),
                pr,
                json_mode,
            );
        }
        if secrets_path.exists() {
            return emit_error(
                &format!(
                    "{} already exists — use --force to overwrite",
                    secrets_path.display()
                ),
                pr,
                json_mode,
            );
        }
    }

    // Ensure key directory exists.
    if let Err(e) = std::fs::create_dir_all(&key_dir) {
        return emit_error(
            &format!("cannot create {}: {e}", key_dir.display()),
            pr,
            json_mode,
        );
    }

    // 1. Generate age keypair.
    let output = match Command::new("age-keygen").arg("-o").arg(&key_path).output() {
        Ok(o) => o,
        Err(e) => {
            return emit_error(&format!("failed to run age-keygen: {e}"), pr, json_mode);
        }
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return emit_error(
            &format!("age-keygen failed: {}", stderr.trim()),
            pr,
            json_mode,
        );
    }

    // 2. Set 0600 permissions on key file.
    if let Err(e) = set_file_mode_0600(&key_path) {
        return emit_error(
            &format!("cannot set permissions on {}: {e}", key_path.display()),
            pr,
            json_mode,
        );
    }

    // 3. Extract public key from the key file comment.
    let pubkey = match extract_age_public_key(&key_path) {
        Ok(pk) => pk,
        Err(msg) => return emit_error(&msg, pr, json_mode),
    };

    // 4. Create plaintext YAML, encrypt with sops.
    //    Write empty map as plaintext, then encrypt in-place.
    if let Err(e) = std::fs::write(&secrets_path, "{}\n") {
        return emit_error(
            &format!("cannot write {}: {e}", secrets_path.display()),
            pr,
            json_mode,
        );
    }

    if let Err(msg) = sops_encrypt_in_place(
        latchgate_core::security_constants::SOPS_BIN,
        &key_path,
        &pubkey,
        &secrets_path,
    ) {
        // Clean up the plaintext file on failure.
        let _ = std::fs::remove_file(&secrets_path);
        return emit_error(&msg, pr, json_mode);
    }

    // 5. Update config: sops_secrets_file + sops_key_file.
    //    Use the same run_set machinery that `config set` uses.
    let config_path_arg: Option<&str> = None;
    let quiet_pr = Printer::new(true); // suppress run_set output
    let rc = config::run_set(
        config_path_arg,
        "secrets.sops_secrets_file",
        &secrets_path.display().to_string(),
        &quiet_pr,
        true,
    );
    if rc != 0 {
        return emit_error(
            "failed to set secrets.sops_secrets_file in latchgate.toml",
            pr,
            json_mode,
        );
    }
    let rc = config::run_set(
        config_path_arg,
        "secrets.sops_key_file",
        &key_path.display().to_string(),
        &quiet_pr,
        true,
    );
    if rc != 0 {
        return emit_error(
            "failed to set secrets.sops_key_file in latchgate.toml",
            pr,
            json_mode,
        );
    }

    // 6. Output.
    if json_mode {
        print_json(&json!({
            "ok": true,
            "key_file": key_path.to_string_lossy(),
            "secrets_file": secrets_path.to_string_lossy(),
        }));
    } else {
        pr.blank();
        pr.success(&format!(
            "Age keypair generated       {} (mode 0600)",
            key_path.display()
        ));
        pr.success(&format!(
            "Secrets file created        {}",
            secrets_path.display()
        ));
        pr.success("Config updated              secrets.sops_secrets_file, secrets.sops_key_file");
        pr.blank();
        pr.section("  Add secrets:");
        pr.info("latchgate secrets set GITHUB_TOKEN ghp_xxxx");
        pr.info("latchgate secrets set SLACK_BOT_TOKEN xoxb-xxxx");
        pr.blank();
    }

    0
}

fn run_set(cfg: &Config, key: &str, value: &str, pr: &Printer, json_mode: bool) -> i32 {
    let resolved = match resolve_sops_paths(cfg) {
        Ok(r) => r,
        Err(msg) => return emit_error(&msg, pr, json_mode),
    };

    if key.is_empty() {
        return emit_error("secret key must not be empty", pr, json_mode);
    }

    // Validate key name: only uppercase alphanumeric + underscores.
    if !key
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        return emit_error(
            &format!("invalid secret key {key:?} — use UPPER_SNAKE_CASE (e.g. GITHUB_TOKEN)"),
            pr,
            json_mode,
        );
    }

    // Decrypt => modify => re-encrypt => atomic replace.
    let mut secrets = match sops_decrypt_yaml(
        latchgate_core::security_constants::SOPS_BIN,
        &resolved.key_file,
        &resolved.secrets_file,
    ) {
        Ok(m) => m,
        Err(msg) => return emit_error(&msg, pr, json_mode),
    };

    secrets.insert(key.to_string(), value.to_string());

    if let Err(msg) = write_and_encrypt(
        latchgate_core::security_constants::SOPS_BIN,
        &resolved.key_file,
        &resolved.pubkey,
        &resolved.secrets_file,
        &secrets,
    ) {
        return emit_error(&msg, pr, json_mode);
    }

    // Output — never include the value.
    if json_mode {
        print_json(&json!({
            "ok": true,
            "key": key,
            "secrets_file": resolved.secrets_file.to_string_lossy(),
        }));
    } else {
        pr.blank();
        pr.success(&format!("{key} set in {}", resolved.secrets_file.display()));
        pr.blank();
    }

    0
}

/// Print a single secret value to stdout. No `--json` wrapper — prevents
/// accidental log capture of secret values.
fn run_get(cfg: &Config, key: &str, pr: &Printer) -> i32 {
    let resolved = match resolve_sops_paths(cfg) {
        Ok(r) => r,
        Err(msg) => {
            emit_error(&msg, pr, false);
            return 1;
        }
    };

    let secrets = match sops_decrypt_yaml(
        latchgate_core::security_constants::SOPS_BIN,
        &resolved.key_file,
        &resolved.secrets_file,
    ) {
        Ok(m) => m,
        Err(msg) => {
            emit_error(&msg, pr, false);
            return 1;
        }
    };

    match secrets.get(key) {
        Some(val) => {
            println!("{val}");
            0
        }
        None => {
            pr.blank();
            pr.error(&format!("key {key:?} not found in secrets"));
            pr.blank();
            1
        }
    }
}

fn run_list(cfg: &Config, pr: &Printer, json_mode: bool) -> i32 {
    let resolved = match resolve_sops_paths(cfg) {
        Ok(r) => r,
        Err(msg) => return emit_error(&msg, pr, json_mode),
    };

    let secrets = match sops_decrypt_yaml(
        latchgate_core::security_constants::SOPS_BIN,
        &resolved.key_file,
        &resolved.secrets_file,
    ) {
        Ok(m) => m,
        Err(msg) => return emit_error(&msg, pr, json_mode),
    };

    // Cross-reference with manifest-declared secrets.
    let required = scan_required_secrets(&cfg.manifests_dir);

    if json_mode {
        let entries: Vec<serde_json::Value> = build_list_entries(&secrets, &required)
            .iter()
            .map(|(k, status, actions)| {
                json!({
                    "key": k,
                    "set": status == "set",
                    "required_by": actions,
                })
            })
            .collect();
        print_json(&json!({ "ok": true, "secrets": entries }));
        return 0;
    }

    pr.blank();

    let entries = build_list_entries(&secrets, &required);
    if entries.is_empty() {
        pr.info("No secrets configured. Run: latchgate secrets set <KEY> <VALUE>");
        pr.blank();
        return 0;
    }

    // Compute column widths.
    let key_width = entries
        .iter()
        .map(|(k, _, _)| k.len())
        .max()
        .unwrap_or(3)
        .max(3);

    pr.line(&format!(
        "  {:<key_width$}  Status",
        "Key",
        key_width = key_width,
    ));
    pr.line(&format!("  {}", "─".repeat(key_width + 30)));

    for (key, status, actions) in &entries {
        let sym = if status == "set" {
            pr.ok_sym()
        } else {
            pr.err_sym()
        };
        let detail = if status == "set" {
            "set".to_string()
        } else if actions.is_empty() {
            "missing".to_string()
        } else {
            format!("required by: {}", actions.join(", "))
        };
        pr.line(&format!("  {key:<key_width$}  {sym} {detail}"));
    }

    pr.blank();
    0
}

fn run_remove(cfg: &Config, key: &str, pr: &Printer, json_mode: bool) -> i32 {
    let resolved = match resolve_sops_paths(cfg) {
        Ok(r) => r,
        Err(msg) => return emit_error(&msg, pr, json_mode),
    };

    let mut secrets = match sops_decrypt_yaml(
        latchgate_core::security_constants::SOPS_BIN,
        &resolved.key_file,
        &resolved.secrets_file,
    ) {
        Ok(m) => m,
        Err(msg) => return emit_error(&msg, pr, json_mode),
    };

    if secrets.remove(key).is_none() {
        return emit_error(&format!("key {key:?} not found in secrets"), pr, json_mode);
    }

    if let Err(msg) = write_and_encrypt(
        latchgate_core::security_constants::SOPS_BIN,
        &resolved.key_file,
        &resolved.pubkey,
        &resolved.secrets_file,
        &secrets,
    ) {
        return emit_error(&msg, pr, json_mode);
    }

    if json_mode {
        print_json(&json!({
            "ok": true,
            "key": key,
            "removed": true,
        }));
    } else {
        pr.blank();
        pr.success(&format!(
            "{key} removed from {}",
            resolved.secrets_file.display()
        ));
        pr.blank();
    }

    0
}

/// Scan manifests for declared secrets and return a map of
/// secret_name => list of action_ids that require it.
fn scan_required_secrets(manifests_dir: &str) -> BTreeMap<String, Vec<String>> {
    let mut required: BTreeMap<String, Vec<String>> = BTreeMap::new();

    let dir = Path::new(manifests_dir);
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return required,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "yaml" && ext != "yml" {
            continue;
        }

        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let spec = match ActionSpec::from_yaml(&contents) {
            Ok(s) => s,
            Err(_) => continue,
        };

        for secret in &spec.secrets {
            if secret.required {
                required
                    .entry(secret.name.to_string())
                    .or_default()
                    .push(spec.action_id.clone());
            }
        }
    }

    required
}

/// Build a merged list of (key, status, requiring_actions) for display.
///
/// Includes both secrets that are set and required secrets that are missing.
fn build_list_entries(
    secrets: &BTreeMap<String, String>,
    required: &BTreeMap<String, Vec<String>>,
) -> Vec<(String, String, Vec<String>)> {
    let mut entries = Vec::new();

    // All set secrets.
    for key in secrets.keys() {
        entries.push((key.clone(), "set".to_string(), Vec::new()));
    }

    // Required secrets that are not set.
    for (key, actions) in required {
        if !secrets.contains_key(key) {
            entries.push((key.clone(), "missing".to_string(), actions.clone()));
        }
    }

    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries
}

fn emit_error(msg: &str, pr: &Printer, json_mode: bool) -> i32 {
    if json_mode {
        print_json(&json!({ "ok": false, "error": msg }));
    } else {
        pr.blank();
        pr.error(msg);
        pr.blank();
    }
    1
}

#[cfg(test)]
mod tests {
    use super::sops::extract_age_public_key;
    use super::yaml::{needs_yaml_quoting, parse_yaml_map, serialize_yaml_map, yaml_escape};
    use super::*;

    // -- YAML round-trip -----------------------------------------------------

    #[test]
    fn empty_yaml_parses_to_empty_map() {
        assert!(parse_yaml_map("{}").unwrap().is_empty());
        assert!(parse_yaml_map("").unwrap().is_empty());
        assert!(parse_yaml_map("  \n  ").unwrap().is_empty());
    }

    #[test]
    fn flat_yaml_round_trips() {
        let mut map = BTreeMap::new();
        map.insert("GITHUB_TOKEN".into(), "ghp_abc123".into());
        map.insert("SLACK_TOKEN".into(), "xoxb-something".into());

        let yaml = serialize_yaml_map(&map);
        let parsed = parse_yaml_map(&yaml).unwrap();
        assert_eq!(parsed, map);
    }

    #[test]
    fn quoted_values_round_trip() {
        let mut map = BTreeMap::new();
        map.insert("KEY_WITH_COLON".into(), "value:with:colons".into());
        map.insert("BOOL_LIKE".into(), "true".into());

        let yaml = serialize_yaml_map(&map);
        let parsed = parse_yaml_map(&yaml).unwrap();
        assert_eq!(parsed, map);
    }

    #[test]
    fn yaml_escape_handles_special_chars() {
        assert_eq!(yaml_escape(r#"a"b"#), r#"a\"b"#);
        assert_eq!(yaml_escape("a\\b"), "a\\\\b");
        assert_eq!(yaml_escape("a\nb"), "a\\nb");
    }

    #[test]
    fn values_needing_quoting_are_detected() {
        assert!(needs_yaml_quoting(""));
        assert!(needs_yaml_quoting("value:with:colons"));
        assert!(needs_yaml_quoting("true"));
        assert!(needs_yaml_quoting("false"));
        assert!(needs_yaml_quoting("null"));
        assert!(needs_yaml_quoting(" leading space"));
        assert!(!needs_yaml_quoting("ghp_abc123"));
        assert!(!needs_yaml_quoting("xoxb-something"));
    }

    // -- public key extraction -----------------------------------------------

    #[test]
    fn extract_pubkey_from_age_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("test.key");
        std::fs::write(
            &key_path,
            "# created: 2025-01-01T00:00:00Z\n\
             # public key: age1qmxnupz7q88example\n\
             AGE-SECRET-KEY-1EXAMPLE\n",
        )
        .unwrap();

        let pk = extract_age_public_key(&key_path).unwrap();
        assert_eq!(pk, "age1qmxnupz7q88example");
    }

    #[test]
    fn extract_pubkey_missing_key_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("bad.key");
        std::fs::write(&key_path, "# no public key here\n").unwrap();

        let result = extract_age_public_key(&key_path);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("cannot find"),
            "error should mention missing key"
        );
    }

    // -- build_list_entries ---------------------------------------------------

    #[test]
    fn list_entries_merges_set_and_required() {
        let mut secrets = BTreeMap::new();
        secrets.insert("GITHUB_TOKEN".into(), "ghp_xxx".into());
        secrets.insert("CUSTOM_KEY".into(), "val".into());

        let mut required = BTreeMap::new();
        required.insert("GITHUB_TOKEN".into(), vec!["github_read".into()]);
        required.insert(
            "SLACK_BOT_TOKEN".into(),
            vec!["slack_post".into(), "slack_read".into()],
        );

        let entries = build_list_entries(&secrets, &required);

        // CUSTOM_KEY is set but not required.
        let custom = entries.iter().find(|(k, _, _)| k == "CUSTOM_KEY").unwrap();
        assert_eq!(custom.1, "set");
        assert!(custom.2.is_empty());

        // GITHUB_TOKEN is set and required — shows as "set".
        let github = entries
            .iter()
            .find(|(k, _, _)| k == "GITHUB_TOKEN")
            .unwrap();
        assert_eq!(github.1, "set");

        // SLACK_BOT_TOKEN is required but missing.
        let slack = entries
            .iter()
            .find(|(k, _, _)| k == "SLACK_BOT_TOKEN")
            .unwrap();
        assert_eq!(slack.1, "missing");
        assert_eq!(slack.2, vec!["slack_post", "slack_read"]);
    }

    // -- scan_required_secrets -----------------------------------------------

    #[test]
    fn scan_required_secrets_from_manifests() {
        let dir = tempfile::tempdir().unwrap();
        let manifests_dir = dir.path().join("manifests");
        crate::embedded_manifests::extract_manifests(
            crate::embedded_manifests::ManifestFilter::All,
            &manifests_dir,
        )
        .unwrap();

        let required = scan_required_secrets(manifests_dir.to_str().unwrap());

        // At minimum, some manifests declare required secrets.
        // The exact set depends on the embedded manifests, but the function
        // must return a non-empty map.
        assert!(
            !required.is_empty(),
            "expected at least some manifests to declare required secrets"
        );

        // Every action_id in the values must be a valid action name.
        for (secret_name, action_ids) in &required {
            assert!(!secret_name.is_empty(), "secret name must not be empty");
            for aid in action_ids {
                assert!(!aid.is_empty(), "action_id must not be empty");
            }
        }
    }

    // -- parse_yaml_map edge cases -------------------------------------------

    #[test]
    fn parse_yaml_rejects_malformed_line() {
        let result = parse_yaml_map("this has no colon");
        assert!(result.is_err());
    }

    #[test]
    fn parse_yaml_skips_comments() {
        let yaml = "# comment\nKEY: value\n";
        let map = parse_yaml_map(yaml).unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map["KEY"], "value");
    }
}
