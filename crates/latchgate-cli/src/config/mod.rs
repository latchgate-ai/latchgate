//! `latchgate config` — configuration management.
//!
//! Split into submodules by domain. Shared TOML editing helpers live here.

mod get;
mod operator;
mod principal;
mod resources;
mod set;
mod unset;
mod validate;
mod webhook;

pub use get::run_get;
pub use operator::{run_add_operator, run_remove_operator};
pub use principal::{
    run_add_principal, run_list_principals, run_remove_principal, AddPrincipalArgs,
};
pub use resources::{run_path, run_resources};
pub use set::run_set;
use std::path::PathBuf;
pub use unset::run_unset;
pub use validate::run_validate;
pub use webhook::{
    run_add_webhook, run_list_webhooks, run_remove_webhook, run_test_webhook, AddWebhookArgs,
};

use latchgate_config::Config;

use crate::cmd::{output, paths, secure_file};
use crate::output::Printer;

use clap::Subcommand;

/// Load a TOML config, let `edit` mutate it, validate, and atomic-write.
///
/// Centralises the resolve → read → parse → validate → write pipeline that
/// every config mutation command repeats. The closure receives a mutable
/// `DocumentMut` and returns either a value to propagate or a user-facing
/// error message.
///
/// # Security
///
/// Every write path goes through [`validate_toml_as_config`] — the closure
/// cannot produce an invalid config on disk. [`secure_file::atomic_write`]
/// ensures crash-safe writes (write-to-tmp → fsync → rename).
pub(super) fn edit_config_doc<T>(
    pr: &Printer,
    config_path: Option<&str>,
    edit: impl FnOnce(&mut toml_edit::DocumentMut) -> Result<T, String>,
) -> Result<T, i32> {
    let path =
        paths::resolve_config_path(config_path).map_err(|msg| output::emit_error(pr, &msg))?;

    let raw = std::fs::read_to_string(&path)
        .map_err(|e| output::emit_error(pr, &format!("cannot read {}: {e}", path.display())))?;

    let mut doc: toml_edit::DocumentMut = raw.parse().map_err(|e| {
        output::emit_error(pr, &format!("{} is not valid TOML: {e}", path.display()))
    })?;

    let result = edit(&mut doc).map_err(|msg| output::emit_error(pr, &msg))?;

    let modified = doc.to_string();
    validate_toml_as_config(&modified)
        .map_err(|msg| output::emit_error(pr, &format!("config validation failed: {msg}")))?;

    secure_file::atomic_write(&path, &modified)
        .map_err(|e| output::emit_error(pr, &format!("cannot write {}: {e}", path.display())))?;

    Ok(result)
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    /// Print the resolved config file path and discovery source.
    Path,
    /// Show where manifests, providers, and policies are loaded from.
    ///
    /// Loads the registry without starting the gate and reports how many
    /// actions come from embedded vs. user manifests, which overrides are
    /// active, and where provider and policy files live.
    Resources,
    /// Query a configuration value by dotted key.
    ///
    /// Prints the value with type-aware formatting: strings unquoted,
    /// integers and booleans as-is, arrays as newline-separated values,
    /// tables pretty-printed as TOML. With no key, dumps the entire config.
    ///
    /// Examples:
    ///   latchgate config get redis_url
    ///   latchgate config get sandbox.mode
    ///   latchgate config get sandbox
    ///   latchgate config get --json
    Get {
        /// Dotted key path (e.g. `redis_url`, `sandbox.mode`).
        /// Omit to dump the entire config.
        #[arg(value_name = "KEY")]
        key: Option<String>,
    },
    /// Set a configuration value. Type inferred from existing field;
    /// new fields default to string.
    ///
    /// Examples:
    ///   latchgate config set redis_url "redis://new:6379"
    ///   latchgate config set sandbox.mode strict
    ///   latchgate config set opa_timeout_ms 2000
    Set {
        /// Dotted key path (e.g. `redis_url`, `sandbox.mode`).
        #[arg(value_name = "KEY")]
        key: String,
        /// Value to set. Parsed as the existing field's type.
        #[arg(value_name = "VALUE")]
        value: String,
    },
    /// Remove a configuration field.
    ///
    /// Uses `toml_edit` to remove the key while preserving comments and
    /// formatting. The resulting config is validated — if removing the
    /// field makes the config invalid, the change is rejected.
    ///
    /// Idempotent: unsetting an absent key exits 0.
    ///
    /// Example:
    ///   latchgate config unset listen_http_addr
    Unset {
        /// Dotted key path to remove (e.g. `listen_http_addr`, `sandbox.strict_for_actions`).
        #[arg(value_name = "KEY")]
        key: String,
    },
    /// Validate config without starting the server or checking dependencies.
    ///
    /// Runs all production security checks and reports pass/fail per check.
    /// In dev mode, checks that would only apply in production are skipped.
    Validate,
    /// Add an operator credential with auto-generated DPoP keypair.
    ///
    /// Generates a P-256 keypair, computes the JWK thumbprint, writes the
    /// private key to `<key-dir>/<name>.pem` (mode 0600), and adds a
    /// `[operator_credentials.<name>]` section to latchgate.toml.
    ///
    /// The API key is shown once and never logged.
    AddOperator {
        /// Operator name (becomes the TOML section key).
        #[arg(long)]
        name: String,
        /// Explicit API key. Auto-generated if omitted.
        #[arg(long)]
        api_key: Option<String>,
        /// Directory for the private key PEM file.
        #[arg(long, default_value = ".latchgate")]
        key_dir: PathBuf,
    },
    /// Remove an operator credential from latchgate.toml.
    ///
    /// Removes the `[operator_credentials.<name>]` section. Does NOT
    /// delete the PEM file (operator may want a backup).
    RemoveOperator {
        /// Operator name to remove.
        #[arg(value_name = "NAME")]
        name: String,
    },

    /// Map a Unix UID to a named principal for peercred identity.
    ///
    /// Sets `identity.provider = "peercred"` if currently `"none"`.
    /// Generates a `[identity.peercred.principals.<UID>]` section in
    /// latchgate.toml with the given name, scopes, and optional owner.
    ///
    /// Example:
    ///   latchgate config add-principal --uid 1001 --name agent-ops \
    ///     --scopes tools:call,db:query --owner bob@corp.com
    AddPrincipal {
        /// Unix UID to map.
        #[arg(long)]
        uid: u32,
        /// Principal name (becomes `sub` in the Lease JWT).
        #[arg(long)]
        name: String,
        /// Comma-separated scopes this principal may request.
        #[arg(long)]
        scopes: String,
        /// Owner/responsible person (e.g. `alice@corp.com`).
        #[arg(long)]
        owner: Option<String>,
        /// Overwrite if UID already exists.
        #[arg(long)]
        force: bool,
    },

    /// Remove a principal mapping by UID.
    RemovePrincipal {
        /// Unix UID to remove.
        #[arg(long)]
        uid: u32,
    },

    /// List all configured principal mappings.
    ListPrincipals,

    /// Add a webhook endpoint for event notifications.
    ///
    /// Appends a `[[webhooks]]` entry to latchgate.toml. HTTPS required
    /// in production (HTTP allowed in dev mode). The endpoint is validated
    /// via `latchgate_webhooks::validate_webhook_configs` before writing.
    ///
    /// Example:
    ///   latchgate config add-webhook --name slack-alerts \
    ///     --url `https://hooks.slack.com/services/T.../B.../xxx` \
    ///     --secret whsec_abc123 --events approval.pending,approval.expired
    AddWebhook {
        /// Endpoint name (must be unique across webhooks).
        #[arg(long)]
        name: String,
        /// HTTPS endpoint URL.
        #[arg(long)]
        url: String,
        /// HMAC-SHA256 signing secret. Auto-generated if omitted.
        #[arg(long)]
        secret: Option<String>,
        /// Comma-separated event types to subscribe to.
        #[arg(long)]
        events: String,
        /// Extra HTTP headers as K=V pairs (comma-separated).
        #[arg(long)]
        headers: Option<String>,
        /// Per-request timeout in seconds.
        #[arg(long, default_value = "10")]
        timeout: u64,
        /// Payload format: `generic` (default) or `slack`.
        #[arg(long, default_value = "generic")]
        format: String,
    },

    /// Remove a webhook endpoint by name.
    RemoveWebhook {
        /// Webhook name to remove.
        #[arg(long)]
        name: String,
    },

    /// List all configured webhook endpoints.
    ListWebhooks,

    /// Send a test event to a webhook endpoint and report delivery status.
    ///
    /// Sends a synthetic `test` event through the full delivery pipeline
    /// (HMAC signing, SSRF check, HTTP POST) without retries. Useful for
    /// verifying endpoint connectivity and signature validation.
    ///
    /// Example:
    ///   latchgate config test-webhook --name slack-alerts
    ///   latchgate config test-webhook              # tests all endpoints
    TestWebhook {
        /// Webhook name to test. Omit to test all configured endpoints.
        #[arg(long)]
        name: Option<String>,
    },
}

/// Set a dotted key in a `toml_edit::DocumentMut`, preserving the type of
/// existing fields. New fields default to string.
pub(super) fn set_value_in_document(
    doc: &mut toml_edit::DocumentMut,
    key: &str,
    value: &str,
) -> Result<(), String> {
    let segments: Vec<&str> = key.split('.').collect();
    if segments.is_empty() || segments.iter().any(|s| s.is_empty()) {
        return Err(format!("invalid key: {key:?}"));
    }

    // Navigate to the parent table, creating intermediate tables.
    let (parent_segments, leaf) = segments.split_at(segments.len() - 1);

    let mut table: &mut toml_edit::Item = doc.as_item_mut();
    for &seg in parent_segments {
        // Ensure the intermediate is a table.
        if table.get(seg).is_none() {
            table[seg] = toml_edit::Item::Table(toml_edit::Table::new());
        }
        table = &mut table[seg];
        if !table.is_table() && !table.is_table_like() {
            return Err(format!(
                "'{seg}' in key '{key}' is not a table — cannot navigate further"
            ));
        }
    }

    let leaf_key = leaf[0];
    let typed_value = infer_typed_value(table.get(leaf_key), value)?;
    table[leaf_key] = toml_edit::value(typed_value);
    Ok(())
}

/// Infer the `toml_edit::Value` from the existing field type (if any) or
/// default to string for new fields.
///
/// Type preservation prevents "3000" being written as a string when the
/// field is already an integer.
fn infer_typed_value(
    existing: Option<&toml_edit::Item>,
    raw: &str,
) -> Result<toml_edit::Value, String> {
    // If the field already exists, match its type.
    if let Some(item) = existing {
        if let Some(v) = item.as_value() {
            return match v {
                toml_edit::Value::Integer(_) => {
                    let n: i64 = raw
                        .parse()
                        .map_err(|_| format!("expected integer, got {raw:?}"))?;
                    Ok(toml_edit::Value::from(n))
                }
                toml_edit::Value::Float(_) => {
                    let f: f64 = raw
                        .parse()
                        .map_err(|_| format!("expected float, got {raw:?}"))?;
                    Ok(toml_edit::Value::from(f))
                }
                toml_edit::Value::Boolean(_) => {
                    let b: bool = raw
                        .parse()
                        .map_err(|_| format!("expected boolean (true/false), got {raw:?}"))?;
                    Ok(toml_edit::Value::from(b))
                }
                // String, datetime, array, inline-table — write as string.
                _ => Ok(toml_edit::Value::from(raw)),
            };
        }
    }

    // New field or non-value item: default to string (safe default).
    Ok(toml_edit::Value::from(raw))
}

/// Deserialize TOML text into Config and run semantic validation.
pub(super) fn validate_toml_as_config(toml_text: &str) -> Result<(), String> {
    let config: Config = toml::from_str(toml_text).map_err(|e| format!("parse error: {e}"))?;

    // Run all semantic checks. Collect first error.
    config
        .validate_production_security()
        .map_err(|e| e.to_string())
}

#[cfg(test)]
pub(crate) mod test_fixtures {
    use std::path::{Path, PathBuf};

    pub fn write_test_config(dir: &Path, content: &str) -> PathBuf {
        let path = dir.join("latchgate.toml");
        std::fs::write(&path, content).unwrap();
        path
    }

    pub const DEV_TOML: &str = r#"
listen_uds_path = "/tmp/lg-test.sock"
listen_admin_uds_path = "/tmp/lg-test-admin.sock"
redis_url = "redis://127.0.0.1:6379"
opa_url = "http://127.0.0.1:8181"

[sandbox]
mode = "degraded_ok"

[identity]
provider = "none"

[operator_credentials.dev]
api_key = "test-key"
"#;

    pub const PROD_TOML: &str = r#"
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

    pub const PRINCIPAL_TEST_TOML: &str = r#"
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
provider = "none"

[operator_credentials.admin]
api_key = "key-admin-test"
dpop_jkt = "test-thumbprint-sha256"
"#;
}
