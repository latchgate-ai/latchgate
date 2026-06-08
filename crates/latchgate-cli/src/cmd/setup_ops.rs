//! [`SetupOps`] implementation for the TUI — edits latchgate.toml in place.

use std::path::{Path, PathBuf};

use latchgate_config::Config;
use latchgate_tui::SetupOps;

use super::credential;

/// Resolve the durable (persistent) config file for setup mutations.
///
/// Setup edits must persist to the project or user-global config, never to
/// the ephemeral `up`-session config in the runtime state directory (which is
/// regenerated on every `latchgate up`).
///
/// Discovery order mirrors [`Config::load`] but excludes the
/// `active_session_config()` branch:
///   1. `<project_root>/.latchgate/latchgate.toml` (project-local)
///   2. `$XDG_CONFIG_HOME/latchgate/latchgate.toml` (user-global)
fn resolve_durable_config(project_root: Option<&Path>) -> Option<PathBuf> {
    if let Some(root) = project_root {
        let candidate = root.join(".latchgate/latchgate.toml");
        if candidate.exists() {
            return Some(candidate);
        }
    }

    if let Ok(user) = latchgate_config::UserDirs::resolve() {
        let candidate = user.config_file();
        if candidate.exists() {
            return Some(candidate);
        }
    }

    None
}

/// Concrete [`SetupOps`] backed by local TOML file editing.
pub struct CliSetupOps {
    config_path: Option<PathBuf>,
}

impl CliSetupOps {
    pub fn new(config: &Config) -> Self {
        // Resolve the durable config independently of the (possibly ephemeral)
        // runtime config. The ephemeral `up`-session config is a derived
        // artifact in the state dir; the source of truth for operator edits is
        // the project or user-global config.
        let config_path = resolve_durable_config(std::env::current_dir().ok().as_deref())
            .or_else(|| config.source.config_file());
        Self { config_path }
    }

    /// Read, parse, and return the TOML document + path.
    fn load_doc(&self) -> Result<(toml_edit::DocumentMut, PathBuf), String> {
        let path = self
            .config_path
            .clone()
            .ok_or_else(|| "no config file found — run `latchgate init` first".to_string())?;
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let doc: toml_edit::DocumentMut = raw
            .parse()
            .map_err(|e| format!("{} is not valid TOML: {e}", path.display()))?;
        Ok((doc, path))
    }

    /// Write the document back and reload Config.
    fn save_and_reload(
        &self,
        doc: &toml_edit::DocumentMut,
        path: &std::path::Path,
    ) -> Result<Config, String> {
        std::fs::write(path, doc.to_string())
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        Config::from_file(path).map_err(|e| format!("config validation failed after edit: {e}"))
    }

    fn reload_config(&self) -> Result<Config, String> {
        let path = self
            .config_path
            .as_ref()
            .ok_or_else(|| "no config file found".to_string())?;
        Config::from_file(path).map_err(|e| format!("cannot load config: {e}"))
    }
}

/// Scan manifest YAML files for declared secrets.
fn scan_required_secrets(manifests_dir: &str) -> std::collections::BTreeMap<String, Vec<String>> {
    use latchgate_registry::ActionSpec;
    let mut required: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    let dir = std::path::Path::new(manifests_dir);
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
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(spec) = ActionSpec::from_yaml(&contents) else {
            continue;
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

impl SetupOps for CliSetupOps {
    fn set_config(&self, key: &str, value: &str) -> Result<Config, String> {
        let (mut doc, path) = self.load_doc()?;

        let parts: Vec<&str> = key.split('.').collect();
        if parts.is_empty() {
            return Err("key must not be empty".into());
        }

        // Navigate to parent table, creating intermediate tables as needed.
        let mut table = doc.as_table_mut() as &mut dyn toml_edit::TableLike;
        for &part in &parts[..parts.len() - 1] {
            if !table.contains_key(part) {
                table.insert(part, toml_edit::Item::Table(toml_edit::Table::new()));
            }
            table = table
                .get_mut(part)
                .and_then(|v| v.as_table_like_mut())
                .ok_or_else(|| format!("{part} is not a table"))?;
        }

        let leaf = parts[parts.len() - 1];
        // Infer type from existing value, or treat as string.
        let item = if let Some(existing) = table.get(leaf) {
            match existing.as_value() {
                Some(toml_edit::Value::Boolean(_)) => {
                    let b: bool = value
                        .parse()
                        .map_err(|_| format!("expected bool for {key}"))?;
                    toml_edit::value(b)
                }
                Some(toml_edit::Value::Integer(_)) => {
                    let n: i64 = value
                        .parse()
                        .map_err(|_| format!("expected integer for {key}"))?;
                    toml_edit::value(n)
                }
                _ => toml_edit::value(value),
            }
        } else {
            toml_edit::value(value)
        };
        table.insert(leaf, item);

        self.save_and_reload(&doc, &path)
    }

    fn add_principal(
        &self,
        uid: u32,
        name: &str,
        scopes: &str,
        owner: Option<&str>,
    ) -> Result<Config, String> {
        if uid == 0 {
            return Err("UID 0 (root) is not allowed".into());
        }
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err("invalid principal name — alphanumeric, hyphens, underscores only".into());
        }
        let scope_list: Vec<&str> = scopes
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        if scope_list.is_empty() {
            return Err("at least one scope is required".into());
        }

        let (mut doc, path) = self.load_doc()?;

        // Ensure identity.provider = "peercred".
        let current_provider = doc
            .get("identity")
            .and_then(|t| t.get("provider"))
            .and_then(|v| v.as_str())
            .unwrap_or("none");
        match current_provider {
            "none" | "peercred" => {}
            other => {
                return Err(format!(
                    "identity.provider is '{other}' — cannot add peercred principal"
                ))
            }
        }

        // Set identity.provider = "peercred" if needed.
        if current_provider == "none" {
            doc["identity"]["provider"] = toml_edit::value("peercred");
        }

        // Ensure tables exist.
        if doc
            .get("identity")
            .and_then(|t| t.get("peercred"))
            .is_none()
        {
            doc["identity"]["peercred"] = toml_edit::Item::Table(toml_edit::Table::new());
        }
        if doc["identity"]["peercred"].get("principals").is_none() {
            doc["identity"]["peercred"]["principals"] =
                toml_edit::Item::Table(toml_edit::Table::new());
        }

        // Build principal inline table.
        let mut principal = toml_edit::InlineTable::new();
        principal.insert("principal", toml_edit::Value::from(name));
        let mut scopes_array = toml_edit::Array::new();
        for s in &scope_list {
            scopes_array.push(*s);
        }
        principal.insert("scopes", toml_edit::Value::Array(scopes_array));
        if let Some(o) = owner {
            principal.insert("owner", toml_edit::Value::from(o));
        }

        doc["identity"]["peercred"]["principals"][&uid.to_string()] =
            toml_edit::Item::Value(toml_edit::Value::InlineTable(principal));

        // Set allow_unmapped = false if missing.
        if doc["identity"]["peercred"].get("allow_unmapped").is_none() {
            doc["identity"]["peercred"]["allow_unmapped"] = toml_edit::value(false);
        }

        self.save_and_reload(&doc, &path)
    }

    fn remove_principal(&self, uid: u32) -> Result<Config, String> {
        let (mut doc, path) = self.load_doc()?;

        let removed = doc
            .get_mut("identity")
            .and_then(|t| t.get_mut("peercred"))
            .and_then(|t| t.get_mut("principals"))
            .and_then(|t| t.as_table_like_mut())
            .map(|t| t.remove(&uid.to_string()).is_some())
            .unwrap_or(false);

        if !removed {
            return Err(format!("principal UID {uid} not found"));
        }

        self.save_and_reload(&doc, &path)
    }

    fn add_operator(&self, name: &str) -> Result<(Config, String, String), String> {
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err("invalid operator name — alphanumeric, hyphens, underscores only".into());
        }

        let (mut doc, path) = self.load_doc()?;

        // Check for duplicates.
        if doc
            .get("operator_credentials")
            .and_then(|t| t.get(name))
            .is_some()
        {
            return Err(format!("operator '{name}' already exists"));
        }

        // Generate API key.
        let api_key = credential::generate_api_key(name);

        // Generate DPoP keypair.
        let (signing_key, _pub_key) = latchgate_auth::dpop::generate_dpop_keypair()
            .map_err(|e| format!("keygen failed: {e}"))?;

        let thumbprint = signing_key
            .thumbprint()
            .map_err(|e| format!("thumbprint computation failed: {e}"))?;

        // Write PEM key file.
        let key_dir = path
            .parent()
            .ok_or_else(|| "cannot determine key directory".to_string())?;
        let key_path = key_dir.join(format!("{name}.operator.pem"));
        if key_path.exists() {
            return Err(format!(
                "{} already exists — remove it first",
                key_path.display()
            ));
        }

        use p256::pkcs8::EncodePrivateKey;
        let pem = signing_key
            .as_inner()
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .map_err(|e| format!("PEM encoding failed: {e}"))?;
        std::fs::write(&key_path, pem.as_bytes())
            .map_err(|e| format!("cannot write key file: {e}"))?;

        // Restrict permissions to owner-only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
        }

        // Write operator credential to TOML.
        if doc.get("operator_credentials").is_none() {
            doc["operator_credentials"] = toml_edit::Item::Table(toml_edit::Table::new());
        }

        let mut cred = toml_edit::Table::new();
        cred.insert("api_key", toml_edit::value(&api_key));
        cred.insert("dpop_jkt", toml_edit::value(&thumbprint));
        doc["operator_credentials"][name] = toml_edit::Item::Table(cred);

        let cfg = self.save_and_reload(&doc, &path)?;
        Ok((cfg, api_key, key_path.display().to_string()))
    }

    fn remove_operator(&self, name: &str) -> Result<Config, String> {
        let (mut doc, path) = self.load_doc()?;

        let removed = doc
            .get_mut("operator_credentials")
            .and_then(|t| t.as_table_like_mut())
            .map(|t| t.remove(name).is_some())
            .unwrap_or(false);

        if !removed {
            return Err(format!("operator '{name}' not found"));
        }

        self.save_and_reload(&doc, &path)
    }

    fn add_webhook(
        &self,
        name: &str,
        url: &str,
        events: &str,
        format: &str,
    ) -> Result<(Config, String), String> {
        if name.is_empty() {
            return Err("webhook name must not be empty".into());
        }
        if !url.starts_with("https://") && !url.starts_with("http://") {
            return Err("webhook URL must start with https:// or http://".into());
        }

        let secret = credential::generate_webhook_secret();

        let event_list: Vec<&str> = events
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        if event_list.is_empty() {
            return Err("at least one event pattern is required".into());
        }

        let (mut doc, path) = self.load_doc()?;

        // Check for duplicate name.
        if let Some(arr) = doc.get("webhooks").and_then(|v| v.as_array_of_tables()) {
            for entry in arr.iter() {
                if entry.get("name").and_then(|v| v.as_str()) == Some(name) {
                    return Err(format!("webhook '{name}' already exists"));
                }
            }
        }

        // Ensure [[webhooks]] array exists.
        if doc.get("webhooks").is_none() {
            doc.insert(
                "webhooks",
                toml_edit::Item::ArrayOfTables(toml_edit::ArrayOfTables::new()),
            );
        }

        let mut entry = toml_edit::Table::new();
        entry.insert("name", toml_edit::value(name));
        entry.insert("url", toml_edit::value(url));
        entry.insert("secret", toml_edit::value(&secret));

        let mut events_arr = toml_edit::Array::new();
        for e in &event_list {
            events_arr.push(*e);
        }
        entry.insert(
            "events",
            toml_edit::Item::Value(toml_edit::Value::Array(events_arr)),
        );

        // Only write format if non-default — keeps config tidy for generic endpoints.
        if format != "generic" {
            entry.insert("format", toml_edit::value(format));
        }

        doc.get_mut("webhooks")
            .and_then(|v| v.as_array_of_tables_mut())
            .ok_or_else(|| "cannot access [[webhooks]] array".to_string())?
            .push(entry);

        let config = self.save_and_reload(&doc, &path)?;
        Ok((config, secret))
    }

    fn remove_webhook(&self, name: &str) -> Result<Config, String> {
        let (mut doc, path) = self.load_doc()?;

        let arr = doc
            .get_mut("webhooks")
            .and_then(|v| v.as_array_of_tables_mut())
            .ok_or_else(|| "no [[webhooks]] configured".to_string())?;

        let idx = arr
            .iter()
            .position(|entry| entry.get("name").and_then(|v| v.as_str()) == Some(name))
            .ok_or_else(|| format!("webhook '{name}' not found"))?;

        arr.remove(idx);

        self.save_and_reload(&doc, &path)
    }

    fn test_webhook(
        &self,
        name: &str,
        config: &Config,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = latchgate_tui::WebhookTestResult> + Send>>
    {
        let name = name.to_string();
        let webhooks = config.webhooks.clone();
        let dev_mode = config.dev_mode();

        Box::pin(async move {
            // Find and parse the named endpoint.
            let endpoint = webhooks.iter().find_map(|raw| {
                let ep_name = raw.get("name")?.as_str()?;
                if ep_name != name {
                    return None;
                }
                raw.clone()
                    .try_into::<latchgate_webhooks::WebhookEndpointConfig>()
                    .ok()
            });

            let Some(ep) = endpoint else {
                return latchgate_tui::WebhookTestResult {
                    endpoint_name: name,
                    ok: false,
                    elapsed_ms: 0,
                    error: Some("endpoint not found or invalid config".into()),
                };
            };

            let result =
                latchgate_webhooks::test_deliver(&ep, env!("CARGO_PKG_VERSION"), dev_mode).await;

            let ok = result.is_ok();
            let elapsed_ms = result.elapsed.as_millis() as u64;

            latchgate_tui::WebhookTestResult {
                endpoint_name: result.endpoint_name,
                ok,
                elapsed_ms,
                error: result.error,
            }
        })
    }

    fn execute_init(&self, plan: &latchgate_tui::InitPlan) -> Result<Config, String> {
        use crate::cmd::init::execute::execute_plan;
        let result = execute_plan(plan)?;
        Config::from_file(&result.config_path)
            .map_err(|e| format!("init succeeded but config reload failed: {e}"))
    }

    fn secrets_init(&self, force: bool) -> Result<Config, String> {
        use super::secrets::sops;

        sops::check_binary("age-keygen", "https://github.com/FiloSottile/age")?;
        sops::check_binary(
            latchgate_core::security_constants::SOPS_BIN,
            "https://github.com/getsops/sops",
        )?;

        let key_dir = std::path::PathBuf::from(".latchgate");
        let key_path = key_dir.join("sops-age.key");
        let secrets_path = key_dir.join("secrets.enc.yaml");

        let key_exists = key_path.exists();
        let secrets_exists = secrets_path.exists();

        if !force && key_exists && secrets_exists {
            // Both files already exist — re-link them into the config
            // without regenerating key material or overwriting data.
            let (mut doc, cfg_path) = self.load_doc()?;
            doc["secrets"]["sops_secrets_file"] =
                toml_edit::value(secrets_path.display().to_string());
            doc["secrets"]["sops_key_file"] = toml_edit::value(key_path.display().to_string());
            return self.save_and_reload(&doc, &cfg_path);
        }

        if !force {
            if key_exists {
                return Err(format!(
                    "{} already exists but {} is missing — \
                     resolve manually or re-run with force",
                    key_path.display(),
                    secrets_path.display()
                ));
            }
            if secrets_exists {
                return Err(format!(
                    "{} already exists but {} is missing — \
                     resolve manually or re-run with force",
                    secrets_path.display(),
                    key_path.display()
                ));
            }
        }

        std::fs::create_dir_all(&key_dir)
            .map_err(|e| format!("cannot create {}: {e}", key_dir.display()))?;

        // Generate age keypair.
        let output = std::process::Command::new("age-keygen")
            .arg("-o")
            .arg(&key_path)
            .output()
            .map_err(|e| format!("failed to run age-keygen: {e}"))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("age-keygen failed: {}", stderr.trim()));
        }
        sops::set_file_mode_0600(&key_path).map_err(|e| format!("cannot set permissions: {e}"))?;

        // Extract public key.
        let pubkey = sops::extract_age_public_key(&key_path)?;

        // Create empty encrypted secrets file.
        let empty_yaml = "# LatchGate secrets (SOPS-encrypted)\n{}\n";
        std::fs::write(&secrets_path, empty_yaml)
            .map_err(|e| format!("cannot write {}: {e}", secrets_path.display()))?;

        // Encrypt in place.
        sops::sops_encrypt_in_place(
            latchgate_core::security_constants::SOPS_BIN,
            &key_path,
            &pubkey,
            &secrets_path,
        )?;

        // Update config: set sops_secrets_file and sops_key_file.
        let (mut doc, cfg_path) = self.load_doc()?;
        doc["secrets"]["sops_secrets_file"] = toml_edit::value(secrets_path.display().to_string());
        doc["secrets"]["sops_key_file"] = toml_edit::value(key_path.display().to_string());
        self.save_and_reload(&doc, &cfg_path)
    }

    fn secrets_set(&self, key: &str, value: &str) -> Result<(), String> {
        use super::secrets::sops;

        let config = self.reload_config()?;
        let paths = sops::resolve_sops_paths(&config)?;
        let pubkey = sops::extract_age_public_key(&paths.key_file)?;

        let mut secrets = sops::sops_decrypt_yaml(
            latchgate_core::security_constants::SOPS_BIN,
            &paths.key_file,
            &paths.secrets_file,
        )?;

        secrets.insert(key.to_string(), value.to_string());

        sops::write_and_encrypt(
            latchgate_core::security_constants::SOPS_BIN,
            &paths.key_file,
            &pubkey,
            &paths.secrets_file,
            &secrets,
        )
    }

    fn secrets_list(&self) -> Result<Vec<latchgate_tui::SecretEntry>, String> {
        use super::secrets::sops;

        let config = self.reload_config()?;
        let paths = sops::resolve_sops_paths(&config)?;

        let secrets = sops::sops_decrypt_yaml(
            latchgate_core::security_constants::SOPS_BIN,
            &paths.key_file,
            &paths.secrets_file,
        )?;

        // Scan manifests for required secrets.
        let required = scan_required_secrets(&config.manifests_dir);

        // Build unified list: all set secrets + all required-but-missing.
        let mut all_keys: std::collections::BTreeSet<String> = secrets.keys().cloned().collect();
        for k in required.keys() {
            all_keys.insert(k.clone());
        }

        Ok(all_keys
            .into_iter()
            .map(|k| {
                let is_set = secrets.contains_key(&k);
                let required_by = required.get(&k).cloned().unwrap_or_default();
                latchgate_tui::SecretEntry {
                    key: k,
                    is_set,
                    required_by,
                }
            })
            .collect())
    }

    fn secrets_remove(&self, key: &str) -> Result<(), String> {
        use super::secrets::sops;

        let config = self.reload_config()?;
        let paths = sops::resolve_sops_paths(&config)?;
        let pubkey = sops::extract_age_public_key(&paths.key_file)?;

        let mut secrets = sops::sops_decrypt_yaml(
            latchgate_core::security_constants::SOPS_BIN,
            &paths.key_file,
            &paths.secrets_file,
        )?;

        if secrets.remove(key).is_none() {
            return Err(format!("secret '{key}' not found"));
        }

        sops::write_and_encrypt(
            latchgate_core::security_constants::SOPS_BIN,
            &paths.key_file,
            &pubkey,
            &paths.secrets_file,
            &secrets,
        )
    }

    fn list_manifests(&self) -> Result<Vec<latchgate_tui::ManifestInfo>, String> {
        let config = self.reload_config()?;
        let dir = std::path::Path::new(&config.manifests_dir);
        if !dir.is_dir() {
            return Err(format!(
                "manifests directory not found: {} — run `latchgate init` first",
                dir.display()
            ));
        }

        let entries =
            std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;

        let mut result = Vec::new();
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
            let spec = match latchgate_registry::ActionSpec::from_yaml(&contents) {
                Ok(s) => s,
                Err(_) => continue,
            };
            result.push(latchgate_tui::ManifestInfo {
                action_id: spec.action_id.clone(),
                version: spec.version.to_string(),
                risk_level: spec.risk_level.as_str().to_string(),
                provider_module_digest: spec.provider_module_digest.to_string(),
                file_path: path,
            });
        }

        result.sort_by(|a, b| a.action_id.cmp(&b.action_id));
        Ok(result)
    }

    fn read_manifest(&self, action_id: &str) -> Result<latchgate_registry::ActionSpec, String> {
        let config = self.reload_config()?;
        let dir = std::path::Path::new(&config.manifests_dir);
        if !dir.is_dir() {
            return Err(format!("manifests directory not found: {}", dir.display()));
        }

        let entries =
            std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;

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
            let spec = match latchgate_registry::ActionSpec::from_yaml(&contents) {
                Ok(s) => s,
                Err(_) => continue,
            };
            if spec.action_id == action_id {
                return Ok(spec);
            }
        }

        Err(format!(
            "manifest for action '{action_id}' not found in {}",
            dir.display()
        ))
    }

    fn write_manifest(
        &self,
        spec: &latchgate_registry::ActionSpec,
    ) -> Result<std::path::PathBuf, String> {
        let config = self.reload_config()?;
        let dir = std::path::Path::new(&config.manifests_dir);
        if !dir.is_dir() {
            return Err(format!("manifests directory not found: {}", dir.display()));
        }

        // Determine target path: reuse existing file if one matches this
        // action_id, otherwise create a new file named after the action.
        let target = find_manifest_file(dir, &spec.action_id)
            .unwrap_or_else(|| dir.join(format!("{}.yaml", spec.action_id)));

        // SECURITY: ensure the resolved path stays inside the manifests dir.
        // Prevents path traversal via crafted action_ids (though action_id
        // validation in ActionSpec already restricts to [a-zA-Z0-9_-]).
        let canonical_dir = dir
            .canonicalize()
            .map_err(|e| format!("cannot resolve {}: {e}", dir.display()))?;
        let canonical_target = if target.exists() {
            target
                .canonicalize()
                .map_err(|e| format!("cannot resolve {}: {e}", target.display()))?
        } else {
            // File doesn't exist yet — resolve the parent and append filename.
            let parent = target
                .parent()
                .ok_or_else(|| "manifest path has no parent".to_string())?
                .canonicalize()
                .map_err(|e| format!("cannot resolve parent: {e}"))?;
            parent.join(target.file_name().unwrap())
        };

        if !canonical_target.starts_with(&canonical_dir) {
            return Err(format!(
                "path traversal rejected: {} escapes {}",
                canonical_target.display(),
                canonical_dir.display()
            ));
        }

        // Validate + serialize + round-trip check + atomic write.
        spec.write_to_file(&target)
            .map_err(|e| format!("manifest write failed: {e}"))?;

        Ok(target)
    }

    fn export_preset(
        &self,
        name: &str,
        description: &str,
        action_ids: &[String],
        wildcard_grant: &str,
    ) -> Result<std::path::PathBuf, String> {
        if name.is_empty() {
            return Err("preset name must not be empty".into());
        }
        if description.is_empty() {
            return Err("preset description must not be empty".into());
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err("preset name must be [a-zA-Z0-9_-]".into());
        }

        if action_ids.is_empty() {
            return Err("action_ids must not be empty — select at least one action".into());
        }

        let manifests_value = format!("listed:{}", action_ids.join(","));

        // Validate the wildcard_grant value by parsing it through the
        // embed crate. We reconstruct it as a string rather than importing
        // the parser directly, so a round-trip check ensures validity.
        let valid_grants = [
            "none",
            "all",
            "risk_below:low",
            "risk_below:medium",
            "risk_below:high",
            "risk_below:critical",
        ];
        if !valid_grants.contains(&wildcard_grant) {
            return Err(format!("invalid wildcard_grant: {wildcard_grant:?}"));
        }

        let toml_content = format!(
            "[preset]\n\
             name = {name:?}\n\
             description = {description:?}\n\
             manifests = {manifests_value:?}\n\
             \n\
             [preset.policy]\n\
             wildcard_grant = {wildcard_grant:?}\n"
        );

        // Determine output path: use definitions/presets/ if it exists, otherwise
        // write next to the config file.
        let config = self.reload_config()?;
        let presets_dir = config
            .source
            .config_file()
            .and_then(|p| p.parent().map(|d| d.join("presets")))
            .unwrap_or_else(|| std::path::PathBuf::from("presets"));

        std::fs::create_dir_all(&presets_dir)
            .map_err(|e| format!("cannot create {}: {e}", presets_dir.display()))?;

        let path = presets_dir.join(format!("{name}.toml"));
        latchgate_core::atomic_write_str(&path, &toml_content)
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;

        Ok(path)
    }

    fn list_presets(&self) -> Vec<latchgate_tui::PresetListEntry> {
        use latchgate_embed::embedded_presets;
        use latchgate_tui::{PresetListEntry, PresetSource};

        let mut entries: Vec<PresetListEntry> = embedded_presets::list_builtin()
            .into_iter()
            .map(|preset| PresetListEntry {
                preset,
                source: PresetSource::Builtin,
            })
            .collect();

        // Deduplicate: user/project presets override builtins with the same name.
        let mut seen: std::collections::HashSet<String> =
            entries.iter().map(|e| e.preset.name.clone()).collect();

        // Scan user-global presets (~/.config/latchgate/presets/).
        if let Ok(dirs) = latchgate_config::UserDirs::resolve() {
            Self::scan_preset_dir(
                &dirs.config_dir().join("presets"),
                PresetSource::User,
                &mut seen,
                &mut entries,
            );
        }

        // Scan project-local presets (.latchgate/presets/).
        if let Some(cfg_path) = self.config_path.as_ref() {
            if let Some(parent) = cfg_path.parent() {
                Self::scan_preset_dir(
                    &parent.join("presets"),
                    PresetSource::Project,
                    &mut seen,
                    &mut entries,
                );
            }
        }

        entries.sort_by(|a, b| a.preset.name.cmp(&b.preset.name));
        entries
    }

    fn check_manifests_dir_consistency(&self) -> Option<String> {
        let config = self.reload_config().ok()?;
        let configured = std::path::PathBuf::from(&config.manifests_dir);

        let cwd = std::env::current_dir().ok()?;
        let resources = crate::cmd::up::try_discover_resources_in(&cwd)?;

        let configured_canon = configured
            .canonicalize()
            .unwrap_or_else(|_| configured.clone());
        let discovered_canon = resources
            .manifests_dir
            .canonicalize()
            .unwrap_or_else(|_| resources.manifests_dir.clone());

        if configured_canon == discovered_canon {
            return None;
        }

        Some(format!(
            "manifests_dir ({}) differs from discovery ({}) \
             — saved actions may not load after restart",
            configured.display(),
            resources.manifests_dir.display(),
        ))
    }
}

impl CliSetupOps {
    /// Scan a directory for `.toml` preset files and append valid ones.
    fn scan_preset_dir(
        dir: &std::path::Path,
        source: latchgate_tui::PresetSource,
        seen: &mut std::collections::HashSet<String>,
        entries: &mut Vec<latchgate_tui::PresetListEntry>,
    ) {
        let Ok(read_dir) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in read_dir.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            let Ok(preset) =
                latchgate_embed::embedded_presets::resolve(&path.display().to_string())
            else {
                continue;
            };
            if seen.insert(preset.name.clone()) {
                entries.push(latchgate_tui::PresetListEntry { preset, source });
            }
        }
    }
}

/// Find the existing YAML file for a given action_id, if any.
fn find_manifest_file(dir: &std::path::Path, action_id: &str) -> Option<std::path::PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "yaml" && ext != "yml" {
            continue;
        }
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(spec) = latchgate_registry::ActionSpec::from_yaml(&contents) else {
            continue;
        };
        if spec.action_id == action_id {
            return Some(path);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use latchgate_config::Config;
    use latchgate_core::{FsOperation, RiskLevel};
    use latchgate_registry::manifest::{EgressConfig, FsConfig, IoConfig, TemplateConfig};
    use latchgate_registry::ActionSpec;
    use latchgate_tui::SetupOps;
    use std::collections::HashMap;

    // -- Test harness --------------------------------------------------------

    /// Minimal HTTP action spec for generating test YAML.
    fn test_http_spec(action_id: &str) -> ActionSpec {
        let mut spec = ActionSpec {
            action_id: action_id.into(),
            version: "1.0.0".into(),
            provider_module_digest: "builtin:http_api".into(),
            provider_source: None,
            required_imports: vec!["latchgate:io/http".into(), "latchgate:io/log".into()],
            resource_limits: Default::default(),
            verifier_kind: latchgate_core::VerifierKind::HttpStatus,
            verification_config: None,
            io: IoConfig::default(),
            egress: EgressConfig {
                profile: "proxy_allowlist".into(),
                allowed_domains: vec!["api.example.com".into()],
                allowed_methods: Vec::new(),
            },
            secrets: Vec::new(),
            risk_level: RiskLevel::Low,
            declared_side_effects: vec!["http_read".into()],
            required_scopes: vec!["tools:call".into()],
            database_config: None,
            template: Some(TemplateConfig {
                method: "GET".into(),
                url_template: "https://api.example.com/{{id}}".into(),
                headers: HashMap::new(),
                body_template: None,
            }),
            tags: Vec::new(),
            fs: None,
            database_mode: None,
            secret_names: Vec::new(),
            content_digest: String::new(),
        };
        spec.finalize_digest();
        spec
    }

    fn test_fs_spec(action_id: &str) -> ActionSpec {
        let mut spec = ActionSpec {
            action_id: action_id.into(),
            version: "1.0.0".into(),
            provider_module_digest: "builtin:fs".into(),
            provider_source: None,
            required_imports: vec!["latchgate:io/fs".into(), "latchgate:io/log".into()],
            resource_limits: Default::default(),
            verifier_kind: latchgate_core::VerifierKind::FsHash,
            verification_config: None,
            io: IoConfig::default(),
            egress: EgressConfig::default(),
            secrets: Vec::new(),
            risk_level: RiskLevel::Medium,
            declared_side_effects: vec!["fs_read".into(), "fs_write".into()],
            required_scopes: vec!["tools:call".into()],
            database_config: None,
            template: None,
            tags: Vec::new(),
            fs: Some(FsConfig {
                allowed_operations: vec![
                    FsOperation::Read,
                    FsOperation::Create,
                    FsOperation::Overwrite,
                ],
                allowed_paths: vec!["/tmp/**".into()],
                denied_paths: vec!["**/.git/**".into()],
                max_file_bytes: 10 * 1024 * 1024,
                compiled_allowed: Vec::new(),
                compiled_denied: Vec::new(),
            }),
            database_mode: None,
            secret_names: Vec::new(),
            content_digest: String::new(),
        };
        spec.finalize_digest();
        spec
    }

    /// Set up a temp dir with a valid config and manifests dir.
    /// Returns (temp_dir, ops). Caller must keep temp_dir alive.
    fn setup_env() -> (tempfile::TempDir, CliSetupOps) {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifests_dir = tmp.path().join("manifests");
        std::fs::create_dir_all(&manifests_dir).unwrap();

        let config_path = tmp.path().join("latchgate.toml");
        let toml = format!(
            "manifests_dir = {dir:?}\n",
            dir = manifests_dir.display().to_string()
        );
        std::fs::write(&config_path, toml).unwrap();

        let config = Config::from_file(&config_path).unwrap();
        let ops = CliSetupOps::new(&config);
        (tmp, ops)
    }

    /// Write a manifest YAML to the manifests directory.
    fn write_manifest_fixture(tmp: &tempfile::TempDir, spec: &ActionSpec) {
        let dir = tmp.path().join("manifests");
        let yaml = spec.to_yaml().unwrap();
        let path = dir.join(format!("{}.yaml", spec.action_id));
        std::fs::write(path, yaml).unwrap();
    }

    // -- find_manifest_file --------------------------------------------------

    #[test]
    fn find_manifest_file_locates_by_action_id() {
        let (tmp, _ops) = setup_env();
        write_manifest_fixture(&tmp, &test_http_spec("github_read"));
        write_manifest_fixture(&tmp, &test_fs_spec("file_write"));

        let dir = tmp.path().join("manifests");
        let found = find_manifest_file(&dir, "file_write");
        assert!(found.is_some());
        let path = found.unwrap();
        assert!(path.to_string_lossy().contains("file_write"));
    }

    #[test]
    fn find_manifest_file_returns_none_for_missing() {
        let (tmp, _ops) = setup_env();
        let dir = tmp.path().join("manifests");
        assert!(find_manifest_file(&dir, "nonexistent").is_none());
    }

    #[test]
    fn find_manifest_file_skips_non_yaml() {
        let (tmp, _ops) = setup_env();
        let dir = tmp.path().join("manifests");
        std::fs::write(dir.join("readme.txt"), "not a manifest").unwrap();
        assert!(find_manifest_file(&dir, "readme").is_none());
    }

    // -- list_manifests ------------------------------------------------------

    #[test]
    fn list_manifests_returns_sorted_entries() {
        let (tmp, ops) = setup_env();
        write_manifest_fixture(&tmp, &test_http_spec("zebra_api"));
        write_manifest_fixture(&tmp, &test_fs_spec("alpha_fs"));

        let list = ops.list_manifests().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].action_id, "alpha_fs");
        assert_eq!(list[1].action_id, "zebra_api");
    }

    #[test]
    fn list_manifests_skips_non_yaml_files() {
        let (tmp, ops) = setup_env();
        write_manifest_fixture(&tmp, &test_http_spec("valid_action"));
        let dir = tmp.path().join("manifests");
        std::fs::write(dir.join("notes.txt"), "not yaml").unwrap();
        std::fs::write(dir.join("config.json"), "{}").unwrap();

        let list = ops.list_manifests().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].action_id, "valid_action");
    }

    #[test]
    fn list_manifests_skips_invalid_yaml() {
        let (tmp, ops) = setup_env();
        write_manifest_fixture(&tmp, &test_http_spec("good_action"));
        let dir = tmp.path().join("manifests");
        std::fs::write(dir.join("broken.yaml"), "not: valid: manifest: yaml: [[[").unwrap();

        let list = ops.list_manifests().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].action_id, "good_action");
    }

    #[test]
    fn list_manifests_populates_metadata() {
        let (tmp, ops) = setup_env();
        write_manifest_fixture(&tmp, &test_http_spec("example_api"));

        let list = ops.list_manifests().unwrap();
        assert_eq!(list.len(), 1);
        let info = &list[0];
        assert_eq!(info.action_id, "example_api");
        assert_eq!(info.version, "1.0.0");
        assert_eq!(info.risk_level, "low");
        assert_eq!(info.provider_module_digest, "builtin:http_api");
        assert!(info.file_path.exists());
    }

    #[test]
    fn list_manifests_empty_dir() {
        let (_tmp, ops) = setup_env();
        let list = ops.list_manifests().unwrap();
        assert!(list.is_empty());
    }

    // -- read_manifest -------------------------------------------------------

    #[test]
    fn read_manifest_finds_by_action_id() {
        let (tmp, ops) = setup_env();
        let original = test_http_spec("target_action");
        write_manifest_fixture(&tmp, &original);
        write_manifest_fixture(&tmp, &test_fs_spec("other_action"));

        let spec = ops.read_manifest("target_action").unwrap();
        assert_eq!(spec.action_id, "target_action");
        assert_eq!(spec.risk_level, RiskLevel::Low);
        assert_eq!(spec.egress.profile, "proxy_allowlist");
    }

    #[test]
    fn read_manifest_returns_error_for_missing() {
        let (_tmp, ops) = setup_env();
        let err = ops.read_manifest("nonexistent").unwrap_err();
        assert!(err.contains("not found"));
    }

    // -- write_manifest ------------------------------------------------------

    #[test]
    fn write_manifest_creates_new_file() {
        let (_tmp, ops) = setup_env();
        let spec = test_http_spec("new_action");

        let path = ops.write_manifest(&spec).unwrap();
        assert!(path.exists());
        assert!(path.to_string_lossy().contains("new_action"));

        // Verify round-trip: read it back.
        let loaded = ops.read_manifest("new_action").unwrap();
        assert_eq!(loaded.action_id, "new_action");
        assert_eq!(loaded.risk_level, spec.risk_level);
    }

    #[test]
    fn write_manifest_overwrites_existing() {
        let (_tmp, ops) = setup_env();

        // Write initial version.
        let mut spec = test_http_spec("mutable_action");
        ops.write_manifest(&spec).unwrap();

        // Modify and rewrite.
        spec.risk_level = RiskLevel::Medium;
        spec.egress.allowed_domains.push("cdn.example.com".into());
        ops.write_manifest(&spec).unwrap();

        // Verify the update took effect.
        let loaded = ops.read_manifest("mutable_action").unwrap();
        assert_eq!(loaded.risk_level, RiskLevel::Medium);
        assert_eq!(loaded.egress.allowed_domains.len(), 2);

        // Still only one file on disk.
        let list = ops.list_manifests().unwrap();
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn write_manifest_round_trips_fs_spec() {
        let (_tmp, ops) = setup_env();
        let spec = test_fs_spec("fs_roundtrip");

        ops.write_manifest(&spec).unwrap();
        let loaded = ops.read_manifest("fs_roundtrip").unwrap();

        assert_eq!(loaded.action_id, "fs_roundtrip");
        assert_eq!(loaded.risk_level, RiskLevel::Medium);
        let fs = loaded.fs.as_ref().unwrap();
        assert_eq!(fs.allowed_paths, vec!["/tmp/**"]);
        assert_eq!(fs.denied_paths, vec!["**/.git/**"]);
        assert!(fs.allowed_operations.contains(&FsOperation::Read));
    }

    // -- export_preset -------------------------------------------------------

    #[test]
    fn export_preset_creates_valid_toml() {
        let (_tmp, ops) = setup_env();
        let path = ops
            .export_preset(
                "my-preset",
                "A test preset",
                &["action_a".into(), "action_b".into()],
                "risk_below:medium",
            )
            .unwrap();

        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("[preset]"));
        assert!(content.contains("name = \"my-preset\""));
        assert!(content.contains("description = \"A test preset\""));
        assert!(content.contains("listed:action_a,action_b"));
        assert!(content.contains("[preset.policy]"));
        assert!(content.contains("wildcard_grant = \"risk_below:medium\""));
    }

    #[test]
    fn export_preset_rejects_empty_name() {
        let (_tmp, ops) = setup_env();
        let err = ops
            .export_preset("", "desc", &["a".into()], "none")
            .unwrap_err();
        assert!(err.contains("name"));
    }

    #[test]
    fn export_preset_rejects_empty_description() {
        let (_tmp, ops) = setup_env();
        let err = ops
            .export_preset("ok", "", &["a".into()], "none")
            .unwrap_err();
        assert!(err.contains("description"));
    }

    #[test]
    fn export_preset_rejects_invalid_name_chars() {
        let (_tmp, ops) = setup_env();
        let err = ops
            .export_preset("bad name!", "desc", &["a".into()], "none")
            .unwrap_err();
        assert!(err.contains("[a-zA-Z0-9_-]"));
    }

    #[test]
    fn export_preset_rejects_invalid_wildcard_grant() {
        let (_tmp, ops) = setup_env();
        let err = ops
            .export_preset("ok", "desc", &["a".into()], "everything")
            .unwrap_err();
        assert!(err.contains("invalid wildcard_grant"));
    }

    #[test]
    fn export_preset_rejects_empty_action_ids() {
        let (_tmp, ops) = setup_env();
        let err = ops.export_preset("ok", "desc", &[], "none").unwrap_err();
        assert!(err.contains("action_ids"));
    }

    #[test]
    fn export_preset_accepts_all_valid_grant_levels() {
        let (_tmp, ops) = setup_env();
        let grants = [
            "none",
            "all",
            "risk_below:low",
            "risk_below:medium",
            "risk_below:high",
            "risk_below:critical",
        ];
        for (i, grant) in grants.iter().enumerate() {
            let name = format!("preset_{i}");
            let result = ops.export_preset(&name, "test", &["a".into()], grant);
            assert!(result.is_ok(), "grant {grant:?} should be accepted");
        }
    }

    // -- resolve_durable_config -----------------------------------------------

    #[test]
    fn durable_config_prefers_project_over_ephemeral() {
        let tmp = tempfile::TempDir::new().unwrap();

        // Create a project config at .latchgate/latchgate.toml.
        let project_dir = tmp.path().join(".latchgate");
        std::fs::create_dir_all(&project_dir).unwrap();
        let project_cfg = project_dir.join("latchgate.toml");
        std::fs::write(&project_cfg, "manifests_dir = \"m\"\n").unwrap();

        // Create a separate ephemeral config (simulates latchgate-up.toml).
        let ephemeral_dir = tmp.path().join("state");
        std::fs::create_dir_all(&ephemeral_dir).unwrap();
        let ephemeral_cfg = ephemeral_dir.join("latchgate-up.toml");
        std::fs::write(&ephemeral_cfg, "manifests_dir = \"m\"\n").unwrap();

        // resolve_durable_config must find the project config.
        let resolved = resolve_durable_config(Some(tmp.path()));
        assert_eq!(resolved.as_deref(), Some(project_cfg.as_path()));
    }

    #[test]
    fn durable_config_returns_none_when_no_project() {
        let tmp = tempfile::TempDir::new().unwrap();
        // No .latchgate/ directory at all.
        let resolved = resolve_durable_config(Some(tmp.path()));
        // User-global may or may not exist depending on the test host,
        // but the project path must not appear.
        if let Some(path) = &resolved {
            assert!(
                !path.starts_with(tmp.path()),
                "should not resolve inside {}: got {}",
                tmp.path().display(),
                path.display()
            );
        }
    }

    #[test]
    fn durable_config_handles_none_root() {
        // No project root at all (e.g. cwd unresolvable).
        let resolved = resolve_durable_config(None);
        // Must not panic; result depends on user-global existence.
        let _ = resolved;
    }

    #[test]
    fn new_targets_project_config_over_ephemeral_source() {
        let tmp = tempfile::TempDir::new().unwrap();

        // Set up a project config.
        let project_dir = tmp.path().join(".latchgate");
        std::fs::create_dir_all(&project_dir).unwrap();
        let project_cfg = project_dir.join("latchgate.toml");
        std::fs::write(&project_cfg, "manifests_dir = \"m\"\n").unwrap();

        // Load config from an ephemeral path (simulates active_session_config).
        let ephemeral_dir = tmp.path().join("state");
        std::fs::create_dir_all(&ephemeral_dir).unwrap();
        let ephemeral_cfg = ephemeral_dir.join("latchgate-up.toml");
        std::fs::write(&ephemeral_cfg, "manifests_dir = \"m\"\n").unwrap();

        let config = Config::from_file(&ephemeral_cfg).unwrap();
        // Sanity: the loaded config source points at the ephemeral file.
        assert_eq!(
            config.source.config_file().as_deref(),
            Some(ephemeral_cfg.as_path())
        );

        // CliSetupOps should target the project config when project_root
        // is available. We test the underlying resolution directly since
        // new() uses std::env::current_dir() which may not equal tmp.
        let durable = resolve_durable_config(Some(tmp.path()));
        let target = durable.or_else(|| config.source.config_file());
        assert_eq!(target.as_deref(), Some(project_cfg.as_path()));
    }

    #[test]
    fn new_falls_back_to_config_source_without_project() {
        let tmp = tempfile::TempDir::new().unwrap();

        // No .latchgate/ directory — only an explicit config.
        let cfg_path = tmp.path().join("custom.toml");
        std::fs::write(&cfg_path, "manifests_dir = \"m\"\n").unwrap();

        let config = Config::from_file(&cfg_path).unwrap();

        let durable = resolve_durable_config(Some(tmp.path()));
        let target = durable.or_else(|| config.source.config_file());
        assert_eq!(target.as_deref(), Some(cfg_path.as_path()));
    }
}
