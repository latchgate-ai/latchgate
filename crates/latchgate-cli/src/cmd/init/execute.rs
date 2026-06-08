//! Plan execution — all filesystem mutations for `latchgate init`.

use std::io::Write;
use std::path::{Path, PathBuf};

use p256::pkcs8::{EncodePrivateKey, LineEnding};

use latchgate_auth::dpop::generate_dpop_keypair;

use rand::RngCore;

use crate::cmd::{credential, secure_file};
use crate::embedded_manifests;

use super::config_gen::{build_config_toml, generate_policies};
use super::InitPlan;
use latchgate_embed::embedded_presets::ManifestSelector;
use latchgate_tui::{IdentityChoice, SigningChoice};

/// Result of a successful init.
pub(crate) struct InitResult {
    pub config_path: PathBuf,
    pub manifests_count: usize,
    pub policies_generated: bool,
    pub operator_name: String,
    pub api_key: String,
    pub dpop_jkt: String,
    pub pem_path: PathBuf,
    pub install_dir: PathBuf,
}

/// Execute the init plan: generate all files atomically where possible.
///
/// Install location determines the root directory:
///   - Project: `$PWD/.latchgate/`
///   - User: `$XDG_CONFIG_HOME/latchgate/` (config) + `$XDG_DATA_HOME/latchgate/` (data)
pub(crate) fn execute_plan(plan: &InitPlan) -> Result<InitResult, String> {
    // SECURITY: permissive preset refuses to apply outside dev_mode.
    if plan.preset.wildcard_grant.requires_dev_mode() {
        let is_dev = std::env::var("LATCHGATE_UNSAFE_DEV")
            .map(|v| v == "1")
            .unwrap_or(false);
        if !is_dev {
            return Err(format!(
                "preset '{}' grants all actions to the wildcard principal and is \
                 restricted to dev_mode.\n\
                 Set LATCHGATE_UNSAFE_DEV=1 to use this preset (never in production).",
                plan.preset.name
            ));
        }
    }

    let dirs = resolve_dirs(plan.location)?;

    let install_dir = dirs.install_dir;
    let config_path = dirs.config_path;
    let manifests_dir = dirs.manifests_dir;
    let policies_dir = dirs.policies_dir;
    let operators_dir = dirs.operators_dir;
    let data_dir = dirs.data_dir;
    let providers_dir = dirs.providers_dir;
    let operator_name = "default";

    // --- Guard: overwrite protection ---
    // Check the install directory *and* the config file — a previous
    // interrupted init can leave the directory without a config file,
    // so checking just the config file is not enough.
    if !plan.force {
        if install_dir.exists() {
            return Err(format!(
                "{} already exists — use --force to overwrite",
                install_dir.display()
            ));
        }
        if config_path.exists() {
            return Err(format!(
                "{} already exists — use --force to overwrite",
                config_path.display()
            ));
        }
    }

    // --- Phase 1: generate credentials (no filesystem writes yet) ---
    let (signing_key, _pub_key) =
        generate_dpop_keypair().map_err(|e| format!("DPoP key generation failed: {e}"))?;

    let dpop_jkt = signing_key
        .thumbprint()
        .map_err(|e| format!("JWK thumbprint computation failed: {e}"))?;

    let pem_doc = signing_key
        .as_inner()
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| format!("PEM serialization failed: {e}"))?;

    let api_key = credential::generate_api_key(operator_name);

    // Signing key paths — only when persistent keys were chosen.
    let keys_dir = operators_dir.join("keys");
    let receipt_key_path = keys_dir.join("receipt.key");
    let grant_key_path = keys_dir.join("grant.key");

    let signing_key_paths = match plan.signing {
        SigningChoice::Persistent => Some(super::config_gen::SigningKeyPaths {
            receipt: &receipt_key_path,
            grant: &grant_key_path,
        }),
        SigningChoice::Ephemeral => None,
    };

    // --- Phase 2: build config TOML (still no writes) ---
    let config_toml = build_config_toml(
        operator_name,
        &api_key,
        &dpop_jkt,
        &super::config_gen::ConfigDirs {
            manifests: &manifests_dir,
            providers: &providers_dir,
            data: &data_dir,
        },
        signing_key_paths.as_ref(),
        plan.identity,
    );

    // --- Phase 2b: resolve agent principals ---
    //
    // The identity choice determines which named principals the gate will
    // authenticate.  These must receive explicit ACL entries so the Rego
    // wildcard fallback is not silently suppressed.
    let agent_principals = resolve_agent_principals(plan.identity);

    // --- Phase 3: determine which manifests to extract ---
    let manifest_filter = match &plan.preset.manifests {
        ManifestSelector::All => embedded_manifests::ManifestFilter::All,
        ManifestSelector::None => embedded_manifests::ManifestFilter::None,
        ManifestSelector::Tagged(tag) => embedded_manifests::ManifestFilter::Tag(tag),
        ManifestSelector::Listed(ids) => embedded_manifests::ManifestFilter::Listed(ids),
    };

    let available = embedded_manifests::list_available()
        .map_err(|e| format!("embedded manifest validation failed: {e}"))?;

    if available.is_empty() {
        return Err("no embedded manifests found — binary may be corrupt".into());
    }

    // --- Phase 4: filesystem writes ---
    // Order: operators dir => manifests => policies => data dir => config => gitignore.
    // Credentials first — if keygen succeeded but write fails, nothing else
    // was touched. Policies depend on manifests (reads declared_side_effects).
    // Config is written last so a crash mid-init never leaves a config
    // without its supporting files.

    std::fs::create_dir_all(&operators_dir)
        .map_err(|e| format!("cannot create {}: {e}", operators_dir.display()))?;

    let pem_path = operators_dir.join(format!("{operator_name}.pem"));
    if pem_path.exists() && !plan.force {
        return Err(format!(
            "{} already exists — use --force to overwrite",
            pem_path.display()
        ));
    }

    secure_file::write_private_file(&pem_path, pem_doc.as_ref())
        .map_err(|e| format!("cannot write {}: {e}", pem_path.display()))?;

    // Create key directory unconditionally — operators may add persistent
    // keys later even if ephemeral was chosen at init time.
    std::fs::create_dir_all(&keys_dir)
        .map_err(|e| format!("cannot create {}: {e}", keys_dir.display()))?;

    // Generate persistent Ed25519 signing keys only when requested.
    // Ephemeral mode relies on runtime auto-generated keys.
    if plan.signing == SigningChoice::Persistent {
        for (label, key_path) in [("receipt", &receipt_key_path), ("grant", &grant_key_path)] {
            if key_path.exists() && !plan.force {
                return Err(format!(
                    "{} already exists — use --force to overwrite",
                    key_path.display()
                ));
            }
            let mut seed = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            std::fs::write(key_path, seed)
                .map_err(|e| format!("cannot write {label} signing key: {e}"))?;
            secure_file::set_file_mode_0600(key_path)
                .map_err(|e| format!("cannot set permissions on {label} key: {e}"))?;
        }
    }

    let extracted = embedded_manifests::extract_manifests(manifest_filter, &manifests_dir)
        .map_err(|e| format!("manifest extraction failed: {e}"))?;

    // --include-examples: reserved for future use. Example manifests
    // (with httpbin.org domains) live in definitions/manifests/_examples/ in the
    // source tree but are not yet extracted by the embedding layer.
    if plan.include_examples {
        tracing::info!("--include-examples: example manifests are available in the source tree at definitions/manifests/_examples/");
    }

    generate_policies(
        &policies_dir,
        &plan.preset,
        &manifests_dir,
        &agent_principals,
    )?;

    std::fs::create_dir_all(&data_dir)
        .map_err(|e| format!("cannot create {}: {e}", data_dir.display()))?;

    std::fs::create_dir_all(&providers_dir)
        .map_err(|e| format!("cannot create {}: {e}", providers_dir.display()))?;

    secure_file::atomic_write(&config_path, &config_toml)
        .map_err(|e| format!("cannot write {}: {e}", config_path.display()))?;

    // .gitignore only relevant for project-local installs.
    if plan.location == super::InstallLocation::Project {
        let project_dir = PathBuf::from(".");
        if let Err(e) = update_gitignore(&project_dir) {
            eprintln!("warning: cannot update .gitignore: {e}");
        }
    }

    Ok(InitResult {
        config_path,
        manifests_count: extracted.len(),
        policies_generated: true,
        operator_name: operator_name.to_string(),
        api_key,
        dpop_jkt,
        pem_path,
        install_dir,
    })
}

/// Derive the list of named agent principals from the identity choice.
///
/// These are the principal names the gate will assign to authenticated
/// callers.  They must appear in `data.json` ACL so the Rego wildcard
/// fallback is not suppressed by the presence of a named entry.
///
/// Uses the same `$USER` resolution as `build_config_toml` so the config
/// and ACL can never drift.
fn resolve_agent_principals(identity: IdentityChoice) -> Vec<String> {
    match identity {
        IdentityChoice::Peercred => {
            let principal = std::env::var("USER").unwrap_or_else(|_| "dev-user".into());
            vec![principal]
        }
        IdentityChoice::None => Vec::new(),
    }
}

/// Resolved output directories for an init operation.
struct InitDirs {
    install_dir: PathBuf,
    config_path: PathBuf,
    manifests_dir: PathBuf,
    policies_dir: PathBuf,
    operators_dir: PathBuf,
    data_dir: PathBuf,
    providers_dir: PathBuf,
}

/// Resolve all output directories for the chosen install location.
fn resolve_dirs(location: super::InstallLocation) -> Result<InitDirs, String> {
    match location {
        super::InstallLocation::Project => {
            let project = latchgate_core::paths::ProjectDirs::from_cwd()
                .map_err(|e| format!("cannot resolve project directory: {e}"))?;
            Ok(InitDirs {
                install_dir: project.install_dir(),
                config_path: project.config_file(),
                manifests_dir: project.manifests_dir(),
                policies_dir: project.policies_dir(),
                operators_dir: project.operators_dir(),
                data_dir: project.data_dir(),
                providers_dir: project.providers_dir(),
            })
        }
        super::InstallLocation::User => {
            let user = latchgate_config::UserDirs::resolve()
                .map_err(|e| format!("cannot resolve user directories: {e}"))?;
            let config_dir = user.config_dir().to_path_buf();
            let data_dir = user.data_dir().to_path_buf();
            Ok(InitDirs {
                install_dir: config_dir.clone(),
                config_path: config_dir.join("latchgate.toml"),
                manifests_dir: config_dir.join("manifests"),
                policies_dir: config_dir.join("policies"),
                operators_dir: config_dir.join("operators"),
                data_dir,
                providers_dir: config_dir.join("providers"),
            })
        }
    }
}

/// Lines that must be present in `.gitignore`.
pub(crate) const GITIGNORE_ENTRIES: &[&str] = &[".latchgate/", "*.key"];

/// Append missing entries to `.gitignore`. Creates the file if absent.
pub(crate) fn update_gitignore(project_dir: &Path) -> std::io::Result<()> {
    let path = project_dir.join(".gitignore");
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let existing_lines: Vec<&str> = existing.lines().collect();

    let mut to_add = Vec::new();
    for entry in GITIGNORE_ENTRIES {
        if !existing_lines.iter().any(|l| l.trim() == *entry) {
            to_add.push(*entry);
        }
    }

    if to_add.is_empty() {
        return Ok(());
    }

    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;

    // Ensure we start on a fresh line.
    if !existing.is_empty() && !existing.ends_with('\n') {
        writeln!(f)?;
    }

    writeln!(f, "\n# LatchGate (generated by latchgate init)")?;
    for entry in &to_add {
        writeln!(f, "{entry}")?;
    }
    f.sync_all()?;
    Ok(())
}
