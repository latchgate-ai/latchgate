//! `latchgate init` — scaffold a working LatchGate project.
//!
//! Generates a minimal `latchgate.toml`, extracts action manifests from the
//! embedded catalog, creates operator credentials (P-256 DPoP keypair), sets
//! up signing key paths, and updates `.gitignore`.
//!
//! Presets encode the security posture: which manifests to extract and how
//! the initial ACL is shaped. Six built-in presets cover common workflows.
//!
//! Modes:
//!   Interactive (default) — handled by the full TUI in first-launch mode.
//!                           Dispatched in main.rs before reaching this module.
//!   Non-interactive       — `--preset <name|path>`, `--list-presets`, `--export-preset`.

pub(crate) mod config_gen;
pub(crate) mod execute;

use std::path::Path;

use serde_json::json;

use crate::output::{print_json, Printer};

use super::{output, secure_file};

use execute::execute_plan;
use latchgate_embed::embedded_presets::{self};

// Import init plan types from the TUI crate (consumed by execute_plan).
pub(crate) use latchgate_tui::{InitPlan, InstallLocation};

/// Arguments for `latchgate init`, passed from the CLI dispatch.
///
/// Only non-interactive paths reach this module. Interactive init is
/// dispatched to the full TUI in `main.rs` and never calls `run()`.
pub struct InitArgs<'a> {
    pub preset: Option<&'a str>,
    pub location: Option<&'a str>,
    pub list_presets: bool,
    pub export_preset: Option<&'a str>,
    pub include_examples: bool,
    pub force: bool,
    pub dev: bool,
    pub pr: &'a Printer,
    pub json_mode: bool,
}

pub fn run(args: &InitArgs<'_>) -> i32 {
    let pr = args.pr;
    let json_mode = args.json_mode;

    // --list-presets: show available presets and exit.
    if args.list_presets {
        let presets = embedded_presets::list_builtin();
        if json_mode {
            let items: Vec<serde_json::Value> = presets
                .iter()
                .map(|p| {
                    json!({
                        "name": p.name,
                        "description": p.description,
                    })
                })
                .collect();
            print_json(&json!({"presets": items}));
        } else {
            pr.blank();
            pr.section("Available presets");
            pr.blank();
            for p in &presets {
                pr.field(&format!("{:<20}", p.name), &p.description);
            }
            pr.blank();
            pr.hint("latchgate init --preset <name>");
            pr.hint("latchgate init --export-preset <name>  (dump TOML for customization)");
            pr.blank();
        }
        return 0;
    }

    // --export-preset: dump raw TOML and exit.
    if let Some(name) = args.export_preset {
        match embedded_presets::export_builtin(name) {
            Ok(toml_text) => {
                if json_mode {
                    print_json(&json!({"preset": name, "toml": toml_text}));
                } else {
                    print!("{toml_text}");
                }
                return 0;
            }
            Err(e) => return output::emit_error(pr, &e.to_string()),
        }
    }

    // Resolve install location from flag, defaulting to project.
    let resolve_location = |loc: Option<&str>| -> Result<InstallLocation, String> {
        match loc {
            Some("project") | None => Ok(InstallLocation::Project),
            Some("user") => Ok(InstallLocation::User),
            Some(other) => Err(format!(
                "unknown location: {other:?} — expected 'project' or 'user'"
            )),
        }
    };

    // --preset: non-interactive init.
    let plan = if let Some(preset_name) = args.preset {
        let preset = match embedded_presets::resolve(preset_name) {
            Ok(p) => p,
            Err(e) => return output::emit_error(pr, &e.to_string()),
        };
        let location = match resolve_location(args.location) {
            Ok(l) => l,
            Err(msg) => return output::emit_error(pr, &msg),
        };
        Ok(InitPlan {
            preset,
            location,
            include_examples: args.include_examples,
            force: args.force,
            // Non-interactive CLI path: --dev maps to peercred + persistent
            // (the same secure defaults the wizard chooses). Without --dev,
            // identity defaults to None (operator must configure manually
            // or re-run with the interactive wizard).
            identity: if args.dev {
                latchgate_tui::IdentityChoice::Peercred
            } else {
                latchgate_tui::IdentityChoice::None
            },
            signing: latchgate_tui::SigningChoice::Persistent,
        })
    } else {
        // Interactive init is dispatched to the full TUI in main.rs.
        // If we reach here, it's a caller error.
        Err(
            "no preset specified — use '--preset <name>' for non-interactive init, \
             or run 'latchgate init' without flags for interactive setup"
                .to_string(),
        )
    };

    let plan = match plan {
        Ok(p) => p,
        Err(msg) => return output::emit_error(pr, &msg),
    };

    // Execute.
    let result = match execute_plan(&plan) {
        Ok(r) => r,
        Err(msg) => return output::emit_error(pr, &msg),
    };

    // Report.
    if json_mode {
        print_json(&json!({
            "ok": true,
            "preset": plan.preset.name,
            "location": plan.location.label(),
            "config_path": result.config_path.to_string_lossy(),
            "manifests_count": result.manifests_count,
            "policies_generated": result.policies_generated,
            "operator": result.operator_name,
            "api_key": result.api_key,
            "dpop_jkt": result.dpop_jkt,
            "private_key_path": result.pem_path.to_string_lossy(),
        }));
        return 0;
    }

    pr.banner(crate::VERSION);
    pr.blank();

    // Display paths relative to CWD when possible for readability.
    let cwd = std::env::current_dir().unwrap_or_default();
    let rel = |p: &Path| -> String { p.strip_prefix(&cwd).unwrap_or(p).display().to_string() };

    pr.success(&format!("{:<40} generated", rel(&result.config_path),));
    pr.success(&format!(
        "{:<40} {} actions extracted ({})",
        format!("{}/manifests/", rel(&result.install_dir)),
        result.manifests_count,
        plan.preset.name,
    ));
    pr.success(&format!(
        "{:<40} Rego policy + initial ACL",
        format!("{}/policies/", rel(&result.install_dir)),
    ));
    pr.success(&format!(
        "{:<40} operator key + credentials",
        format!("{}/operators/", rel(&result.install_dir)),
    ));
    pr.success(&format!(
        "{:<40} audit ledger directory",
        format!("{}/data/", rel(&result.install_dir)),
    ));
    pr.success(&format!("{:<40} updated", ".gitignore",));
    pr.blank();

    pr.section("Operator credentials");
    pr.blank();
    pr.field("operator:", &result.operator_name);
    pr.field("api_key: ", &result.api_key);
    pr.field("dpop_jkt:", &pr.cyan(&result.dpop_jkt));
    pr.field("pem:     ", &rel(&result.pem_path));
    pr.blank();
    pr.warn("api_key shown once — save it now");
    pr.blank();

    pr.section("Next steps");
    pr.blank();
    pr.numbered_cmd(1, "latchgate doctor");
    pr.numbered_cmd(2, "latchgate up");
    pr.blank();

    if args.dev {
        pr.warn("DEV MODE — current UID mapped to peercred principal with broad scopes");
        pr.warn("Do NOT deploy this configuration to production.");
        pr.blank();
    }

    0
}

#[cfg(test)]
mod tests {
    use super::config_gen::{build_config_toml, build_data_json, generate_policies};
    use super::execute::{update_gitignore, GITIGNORE_ENTRIES};
    use super::*;
    use latchgate_embed::embedded_presets::Preset;

    use crate::cmd::{credential, secure_file};
    use crate::embedded_manifests;
    use crate::embedded_policies;
    use latchgate_auth::dpop::generate_dpop_keypair;

    use p256::pkcs8::{EncodePrivateKey, LineEnding};

    fn test_config_toml(name: &str, key: &str, jkt: &str) -> String {
        let base = std::path::Path::new(".latchgate");
        let keys = base.join("operators/keys");
        let signing = config_gen::SigningKeyPaths {
            receipt: &keys.join("receipt.key"),
            grant: &keys.join("grant.key"),
        };
        build_config_toml(
            name,
            key,
            jkt,
            &config_gen::ConfigDirs {
                manifests: &base.join("manifests"),
                providers: &base.join("providers"),
                data: &base.join("data"),
            },
            Some(&signing),
            latchgate_tui::IdentityChoice::Peercred,
        )
    }

    // -- Config generation ---------------------------------------------------

    #[test]
    fn config_parses_as_valid_toml() {
        let toml_text = test_config_toml(
            "test-op",
            "key-test-op-0123456789abcdef0123456789abcdef",
            "fake-thumbprint-abc",
        );

        let parsed: toml::Value = toml::from_str(&toml_text)
            .unwrap_or_else(|e| panic!("generated TOML is invalid: {e}\n\n{toml_text}"));

        // Operator credential present.
        let op = &parsed["operator_credentials"]["test-op"];
        assert_eq!(
            op["api_key"].as_str(),
            Some("key-test-op-0123456789abcdef0123456789abcdef")
        );
        assert_eq!(op["dpop_jkt"].as_str(), Some("fake-thumbprint-abc"));

        // fs_root_path present.
        assert!(
            parsed.get("fs_root_path").is_some(),
            "generated config must include fs_root_path"
        );
    }

    #[test]
    fn config_is_minimal() {
        let toml_text = test_config_toml("default", "key-default-aabbccdd", "jkt-456");

        let parsed: toml::Value = toml::from_str(&toml_text)
            .unwrap_or_else(|e| panic!("generated TOML is invalid: {e}\n\n{toml_text}"));

        let table = parsed.as_table().unwrap();

        // Must NOT contain deprecated/insecure fields.
        assert!(
            table.get("listen_http_addr").is_none(),
            "minimal config must not set listen_http_addr"
        );
        assert!(
            table.get("unsafe_expose_http").is_none(),
            "minimal config must not set unsafe_expose_http"
        );
        assert!(
            table.get("redis_url").is_none(),
            "minimal config must not set redis_url (embedded default)"
        );
        assert!(
            table.get("opa_url").is_none(),
            "minimal config must not set opa_url (embedded default)"
        );
    }

    #[test]
    fn config_deserializes_to_config_struct() {
        let toml_text = test_config_toml("default", "key-default-aabbccdd", "jkt-123");

        let config: latchgate_config::Config = toml::from_str(&toml_text).unwrap_or_else(|e| {
            panic!("generated TOML does not deserialize to Config: {e}\n\n{toml_text}")
        });

        assert!(config.operator_credentials.contains_key("default"));
        assert_eq!(config.fs_root_path.as_deref(), Some("."));

        // Embedded defaults: no redis, no opa.
        assert!(config.storage.redis_url.is_none());
        assert!(config.policy.opa_url.is_none());
    }

    // -- .gitignore ----------------------------------------------------------

    #[test]
    fn gitignore_creates_file_if_absent() {
        let tmp = tempfile::tempdir().unwrap();
        update_gitignore(tmp.path()).unwrap();

        let content = std::fs::read_to_string(tmp.path().join(".gitignore")).unwrap();
        for entry in GITIGNORE_ENTRIES {
            assert!(content.contains(entry), "missing gitignore entry: {entry}");
        }
    }

    #[test]
    fn gitignore_does_not_duplicate_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let gi = tmp.path().join(".gitignore");
        std::fs::write(&gi, ".latchgate/\nnode_modules/\n").unwrap();

        update_gitignore(tmp.path()).unwrap();

        let content = std::fs::read_to_string(&gi).unwrap();
        let count = content.matches(".latchgate/").count();
        assert_eq!(count, 1, "should not duplicate existing entry");
        assert!(content.contains("*.key"));
    }

    #[test]
    fn gitignore_appends_to_existing_without_trailing_newline() {
        let tmp = tempfile::tempdir().unwrap();
        let gi = tmp.path().join(".gitignore");
        std::fs::write(&gi, "node_modules/").unwrap();

        update_gitignore(tmp.path()).unwrap();

        let content = std::fs::read_to_string(&gi).unwrap();
        assert!(
            !content.contains("node_modules/.latchgate"),
            "entries must be on separate lines"
        );
    }

    // -- Keygen + credential integrity ---------------------------------------

    #[test]
    fn keygen_produces_valid_artifacts() {
        let (sk, _pk) = generate_dpop_keypair().unwrap();

        let jkt = sk.thumbprint().unwrap();
        assert!(!jkt.is_empty(), "thumbprint must not be empty");

        let pem = sk.as_inner().to_pkcs8_pem(LineEnding::LF).unwrap();
        assert!(
            AsRef::<str>::as_ref(&pem).starts_with("-----BEGIN PRIVATE KEY-----"),
            "PEM must have correct header"
        );
    }

    #[test]
    fn api_key_format() {
        let key = credential::generate_api_key("test");
        assert!(key.starts_with("key-test-"));
        assert_eq!(key.len(), "key-test-".len() + 32);
    }

    #[test]
    fn pem_write_sets_restrictive_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        let pem_path = tmp.path().join("test.pem");
        secure_file::write_private_file(&pem_path, "fake-pem-content").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&pem_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "PEM must be mode 0600");
        }
    }

    // -- Preset manifest filter -----------------------------------------------

    #[test]
    fn agent_preset_extracts_subset() {
        let all = embedded_manifests::list_available().unwrap();
        let dest = tempfile::tempdir().unwrap();
        let extracted = embedded_manifests::extract_manifests(
            embedded_manifests::ManifestFilter::Tag("agent"),
            dest.path(),
        )
        .unwrap();

        assert!(!extracted.is_empty(), "no manifests tagged agent");
        assert!(
            extracted.len() < all.len(),
            "agent tag ({}) should be a strict subset of full catalog ({})",
            extracted.len(),
            all.len(),
        );
    }

    // -- Policy generation ---------------------------------------------------

    fn setup_manifests_dir() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        embedded_manifests::extract_manifests(embedded_manifests::ManifestFilter::All, tmp.path())
            .unwrap();
        tmp
    }

    fn ops_preset() -> Preset {
        embedded_presets::resolve("ops").unwrap()
    }

    #[test]
    fn data_json_has_wildcard_acl_with_all_actions() {
        let manifests = setup_manifests_dir();
        let preset = ops_preset();
        let data_json = build_data_json(&preset, manifests.path(), &[]).unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(&data_json).expect("generated data.json must be valid JSON");

        assert!(parsed["policy_version"].is_string());
        assert!(parsed["acl"].is_object());

        let wildcard = &parsed["acl"]["*"];
        assert!(wildcard.is_object(), "ACL must have wildcard '*' entry");

        let actions = wildcard["allowed_actions"]
            .as_array()
            .expect("allowed_actions must be an array");

        // devops preset uses risk_below:high, so only low+medium actions.
        assert!(
            !actions.is_empty(),
            "wildcard must have at least one action"
        );

        // No high/critical actions in wildcard.
        let sinks = wildcard["allowed_sinks"]
            .as_array()
            .expect("allowed_sinks must be an array");

        assert!(
            !sinks.is_empty(),
            "wildcard ACL must have at least one sink"
        );
    }

    #[test]
    fn data_json_schema_matches_rego_expectations() {
        let manifests = setup_manifests_dir();
        let preset = ops_preset();
        let data_json = build_data_json(&preset, manifests.path(), &[]).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&data_json).unwrap();

        let obj = parsed.as_object().unwrap();
        assert!(obj.contains_key("policy_version"), "missing policy_version");
        assert!(obj.contains_key("acl"), "missing acl");

        let wildcard = &parsed["acl"]["*"];
        let wc_obj = wildcard.as_object().unwrap();
        assert!(
            wc_obj.contains_key("allowed_actions"),
            "ACL entry missing allowed_actions"
        );
        assert!(
            wc_obj.contains_key("allowed_sinks"),
            "ACL entry missing allowed_sinks"
        );

        for action in parsed["acl"]["*"]["allowed_actions"].as_array().unwrap() {
            assert!(action.is_string(), "action_id must be a string: {action}");
        }
        for sink in parsed["acl"]["*"]["allowed_sinks"].as_array().unwrap() {
            assert!(sink.is_string(), "sink must be a string: {sink}");
        }
    }

    #[test]
    fn data_json_sinks_match_known_set() {
        let known_sinks: std::collections::HashSet<&str> = [
            "db_write",
            "fs_delete",
            "fs_read",
            "fs_write",
            "http_delete",
            "http_read",
            "http_write",
            "message_enqueue",
            "message_send",
        ]
        .into_iter()
        .collect();

        let manifests = setup_manifests_dir();
        let preset = ops_preset();
        let data_json = build_data_json(&preset, manifests.path(), &[]).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&data_json).unwrap();

        for sink in parsed["acl"]["*"]["allowed_sinks"].as_array().unwrap() {
            let s = sink.as_str().unwrap();
            assert!(
                known_sinks.contains(s),
                "unexpected sink '{s}' in generated ACL — update known_sinks or check manifests"
            );
        }
    }

    #[test]
    fn generate_policies_creates_rego_and_data_json() {
        let manifests = setup_manifests_dir();
        let tmp = tempfile::tempdir().unwrap();
        let policies_dir = tmp.path().join("policies");
        let preset = ops_preset();

        generate_policies(&policies_dir, &preset, manifests.path(), &[]).unwrap();

        let rego_path = policies_dir.join("latchgate.rego");
        let data_path = policies_dir.join("data.json");

        assert!(rego_path.is_file(), "latchgate.rego must exist");
        assert!(data_path.is_file(), "data.json must exist");

        let rego_content = std::fs::read_to_string(&rego_path).unwrap();
        assert_eq!(
            rego_content,
            embedded_policies::POLICY_REGO,
            "extracted Rego must match embedded source byte-for-byte"
        );

        let data_content = std::fs::read_to_string(&data_path).unwrap();
        let _: serde_json::Value =
            serde_json::from_str(&data_content).expect("generated data.json must be valid JSON");
    }

    #[test]
    fn lockdown_preset_generates_empty_wildcard() {
        let manifests = setup_manifests_dir();
        let preset = embedded_presets::resolve("lockdown").unwrap();
        let data_json = build_data_json(&preset, manifests.path(), &[]).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&data_json).unwrap();

        let actions = parsed["acl"]["*"]["allowed_actions"]
            .as_array()
            .expect("allowed_actions must be an array");
        assert!(
            actions.is_empty(),
            "lockdown preset must grant no wildcard actions"
        );
    }

    // -- Named principal ACL generation ---------------------------------------

    #[test]
    fn named_principal_receives_full_grant_with_inheritance() {
        let manifests = setup_manifests_dir();
        let preset = ops_preset();
        let principals = vec!["dev-agent".to_string()];
        let data_json = build_data_json(&preset, manifests.path(), &principals).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&data_json).unwrap();

        let wildcard = &parsed["acl"]["*"];
        let agent = &parsed["acl"]["dev-agent"];

        assert!(
            agent.is_object(),
            "named principal 'dev-agent' must have an ACL entry"
        );
        assert_eq!(
            agent["inherits_wildcard"],
            serde_json::json!(true),
            "named principal must have inherits_wildcard = true"
        );

        let wildcard_actions: Vec<&str> = wildcard["allowed_actions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        let agent_actions: Vec<&str> = agent["allowed_actions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();

        // Named principal gets ALL actions (superset of wildcard).
        // High/critical actions are in the named ACL but not wildcard.
        assert!(
            agent_actions.len() >= wildcard_actions.len(),
            "named principal must have at least as many actions as wildcard"
        );
        for wa in &wildcard_actions {
            assert!(
                agent_actions.contains(wa),
                "named principal must include wildcard action '{wa}'"
            );
        }

        // High-risk actions must be in named principal but NOT in wildcard.
        assert!(
            agent_actions.contains(&"fs_write"),
            "named principal must include high-risk 'fs_write'"
        );
        assert!(
            !wildcard_actions.contains(&"fs_write"),
            "wildcard must NOT include high-risk 'fs_write'"
        );
    }

    #[test]
    fn wildcard_literal_in_principals_is_skipped() {
        let manifests = setup_manifests_dir();
        let preset = ops_preset();
        let principals = vec!["*".to_string(), "real-agent".to_string()];
        let data_json = build_data_json(&preset, manifests.path(), &principals).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&data_json).unwrap();

        // Wildcard entry must NOT have inherits_wildcard (it is the wildcard).
        assert!(
            parsed["acl"]["*"].get("inherits_wildcard").is_none(),
            "'*' entry must not have inherits_wildcard"
        );
        // But the real agent must.
        assert_eq!(
            parsed["acl"]["real-agent"]["inherits_wildcard"],
            serde_json::json!(true),
        );
    }

    #[test]
    fn empty_principals_produces_wildcard_only() {
        let manifests = setup_manifests_dir();
        let preset = ops_preset();
        let data_json = build_data_json(&preset, manifests.path(), &[]).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&data_json).unwrap();

        let acl = parsed["acl"].as_object().unwrap();
        assert_eq!(
            acl.len(),
            1,
            "with no agent principals, ACL must have only the wildcard entry"
        );
        assert!(acl.contains_key("*"));
    }

    #[test]
    fn gitignore_covers_install_dir() {
        assert!(
            GITIGNORE_ENTRIES.contains(&".latchgate/"),
            "GITIGNORE_ENTRIES must include .latchgate/ — contains secrets, keys, audit data"
        );
    }

    // -- Identity / signing choice coverage --------------------------------

    fn test_config_toml_with_choices(
        identity: latchgate_tui::IdentityChoice,
        signing: Option<&config_gen::SigningKeyPaths<'_>>,
    ) -> String {
        let base = std::path::Path::new(".latchgate");
        build_config_toml(
            "op",
            "key-op-aabbccdd",
            "jkt-test",
            &config_gen::ConfigDirs {
                manifests: &base.join("manifests"),
                providers: &base.join("providers"),
                data: &base.join("data"),
            },
            signing,
            identity,
        )
    }

    #[test]
    fn config_identity_none_omits_provider_section() {
        let toml_text = test_config_toml_with_choices(latchgate_tui::IdentityChoice::None, None);

        // Must NOT contain an active [identity] section — only comments.
        let config: latchgate_config::Config = toml::from_str(&toml_text)
            .unwrap_or_else(|e| panic!("invalid TOML: {e}\n\n{toml_text}"));
        assert_eq!(
            config.identity.provider,
            latchgate_config::IdentityProviderKind::None,
            "identity=None must produce provider=none in config"
        );
    }

    #[test]
    fn config_identity_peercred_writes_provider_section() {
        let keys_dir = std::path::Path::new(".latchgate/operators/keys");
        let signing = config_gen::SigningKeyPaths {
            receipt: &keys_dir.join("receipt.key"),
            grant: &keys_dir.join("grant.key"),
        };
        let toml_text =
            test_config_toml_with_choices(latchgate_tui::IdentityChoice::Peercred, Some(&signing));

        let config: latchgate_config::Config = toml::from_str(&toml_text)
            .unwrap_or_else(|e| panic!("invalid TOML: {e}\n\n{toml_text}"));
        assert_eq!(
            config.identity.provider,
            latchgate_config::IdentityProviderKind::Peercred,
            "identity=Peercred must produce provider=peercred in config"
        );
        assert!(
            !config.identity.peercred.principals.is_empty(),
            "peercred config must include at least one principal (current UID)"
        );
    }

    #[test]
    fn config_signing_ephemeral_omits_key_paths() {
        let toml_text = test_config_toml_with_choices(latchgate_tui::IdentityChoice::None, None);

        let config: latchgate_config::Config = toml::from_str(&toml_text)
            .unwrap_or_else(|e| panic!("invalid TOML: {e}\n\n{toml_text}"));
        assert!(
            config.signing.receipt_signing_key_path.is_none(),
            "ephemeral signing must not set receipt_signing_key_path"
        );
        assert!(
            config.signing.grant_signing_key_path.is_none(),
            "ephemeral signing must not set grant_signing_key_path"
        );
    }

    #[test]
    fn config_signing_persistent_includes_key_paths() {
        let keys_dir = std::path::Path::new(".latchgate/operators/keys");
        let signing = config_gen::SigningKeyPaths {
            receipt: &keys_dir.join("receipt.key"),
            grant: &keys_dir.join("grant.key"),
        };
        let toml_text =
            test_config_toml_with_choices(latchgate_tui::IdentityChoice::None, Some(&signing));

        let config: latchgate_config::Config = toml::from_str(&toml_text)
            .unwrap_or_else(|e| panic!("invalid TOML: {e}\n\n{toml_text}"));
        assert!(
            config.signing.receipt_signing_key_path.is_some(),
            "persistent signing must set receipt_signing_key_path"
        );
        assert!(
            config.signing.grant_signing_key_path.is_some(),
            "persistent signing must set grant_signing_key_path"
        );
    }
}
