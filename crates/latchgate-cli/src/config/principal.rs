//! `config add/remove/list principal` — peercred identity management.

use latchgate_config::Config;
use serde_json::json;
use toml_edit;

use crate::cmd::output;
use crate::output::{print_json, Printer};

use super::edit_config_doc;

/// Arguments for `run_add_principal`, bundled to stay under clippy's argument limit.
pub struct AddPrincipalArgs<'a> {
    pub config_path: Option<&'a str>,
    pub uid: u32,
    pub name: &'a str,
    pub scopes_csv: &'a str,
    pub owner: Option<&'a str>,
    pub force: bool,
}

/// Add a peercred principal mapping to latchgate.toml.
///
/// Sets `identity.provider = "peercred"` if currently `"none"`.
/// Sets `identity.peercred.allow_unmapped = false` if missing.
/// Rejects if a different identity provider is configured.
pub fn run_add_principal(args: &AddPrincipalArgs<'_>, pr: &Printer, json_mode: bool) -> i32 {
    let uid = args.uid;
    let name = args.name;
    let owner = args.owner;
    let force = args.force;
    // ── Validate inputs ───────────────────────────────────────────────

    if uid == 0 {
        return output::emit_error(pr, "UID 0 (root) is not allowed as a principal");
    }

    if name.is_empty() || name.contains(|c: char| c.is_whitespace() || c.is_control()) {
        return output::emit_error(
            pr,
            &format!("invalid principal name: {name:?} — must be non-empty, no whitespace"),
        );
    }

    // Alphanumeric + hyphens + underscores only.
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return output::emit_error(
            pr,
            &format!("invalid principal name: {name:?} — only alphanumeric, hyphens, underscores"),
        );
    }

    let scopes: Vec<String> = args
        .scopes_csv
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if scopes.is_empty() {
        return output::emit_error(pr, "at least one scope is required");
    }

    for scope in &scopes {
        if !scope
            .chars()
            .all(|c| c.is_ascii_lowercase() || c == '_' || c == ':')
        {
            return output::emit_error(
                pr,
                &format!("invalid scope: {scope:?} — must match [a-z_:]+"),
            );
        }
    }

    // ── Load, mutate, validate, and write config ───────────────────────

    let result = edit_config_doc(pr, args.config_path, |doc| {
        // ── Check identity provider compatibility ─────────────────────────

        let current_provider = doc
            .get("identity")
            .and_then(|t| t.get("provider"))
            .and_then(|v| v.as_str())
            .unwrap_or("none");

        match current_provider {
            "none" | "peercred" => {}
            other => {
                return Err(format!(
                    "identity.provider is '{other}' — cannot add peercred principal. \
                     Only 'none' (auto-switched) or 'peercred' is supported."
                ));
            }
        }

        // ── Check for duplicate UID ───────────────────────────────────────

        let uid_str = uid.to_string();
        let already_exists = doc
            .get("identity")
            .and_then(|t| t.get("peercred"))
            .and_then(|t| t.get("principals"))
            .and_then(|t| t.get(&uid_str))
            .is_some();

        if already_exists && !force {
            return Err(format!(
                "UID {uid} already mapped — use --force to overwrite"
            ));
        }

        // ── Build TOML structure ──────────────────────────────────────────

        // Ensure [identity] exists and set provider.
        let identity = doc
            .entry("identity")
            .or_insert(toml_edit::Item::Table(toml_edit::Table::new()));
        identity["provider"] = toml_edit::value("peercred");

        // Ensure [identity.peercred] exists with allow_unmapped = false.
        let identity_table = identity
            .as_table_mut()
            .ok_or("internal: [identity] is not a TOML table")?;
        let peercred = identity_table
            .entry("peercred")
            .or_insert(toml_edit::Item::Table(toml_edit::Table::new()));

        if peercred.get("allow_unmapped").is_none() {
            peercred["allow_unmapped"] = toml_edit::value(false);
        }

        // Ensure [identity.peercred.principals] exists.
        let peercred_table = peercred
            .as_table_mut()
            .ok_or("internal: [identity.peercred] is not a TOML table")?;
        let principals = peercred_table
            .entry("principals")
            .or_insert(toml_edit::Item::Table(toml_edit::Table::new()));

        // Build the principal entry.
        let mut entry = toml_edit::Table::new();
        entry.insert("principal", toml_edit::value(name));

        let mut scopes_array = toml_edit::Array::new();
        for scope in &scopes {
            scopes_array.push(scope.as_str());
        }
        entry.insert("scopes", toml_edit::value(scopes_array));

        if let Some(owner_val) = owner {
            entry.insert("owner", toml_edit::value(owner_val));
        }

        principals[&uid_str] = toml_edit::Item::Table(entry);

        Ok(())
    });

    if let Err(code) = result {
        return code;
    }

    // ── Report ────────────────────────────────────────────────────────

    if json_mode {
        print_json(&json!({
            "ok": true,
            "uid": uid,
            "principal": name,
            "scopes": scopes,
            "owner": owner,
        }));
    } else {
        pr.blank();
        pr.success(&format!("Principal '{name}' added (UID {uid})"));
        pr.blank();
        pr.field("  uid      ", &uid.to_string());
        pr.field("  principal", name);
        pr.field("  scopes   ", &scopes.join(", "));
        if let Some(o) = owner {
            pr.field("  owner    ", o);
        }
        pr.blank();
    }
    0
}

pub fn run_remove_principal(
    config_path: Option<&str>,
    uid: u32,
    pr: &Printer,
    json_mode: bool,
) -> i32 {
    let result = edit_config_doc(pr, config_path, |doc| {
        let uid_str = uid.to_string();

        let exists = doc
            .get("identity")
            .and_then(|t| t.get("peercred"))
            .and_then(|t| t.get("principals"))
            .and_then(|t| t.get(&uid_str))
            .is_some();

        if !exists {
            return Err(format!("UID {uid} not found in peercred principals"));
        }

        let principals_table = doc["identity"]["peercred"]["principals"]
            .as_table_mut()
            .ok_or("internal: [identity.peercred.principals] is not a TOML table")?;
        principals_table.remove(&uid_str);

        Ok(())
    });

    if let Err(code) = result {
        return code;
    }

    if json_mode {
        print_json(&json!({ "ok": true, "uid": uid, "removed": true }));
    } else {
        pr.blank();
        pr.success(&format!("Principal for UID {uid} removed"));
        pr.blank();
    }
    0
}

pub fn run_list_principals(config: &Config, pr: &Printer, json_mode: bool) -> i32 {
    let principals = &config.identity.peercred.principals;

    if json_mode {
        let entries: Vec<serde_json::Value> = principals
            .iter()
            .map(|(uid, p)| {
                json!({
                    "uid": uid,
                    "principal": p.principal,
                    "scopes": p.scopes,
                    "owner": p.owner,
                })
            })
            .collect();
        print_json(&json!({ "ok": true, "principals": entries }));
        return 0;
    }

    if principals.is_empty() {
        pr.blank();
        pr.info("No peercred principals configured.");
        pr.blank();
        return 0;
    }

    pr.blank();
    println!(
        "  {:<8} {:<20} {:<28} {}",
        pr.bold("UID"),
        pr.bold("Principal"),
        pr.bold("Scopes"),
        pr.bold("Owner"),
    );
    println!("  {}", "─".repeat(72));

    let mut uids: Vec<&String> = principals.keys().collect();
    uids.sort();
    for uid in uids {
        let p = &principals[uid];
        let scopes_str = p.scopes.join(", ");
        let owner_str = p.owner.as_deref().unwrap_or("");
        println!(
            "  {:<8} {:<20} {:<28} {}",
            uid, p.principal, scopes_str, owner_str
        );
    }
    pr.blank();

    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_fixtures::*;

    // -- add/remove/list principal -------------------------------------------

    #[test]
    fn add_principal_generates_correct_toml_structure() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), PRINCIPAL_TEST_TOML);
        let pr = Printer::new(false);

        let code = run_add_principal(
            &AddPrincipalArgs {
                config_path: Some(path.to_str().unwrap()),
                uid: 1001,
                name: "agent-support",
                scopes_csv: "tools:call",
                owner: Some("alice@corp.com"),
                force: false,
            },
            &pr,
            false,
        );
        assert_eq!(code, 0, "add_principal failed");

        let content = std::fs::read_to_string(&path).unwrap();
        let config: latchgate_config::Config = toml::from_str(&content)
            .unwrap_or_else(|e| panic!("generated TOML is invalid: {e}\n\n{content}"));

        // Provider switched to peercred.
        assert_eq!(
            config.identity.provider,
            latchgate_config::IdentityProviderKind::Peercred,
        );

        // Principal exists with correct fields.
        let p = config
            .identity
            .peercred
            .principals
            .get("1001")
            .expect("principal 1001 must exist");
        assert_eq!(p.principal, "agent-support");
        assert_eq!(p.scopes, vec!["tools:call"]);
        assert_eq!(p.owner.as_deref(), Some("alice@corp.com"));

        // allow_unmapped should be false.
        assert!(!config.identity.peercred.allow_unmapped);
    }

    #[test]
    fn add_principal_sets_provider_to_peercred_if_none() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), PRINCIPAL_TEST_TOML);
        let pr = Printer::new(false);

        let code = run_add_principal(
            &AddPrincipalArgs {
                config_path: Some(path.to_str().unwrap()),
                uid: 1001,
                name: "test",
                scopes_csv: "tools:call",
                owner: None,
                force: false,
            },
            &pr,
            false,
        );
        assert_eq!(code, 0);

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("provider = \"peercred\""));
    }

    #[test]
    fn add_principal_rejects_duplicate_uid() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), PRINCIPAL_TEST_TOML);
        let pr = Printer::new(false);

        let code = run_add_principal(
            &AddPrincipalArgs {
                config_path: Some(path.to_str().unwrap()),
                uid: 1001,
                name: "first",
                scopes_csv: "tools:call",
                owner: None,
                force: false,
            },
            &pr,
            false,
        );
        assert_eq!(code, 0);

        let code = run_add_principal(
            &AddPrincipalArgs {
                config_path: Some(path.to_str().unwrap()),
                uid: 1001,
                name: "second",
                scopes_csv: "tools:call",
                owner: None,
                force: false,
            },
            &pr,
            false,
        );
        assert_ne!(code, 0, "duplicate UID must be rejected without --force");
    }

    #[test]
    fn add_principal_force_overwrites_uid() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), PRINCIPAL_TEST_TOML);
        let pr = Printer::new(false);

        run_add_principal(
            &AddPrincipalArgs {
                config_path: Some(path.to_str().unwrap()),
                uid: 1001,
                name: "first",
                scopes_csv: "tools:call",
                owner: None,
                force: false,
            },
            &pr,
            false,
        );
        let code = run_add_principal(
            &AddPrincipalArgs {
                config_path: Some(path.to_str().unwrap()),
                uid: 1001,
                name: "second",
                scopes_csv: "tools:call,db:query",
                owner: None,
                force: true,
            },
            &pr,
            false,
        );
        assert_eq!(code, 0, "--force should allow overwrite");

        let content = std::fs::read_to_string(&path).unwrap();
        let config: latchgate_config::Config = toml::from_str(&content).unwrap();
        let p = &config.identity.peercred.principals["1001"];
        assert_eq!(p.principal, "second");
        assert_eq!(p.scopes, vec!["tools:call", "db:query"]);
    }

    #[test]
    fn add_principal_rejects_uid_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), PRINCIPAL_TEST_TOML);
        let pr = Printer::new(false);

        let code = run_add_principal(
            &AddPrincipalArgs {
                config_path: Some(path.to_str().unwrap()),
                uid: 0,
                name: "root",
                scopes_csv: "tools:call",
                owner: None,
                force: false,
            },
            &pr,
            false,
        );
        assert_ne!(code, 0, "UID 0 must be rejected");
    }

    #[test]
    fn add_principal_rejects_invalid_scope() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), PRINCIPAL_TEST_TOML);
        let pr = Printer::new(false);

        let code = run_add_principal(
            &AddPrincipalArgs {
                config_path: Some(path.to_str().unwrap()),
                uid: 1001,
                name: "test",
                scopes_csv: "INVALID SCOPE",
                owner: None,
                force: false,
            },
            &pr,
            false,
        );
        assert_ne!(code, 0, "uppercase/space in scope must be rejected");
    }

    #[test]
    fn remove_principal_cleans_up_section() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), PRINCIPAL_TEST_TOML);
        let pr = Printer::new(false);

        // Add two principals so removing one still leaves a valid config.
        run_add_principal(
            &AddPrincipalArgs {
                config_path: Some(path.to_str().unwrap()),
                uid: 1001,
                name: "keep",
                scopes_csv: "tools:call",
                owner: None,
                force: false,
            },
            &pr,
            false,
        );
        run_add_principal(
            &AddPrincipalArgs {
                config_path: Some(path.to_str().unwrap()),
                uid: 1002,
                name: "remove-me",
                scopes_csv: "tools:call",
                owner: None,
                force: false,
            },
            &pr,
            false,
        );

        let code = run_remove_principal(Some(path.to_str().unwrap()), 1002, &pr, false);
        assert_eq!(code, 0);

        let content = std::fs::read_to_string(&path).unwrap();
        let config: latchgate_config::Config = toml::from_str(&content).unwrap();
        assert!(
            !config.identity.peercred.principals.contains_key("1002"),
            "removed principal must be gone"
        );
        assert!(
            config.identity.peercred.principals.contains_key("1001"),
            "other principal must remain"
        );
    }

    #[test]
    fn remove_nonexistent_principal_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), PRINCIPAL_TEST_TOML);
        let pr = Printer::new(false);

        let code = run_remove_principal(Some(path.to_str().unwrap()), 9999, &pr, false);
        assert_ne!(code, 0);
    }

    #[test]
    fn scopes_round_trip_as_array() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_test_config(tmp.path(), PRINCIPAL_TEST_TOML);
        let pr = Printer::new(false);

        run_add_principal(
            &AddPrincipalArgs {
                config_path: Some(path.to_str().unwrap()),
                uid: 1001,
                name: "multi-scope",
                scopes_csv: "tools:call,db:query,admin:read",
                owner: None,
                force: false,
            },
            &pr,
            false,
        );

        let content = std::fs::read_to_string(&path).unwrap();
        let config: latchgate_config::Config = toml::from_str(&content).unwrap();
        let p = &config.identity.peercred.principals["1001"];
        assert_eq!(
            p.scopes,
            vec!["tools:call", "db:query", "admin:read"],
            "scopes must round-trip as array, not string"
        );
    }
}
