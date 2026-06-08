//! `config path` and `config resources` — config discovery diagnostics.

use std::path::Path;

use serde_json::json;

use latchgate_config::Config;

use crate::output::{print_json, Printer};

/// Print the resolved config file path and discovery source.
pub fn run_path(config: &Config, pr: &Printer, json_mode: bool) -> i32 {
    let source = &config.source;
    let config_file = source.config_file();

    if json_mode {
        print_json(&json!({
            "source": format!("{source}"),
            "config_file": config_file.as_ref().map(|p| p.display().to_string()),
        }));
        return 0;
    }

    pr.blank();
    match config_file {
        Some(path) => {
            println!("  Config:  {}", path.display());
            println!("  Source:  {source}");
        }
        None => {
            println!("  Config:  (none — using compiled defaults)");
            println!("  Source:  {source}");
        }
    }
    pr.blank();

    0
}

/// Report where manifests, providers, and policies come from.
///
/// Loads the registry the same way the server would (embedded + user dir)
/// and reports provenance per action. Does not require a running gate.
pub fn run_resources(config: &Config, pr: &Printer, json_mode: bool) -> i32 {
    let embedded_manifests = match crate::embedded_manifests::list_available() {
        Ok(m) => m,
        Err(e) => {
            pr.error(&format!("embedded manifests failed validation: {e}"));
            return 1;
        }
    };
    let embedded_count = embedded_manifests.len();

    let manifests_dir = Path::new(&config.manifests_dir);

    let registry = latchgate_registry::RegistryStore::builder()
        .add_embedded(crate::embedded_manifests::iter_yaml())
        .unwrap_or_else(|e| {
            pr.error(&format!("embedded manifest load failed: {e}"));
            std::process::exit(1);
        })
        .add_dir(manifests_dir)
        .unwrap_or_else(|e| {
            pr.error(&format!("manifest dir load failed: {e}"));
            std::process::exit(1);
        })
        .build();

    let final_embedded = registry
        .provenance_iter()
        .filter(|(_, s)| matches!(s, latchgate_registry::SourceKind::Embedded))
        .count();
    let final_from_dir = registry.len() - final_embedded;
    let overrides = embedded_count - final_embedded;

    let embedded_providers = crate::embedded_providers::PROVIDERS;
    let embedded_provider_count = embedded_providers
        .iter()
        .filter(|(_, bytes)| !bytes.is_empty())
        .count();

    let providers_dir = Path::new(&config.wasm_providers_dir);
    let user_provider_count = count_wasm_files(providers_dir);

    let policies_dir = resolve_policies_dir(config);
    let user_policy_count = count_rego_files(&policies_dir);

    if json_mode {
        let overrides_list: Vec<_> = registry
            .provenance_iter()
            .filter(|(_, src)| !matches!(src, latchgate_registry::SourceKind::Embedded))
            .map(|(id, src)| json!({"action_id": id, "source": format!("{src}")}))
            .collect();

        print_json(&json!({
            "manifests": {
                "total": registry.len(),
                "embedded": final_embedded,
                "user": final_from_dir,
                "manifests_dir": config.manifests_dir,
            },
            "providers": {
                "embedded": embedded_provider_count,
                "user": user_provider_count,
                "providers_dir": config.wasm_providers_dir,
            },
            "policies": {
                "embedded": 1,
                "user": user_policy_count,
                "policies_dir": policies_dir.display().to_string(),
            },
            "overrides": overrides_list,
        }));
        return 0;
    }

    pr.blank();
    pr.section("Resources");
    pr.blank();

    println!(
        "  Actions:    {} total ({} built-in, {} user)",
        registry.len(),
        final_embedded,
        final_from_dir,
    );
    println!("              manifests_dir = {}", config.manifests_dir);

    println!(
        "  Providers:  {} total ({} built-in, {} user)",
        embedded_provider_count + user_provider_count,
        embedded_provider_count,
        user_provider_count,
    );
    println!(
        "              wasm_providers_dir = {}",
        config.wasm_providers_dir
    );

    println!(
        "  Policies:   {} total (1 built-in, {} user)",
        1 + user_policy_count,
        user_policy_count,
    );
    if policies_dir.exists() {
        println!("              policies_dir = {}", policies_dir.display());
    }

    if overrides > 0 {
        pr.blank();
        pr.warn(&format!(
            "{overrides} built-in action(s) overridden by user manifests:"
        ));
        let mut override_ids: Vec<_> = registry
            .provenance_iter()
            .filter(|(_, src)| !matches!(src, latchgate_registry::SourceKind::Embedded))
            .collect();
        override_ids.sort_by_key(|(id, _)| *id);
        for (id, src) in &override_ids {
            println!("    {id}  ← {src}");
        }
    }

    pr.blank();

    0
}

fn count_wasm_files(dir: &Path) -> usize {
    dir.read_dir()
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.path()
                        .extension()
                        .map(|ext| ext == "wasm")
                        .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or(0)
}

fn count_rego_files(dir: &Path) -> usize {
    dir.read_dir()
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.path()
                        .extension()
                        .map(|ext| ext == "rego")
                        .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or(0)
}

/// Derive the policies directory from the install context.
///
/// Mirrors the layout created by `latchgate init`: policies/ is a sibling
/// of manifests/ under the install root.
fn resolve_policies_dir(config: &Config) -> std::path::PathBuf {
    use latchgate_config::ConfigSource;
    match &config.source {
        ConfigSource::DevWorkspace(w) => w.policies_dir(),
        ConfigSource::Project(p) => p.policies_dir(),
        ConfigSource::UserGlobal(u) => u.config_dir().join("policies"),
        ConfigSource::Explicit(path) => path.parent().unwrap_or(Path::new(".")).join("policies"),
        ConfigSource::Defaults => {
            // Sibling of the resolved manifests_dir.
            Path::new(&config.manifests_dir)
                .parent()
                .map(|p| p.join("policies"))
                .unwrap_or_else(|| std::path::PathBuf::from("policies"))
        }
    }
}
