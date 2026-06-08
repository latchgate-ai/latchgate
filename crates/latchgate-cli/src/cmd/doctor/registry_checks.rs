//! Registry and manifest checks.

use std::path::Path;

use latchgate_config::{Config, SandboxMode};
use latchgate_registry::manifest::ActionSpec;

use super::Check;

pub(super) fn check_manifests_dir(config: &Config) -> Check {
    let p = Path::new(&config.manifests_dir);
    if !p.exists() {
        return Check::warn(
            "manifests_dir",
            format!(
                "{} — not found (no actions will be registered)",
                config.manifests_dir
            ),
        );
    }
    match latchgate_registry::RegistryStore::load_from_dir(p) {
        Ok(store) => {
            let n = store.len();
            if n > 0 {
                Check::ok("manifests_dir", format!("{n} action manifest(s) valid"))
            } else {
                Check::warn(
                    "manifests_dir",
                    "directory exists but no valid manifests found",
                )
            }
        }
        Err(e) => Check::error("manifests_dir", format!("manifest load failed: {e}")),
    }
}

pub(super) fn check_providers_dir(config: &Config) -> Check {
    let p = Path::new(&config.wasm_providers_dir);
    if p.exists() && p.is_dir() {
        Check::ok(
            "providers_dir",
            format!("{} — exists", config.wasm_providers_dir),
        )
    } else {
        let msg = format!(
            "{} — not found or not a directory",
            config.wasm_providers_dir
        );
        match config.sandbox.mode {
            SandboxMode::Strict => Check::error("providers_dir", msg),
            SandboxMode::Degraded | SandboxMode::DegradedOk => Check::warn("providers_dir", msg),
            SandboxMode::Disabled => Check::warn("providers_dir", msg),
        }
    }
}

pub(super) fn check_provider_modules(config: &Config) -> Check {
    // Count providers from both sources: compile-time embedded and on-disk.
    let embedded_count = crate::embedded_providers::PROVIDERS
        .iter()
        .filter(|(_, bytes)| !bytes.is_empty())
        .count();

    let disk_count = Path::new(&config.wasm_providers_dir)
        .read_dir()
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("wasm"))
        .count();

    let total = embedded_count + disk_count;

    if total > 0 {
        let mut detail = Vec::new();
        if embedded_count > 0 {
            detail.push(format!("{embedded_count} embedded"));
        }
        if disk_count > 0 {
            detail.push(format!("{disk_count} from disk"));
        }
        Check::ok(
            "provider_modules",
            format!("{total} .wasm module(s) ({})", detail.join(", ")),
        )
    } else {
        Check::warn(
            "provider_modules",
            "no .wasm modules found (embedded or on-disk) —              run `make providers && cargo build --release` to embed,              or place .wasm files in wasm_providers_dir",
        )
    }
}

/// Report user manifests that shadow embedded (built-in) manifests.
///
/// Overrides are intentional — the operator wants a customized version of a
/// built-in action. But silent overrides are a troubleshooting hazard and an
/// audit concern: an operator deploying a fresh install may not realize a
/// stale user manifest is hiding a newer built-in with security fixes.
///
/// Warn when any overrides exist so the operator can verify intent.
pub(super) fn check_manifest_overrides(config: &Config) -> Check {
    let manifests_dir = Path::new(&config.manifests_dir);

    let registry = match latchgate_registry::RegistryStore::builder()
        .add_embedded(crate::embedded_manifests::iter_yaml())
        .and_then(|b| b.add_dir(manifests_dir))
        .map(|b| b.build())
    {
        Ok(store) => store,
        // Schema compilation or I/O errors — other checks cover these.
        Err(_) => return Check::skip("manifest_overrides", "merged registry unavailable"),
    };

    let count = registry.override_count();
    if count > 0 {
        Check::warn(
            "manifest_overrides",
            format!(
                "{count} embedded manifest(s) overridden by user manifests — \
                 verify with: latchgate config resources"
            ),
        )
    } else {
        Check::ok("manifest_overrides", "no embedded manifests overridden")
    }
}

/// Cross-check manifest provider_module_digest digests against actual .wasm files.
///
/// In dev posture (`config.dev_mode()`), digest mismatches and missing WASM
/// files are downgraded to warnings with a fix hint. Production posture
/// keeps them as hard errors that abort preflight.
pub(super) fn check_manifest_digests(config: &Config) -> Vec<Check> {
    let manifests_dir = Path::new(&config.manifests_dir);
    let providers_dir = Path::new(&config.wasm_providers_dir);

    if !manifests_dir.exists() || !providers_dir.exists() {
        return vec![];
    }

    let entries = match std::fs::read_dir(manifests_dir) {
        Ok(e) => e,
        Err(_) => return vec![],
    };

    let is_dev = config.dev_mode();
    let mut checks = Vec::new();

    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "yaml" && ext != "yml" {
            continue;
        }

        let spec = match ActionSpec::from_file(&path) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let source = match &spec.provider_source {
            Some(s) => s.clone(),
            None => continue,
        };

        let wasm_path = providers_dir.join(&source);
        if !wasm_path.exists() {
            let msg = format!(
                "{}: {} not found in {}",
                spec.action_id, source, config.wasm_providers_dir,
            );
            checks.push(if is_dev {
                Check::warn(
                    "manifest_digest",
                    format!("{msg} — run: latchgate providers rehash"),
                )
            } else {
                Check::error("manifest_digest", msg)
            });
            continue;
        }

        match std::fs::read(&wasm_path) {
            Ok(bytes) => {
                let actual = latchgate_core::crypto::sha256_digest(&bytes);
                if *actual == *spec.provider_module_digest {
                    checks.push(Check::ok(
                        "manifest_digest",
                        format!("{}: digest matches", spec.action_id),
                    ));
                } else {
                    let msg = format!(
                        "{}: digest MISMATCH — run: latchgate providers rehash",
                        spec.action_id,
                    );
                    checks.push(if is_dev {
                        Check::warn("manifest_digest", msg)
                    } else {
                        Check::error("manifest_digest", msg)
                    });
                }
            }
            Err(e) => {
                let msg = format!("{}: cannot read {}: {e}", spec.action_id, source);
                checks.push(if is_dev {
                    Check::warn("manifest_digest", msg)
                } else {
                    Check::error("manifest_digest", msg)
                });
            }
        }
    }

    checks
}

/// Cross-check the configured `manifests_dir` against what resource discovery
/// would resolve from the current working directory.
///
/// If the two paths differ, actions saved by the TUI editor (which writes to
/// `config.manifests_dir`) will vanish on the next restart because `up::run`
/// discovers and loads from a different directory.
pub(super) fn check_manifests_dir_consistency(config: &Config) -> Check {
    let configured = std::path::PathBuf::from(&config.manifests_dir);

    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(_) => {
            return Check::skip(
                "manifests_dir_consistency",
                "cannot determine working directory",
            );
        }
    };

    let Some(resources) = crate::cmd::up::try_discover_resources_in(&cwd) else {
        return Check::skip(
            "manifests_dir_consistency",
            "resource discovery found nothing (see manifests_dir check)",
        );
    };

    let configured_canon = configured
        .canonicalize()
        .unwrap_or_else(|_| configured.clone());
    let discovered_canon = resources
        .manifests_dir
        .canonicalize()
        .unwrap_or_else(|_| resources.manifests_dir.clone());

    if configured_canon == discovered_canon {
        Check::ok(
            "manifests_dir_consistency",
            format!("config and discovery agree: {}", configured.display()),
        )
    } else {
        Check::warn(
            "manifests_dir_consistency",
            format!(
                "config.manifests_dir ({}) differs from discovery ({}). \
                 Saved actions may not load after restart.",
                configured.display(),
                resources.manifests_dir.display(),
            ),
        )
    }
}
