//! `latchgate status` — single-screen operational overview.

use std::path::Path;
use std::time::Duration;

use serde_json::json;

use latchgate_config::Config;

use crate::client::GateClient;
use crate::output::{print_json, Printer};

pub async fn run(config: &Config, pr: &Printer) -> i32 {
    let client = match GateClient::from_config(config) {
        Ok(c) => c,
        Err(e) => {
            pr.error(&e.to_string());
            return 1;
        }
    };

    let gate_up = client.healthz().await.unwrap_or(false);
    let action_count = if gate_up {
        client.list_actions().await.ok().map(|a| a.len())
    } else {
        None
    };

    let embedded_count = crate::embedded_manifests::list_available()
        .map(|m| m.len())
        .unwrap_or(0);
    let user_manifest_count = count_files_with_ext(Path::new(&config.manifests_dir), "yaml")
        + count_files_with_ext(Path::new(&config.manifests_dir), "yml");
    let manifest_override_count = latchgate_registry::RegistryStore::builder()
        .add_embedded(crate::embedded_manifests::iter_yaml())
        .and_then(|b| b.add_dir(Path::new(&config.manifests_dir)))
        .map(|b| b.build())
        .map(|r| r.override_count())
        .unwrap_or(0);
    let embedded_provider_count = crate::embedded_providers::PROVIDERS
        .iter()
        .filter(|(_, bytes)| !bytes.is_empty())
        .count();
    let user_provider_count = count_files_with_ext(Path::new(&config.wasm_providers_dir), "wasm");

    let redis_ok = match config.storage.redis_url.as_deref() {
        Some(url) => probe_redis(url).await,
        None => true, // embedded mode — no Redis needed
    };
    let opa_ok = match config.policy.opa_url.as_deref() {
        Some(url) => probe_opa(url).await,
        None => true, // embedded mode is always "ok"
    };

    if pr.json {
        print_json(&json!({
            "config": config.source.config_file().map(|p| p.display().to_string()),
            "source": format!("{}", config.source),
            "dev_mode": config.dev_mode(),
            "gate": { "running": gate_up },
            "actions": {
                "registered": action_count,
                "embedded": embedded_count,
                "user": user_manifest_count,
                "overrides": manifest_override_count,
            },
            "providers": {
                "embedded": embedded_provider_count,
                "user": user_provider_count,
            },
            "redis": { "ok": redis_ok, "url": config.storage.redis_url.as_deref().unwrap_or("embedded") },
            "opa": { "ok": opa_ok, "url": config.policy.opa_url.as_deref().unwrap_or("embedded") },
        }));
        return if gate_up { 0 } else { 1 };
    }

    pr.banner(crate::VERSION);
    pr.blank();

    // Config
    match config.source.config_file() {
        Some(path) => println!(
            "  Config:     {} ({})",
            path.display(),
            source_label(&config.source)
        ),
        None => println!("  Config:     (defaults — no config file)"),
    }
    println!(
        "  Mode:       {}",
        if config.dev_mode() {
            pr.yellow("dev")
        } else {
            pr.green("production")
        }
    );

    // Actions
    if manifest_override_count > 0 {
        println!(
            "  Actions:    {} ({} built-in, {} user, {} override(s))",
            embedded_count + user_manifest_count,
            embedded_count,
            user_manifest_count,
            manifest_override_count,
        );
    } else {
        println!(
            "  Actions:    {} ({} built-in, {} user)",
            embedded_count + user_manifest_count,
            embedded_count,
            user_manifest_count,
        );
    }
    println!(
        "  Providers:  {} ({} built-in, {} user)",
        embedded_provider_count + user_provider_count,
        embedded_provider_count,
        user_provider_count,
    );

    pr.blank();

    // Gate
    if gate_up {
        let count_str = action_count
            .map(|n| format!(" — {n} action(s) registered"))
            .unwrap_or_default();
        println!(
            "  {}  Gate      {}{count_str}",
            pr.ok_sym(),
            pr.bold("running")
        );
    } else {
        println!("  {}  Gate      not running", pr.err_sym());
    }

    // Redis
    match config.storage.redis_url.as_deref() {
        Some(url) => {
            if redis_ok {
                println!("  {}  Redis     ok    ({})", pr.ok_sym(), url);
            } else {
                println!("  {}  Redis     unreachable ({})", pr.err_sym(), url);
            }
        }
        None => {
            println!("  {}  Redis     not configured (using SQLite)", pr.ok_sym());
        }
    }

    // OPA
    match config.policy.opa_url.as_deref() {
        None => {
            println!("  {}  OPA       embedded (regorus)", pr.ok_sym());
        }
        Some(url) if opa_ok => {
            println!("  {}  OPA       ok    ({url})", pr.ok_sym());
        }
        Some(url) => {
            println!("  {}  OPA       unreachable ({url})", pr.err_sym());
        }
    }

    pr.blank();

    if gate_up {
        0
    } else {
        1
    }
}

fn source_label(source: &latchgate_config::ConfigSource) -> &'static str {
    match source {
        latchgate_config::ConfigSource::Explicit(_) => "explicit",
        latchgate_config::ConfigSource::DevWorkspace(_) => "dev-workspace",
        latchgate_config::ConfigSource::Project(_) => "project",
        latchgate_config::ConfigSource::UserGlobal(_) => "user-global",
        latchgate_config::ConfigSource::Defaults => "defaults",
    }
}

fn count_files_with_ext(dir: &Path, ext: &str) -> usize {
    dir.read_dir()
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().map(|x| x == ext).unwrap_or(false))
                .count()
        })
        .unwrap_or(0)
}

async fn probe_redis(url: &str) -> bool {
    let addr = url
        .trim_start_matches("redis://")
        .trim_start_matches("rediss://")
        .split('/')
        .next()
        .and_then(|s| s.split('@').next_back())
        .unwrap_or("127.0.0.1:6379");

    let addr: std::net::SocketAddr = addr
        .parse()
        .or_else(|_| format!("{addr}:6379").parse())
        .unwrap_or_else(|_| ([127, 0, 0, 1], 6379).into());

    tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(addr))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
}

async fn probe_opa(url: &str) -> bool {
    let health_url = format!("{}/health", url.trim_end_matches('/'));
    tokio::time::timeout(Duration::from_secs(2), reqwest::get(&health_url))
        .await
        .map(|r| r.map(|resp| resp.status().is_success()).unwrap_or(false))
        .unwrap_or(false)
}
