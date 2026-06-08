//! Verify that every Docker Compose configuration binds host ports
//! exclusively to 127.0.0.1 — never to 0.0.0.0 or all interfaces.
//!
//! Covers:
//!   - docker-compose.yml                       (dev stack at repo root)
//!   - crates/latchgate-cli/src/cmd/up.rs       (embedded compose template)
//!
//! Static analysis — does not require a running stack or Docker.

use std::fs;
use std::path::PathBuf;

/// Workspace root — one level up from this crate's manifest dir.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("tests crate must be inside workspace")
        .to_path_buf()
}

/// Assert that every port mapping in a YAML string binds to 127.0.0.1.
///
/// Handles both quoted (`- "127.0.0.1:6379:6379"`) and unquoted
/// (`- 127.0.0.1:6379:6379`) YAML list items, as well as bare
/// `host:container` mappings that omit the bind address entirely
/// (which Docker interprets as 0.0.0.0).
fn assert_ports_localhost_only(content: &str, file_label: &str) {
    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        // Only YAML list items.
        if !trimmed.starts_with('-') {
            continue;
        }

        // Strip leading `- ` and surrounding quotes to get the raw value.
        let value = trimmed
            .trim_start_matches('-')
            .trim()
            .trim_matches('"')
            .trim_matches('\'');

        // Identify port-mapping entries: the host part consists only of
        // digits, dots, brackets (IPv6), and colons. Named volumes and
        // path mounts won't match.
        let is_port_mapping = value
            .split(':')
            .next()
            .map(|host_part| {
                !host_part.is_empty()
                    && host_part
                        .chars()
                        .all(|c| c.is_ascii_digit() || matches!(c, '.' | '[' | ']'))
            })
            .unwrap_or(false);

        if is_port_mapping {
            assert!(
                value.starts_with("127.0.0.1:"),
                "{file_label}:{line_num}: port mapping must bind to 127.0.0.1, \
                 got: {trimmed}\n\
                 Binding to 0.0.0.0 (or omitting the address) exposes the port \
                 on all network interfaces. Security project requirement: \
                 all compose port bindings must be explicitly localhost-only."
            );
        }
    }
}

// ── Test: root docker-compose.yml (dev stack) ───────────────────────────────

/// The development compose stack must bind all host ports to 127.0.0.1.
///
/// This file is used by `make dev` and `docker compose up` during local
/// development. Binding to 0.0.0.0 would expose Redis, OPA, and
/// Prometheus to the network.
#[test]
fn dev_compose_binds_only_to_localhost() {
    let path = workspace_root().join("docker-compose.yml");
    let content =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("{} must exist: {e}", path.display()));

    assert_ports_localhost_only(&content, "docker-compose.yml");
}

// ── Test: up.rs embedded compose template ──────────────────────────────────

/// The compose template embedded in `latchgate up` must bind all ports
/// to 127.0.0.1.
///
/// `latchgate up` writes a Docker Compose file to a temp directory at
/// runtime. We validate the Rust source that generates it, because:
///   - The template is a string literal — easy to verify statically.
///   - Runtime generation means no static YAML file to check.
///   - A regression here would silently expose ports on `latchgate up`.
#[test]
fn up_compose_template_binds_only_to_localhost() {
    let path = workspace_root().join("crates/latchgate-cli/src/cmd/up.rs");
    let source =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("{} must exist: {e}", path.display()));

    // The compose template is embedded as a Rust raw string literal inside
    // a format!() call. Port mappings appear as YAML list items within
    // that string, e.g.:
    //
    //       - "127.0.0.1:6379:6379"
    //
    // We scan for quoted port-mapping patterns: "IP:PORT:PORT" where IP
    // is a dotted-quad. This catches both the template lines and any
    // future additions.

    let mut found_ports = 0;

    for (line_num, line) in source.lines().enumerate() {
        // Look for quoted port mappings: "X.X.X.X:NNNN:NNNN"
        // These appear inside the raw string template.
        let trimmed = line.trim();

        // Match lines containing a quoted IP:port:port pattern.
        // We look for `"<digits-and-dots>:<digits>:<digits>"`.
        if let Some(start) = trimmed.find('"') {
            if let Some(end) = trimmed[start + 1..].find('"') {
                let inner = &trimmed[start + 1..start + 1 + end];

                // Split by ':' — a port mapping has exactly 3 parts
                // (bind_addr:host_port:container_port) or 2 parts
                // (host_port:container_port, implying 0.0.0.0).
                let parts: Vec<&str> = inner.split(':').collect();

                let is_port_mapping = match parts.len() {
                    2 => {
                        // "HOST_PORT:CONTAINER_PORT" — no bind address.
                        parts
                            .iter()
                            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
                    }
                    3 => {
                        // "ADDR:HOST_PORT:CONTAINER_PORT"
                        let addr = parts[0];
                        let host_port = parts[1];
                        let container_port = parts[2];
                        addr.chars().all(|c| c.is_ascii_digit() || c == '.')
                            && !addr.is_empty()
                            && host_port.chars().all(|c| c.is_ascii_digit())
                            && !host_port.is_empty()
                            && container_port.chars().all(|c| c.is_ascii_digit())
                            && !container_port.is_empty()
                    }
                    _ => false,
                };

                if is_port_mapping {
                    found_ports += 1;
                    assert!(
                        inner.starts_with("127.0.0.1:"),
                        "up.rs:{line_num}: embedded compose template port mapping \
                         must bind to 127.0.0.1, got: \"{inner}\"\n\
                         The `latchgate up` command generates a compose file at \
                         runtime — all port bindings must be localhost-only."
                    );
                }
            }
        }
    }

    assert!(
        found_ports >= 3,
        "up.rs: expected at least 3 port mappings in the embedded compose \
         template (Redis + OPA + Squid), found {found_ports}. The template \
         format may have changed — update this test."
    );
}
