//! Build script — git metadata + embedded WASM provider generation.
//!
//! Sets cargo environment variables:
//!   - `GIT_SHA`     — short commit hash (or "unknown" outside a repo)
//!   - `BUILD_DATE`  — UTC date in YYYY-MM-DD format
//!
//! Generates `embedded_providers.gen.rs` in `$OUT_DIR`:
//!   - If `target/providers/*.wasm` exist: embeds via `include_bytes!`
//!   - If missing: empty PROVIDERS slice (dev without `make providers`)

use std::fmt::Write as _;
use std::path::Path;

// Providers shipped in this build. Must match the providers actually compiled
// by `make providers` (the `PROVIDERS` list in the Makefile) and the providers
// referenced by `builtin:<name>` in definitions/manifests. Keep these three in sync:
// adding a provider means building it, embedding it here, and referencing it
// from a manifest — anything less ships a half-wired provider.
const PROVIDERS: &[&str] = &["http_api", "fs"];

fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");
    // Manifest YAMLs are embedded via include_dir! — rebuild when they change.
    println!("cargo:rerun-if-changed=../../definitions/manifests");

    let sha = run("git", &["rev-parse", "--short=8", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let date = run("date", &["-u", "+%Y-%m-%d"]).unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=GIT_SHA={sha}");
    println!("cargo:rustc-env=BUILD_DATE={date}");

    generate_embedded_providers();
}

fn generate_embedded_providers() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir).join("embedded_providers.gen.rs");

    // Workspace root is three levels up from crates/latchgate-cli/src/
    let providers_dir = Path::new("../../target/providers");

    let mut code = String::new();
    writeln!(
        code,
        "/// Built-in provider modules, embedded at compile time."
    )
    .unwrap();
    writeln!(code, "///").unwrap();
    writeln!(
        code,
        "/// Each entry is `(name, wasm_bytes)` where `name` matches the file stem"
    )
    .unwrap();
    writeln!(
        code,
        "/// used for `builtin:<name>` resolution in action manifests."
    )
    .unwrap();
    writeln!(code, "///").unwrap();

    // Check which providers are available.
    let mut found = Vec::new();
    let mut missing = Vec::new();
    for &name in PROVIDERS {
        let wasm_path = providers_dir.join(format!("{name}.wasm"));
        // rerun-if-changed for every provider, present or not.
        println!("cargo:rerun-if-changed={}", wasm_path.display());
        if wasm_path.exists() {
            found.push((name, wasm_path));
        } else {
            missing.push(name);
        }
    }

    if found.is_empty() {
        writeln!(
            code,
            "/// **No providers embedded** — `make providers` was not run before build."
        )
        .unwrap();
        writeln!(
            code,
            "/// The server will rely on filesystem-loaded providers from `wasm_providers_dir`."
        )
        .unwrap();
        writeln!(code, "pub static PROVIDERS: &[(&str, &[u8])] = &[];").unwrap();
    } else {
        if !missing.is_empty() {
            writeln!(code, "/// **Partial embed** — missing: {missing:?}. Run `make providers` for a complete build.").unwrap();
        }
        writeln!(code, "pub static PROVIDERS: &[(&str, &[u8])] = &[").unwrap();
        for (name, path) in &found {
            let abs = std::fs::canonicalize(path)
                .unwrap_or_else(|e| panic!("cannot resolve {}: {e}", path.display()));
            writeln!(
                code,
                "    (\"{name}\", include_bytes!(\"{}\")),",
                abs.display()
            )
            .unwrap();
        }
        writeln!(code, "];").unwrap();
    }

    std::fs::write(&out_path, code).unwrap_or_else(|e| {
        panic!("cannot write {}: {e}", out_path.display());
    });
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    std::process::Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
}
