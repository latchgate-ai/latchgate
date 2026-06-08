//! Build script — embedded WASM provider generation.
//!
//! Generates `embedded_providers.gen.rs` in `$OUT_DIR`:
//!   - If `target/providers/*.wasm` exist at build time: bytes are embedded.
//!   - If missing: empty PROVIDERS slice (dev without `make providers`).

use std::fmt::Write as _;
use std::path::Path;

// Providers shipped in this build. Must match the providers actually compiled
// by `make providers` (the `PROVIDERS` list in the Makefile) and the providers
// referenced by `builtin:<name>` in definitions/manifests. Keep these three in sync:
// adding a provider means building it, embedding it here, and referencing it
// from a manifest — anything less ships a half-wired provider.
const PROVIDERS: &[&str] = &["http_api", "fs"];

fn main() {
    generate_embedded_providers();
}

fn generate_embedded_providers() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir).join("embedded_providers.gen.rs");

    // Workspace root is two levels up from crates/latchgate-shared/
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

    let mut found = Vec::new();
    let mut missing = Vec::new();
    for &name in PROVIDERS {
        let wasm_path = providers_dir.join(format!("{name}.wasm"));
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

    std::fs::write(&out_path, code)
        .unwrap_or_else(|e| panic!("cannot write {}: {e}", out_path.display()));
}
