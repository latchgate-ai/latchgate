//! Execution path structural audits.
//!
//! Static analysis that verifies the shared execution tail in `execution.rs`
//! is the **only** code path that dispatches WASM providers. Any code that
//! calls `wasm_runtime.execute()` outside `execution.rs` is a security
//! violation — it would bypass grant validation, evidence durability, and
//! verifier checks.
//!
//! `DecisionSource` serialization stability is covered by unit tests in
//! `latchgate-kernel::execution`.

use std::fs;
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("tests crate must be inside workspace")
        .to_path_buf()
}

/// The WASM runtime's `execute()` method must only be called from
/// `execution.rs` (the shared execution tail) and test code.
///
/// SECURITY: `execute_authorized_plan` owns grant validation, evidence
/// durability, schema enforcement, and verifier execution. Any caller
/// that bypasses it could:
///   - Execute without a valid grant (authorization bypass)
///   - Execute without writing evidence (audit gap)
///   - Execute without running the verifier (verification bypass)
///   - Execute without schema validation (data exfiltration)
#[test]
fn wasm_execute_only_called_from_execution_module() {
    let kernel_dir = workspace_root().join("crates/latchgate-kernel/src");
    let api_dir = workspace_root().join("crates/latchgate-api/src");

    let mut violations = Vec::new();

    for dir in [&kernel_dir, &api_dir] {
        for entry in fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let filename = path.file_name().unwrap().to_string_lossy();

            // execution.rs is the authorized caller.
            if filename == "execution.rs" {
                continue;
            }

            let content = fs::read_to_string(&path).unwrap();

            // Skip test modules — test code may call execute() for testing.
            let prod_content = if let Some(test_start) = content.find("#[cfg(test)]") {
                &content[..test_start]
            } else {
                &content
            };

            // Check for direct wasm_runtime.execute calls in production code.
            for (line_num, line) in prod_content.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("//") {
                    continue;
                }
                if trimmed.contains("wasm_runtime.execute(")
                    || trimmed.contains("wasm_runtime.execute(&")
                {
                    violations.push(format!(
                        "{}:{}: direct wasm_runtime.execute() call outside execution.rs",
                        path.display(),
                        line_num + 1,
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "SECURITY VIOLATION: wasm_runtime.execute() must only be called from \
         execution.rs (the shared execution tail). Found {} violations:\n{}",
        violations.len(),
        violations.join("\n")
    );
}

/// The approval endpoint must not construct RunTask or call provider dispatch
/// directly — it must delegate to `execute_authorized_plan`.
///
/// SECURITY: if the approval endpoint bypasses the shared execution tail,
/// approved actions would skip grant validation, evidence durability, and
/// verifier checks.
#[test]
fn approval_endpoint_delegates_to_shared_execution() {
    let path = workspace_root().join("crates/latchgate-api/src/approvals.rs");
    let content = fs::read_to_string(&path).unwrap();

    // Strip test modules.
    let prod_content = if let Some(test_start) = content.find("#[cfg(test)]") {
        &content[..test_start]
    } else {
        &content
    };

    // The approval endpoint MUST call execute_authorized_plan.
    assert!(
        prod_content.contains("execute_authorized_plan"),
        "approvals.rs must delegate to execute_authorized_plan — \
         direct provider dispatch from the approval endpoint is a security violation"
    );

    // The approval endpoint must NOT call wasm_runtime.execute directly.
    let has_direct_dispatch = prod_content.lines().any(|line| {
        let t = line.trim();
        !t.starts_with("//")
            && (t.contains("wasm_runtime.execute(") || t.contains(".execute(&task"))
            && !t.contains("execute_authorized_plan")
    });

    assert!(
        !has_direct_dispatch,
        "approvals.rs must NOT call wasm_runtime.execute() directly — \
         all execution must go through execute_authorized_plan"
    );
}
