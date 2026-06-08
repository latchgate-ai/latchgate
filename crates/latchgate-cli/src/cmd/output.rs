//! Structured CLI error output (JSON and human-readable).

use serde_json::json;

use crate::output::{print_json, Printer};

/// Emit an error in JSON or human-readable format. Returns exit code 1.
///
/// JSON shape: `{"ok": false, "error": "<msg>"}`.
/// Human: blank line, `✗  <msg>`, blank line.
pub fn emit_error(pr: &Printer, msg: &str) -> i32 {
    if pr.json {
        print_json(&json!({ "ok": false, "error": msg }));
    } else {
        pr.blank();
        pr.error(msg);
        pr.blank();
    }
    1
}

/// Emit a structured error with machine-readable code. Returns exit code 1.
///
/// JSON shape: `{"ok": false, "error": "<code>", "detail": "<detail>"}`.
/// Human: blank line, `✗  <detail>`, blank line.
pub fn emit_error_coded(pr: &Printer, code: &str, detail: &str) -> i32 {
    if pr.json {
        print_json(&json!({ "ok": false, "error": code, "detail": detail }));
    } else {
        pr.blank();
        pr.error(detail);
        pr.blank();
    }
    1
}
