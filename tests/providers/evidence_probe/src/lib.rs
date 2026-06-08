//! Deterministic WASM fixture: returns a canned success payload.
//!
//! Used by integration tests that need a provider dispatch to succeed
//! so the pipeline reaches the evidence-finalization step. The module
//! imports nothing beyond wit-bindgen — no host I/O, no sinks, no
//! secrets — so the run is fully in-sandbox and independent of the
//! environment the test runs in.
//!
//! Response shape matches what the `http_status` verifier expects:
//! a top-level `status` field with a numeric HTTP status code.

wit_bindgen::generate!({
    world: "provider",
    path: "../../../providers/wit",
});

struct Provider;
export!(Provider);

impl Guest for Provider {
    fn execute(_task_json: String) -> Result<String, String> {
        // Response envelope: the kernel enforces `ok: <bool>` on every
        // provider response (schema::check_action_envelope). Omitting
        // `ok` would surface as a 422 schema violation long before the
        // evidence-finalisation step any test here cares about.
        Ok(r#"{"ok":true,"status":200,"data":{"detail":"probe_ok"}}"#.to_string())
    }
}
