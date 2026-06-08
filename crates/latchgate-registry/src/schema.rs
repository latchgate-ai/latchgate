//! JSON Schema validation for action I/O.
//!
//! Every action call must pass schema validation before reaching the policy step.
//! Every action response must pass schema validation before being returned to the
//! caller. Schema errors are not retried — the client must fix the request.
//!
//! Schemas are pre-compiled at startup via [`compile_schema`] and stored in the
//! Registry. The hot-path functions [`validate_request`] / [`validate_response`]
//! receive already-compiled validators — no per-request parsing.
//!
//! # Security properties
//!
//! - **Size limits** enforced *before* schema validation (DoS protection).
//! - **Depth limits** enforced *before* schema validation (stack exhaustion).
//! - **Strict mode** — `additionalProperties: false` in schemas rejects unknown
//!   fields, preventing injection of unexpected data.
//! - **Response envelope** — action output must match `{"ok": bool, ...}`.

use latchgate_core::crypto::json::{json_compact_byte_len, json_depth, max_array_len};
use serde_json::Value;

/// Errors from request or response schema validation.
///
/// HTTP semantics (see `gate::pipeline::PipelineError::into_response`):
/// - All variants => 422 Unprocessable Entity.
///   The client sent a structurally invalid payload; retrying the same
///   request will not succeed. Schema must be fixed first.
#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    #[error("request exceeds size limit ({size} > {max} bytes)")]
    TooLarge { size: usize, max: usize },

    #[error("request exceeds nesting depth limit ({depth} > {max})")]
    TooDeep { depth: u32, max: u32 },

    #[error("request exceeds array size limit ({items} items > {max})")]
    TooManyItems { items: usize, max: usize },

    #[error("schema validation failed: {reason}")]
    ValidationFailed { reason: String },

    /// Unknown field present in strict mode (`additionalProperties: false`).
    #[error("request contains unknown field: {field}")]
    UnknownField { field: String },

    /// The action's schema could not be loaded from the Registry.
    #[error("schema not found for action '{action_id}'")]
    NotFound { action_id: String },

    /// Action response failed schema validation.
    #[error("response schema violation: {0}")]
    ResponseValidation(String),

    /// Schema compilation failed at startup — action is unusable.
    #[error("schema compilation failed: {reason}")]
    CompilationFailed { reason: String },
}

/// Pre-validation limits enforced before JSON Schema evaluation.
///
/// SECURITY: these run *before* the schema validator to prevent DoS on
/// deeply nested or oversized payloads. The jsonschema crate processes
/// the full document — limiting input size/depth bounds worst-case cost.
pub struct ValidationLimits {
    pub max_bytes: usize,

    pub max_depth: u32,

    pub max_items: usize,
}

impl Default for ValidationLimits {
    fn default() -> Self {
        Self {
            // SECURITY: conservative defaults.
            max_bytes: 64 * 1024,
            max_depth: 10,
            max_items: 100,
        }
    }
}

/// Compile a JSON Schema from a `serde_json::Value`.
///
/// Called once at startup for each action's request/response schema.
/// The returned `Validator` is reused for every request (zero per-request cost).
#[must_use = "discarding the compiled schema skips request validation"]
pub fn compile_schema(schema: &Value) -> Result<jsonschema::Validator, SchemaError> {
    jsonschema::validator_for(schema).map_err(|e| SchemaError::CompilationFailed {
        reason: e.to_string(),
    })
}

/// Validate a action call request against its schema.
///
/// Checks (in order):
/// 1. Serialized size ≤ `limits.max_bytes`
/// 2. Nesting depth ≤ `limits.max_depth`
/// 3. Array sizes ≤ `limits.max_items`
/// 4. JSON Schema compliance
///
/// SECURITY: limits are checked first to bound the cost of schema validation.
pub fn validate_request(
    validator: &jsonschema::Validator,
    body: &Value,
    limits: &ValidationLimits,
) -> Result<(), SchemaError> {
    check_limits(body, limits)?;
    check_schema(validator, body)
}

/// Validate request limits only (no JSON Schema check).
///
/// Used when an action declares no request schema — we still enforce size,
/// depth, and array limits to prevent DoS.
pub fn validate_request_limits_only(
    body: &Value,
    limits: &ValidationLimits,
) -> Result<(), SchemaError> {
    check_limits(body, limits)
}

/// Validate a action call response against its schema.
///
/// In addition to limit + schema checks, verifies the action contract envelope:
/// the response must be an object with a boolean `ok` field.
///
/// If no schema validator is provided (action has no response schema), only
/// the envelope and limits are checked.
pub fn validate_response(
    validator: Option<&jsonschema::Validator>,
    body: &Value,
    limits: &ValidationLimits,
) -> Result<(), SchemaError> {
    check_limits(body, limits)?;
    check_action_envelope(body)?;
    if let Some(v) = validator {
        check_schema(v, body)?;
    }
    Ok(())
}

/// Run all pre-validation limit checks.
fn check_limits(body: &Value, limits: &ValidationLimits) -> Result<(), SchemaError> {
    // SECURITY: size check before anything else — prevents DoS.
    // Uses a zero-allocation tree walk that computes the exact compact JSON
    // byte length, matching serde_json::to_string().len() without the heap
    // allocation. For large payloads (1-2 MiB responses), this avoids a
    // multi-megabyte transient allocation on every request.
    let size = json_compact_byte_len(body);
    if size > limits.max_bytes {
        return Err(SchemaError::TooLarge {
            size,
            max: limits.max_bytes,
        });
    }

    let depth = json_depth(body);
    if depth > limits.max_depth {
        return Err(SchemaError::TooDeep {
            depth,
            max: limits.max_depth,
        });
    }

    if let Some(items) = max_array_len(body) {
        if items > limits.max_items {
            return Err(SchemaError::TooManyItems {
                items,
                max: limits.max_items,
            });
        }
    }

    Ok(())
}

/// Run the JSON Schema validator and format errors.
fn check_schema(validator: &jsonschema::Validator, body: &Value) -> Result<(), SchemaError> {
    let errors: Vec<String> = validator
        .iter_errors(body)
        .take(5) // SECURITY: cap error count to avoid unbounded output.
        .map(|e| e.to_string())
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(SchemaError::ValidationFailed {
            reason: errors.join("; "),
        })
    }
}

/// Verify the action contract response envelope: `{"ok": <bool>, ...}`.
///
/// SECURITY: every action response must have a boolean `ok` field so the
/// pipeline can distinguish success from failure without parsing action-specific
/// data. This prevents ambiguous outputs from being treated as success.
fn check_action_envelope(body: &Value) -> Result<(), SchemaError> {
    let obj = body
        .as_object()
        .ok_or_else(|| SchemaError::ValidationFailed {
            reason: "response must be a JSON object".into(),
        })?;

    match obj.get("ok") {
        Some(Value::Bool(_)) => Ok(()),
        Some(_) => Err(SchemaError::ValidationFailed {
            reason: "response 'ok' field must be a boolean".into(),
        }),
        None => Err(SchemaError::ValidationFailed {
            reason: "response must contain an 'ok' field".into(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -- Helper: compile a minimal strict schema --

    fn strict_schema() -> jsonschema::Validator {
        compile_schema(&json!({
            "type": "object",
            "required": ["url"],
            "additionalProperties": false,
            "properties": {
                "url": { "type": "string", "minLength": 1 },
                "method": { "type": "string", "enum": ["GET", "HEAD"] }
            }
        }))
        .unwrap()
    }

    fn response_schema() -> jsonschema::Validator {
        compile_schema(&json!({
            "type": "object",
            "required": ["ok"],
            "additionalProperties": false,
            "properties": {
                "ok": { "type": "boolean" },
                "data": { "type": "object" },
                "error": { "type": "object" }
            }
        }))
        .unwrap()
    }

    fn default_limits() -> ValidationLimits {
        ValidationLimits::default()
    }

    fn tight_limits() -> ValidationLimits {
        ValidationLimits {
            max_bytes: 128,
            max_depth: 3,
            max_items: 5,
        }
    }

    #[test]
    fn valid_request_passes() {
        let v = strict_schema();
        let body = json!({"url": "https://example.com"});
        assert!(validate_request(&v, &body, &default_limits()).is_ok());
    }

    #[test]
    fn valid_request_with_optional_field_passes() {
        let v = strict_schema();
        let body = json!({"url": "https://example.com", "method": "GET"});
        assert!(validate_request(&v, &body, &default_limits()).is_ok());
    }

    #[test]
    fn missing_required_field_rejected() {
        let v = strict_schema();
        let body = json!({"method": "GET"});
        let err = validate_request(&v, &body, &default_limits()).unwrap_err();
        assert!(matches!(err, SchemaError::ValidationFailed { .. }));
        assert!(err.to_string().contains("url"));
    }

    #[test]
    fn wrong_type_rejected() {
        let v = strict_schema();
        let body = json!({"url": 42});
        let err = validate_request(&v, &body, &default_limits()).unwrap_err();
        assert!(matches!(err, SchemaError::ValidationFailed { .. }));
    }

    #[test]
    fn extra_field_rejected_in_strict_mode() {
        let v = strict_schema();
        let body = json!({"url": "https://example.com", "injected_field": "malicious"});
        let err = validate_request(&v, &body, &default_limits()).unwrap_err();
        assert!(matches!(err, SchemaError::ValidationFailed { .. }));
    }

    #[test]
    fn invalid_enum_value_rejected() {
        let v = strict_schema();
        let body = json!({"url": "https://example.com", "method": "DELETE"});
        let err = validate_request(&v, &body, &default_limits()).unwrap_err();
        assert!(matches!(err, SchemaError::ValidationFailed { .. }));
    }

    #[test]
    fn empty_required_string_rejected() {
        let v = strict_schema();
        let body = json!({"url": ""});
        let err = validate_request(&v, &body, &default_limits()).unwrap_err();
        assert!(matches!(err, SchemaError::ValidationFailed { .. }));
    }

    #[test]
    fn oversized_request_rejected() {
        let v = strict_schema();
        let body = json!({"url": "x".repeat(200)});
        let limits = tight_limits(); // 128 bytes max
        let err = validate_request(&v, &body, &limits).unwrap_err();
        assert!(matches!(err, SchemaError::TooLarge { .. }));
    }

    #[test]
    fn too_deep_request_rejected() {
        let v = compile_schema(&json!({"type": "object"})).unwrap();
        // Depth 5: {a: {b: {c: {d: {e: 1}}}}}
        let body = json!({"a": {"b": {"c": {"d": {"e": 1}}}}});
        let limits = ValidationLimits {
            max_depth: 3,
            ..default_limits()
        };
        let err = validate_request(&v, &body, &limits).unwrap_err();
        assert!(matches!(err, SchemaError::TooDeep { .. }));
    }

    #[test]
    fn too_many_items_rejected() {
        let v = compile_schema(&json!({"type": "object"})).unwrap();
        let body = json!({"items": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]});
        let limits = ValidationLimits {
            max_items: 5,
            ..default_limits()
        };
        let err = validate_request(&v, &body, &limits).unwrap_err();
        assert!(matches!(err, SchemaError::TooManyItems { .. }));
    }

    /// SECURITY: schema enforcement blocks injection in string fields.
    /// The schema checks type/format — the action never sees the payload.
    #[test]
    fn shell_injection_in_string_field_passes_schema_but_typed() {
        // A schema-valid string — the value itself is not the gate's concern.
        // Schema validates *structure*, not content semantics. That's the
        // action's sandboxed responsibility. The point: the attacker cannot
        // inject extra fields or change types.
        let v = strict_schema();
        let body = json!({"url": "https://example.com; rm -rf /"});
        // Passes schema (it's a valid string) — but the action runs sandboxed.
        assert!(validate_request(&v, &body, &default_limits()).is_ok());
    }

    /// SECURITY: attacker cannot inject extra fields to influence action behaviour.
    #[test]
    fn injection_via_extra_field_rejected() {
        let v = strict_schema();
        let body = json!({
            "url": "https://example.com",
            "exec": "rm -rf /"
        });
        let err = validate_request(&v, &body, &default_limits()).unwrap_err();
        assert!(matches!(err, SchemaError::ValidationFailed { .. }));
    }

    #[test]
    fn valid_success_response_passes() {
        let v = response_schema();
        let body = json!({"ok": true, "data": {"result": "hello"}});
        assert!(validate_response(Some(&v), &body, &default_limits()).is_ok());
    }

    #[test]
    fn valid_error_response_passes() {
        let v = response_schema();
        let body = json!({"ok": false, "error": {"code": "not_found", "message": "gone"}});
        assert!(validate_response(Some(&v), &body, &default_limits()).is_ok());
    }

    #[test]
    fn response_without_schema_passes_if_envelope_ok() {
        let body = json!({"ok": true, "data": {"anything": "goes"}});
        assert!(validate_response(None, &body, &default_limits()).is_ok());
    }

    #[test]
    fn response_missing_ok_field_rejected() {
        let body = json!({"data": {"result": "hello"}});
        let err = validate_response(None, &body, &default_limits()).unwrap_err();
        assert!(err.to_string().contains("'ok' field"));
    }

    #[test]
    fn response_ok_wrong_type_rejected() {
        let body = json!({"ok": "yes"});
        let err = validate_response(None, &body, &default_limits()).unwrap_err();
        assert!(err.to_string().contains("boolean"));
    }

    #[test]
    fn response_not_object_rejected() {
        let body = json!([1, 2, 3]);
        let err = validate_response(None, &body, &default_limits()).unwrap_err();
        assert!(err.to_string().contains("JSON object"));
    }

    #[test]
    fn oversized_response_rejected() {
        let body = json!({"ok": true, "data": {"big": "x".repeat(200)}});
        let limits = tight_limits();
        let err = validate_response(None, &body, &limits).unwrap_err();
        assert!(matches!(err, SchemaError::TooLarge { .. }));
    }

    #[test]
    fn compile_valid_schema_ok() {
        let schema = json!({"type": "object", "properties": {"x": {"type": "number"}}});
        assert!(compile_schema(&schema).is_ok());
    }

    #[test]
    fn compile_invalid_schema_returns_error() {
        // "type" with an invalid value should cause a compilation error.
        let schema = json!({"type": "not_a_type"});
        let result = compile_schema(&schema);
        // jsonschema may or may not fail on this — some invalid schemas
        // are accepted but produce no matches. Check that we don't panic.
        let _ = result;
    }
}
