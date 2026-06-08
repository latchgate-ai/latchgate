//! Template resolution for parameterised HTTP actions.
//!
//! Resolves `{{variable}}` placeholders in manifest `TemplateConfig` against
//! the validated request body, producing an `http_api` provider–native
//! request (`{url, method, headers, body}`).
//!
//! # Security
//!
//! - Template resolution runs inside the kernel, before WASM dispatch.
//!   The provider never sees raw template strings.
//! - All variables must come from the schema-validated request body.
//!   Unknown variables cause a hard error (fail-closed).
//! - URL placeholders are percent-encoded to prevent path injection.
//! - The resolved URL is still subject to egress allowlist enforcement
//!   at the host I/O layer.

use std::collections::HashMap;

use latchgate_registry::TemplateConfig;
use serde_json::{json, Value};

/// Errors from template resolution.
#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    #[error("unresolved template variable '{{{{{{0}}}}}}' — not present in request body")]
    UnresolvedVariable(String),

    #[error("failed to serialise resolved body: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Resolve a `TemplateConfig` against a validated request body.
///
/// Returns the `http_api` provider's native JSON input:
/// ```json
/// {
///   "url": "https://api.github.com/repos/torvalds/linux/issues",
///   "method": "POST",
///   "headers": {"Accept": "application/vnd.github.v3+json"},
///   "body": {"title": "Hello", "body": "World"}
/// }
/// ```
///
/// # Errors
///
/// Returns `TemplateError::UnresolvedVariable` if a `{{var}}` placeholder
/// in the URL or body template references a key not present in `request_body`.
pub fn resolve_template(
    template: &TemplateConfig,
    request_body: &Value,
) -> Result<Value, TemplateError> {
    let vars = extract_variables(request_body);

    // Resolve URL template.
    // SECURITY: when the entire URL is a single `{{var}}`, the variable is
    // expected to be a complete URL — do NOT percent-encode it (encoding would
    // break the scheme and authority). The egress allowlist enforces domain
    // restrictions regardless.
    // When the URL has a fixed prefix with embedded `{{var}}` segments,
    // percent-encode each variable value to prevent path traversal.
    let url_is_single_var = is_single_variable(&template.url_template);
    let url = resolve_string_template(&template.url_template, &vars, !url_is_single_var)?;

    // Build headers map.
    let headers: HashMap<String, String> = template.headers.clone();

    // Resolve body template (if present).
    let body = match &template.body_template {
        Some(body_tmpl) => Some(resolve_value_template(body_tmpl, &vars)?),
        None => None,
    };

    // Build the http_api provider's native request format.
    let mut result = json!({
        "url": url,
        "method": template.method.to_ascii_uppercase(),
        "headers": headers,
    });

    if let Some(body_val) = body {
        result["body"] = body_val;
    }

    Ok(result)
}

/// Extract flat key=>string mappings from a JSON object.
///
/// Only top-level string and number fields are extracted. Nested objects,
/// arrays, booleans, and nulls are skipped — template variables must be
/// simple scalar values.
fn extract_variables(request_body: &Value) -> HashMap<String, String> {
    let mut vars = HashMap::new();
    if let Value::Object(map) = request_body {
        for (key, val) in map {
            match val {
                Value::String(s) => {
                    vars.insert(key.clone(), s.clone());
                }
                Value::Number(n) => {
                    vars.insert(key.clone(), n.to_string());
                }
                _ => {} // Skip non-scalar values.
            }
        }
    }
    vars
}

/// Returns `true` if the template string is a single `{{variable}}` with no
/// surrounding text (e.g. `"{{url}}"` but not `"https://{{host}}/path"`).
fn is_single_variable(template: &str) -> bool {
    let trimmed = template.trim();
    trimmed.starts_with("{{")
        && trimmed.ends_with("}}")
        && !trimmed[2..trimmed.len() - 2].contains("{{")
}

/// Resolve `{{var}}` placeholders in a string template.
///
/// If `url_encode` is true, variable values are percent-encoded (path segment
/// encoding) to prevent path traversal / injection in URLs.
fn resolve_string_template(
    template: &str,
    vars: &HashMap<String, String>,
    url_encode: bool,
) -> Result<String, TemplateError> {
    let mut result = String::with_capacity(template.len());
    let mut rest = template;

    while let Some(start) = rest.find("{{") {
        result.push_str(&rest[..start]);
        let after_open = &rest[start + 2..];

        let end = after_open
            .find("}}")
            .ok_or_else(|| TemplateError::UnresolvedVariable("unclosed {{".into()))?;

        let var_name = after_open[..end].trim();
        let value = vars
            .get(var_name)
            .ok_or_else(|| TemplateError::UnresolvedVariable(var_name.to_string()))?;

        if url_encode {
            // Percent-encode for safe URL path segment insertion.
            // SECURITY: prevents path traversal (../) and query injection (?&).
            let encoded = percent_encode_path_segment(value);
            result.push_str(&encoded);
        } else {
            result.push_str(value);
        }

        rest = &after_open[end + 2..];
    }

    result.push_str(rest);
    Ok(result)
}

/// Percent-encode a string for use in a URL path segment.
///
/// Encodes everything except unreserved characters (RFC 3986 §2.3):
/// ALPHA / DIGIT / "-" / "." / "_" / "~"
///
/// This is intentionally stricter than full URL encoding — it also encodes
/// `/` to prevent path traversal.
fn percent_encode_path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                out.push('%');
                out.push(HEX_UPPER[(byte >> 4) as usize] as char);
                out.push(HEX_UPPER[(byte & 0x0f) as usize] as char);
            }
        }
    }
    out
}

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// Resolve `{{var}}` placeholders in a JSON value tree.
///
/// Walks the JSON tree recursively:
/// - String values containing `{{var}}`: if the ENTIRE string is a single
///   `{{var}}`, it is replaced with the variable's raw value (preserving type).
///   Otherwise, `{{var}}` substrings are resolved inline (result is a string).
/// - Objects and arrays are traversed recursively.
/// - Numbers, booleans, nulls pass through unchanged.
fn resolve_value_template(
    value: &Value,
    vars: &HashMap<String, String>,
) -> Result<Value, TemplateError> {
    match value {
        Value::String(s) => {
            let trimmed = s.trim();
            // Check if the entire string is a single `{{var}}`.
            if trimmed.starts_with("{{")
                && trimmed.ends_with("}}")
                && !trimmed[2..trimmed.len() - 2].contains("{{")
            {
                let var_name = trimmed[2..trimmed.len() - 2].trim();
                let raw = vars
                    .get(var_name)
                    .ok_or_else(|| TemplateError::UnresolvedVariable(var_name.to_string()))?;
                // Try to parse as JSON (preserves type for structured values
                // passed as JSON strings). Fall back to string.
                Ok(serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.clone())))
            } else if s.contains("{{") {
                // Mixed template — resolve inline, result is always a string.
                let resolved = resolve_string_template(s, vars, false)?;
                Ok(Value::String(resolved))
            } else {
                Ok(value.clone())
            }
        }
        Value::Object(map) => {
            let mut resolved = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                resolved.insert(k.clone(), resolve_value_template(v, vars)?);
            }
            Ok(Value::Object(resolved))
        }
        Value::Array(arr) => {
            let resolved: Result<Vec<Value>, _> = arr
                .iter()
                .map(|v| resolve_value_template(v, vars))
                .collect();
            Ok(Value::Array(resolved?))
        }
        _ => Ok(value.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as StdHashMap;

    fn github_issue_template() -> TemplateConfig {
        TemplateConfig {
            method: "POST".into(),
            url_template: "https://api.github.com/repos/{{owner}}/{{repo}}/issues".into(),
            headers: {
                let mut h = StdHashMap::new();
                h.insert("Accept".into(), "application/vnd.github.v3+json".into());
                h
            },
            body_template: Some(json!({
                "title": "{{title}}",
                "body": "{{body}}"
            })),
        }
    }

    fn github_read_template() -> TemplateConfig {
        TemplateConfig {
            method: "GET".into(),
            url_template: "https://api.github.com/{{path}}".into(),
            headers: {
                let mut h = StdHashMap::new();
                h.insert("Accept".into(), "application/vnd.github.v3+json".into());
                h
            },
            body_template: None,
        }
    }

    // -- resolve_template happy path --

    #[test]
    fn resolve_github_create_issue() {
        let tmpl = github_issue_template();
        let body = json!({
            "owner": "torvalds",
            "repo": "linux",
            "title": "Bug report",
            "body": "Something is broken"
        });

        let resolved = resolve_template(&tmpl, &body).unwrap();

        assert_eq!(
            resolved["url"],
            "https://api.github.com/repos/torvalds/linux/issues"
        );
        assert_eq!(resolved["method"], "POST");
        assert_eq!(
            resolved["headers"]["Accept"],
            "application/vnd.github.v3+json"
        );
        assert_eq!(resolved["body"]["title"], "Bug report");
        assert_eq!(resolved["body"]["body"], "Something is broken");
    }

    #[test]
    fn resolve_github_read() {
        let tmpl = github_read_template();
        let body = json!({"path": "rate_limit"});

        let resolved = resolve_template(&tmpl, &body).unwrap();

        assert_eq!(resolved["url"], "https://api.github.com/rate_limit");
        assert_eq!(resolved["method"], "GET");
        assert!(resolved.get("body").is_none());
    }

    #[test]
    fn resolve_no_body_template() {
        let tmpl = github_read_template();
        let body = json!({"path": "rate_limit"});

        let resolved = resolve_template(&tmpl, &body).unwrap();
        assert!(resolved.get("body").is_none());
    }

    // -- URL encoding --

    #[test]
    fn url_template_encodes_slashes() {
        let tmpl = github_read_template();
        let body = json!({"path": "repos/owner/repo"});

        let resolved = resolve_template(&tmpl, &body).unwrap();
        // Slashes in the variable value are percent-encoded.
        assert_eq!(
            resolved["url"],
            "https://api.github.com/repos%2Fowner%2Frepo"
        );
    }

    #[test]
    fn url_template_encodes_special_chars() {
        let tmpl = github_read_template();
        let body = json!({"path": "search?q=test&sort=stars"});

        let resolved = resolve_template(&tmpl, &body).unwrap();
        let url = resolved["url"].as_str().unwrap();
        assert!(!url.contains('?'), "query char must be encoded");
        assert!(!url.contains('&'), "ampersand must be encoded");
    }

    #[test]
    fn url_template_path_traversal_blocked() {
        let tmpl = github_read_template();
        let body = json!({"path": "../../etc/passwd"});

        let resolved = resolve_template(&tmpl, &body).unwrap();
        let url = resolved["url"].as_str().unwrap();
        assert!(!url.contains("../"), "path traversal must be encoded");
    }

    // -- Error cases --

    #[test]
    fn unresolved_url_variable_fails() {
        let tmpl = github_issue_template();
        let body = json!({"owner": "torvalds"}); // missing repo, title, body

        let err = resolve_template(&tmpl, &body).unwrap_err();
        assert!(matches!(err, TemplateError::UnresolvedVariable(ref v) if v == "repo"));
    }

    #[test]
    fn unresolved_body_variable_fails() {
        let tmpl = github_issue_template();
        let body = json!({
            "owner": "torvalds",
            "repo": "linux",
            // missing title and body
        });

        let err = resolve_template(&tmpl, &body).unwrap_err();
        assert!(matches!(err, TemplateError::UnresolvedVariable(_)));
    }

    // -- Body template resolution --

    #[test]
    fn body_template_preserves_json_structure() {
        let tmpl = TemplateConfig {
            method: "POST".into(),
            url_template: "https://example.com".into(),
            headers: StdHashMap::new(),
            body_template: Some(json!({
                "data": {
                    "name": "{{name}}",
                    "count": "{{count}}"
                }
            })),
        };
        let body = json!({"name": "test", "count": "42"});

        let resolved = resolve_template(&tmpl, &body).unwrap();
        // "42" passed as string => parsed as number in body
        assert_eq!(resolved["body"]["data"]["count"], 42);
        assert_eq!(resolved["body"]["data"]["name"], "test");
    }

    #[test]
    fn body_template_string_passthrough() {
        let tmpl = TemplateConfig {
            method: "POST".into(),
            url_template: "https://example.com".into(),
            headers: StdHashMap::new(),
            body_template: Some(json!("{{payload}}")),
        };
        let body = json!({"payload": "{\"key\":\"value\"}"});

        let resolved = resolve_template(&tmpl, &body).unwrap();
        // JSON string in payload => parsed as object
        assert_eq!(resolved["body"]["key"], "value");
    }

    // -- Variable extraction --

    #[test]
    fn extract_only_scalars() {
        let body = json!({
            "name": "test",
            "count": 42,
            "nested": {"a": 1},
            "list": [1, 2],
            "flag": true,
            "nothing": null
        });

        let vars = extract_variables(&body);
        assert_eq!(vars.len(), 2);
        assert_eq!(vars["name"], "test");
        assert_eq!(vars["count"], "42");
    }

    // -- Percent encoding --

    #[test]
    fn percent_encode_preserves_unreserved() {
        assert_eq!(
            percent_encode_path_segment("hello-world_v2.0~test"),
            "hello-world_v2.0~test"
        );
    }

    #[test]
    fn percent_encode_encodes_reserved() {
        assert_eq!(percent_encode_path_segment("/"), "%2F");
        assert_eq!(percent_encode_path_segment("?"), "%3F");
        assert_eq!(percent_encode_path_segment("&"), "%26");
        assert_eq!(percent_encode_path_segment(" "), "%20");
        assert_eq!(percent_encode_path_segment("#"), "%23");
    }

    // -- Webhook (full URL from variable) --

    #[test]
    fn webhook_full_url_variable() {
        let tmpl = TemplateConfig {
            method: "POST".into(),
            url_template: "{{url}}".into(),
            headers: StdHashMap::new(),
            body_template: Some(json!({"event": "{{event}}"})),
        };
        let body = json!({
            "url": "https://hooks.slack.com/services/T00/B00/xxx",
            "event": "deploy.completed"
        });

        let resolved = resolve_template(&tmpl, &body).unwrap();
        // Single-variable URL template: NOT encoded (it's a full URL).
        assert_eq!(
            resolved["url"],
            "https://hooks.slack.com/services/T00/B00/xxx"
        );
        assert_eq!(resolved["body"]["event"], "deploy.completed");
    }
}
