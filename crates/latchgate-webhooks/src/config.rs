//! Webhook endpoint configuration, validation, and environment variable expansion.
//!
//! Each `[[webhooks]]` entry in `latchgate.toml` maps to a [`WebhookEndpointConfig`].
//! Validation is performed eagerly at startup — invalid config prevents boot.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::EventKind;

fn default_timeout_seconds() -> u64 {
    5
}

fn default_max_retries() -> u32 {
    3
}

fn default_retry_backoff_seconds() -> Vec<u64> {
    vec![1, 5, 30]
}

/// Payload format for a webhook endpoint.
///
/// `Generic` sends the standard LatchGate JSON envelope. Platform-specific
/// formats (e.g. `Slack`) transform the envelope into the platform's native
/// message structure before signing and delivery.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WebhookFormat {
    /// Standard JSON envelope: `{ id, type, timestamp, gate_version, data }`.
    #[default]
    Generic,
    /// Slack Block Kit: `{ text, blocks }` — compatible with Incoming Webhooks
    /// and `chat.postMessage`.
    Slack,
    /// Discord embed: `{ content, embeds }` — compatible with channel webhooks.
    Discord,
    /// PagerDuty Events API v2: `{ routing_key, event_action, payload }`.
    /// Requires `X-Routing-Key` header set to the PagerDuty integration key.
    #[serde(rename = "pagerduty")]
    PagerDuty,
}

impl WebhookFormat {
    /// All supported format values, for CLI/TUI validation and help text.
    pub const ALL: &[WebhookFormat] = &[Self::Generic, Self::Slack, Self::Discord, Self::PagerDuty];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::Slack => "slack",
            Self::Discord => "discord",
            Self::PagerDuty => "pagerduty",
        }
    }
}

impl std::fmt::Display for WebhookFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Configuration for a single webhook endpoint, deserialized from TOML.
///
/// Secrets and header values containing `${ENV_VAR}` are expanded from
/// environment variables at startup via `resolve_env_vars`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebhookEndpointConfig {
    /// Human-readable identifier, used in logs and dead-letter audit.
    pub name: String,

    /// HTTPS endpoint URL. HTTP is rejected unless dev mode is active.
    pub url: String,

    /// HMAC-SHA256 signing secret. Convention: prefix `whsec_`.
    pub secret: String,

    /// Event types this endpoint subscribes to.
    pub events: Vec<EventKind>,

    /// Extra HTTP headers (e.g., auth tokens). Supports `${ENV_VAR}` expansion.
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// Per-request HTTP timeout in seconds.
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,

    /// Retry attempts on 5xx / network failure. 0 = fire once.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Backoff delays per retry attempt (seconds). Truncated or extended
    /// to match `max_retries`.
    #[serde(default = "default_retry_backoff_seconds")]
    pub retry_backoff_seconds: Vec<u64>,

    /// Temporarily disable without removing config.
    #[serde(default)]
    pub disable: bool,

    /// Payload format. Default `generic` sends the standard envelope;
    /// `slack` transforms it into Block Kit for Incoming Webhooks.
    #[serde(default)]
    pub format: WebhookFormat,
}

/// Validate a list of webhook endpoint configs at startup.
///
/// Checks:
/// - No duplicate endpoint names.
/// - Each endpoint has a non-empty name, URL, secret, and events list.
/// - URL is valid HTTPS (or HTTP in dev mode).
/// - Secret is non-empty (after env expansion).
/// - Events list contains no unknown types (enforced by serde deserialization).
///
/// Returns the validated configs with environment variables expanded.
pub fn validate_webhook_configs(
    configs: Vec<WebhookEndpointConfig>,
    dev_mode: bool,
) -> Result<Vec<WebhookEndpointConfig>, WebhookConfigError> {
    let mut seen_names = HashSet::new();
    let mut validated = Vec::with_capacity(configs.len());

    for mut cfg in configs {
        // -- name --
        if cfg.name.is_empty() {
            return Err(WebhookConfigError::MissingField {
                endpoint: "(unnamed)".into(),
                field: "name",
            });
        }

        if !seen_names.insert(cfg.name.clone()) {
            return Err(WebhookConfigError::DuplicateName {
                name: cfg.name.clone(),
            });
        }

        // -- expand env vars --
        cfg.secret =
            expand_env_vars(&cfg.secret).map_err(|var| WebhookConfigError::EnvVarMissing {
                endpoint: cfg.name.clone(),
                field: "secret".into(),
                var,
            })?;
        cfg.url = expand_env_vars(&cfg.url).map_err(|var| WebhookConfigError::EnvVarMissing {
            endpoint: cfg.name.clone(),
            field: "url".into(),
            var,
        })?;
        let mut expanded_headers = HashMap::new();
        for (k, v) in &cfg.headers {
            let expanded = expand_env_vars(v).map_err(|var| WebhookConfigError::EnvVarMissing {
                endpoint: cfg.name.clone(),
                field: format!("headers.{k}"),
                var,
            })?;
            expanded_headers.insert(k.clone(), expanded);
        }
        cfg.headers = expanded_headers;

        // -- secret --
        if cfg.secret.is_empty() {
            return Err(WebhookConfigError::MissingField {
                endpoint: cfg.name.clone(),
                field: "secret",
            });
        }

        // -- events --
        if cfg.events.is_empty() {
            return Err(WebhookConfigError::MissingField {
                endpoint: cfg.name.clone(),
                field: "events",
            });
        }

        // -- URL: valid and HTTPS --
        validate_url(&cfg.url, &cfg.name, dev_mode)?;

        // -- backoff: pad or truncate to match max_retries --
        if cfg.max_retries > 0 {
            let retries = cfg.max_retries as usize;
            cfg.retry_backoff_seconds
                .resize(retries, *cfg.retry_backoff_seconds.last().unwrap_or(&30));
        }

        validated.push(cfg);
    }

    Ok(validated)
}

/// Validate that a webhook URL is well-formed and uses HTTPS.
///
/// SECURITY: HTTP endpoints leak signing secrets and payload data in transit.
/// Only `localhost` / `127.0.0.1` HTTP is allowed in dev mode for local testing.
fn validate_url(raw: &str, endpoint_name: &str, dev_mode: bool) -> Result<(), WebhookConfigError> {
    let parsed = Url::parse(raw).map_err(|e| WebhookConfigError::InvalidUrl {
        endpoint: endpoint_name.into(),
        reason: format!("malformed URL: {e}"),
    })?;

    match parsed.scheme() {
        "https" => Ok(()),
        "http" if dev_mode => {
            let host = parsed.host_str().unwrap_or("");
            if host == "localhost" || host == "127.0.0.1" || host == "[::1]" {
                Ok(())
            } else {
                Err(WebhookConfigError::InvalidUrl {
                    endpoint: endpoint_name.into(),
                    reason: "HTTP is only allowed for localhost in dev mode".into(),
                })
            }
        }
        "http" => Err(WebhookConfigError::InvalidUrl {
            endpoint: endpoint_name.into(),
            reason: "HTTPS required — HTTP endpoints leak secrets in transit".into(),
        }),
        scheme => Err(WebhookConfigError::InvalidUrl {
            endpoint: endpoint_name.into(),
            reason: format!("unsupported scheme '{scheme}' — only HTTPS is allowed"),
        }),
    }
}

/// Expand `${VAR_NAME}` patterns in a string from environment variables.
///
/// Returns `Err(var_name)` if a referenced variable is not set.
/// Literal `$` without braces is left as-is. Nested expansion is not supported.
pub fn expand_env_vars(input: &str) -> Result<String, String> {
    expand_env_vars_with(input, |name| {
        std::env::var(name).map_err(|_| name.to_string())
    })
}

/// Expand `${VAR_NAME}` patterns using a caller-supplied resolver.
///
/// The resolver returns `Ok(value)` on success or `Err(var_name)` when the
/// variable is not found. Extracted from [`expand_env_vars`] so tests can
/// verify expansion logic without mutating global process state.
pub(crate) fn expand_env_vars_with(
    input: &str,
    resolve: impl Fn(&str) -> Result<String, String>,
) -> Result<String, String> {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let mut var_name = String::new();
            loop {
                match chars.next() {
                    Some('}') => break,
                    Some(ch) => var_name.push(ch),
                    None => {
                        // Unclosed `${` — treat as literal.
                        result.push_str("${");
                        result.push_str(&var_name);
                        return Ok(result);
                    }
                }
            }
            let value = resolve(&var_name)?;
            result.push_str(&value);
        } else {
            result.push(c);
        }
    }

    Ok(result)
}

#[derive(Debug, thiserror::Error)]
pub enum WebhookConfigError {
    #[error("webhook '{endpoint}': missing required field '{field}'")]
    MissingField {
        endpoint: String,
        field: &'static str,
    },

    #[error("duplicate webhook endpoint name: '{name}'")]
    DuplicateName { name: String },

    #[error("webhook '{endpoint}': invalid URL — {reason}")]
    InvalidUrl { endpoint: String, reason: String },

    #[error("webhook '{endpoint}': env var ${{{var}}} not set in field '{field}'")]
    EnvVarMissing {
        endpoint: String,
        field: String,
        var: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_config(name: &str, url: &str) -> WebhookEndpointConfig {
        WebhookEndpointConfig {
            name: name.into(),
            url: url.into(),
            secret: "whsec_test-secret-value".into(),
            events: vec![EventKind::ApprovalPending],
            headers: HashMap::new(),
            timeout_seconds: 5,
            max_retries: 3,
            retry_backoff_seconds: vec![1, 5, 30],
            disable: false,
            format: WebhookFormat::Generic,
        }
    }

    // -- happy path --

    #[test]
    fn valid_https_config_passes() {
        let configs = vec![minimal_config(
            "slack",
            "https://hooks.slack.com/services/T/B/x",
        )];
        let result = validate_webhook_configs(configs, false);
        assert!(result.is_ok());
    }

    #[test]
    fn multiple_valid_endpoints_pass() {
        let configs = vec![
            minimal_config("slack", "https://hooks.slack.com/x"),
            minimal_config("siem", "https://siem.corp.internal/v1/events"),
        ];
        let result = validate_webhook_configs(configs, false);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    // -- name validation --

    #[test]
    fn empty_name_is_rejected() {
        let configs = vec![minimal_config("", "https://example.com/hook")];
        let err = validate_webhook_configs(configs, false).unwrap_err();
        assert!(matches!(
            err,
            WebhookConfigError::MissingField { field: "name", .. }
        ));
    }

    #[test]
    fn duplicate_names_are_rejected() {
        let configs = vec![
            minimal_config("slack", "https://example.com/a"),
            minimal_config("slack", "https://example.com/b"),
        ];
        let err = validate_webhook_configs(configs, false).unwrap_err();
        assert!(matches!(err, WebhookConfigError::DuplicateName { .. }));
    }

    // -- secret validation --

    #[test]
    fn empty_secret_is_rejected() {
        let mut cfg = minimal_config("test", "https://example.com/hook");
        cfg.secret = String::new();
        let err = validate_webhook_configs(vec![cfg], false).unwrap_err();
        assert!(matches!(
            err,
            WebhookConfigError::MissingField {
                field: "secret",
                ..
            }
        ));
    }

    // -- events validation --

    #[test]
    fn empty_events_is_rejected() {
        let mut cfg = minimal_config("test", "https://example.com/hook");
        cfg.events = vec![];
        let err = validate_webhook_configs(vec![cfg], false).unwrap_err();
        assert!(matches!(
            err,
            WebhookConfigError::MissingField {
                field: "events",
                ..
            }
        ));
    }

    // -- URL validation --

    #[test]
    fn http_is_rejected_in_production() {
        let configs = vec![minimal_config("test", "http://example.com/hook")];
        let err = validate_webhook_configs(configs, false).unwrap_err();
        assert!(matches!(err, WebhookConfigError::InvalidUrl { .. }));
    }

    #[test]
    fn http_localhost_allowed_in_dev_mode() {
        let configs = vec![minimal_config("test", "http://localhost:9000/hook")];
        assert!(validate_webhook_configs(configs, true).is_ok());
    }

    #[test]
    fn http_127_allowed_in_dev_mode() {
        let configs = vec![minimal_config("test", "http://127.0.0.1:9000/hook")];
        assert!(validate_webhook_configs(configs, true).is_ok());
    }

    #[test]
    fn http_remote_rejected_even_in_dev_mode() {
        let configs = vec![minimal_config("test", "http://example.com/hook")];
        let err = validate_webhook_configs(configs, true).unwrap_err();
        assert!(matches!(err, WebhookConfigError::InvalidUrl { .. }));
    }

    #[test]
    fn ftp_scheme_is_rejected() {
        let configs = vec![minimal_config("test", "ftp://example.com/hook")];
        let err = validate_webhook_configs(configs, false).unwrap_err();
        assert!(matches!(err, WebhookConfigError::InvalidUrl { .. }));
    }

    #[test]
    fn malformed_url_is_rejected() {
        let configs = vec![minimal_config("test", "not a url")];
        let err = validate_webhook_configs(configs, false).unwrap_err();
        assert!(matches!(err, WebhookConfigError::InvalidUrl { .. }));
    }

    // -- env var expansion --

    #[test]
    fn expand_env_vars_substitutes_set_vars() {
        let resolve = |name: &str| match name {
            "LG_TEST_TOKEN" => Ok("secret123".to_string()),
            other => Err(other.to_string()),
        };
        assert_eq!(
            expand_env_vars_with("Bearer ${LG_TEST_TOKEN}", resolve).unwrap(),
            "Bearer secret123"
        );
    }

    #[test]
    fn expand_env_vars_returns_error_for_unset_var() {
        let resolve = |name: &str| -> Result<String, String> { Err(name.to_string()) };
        let err = expand_env_vars_with("${LG_NONEXISTENT_VAR}", resolve).unwrap_err();
        assert_eq!(err, "LG_NONEXISTENT_VAR");
    }

    #[test]
    fn expand_env_vars_leaves_literal_dollar_alone() {
        assert_eq!(expand_env_vars("$100").unwrap(), "$100");
    }

    #[test]
    fn expand_env_vars_handles_no_vars() {
        assert_eq!(expand_env_vars("plain text").unwrap(), "plain text");
    }

    // -- backoff padding --

    #[test]
    fn backoff_is_padded_to_match_max_retries() {
        let mut cfg = minimal_config("test", "https://example.com/hook");
        cfg.max_retries = 5;
        cfg.retry_backoff_seconds = vec![1, 5];
        let validated = validate_webhook_configs(vec![cfg], false).unwrap();
        assert_eq!(validated[0].retry_backoff_seconds, vec![1, 5, 5, 5, 5]);
    }

    #[test]
    fn backoff_is_truncated_to_match_max_retries() {
        let mut cfg = minimal_config("test", "https://example.com/hook");
        cfg.max_retries = 1;
        cfg.retry_backoff_seconds = vec![1, 5, 30];
        let validated = validate_webhook_configs(vec![cfg], false).unwrap();
        assert_eq!(validated[0].retry_backoff_seconds, vec![1]);
    }

    // -- disabled endpoints pass validation --

    #[test]
    fn disabled_endpoint_still_validated() {
        let mut cfg = minimal_config("test", "not a url");
        cfg.disable = true;
        // Even disabled endpoints are validated — typos surface at startup, not
        // when someone re-enables the endpoint in production.
        let err = validate_webhook_configs(vec![cfg], false).unwrap_err();
        assert!(matches!(err, WebhookConfigError::InvalidUrl { .. }));
    }
}
