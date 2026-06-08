//! Pure state-transition logic for the Setup Hub screen.
//!
//! Extracted from `config.rs` to enable unit testing without a terminal.
//! This module owns form wizard progressions, data accessors, and list
//! navigation — everything that can be tested as (state, input) => output
//! without ratatui rendering.

use latchgate_config::Config;

// Sub-tab navigation

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubTab {
    Overview,
    Principals,
    Operators,
    Webhooks,
    Secrets,
    Presets,
}

impl SubTab {
    pub const ALL: &[SubTab] = &[
        SubTab::Overview,
        SubTab::Operators,
        SubTab::Principals,
        SubTab::Webhooks,
        SubTab::Secrets,
        SubTab::Presets,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Principals => "Principals",
            Self::Operators => "Operators",
            Self::Webhooks => "Webhooks",
            Self::Secrets => "Secrets",
            Self::Presets => "Presets",
        }
    }

    pub fn index(self) -> usize {
        Self::ALL.iter().position(|&t| t == self).unwrap_or(0)
    }

    /// Move to the previous sub-tab (clamped).
    pub fn prev(self) -> Self {
        let idx = self.index();
        if idx > 0 {
            Self::ALL[idx - 1]
        } else {
            self
        }
    }

    /// Move to the next sub-tab (clamped).
    pub fn next(self) -> Self {
        let idx = self.index();
        if idx + 1 < Self::ALL.len() {
            Self::ALL[idx + 1]
        } else {
            self
        }
    }

    /// Jump to the sub-tab for digit key '1'–'6'. Returns `None` if out of range.
    pub fn from_digit(c: char) -> Option<Self> {
        let idx = (c as usize).checked_sub('1' as usize)?;
        Self::ALL.get(idx).copied()
    }
}

// Form wizard state machines

/// Outcome of advancing a multi-step form by one submitted value.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FormResult {
    /// Show the next input prompt with the given label.
    NextPrompt(&'static str),
    /// Wizard complete — caller should execute the action.
    Complete,
    /// Submitted value was invalid.
    Invalid(String),
    /// Empty input — wizard cancelled.
    Cancelled,
}

// -- Principal form --

/// Accumulated state for the add-principal wizard.
#[derive(Debug, Clone)]
pub(crate) enum PrincipalForm {
    Uid,
    Name { uid: u32 },
    Scopes { uid: u32, name: String },
}

/// Final output of a completed principal wizard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PrincipalParams {
    pub uid: u32,
    pub name: String,
    pub scopes: String,
}

impl PrincipalForm {
    pub fn prompt(&self) -> &'static str {
        match self {
            Self::Uid => " UID (e.g. 1000) ",
            Self::Name { .. } => " Principal name (Enter/Esc) ",
            Self::Scopes { .. } => " Scopes (comma-separated, e.g. tools:call) ",
        }
    }

    /// Advance the wizard with a submitted value. On `Complete`, the caller
    /// retrieves the params from `into_params()`.
    pub fn advance(&mut self, raw: &str) -> FormResult {
        let val = raw.trim();
        if val.is_empty() {
            return FormResult::Cancelled;
        }
        match self {
            Self::Uid => match val.parse::<u32>() {
                Ok(uid) => {
                    *self = Self::Name { uid };
                    FormResult::NextPrompt(self.prompt())
                }
                Err(_) => FormResult::Invalid("Invalid UID".into()),
            },
            Self::Name { uid } => {
                let uid = *uid;
                *self = Self::Scopes {
                    uid,
                    name: val.to_string(),
                };
                FormResult::NextPrompt(self.prompt())
            }
            Self::Scopes { .. } => {
                // scopes is stored via take_params — just signal completion.
                // Caller reads the final val directly.
                FormResult::Complete
            }
        }
    }

    /// Extract final parameters. Returns `Some` only when the wizard has
    /// reached the terminal `Scopes` state (i.e. `advance` returned `Complete`).
    pub fn into_params(self, final_scopes: &str) -> Option<PrincipalParams> {
        match self {
            Self::Scopes { uid, name } => Some(PrincipalParams {
                uid,
                name,
                scopes: final_scopes.trim().to_string(),
            }),
            _ => None,
        }
    }
}

// -- Webhook form --

/// Accumulated state for the add-webhook wizard.
#[derive(Debug, Clone)]
pub(crate) enum WebhookForm {
    Name,
    Url {
        name: String,
    },
    Events {
        name: String,
        url: String,
    },
    Format {
        name: String,
        url: String,
        events: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WebhookParams {
    pub name: String,
    pub url: String,
    pub events: String,
    pub format: String,
}

impl WebhookForm {
    pub fn prompt(&self) -> &'static str {
        match self {
            Self::Name => " Webhook name (Enter/Esc) ",
            Self::Url { .. } => " URL (https://...) ",
            Self::Events { .. } => " Events (e.g. action.*,approval.*) ",
            Self::Format { .. } => {
                " Format: generic | slack | discord | pagerduty (Enter for generic) "
            }
        }
    }

    pub fn advance(&mut self, raw: &str) -> FormResult {
        let val = raw.trim();
        // Format step: empty means "use default generic", not cancel.
        if val.is_empty() {
            if matches!(self, Self::Format { .. }) {
                return FormResult::Complete;
            }
            return FormResult::Cancelled;
        }
        match self {
            Self::Name => {
                *self = Self::Url {
                    name: val.to_string(),
                };
                FormResult::NextPrompt(self.prompt())
            }
            Self::Url { name } => {
                let name = name.clone();
                *self = Self::Events {
                    name,
                    url: val.to_string(),
                };
                FormResult::NextPrompt(self.prompt())
            }
            Self::Events { name, url } => {
                let name = name.clone();
                let url = url.clone();
                *self = Self::Format {
                    name,
                    url,
                    events: val.to_string(),
                };
                FormResult::NextPrompt(self.prompt())
            }
            Self::Format { .. } => match val {
                "generic" | "slack" | "discord" | "pagerduty" => FormResult::Complete,
                _ => {
                    FormResult::Invalid("valid formats: generic, slack, discord, pagerduty".into())
                }
            },
        }
    }

    /// Extract final parameters. Returns `Some` only when the wizard has
    /// reached the terminal `Format` state (i.e. `advance` returned `Complete`).
    pub fn into_params(self, final_format: &str) -> Option<WebhookParams> {
        match self {
            Self::Format { name, url, events } => {
                let format = final_format.trim();
                Some(WebhookParams {
                    name,
                    url,
                    events,
                    format: if format.is_empty() { "generic" } else { format }.to_string(),
                })
            }
            _ => None,
        }
    }
}

// -- Two-step key/value form (config set, secrets set) --

#[derive(Debug, Clone)]
pub(crate) enum KeyValueForm {
    Key {
        key_prompt: &'static str,
    },
    Value {
        key: String,
        value_prompt: &'static str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyValueParams {
    pub key: String,
    pub value: String,
}

impl KeyValueForm {
    pub fn config_set() -> Self {
        Self::Key {
            key_prompt: " Config key (e.g. storage.redis_url) ",
        }
    }

    pub fn secrets_set() -> Self {
        Self::Key {
            key_prompt: " Secret name (UPPER_SNAKE_CASE) ",
        }
    }

    pub fn prompt(&self) -> &'static str {
        match self {
            Self::Key { key_prompt } => key_prompt,
            Self::Value { value_prompt, .. } => value_prompt,
        }
    }

    pub fn advance(&mut self, raw: &str) -> FormResult {
        let val = raw.trim();
        if val.is_empty() {
            return FormResult::Cancelled;
        }
        match self {
            Self::Key { .. } => {
                *self = Self::Value {
                    key: val.to_string(),
                    value_prompt: " Value (Enter/Esc) ",
                };
                FormResult::NextPrompt(self.prompt())
            }
            Self::Value { .. } => FormResult::Complete,
        }
    }

    /// Extract final parameters. Returns `Some` only when the wizard has
    /// reached the terminal `Value` state (i.e. `advance` returned `Complete`).
    pub fn into_params(self, final_value: &str) -> Option<KeyValueParams> {
        match self {
            Self::Value { key, .. } => Some(KeyValueParams {
                key,
                value: final_value.trim().to_string(),
            }),
            _ => None,
        }
    }
}

// Data accessors — pure functions on Config

/// Sorted (uid_string, principal_name, comma_separated_scopes) triples.
pub(crate) fn principals_sorted(config: &Config) -> Vec<(String, String, String)> {
    let pc = &config.identity.peercred;
    let mut items: Vec<_> = pc
        .principals
        .iter()
        .map(|(uid, p)| (uid.clone(), p.principal.clone(), p.scopes.join(", ")))
        .collect();
    items.sort_by(|a, b| a.0.cmp(&b.0));
    items
}

/// Sorted (operator_name, has_dpop) pairs.
pub(crate) fn operators_sorted(config: &Config) -> Vec<(String, bool)> {
    let mut items: Vec<_> = config
        .operator_credentials
        .iter()
        .map(|(name, cred)| (name.clone(), cred.dpop_jkt.is_some()))
        .collect();
    items.sort_by(|a, b| a.0.cmp(&b.0));
    items
}

/// List of (name, url, format) triples from the raw webhook TOML values.
pub(crate) fn webhooks_list(config: &Config) -> Vec<(String, String, String)> {
    config
        .webhooks
        .iter()
        .filter_map(|v| {
            let name = v.get("name")?.as_str()?.to_string();
            let url = v.get("url")?.as_str()?.to_string();
            let format = v
                .get("format")
                .and_then(|f| f.as_str())
                .unwrap_or("generic")
                .to_string();
            Some((name, url, format))
        })
        .collect()
}

/// Extract allowed actions for a principal from an OPA policy ACL.
///
/// The ACL is a JSON object keyed by principal name. Each entry has an
/// `allowed_actions` array. Returns an empty vec for unknown principals
/// or malformed data — never panics on unexpected shapes.
pub(crate) fn policy_actions_for(acl: &serde_json::Value, principal: &str) -> Vec<String> {
    acl[principal]["allowed_actions"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

// List navigation

/// Move cursor up (saturating).
pub(crate) fn cursor_up(selected: &mut usize) {
    *selected = selected.saturating_sub(1);
}

/// Move cursor down (clamped to list length).
pub(crate) fn cursor_down(selected: &mut usize, list_len: usize) {
    let max = list_len.saturating_sub(1);
    if *selected < max {
        *selected += 1;
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    // -- SubTab navigation --

    #[test]
    fn subtab_prev_clamps_at_first() {
        assert_eq!(SubTab::Overview.prev(), SubTab::Overview);
    }

    #[test]
    fn subtab_next_advances() {
        assert_eq!(SubTab::Overview.next(), SubTab::Operators);
        assert_eq!(SubTab::Operators.next(), SubTab::Principals);
    }

    #[test]
    fn subtab_next_clamps_at_last() {
        assert_eq!(SubTab::Presets.next(), SubTab::Presets);
    }

    #[test]
    fn subtab_from_digit_valid() {
        assert_eq!(SubTab::from_digit('1'), Some(SubTab::Overview));
        assert_eq!(SubTab::from_digit('5'), Some(SubTab::Secrets));
        assert_eq!(SubTab::from_digit('6'), Some(SubTab::Presets));
    }

    #[test]
    fn subtab_from_digit_out_of_range() {
        assert_eq!(SubTab::from_digit('0'), None);
        assert_eq!(SubTab::from_digit('7'), None);
    }

    #[test]
    fn subtab_roundtrip_index() {
        for &tab in SubTab::ALL {
            assert_eq!(SubTab::ALL[tab.index()], tab);
        }
    }

    // -- Principal form --

    #[test]
    fn principal_form_happy_path() {
        let mut form = PrincipalForm::Uid;
        assert_eq!(form.advance("1000"), FormResult::NextPrompt(form.prompt()));

        matches!(form, PrincipalForm::Name { uid: 1000 });
        assert_eq!(form.advance("alice"), FormResult::NextPrompt(form.prompt()));

        assert_eq!(form.advance("tools:call"), FormResult::Complete);

        let params = form.into_params("tools:call").unwrap();
        assert_eq!(
            params,
            PrincipalParams {
                uid: 1000,
                name: "alice".into(),
                scopes: "tools:call".into(),
            }
        );
    }

    #[test]
    fn principal_form_invalid_uid() {
        let mut form = PrincipalForm::Uid;
        assert!(matches!(form.advance("notanumber"), FormResult::Invalid(_)));
        // Form stays in Uid — caller should cancel.
        assert!(matches!(form, PrincipalForm::Uid));
    }

    #[test]
    fn principal_form_empty_cancels() {
        let mut form = PrincipalForm::Uid;
        assert_eq!(form.advance(""), FormResult::Cancelled);
        assert_eq!(form.advance("  "), FormResult::Cancelled);
    }

    #[test]
    fn principal_form_trims_whitespace() {
        let mut form = PrincipalForm::Uid;
        form.advance("  1000  ");
        form.advance("  alice  ");
        form.advance("  tools:call  ");
        let params = form.into_params("  tools:call  ").unwrap();
        assert_eq!(params.name, "alice");
        assert_eq!(params.scopes, "tools:call");
    }

    // -- Webhook form --

    #[test]
    fn webhook_form_happy_path() {
        let mut form = WebhookForm::Name;
        assert_eq!(form.advance("slack"), FormResult::NextPrompt(form.prompt()));
        assert_eq!(
            form.advance("https://hooks.slack.com/x"),
            FormResult::NextPrompt(form.prompt())
        );
        assert_eq!(
            form.advance("action.*"),
            FormResult::NextPrompt(form.prompt())
        );
        assert_eq!(form.advance("slack"), FormResult::Complete);

        let params = form.into_params("slack").unwrap();
        assert_eq!(
            params,
            WebhookParams {
                name: "slack".into(),
                url: "https://hooks.slack.com/x".into(),
                events: "action.*".into(),
                format: "slack".into(),
            }
        );
    }

    #[test]
    fn webhook_form_format_defaults_to_generic_on_empty() {
        let mut form = WebhookForm::Name;
        form.advance("name");
        form.advance("https://url");
        form.advance("events");
        // Empty on Format step → Complete (not Cancelled), defaults to generic.
        assert_eq!(form.advance(""), FormResult::Complete);
        let params = form.into_params("").unwrap();
        assert_eq!(params.format, "generic");
    }

    #[test]
    fn webhook_form_format_rejects_unknown() {
        let mut form = WebhookForm::Name;
        form.advance("name");
        form.advance("https://url");
        form.advance("events");
        assert!(matches!(form.advance("teams"), FormResult::Invalid(_)));
    }

    #[test]
    fn webhook_form_cancel_at_any_step() {
        let inputs = ["name", "https://url", "events"];
        for step in 0..3 {
            let mut form = WebhookForm::Name;
            for input in inputs.iter().take(step) {
                form.advance(input);
            }
            assert_eq!(form.advance(""), FormResult::Cancelled);
        }
    }

    // -- KeyValue form --

    #[test]
    fn config_set_form_happy_path() {
        let mut form = KeyValueForm::config_set();
        assert_eq!(
            form.advance("storage.redis_url"),
            FormResult::NextPrompt(form.prompt())
        );
        assert_eq!(form.advance("redis://localhost"), FormResult::Complete);

        let params = form.into_params("redis://localhost").unwrap();
        assert_eq!(
            params,
            KeyValueParams {
                key: "storage.redis_url".into(),
                value: "redis://localhost".into(),
            }
        );
    }

    #[test]
    fn secrets_set_form_happy_path() {
        let mut form = KeyValueForm::secrets_set();
        assert_eq!(
            form.advance("API_TOKEN"),
            FormResult::NextPrompt(form.prompt())
        );
        assert_eq!(form.advance("tok_abc123"), FormResult::Complete);

        let params = form.into_params("tok_abc123").unwrap();
        assert_eq!(
            params,
            KeyValueParams {
                key: "API_TOKEN".into(),
                value: "tok_abc123".into(),
            }
        );
    }

    #[test]
    fn kv_form_empty_key_cancels() {
        let mut form = KeyValueForm::config_set();
        assert_eq!(form.advance(""), FormResult::Cancelled);
    }

    #[test]
    fn kv_form_empty_value_cancels() {
        let mut form = KeyValueForm::config_set();
        form.advance("some_key");
        assert_eq!(form.advance(""), FormResult::Cancelled);
    }

    // -- Cursor navigation --

    #[test]
    fn cursor_up_saturates_at_zero() {
        let mut sel = 0;
        cursor_up(&mut sel);
        assert_eq!(sel, 0);
    }

    #[test]
    fn cursor_down_clamps_to_list_end() {
        let mut sel = 2;
        cursor_down(&mut sel, 3); // max index = 2
        assert_eq!(sel, 2);
    }

    #[test]
    fn cursor_down_on_empty_list() {
        let mut sel = 0;
        cursor_down(&mut sel, 0);
        assert_eq!(sel, 0);
    }

    #[test]
    fn cursor_down_advances() {
        let mut sel = 0;
        cursor_down(&mut sel, 5);
        assert_eq!(sel, 1);
    }

    // -- Data accessors --

    #[test]
    fn operators_sorted_returns_alphabetical() {
        let mut config = Config::default();
        config.operator_credentials.insert(
            "zulu".into(),
            latchgate_config::OperatorCredential {
                api_key: "key-z".into(),
                dpop_jkt: None,
            },
        );
        config.operator_credentials.insert(
            "alpha".into(),
            latchgate_config::OperatorCredential {
                api_key: "key-a".into(),
                dpop_jkt: Some("thumbprint".into()),
            },
        );
        let ops = operators_sorted(&config);
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].0, "alpha");
        assert!(ops[0].1); // has DPoP
        assert_eq!(ops[1].0, "zulu");
        assert!(!ops[1].1); // no DPoP
    }

    #[test]
    fn operators_sorted_empty() {
        let config = Config::default();
        assert!(operators_sorted(&config).is_empty());
    }

    #[test]
    fn webhooks_list_extracts_name_url() {
        let mut config = Config::default();
        // Config.webhooks stores Vec<toml::Value>. Construct via TOML parse.
        let v: toml::Value = toml::de::from_str(
            r#"name = "slack"
url = "https://hooks.slack.com/abc"
format = "slack""#,
        )
        .unwrap();
        config.webhooks.push(v);
        let wh = webhooks_list(&config);
        assert_eq!(
            wh,
            vec![(
                "slack".into(),
                "https://hooks.slack.com/abc".into(),
                "slack".into()
            )]
        );
    }

    #[test]
    fn webhooks_list_defaults_format_to_generic() {
        let mut config = Config::default();
        let v: toml::Value = toml::de::from_str(
            r#"name = "siem"
url = "https://siem.corp/v1""#,
        )
        .unwrap();
        config.webhooks.push(v);
        let wh = webhooks_list(&config);
        assert_eq!(wh[0].2, "generic");
    }

    #[test]
    fn webhooks_list_skips_malformed() {
        let mut config = Config::default();
        let v: toml::Value = toml::de::from_str(r#"name = "broken""#).unwrap();
        config.webhooks.push(v);
        assert!(webhooks_list(&config).is_empty());
    }

    // -- Policy ACL accessors --

    #[test]
    fn policy_actions_for_returns_granted_list() {
        let acl = serde_json::json!({
            "alice": { "allowed_actions": ["web_read", "http_post"], "allowed_sinks": [] },
        });
        let actions = policy_actions_for(&acl, "alice");
        assert_eq!(actions, vec!["web_read", "http_post"]);
    }

    #[test]
    fn policy_actions_for_wildcard() {
        let acl = serde_json::json!({
            "*": { "allowed_actions": ["list_files"] },
        });
        let actions = policy_actions_for(&acl, "*");
        assert_eq!(actions, vec!["list_files"]);
    }

    #[test]
    fn policy_actions_for_unknown_principal_returns_empty() {
        let acl = serde_json::json!({
            "alice": { "allowed_actions": ["web_read"] },
        });
        assert!(policy_actions_for(&acl, "bob").is_empty());
    }

    #[test]
    fn policy_actions_for_missing_key_returns_empty() {
        let acl = serde_json::json!({
            "alice": { "allowed_sinks": ["http_read"] },
        });
        assert!(policy_actions_for(&acl, "alice").is_empty());
    }

    #[test]
    fn policy_actions_for_null_acl_returns_empty() {
        assert!(policy_actions_for(&serde_json::Value::Null, "alice").is_empty());
    }

    #[test]
    fn policy_actions_for_empty_actions_returns_empty() {
        let acl = serde_json::json!({
            "alice": { "allowed_actions": [] },
        });
        assert!(policy_actions_for(&acl, "alice").is_empty());
    }

    #[test]
    fn policy_actions_for_skips_non_string_entries() {
        let acl = serde_json::json!({
            "alice": { "allowed_actions": ["web_read", 42, null, "http_post"] },
        });
        let actions = policy_actions_for(&acl, "alice");
        assert_eq!(actions, vec!["web_read", "http_post"]);
    }
}
