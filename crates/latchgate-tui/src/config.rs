//! Screen 6 — Setup.
//!
//! Multi-tab configuration and setup screen. Sub-tabs:
//!   1. Overview    — read-only config view + doctor runner + gate lifecycle
//!   2. Operators   — operator credentials with DPoP keygen (add/remove)
//!   3. Principals  — peercred identity mappings + policy ACL (grant/revoke)
//!   4. Webhooks    — webhook endpoint management (add/remove/test)
//!   5. Secrets     — SOPS-encrypted secrets management (init/set/remove)
//!   6. Presets     — browse built-in presets, build custom presets
//!
//! Navigation: `←`/`→` or `1`-`6` to switch sub-tabs. Each sub-tab has
//! its own key bindings for CRUD operations.

use std::path::PathBuf;
use std::sync::Arc;

use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Paragraph, Row, Tabs, Wrap};
use ratatui::Frame;

use latchgate_client::{GateClient, OperatorAuth};
use latchgate_config::Config;

use crate::config_logic::{self, FormResult, KeyValueForm, PrincipalForm, SubTab, WebhookForm};
use crate::input::{FlashMessage, InputAction, TextInput};
use crate::screen::{ScreenAction, TuiScreen};
use crate::theme::Theme;
use crate::widgets::{self, EmptyState, ScrollableTable, Spinner};
use crate::{DiagnosticCheck, DiagnosticSeverity, DoctorRunner, SetupOps};

// Generic form + text-input pairing

/// Pairs a config_logic form state machine with the active TextInput.
///
/// The form tracks accumulated values and state transitions; the TextInput
/// handles keyboard editing. On submit, the value is fed to `form.advance()`
/// which decides the next step.
struct FormInput<F> {
    form: F,
    input: TextInput,
}

// ConfigScreen

pub(crate) struct ConfigScreen {
    config: Config,
    doctor: Arc<dyn DoctorRunner>,
    setup: Arc<dyn SetupOps>,
    // Sub-tab state.
    active_tab: SubTab,
    // Overview tab.
    doctor_results: Option<Vec<DiagnosticCheck>>,
    doctor_running: bool,
    overview_scroll: usize,
    config_set_input: Option<FormInput<KeyValueForm>>,
    // Principals tab (identity + policy ACL).
    principal_selected: usize,
    principal_input: Option<FormInput<PrincipalForm>>,
    principal_removing: bool,
    /// When true, keyboard focus is on the right detail panel (action list).
    policy_detail_focus: bool,
    /// Selected action index within the right panel action list.
    policy_detail_selected: usize,
    /// Vertical scroll offset for the right detail panel.
    policy_detail_scroll: usize,
    // -- Policy ACL (fetched from running gate) --
    policy_acl: serde_json::Value,
    policy_version: String,
    policy_fetched: bool,
    policy_grant_input: Option<PolicyInput>,
    policy_revoke_input: Option<PolicyInput>,
    policy_pending: Option<PendingSetup>,
    // Operators tab.
    operator_selected: usize,
    operator_input: Option<TextInput>,
    operator_removing: bool,
    last_added_operator: Option<(String, String)>, // (api_key, key_path)
    // Webhooks tab.
    webhook_selected: usize,
    webhook_input: Option<FormInput<WebhookForm>>,
    webhook_removing: bool,
    webhook_testing: bool,
    // Secrets tab.
    secrets_list: Vec<crate::SecretEntry>,
    secrets_fetched: bool,
    secrets_selected: usize,
    secrets_input: Option<FormInput<KeyValueForm>>,
    secrets_removing: bool,
    secrets_initializing: bool,
    // Shared.
    pending_action: Option<PendingSetup>,
    /// Monotonic counter incremented each tick, drives Spinner animation.
    tick_count: usize,
    // Presets tab.
    preset: Option<PresetStep>,
    preset_list: Vec<crate::PresetListEntry>,
    preset_list_loaded: bool,
    preset_selected: usize,
    preset_activating: bool,
    /// Set by async actions that need a gate restart (e.g. preset
    /// activation). Consumed by the event loop via `take_restart_request`.
    restart_requested: bool,
}

/// Maximum character length for text inputs in forms.
const FORM_MAX_LEN: usize = 256;

enum PendingSetup {
    Doctor,
    SetConfig {
        key: String,
        value: String,
    },
    AddPrincipal {
        uid: u32,
        name: String,
        scopes: String,
    },
    RemovePrincipal {
        uid: u32,
    },
    AddOperator {
        name: String,
    },
    RemoveOperator {
        name: String,
    },
    AddWebhook {
        name: String,
        url: String,
        events: String,
        format: String,
    },
    RemoveWebhook {
        name: String,
    },
    TestWebhook {
        name: String,
    },
    SecretsInit,
    /// Force re-initialize SOPS, overwriting any partial state.
    SecretsForceInit,
    SecretsSet {
        key: String,
        value: String,
    },
    SecretsRemove {
        key: String,
    },
    ExportPreset {
        name: String,
        description: String,
        action_ids: Vec<String>,
        wildcard_grant: String,
    },
    ActivatePreset {
        plan: crate::InitPlan,
    },
    PolicyGrant {
        principal: String,
        action: String,
    },
    PolicyRevoke {
        principal: String,
        action: String,
    },
}

/// Multi-step wizard for building and exporting a custom preset.
enum PresetStep {
    /// Multi-select: toggle actions with Space, Enter to proceed.
    SelectActions {
        available: Vec<(String, bool)>,
        cursor: usize,
    },
    /// Select wildcard grant level.
    Grant {
        action_ids: Vec<String>,
        cursor: usize,
    },
    /// Enter preset name.
    Name {
        action_ids: Vec<String>,
        grant: String,
        input: TextInput,
    },
    /// Enter description.
    Description {
        action_ids: Vec<String>,
        grant: String,
        name: String,
        input: TextInput,
    },
}

// Policy input — captures principal at initiation to close TOCTOU window

/// Text input bound to the principal it was opened for.
///
/// Captures the principal name when the input opens so a concurrent tick
/// cannot shift `principal_selected` between initiation and submission.
struct PolicyInput {
    principal: String,
    input: TextInput,
}

const WILDCARD_GRANTS: &[(&str, &str)] = &[
    ("none", "No auto-grants (strictest)"),
    ("risk_below:medium", "Auto-grant low-risk only"),
    ("risk_below:high", "Auto-grant low + medium"),
    ("risk_below:critical", "Auto-grant low + medium + high"),
    ("all", "Auto-grant everything (dev only)"),
];

impl ConfigScreen {
    pub fn new(config: Config, doctor: Arc<dyn DoctorRunner>, setup: Arc<dyn SetupOps>) -> Self {
        Self {
            config,
            doctor,
            setup,
            active_tab: SubTab::Overview,
            doctor_results: None,
            doctor_running: false,
            overview_scroll: 0,
            config_set_input: None,
            principal_selected: 0,
            principal_input: None,
            principal_removing: false,
            policy_detail_focus: false,
            policy_detail_selected: 0,
            policy_detail_scroll: 0,
            policy_acl: serde_json::Value::Null,
            policy_version: String::new(),
            policy_fetched: false,
            policy_grant_input: None,
            policy_revoke_input: None,
            policy_pending: None,
            operator_selected: 0,
            operator_input: None,
            operator_removing: false,
            last_added_operator: None,
            webhook_selected: 0,
            webhook_input: None,
            webhook_removing: false,
            webhook_testing: false,
            secrets_list: Vec::new(),
            secrets_fetched: false,
            secrets_selected: 0,
            secrets_input: None,
            secrets_removing: false,
            secrets_initializing: false,
            pending_action: None,
            tick_count: 0,
            preset: None,
            preset_list: Vec::new(),
            preset_list_loaded: false,
            preset_selected: 0,
            preset_activating: false,
            restart_requested: false,
        }
    }

    fn config_file_path(&self) -> Option<PathBuf> {
        self.config.source.config_file()
    }

    /// Whether SOPS secrets are usable — either the config references them
    /// or the well-known files exist on disk (previous init, project config
    /// not yet inherited by the ephemeral up config).
    fn sops_available(&self) -> bool {
        if self.config.secrets.sops_secrets_file.is_some() {
            return true;
        }
        std::path::Path::new(".latchgate/sops-age.key").exists()
            && std::path::Path::new(".latchgate/secrets.enc.yaml").exists()
    }

    /// Detect the half-initialized state: exactly one of the two SOPS files
    /// exists on disk. Returns a description of what's missing, or `None` if
    /// fully initialized or fully absent.
    fn sops_half_state(&self) -> Option<&'static str> {
        let key_exists = std::path::Path::new(".latchgate/sops-age.key").exists();
        let secrets_exists = std::path::Path::new(".latchgate/secrets.enc.yaml").exists();
        match (key_exists, secrets_exists) {
            (true, false) => Some("age key present but .latchgate/secrets.enc.yaml is missing"),
            (false, true) => {
                Some(".latchgate/secrets.enc.yaml present but .latchgate/sops-age.key is missing")
            }
            _ => None,
        }
    }

    fn is_in_input(&self) -> bool {
        self.principal_input.is_some()
            || self.policy_grant_input.is_some()
            || self.policy_revoke_input.is_some()
            || self.operator_input.is_some()
            || self.webhook_input.is_some()
            || self.secrets_input.is_some()
            || self.config_set_input.is_some()
            || self.principal_removing
            || self.operator_removing
            || self.webhook_removing
            || self.secrets_removing
            || self.preset.is_some()
            || self.preset_activating
    }

    // -- Data accessors (delegated to config_logic) ---------------------------

    /// Compute the number of content lines in the overview tab.
    ///
    /// Mirrors the rendering logic in `render_overview` so the scroll bound
    /// in `handle_overview_key` matches the actual content height.
    fn overview_line_count(&self) -> usize {
        let mut n: usize = if self.config_file_path().is_none() {
            // First-launch: blank + message + blank + prompt + description + blank.
            6
        } else {
            // Config fields (8 key-value lines) + trailing blank.
            9
        };

        if self.doctor_running {
            n += 1;
        } else if let Some(ref results) = self.doctor_results {
            // Summary bar (2) + blank + section headers + one line per check.
            n += 3;
            let mut current_section = String::new();
            for c in results {
                if c.section != current_section {
                    current_section.clone_from(&c.section);
                    n += 1; // section header
                }
                n += 1; // check line
            }
        } else {
            // "press [d]" hint.
            n += 1;
        }
        n
    }

    fn principals_sorted(&self) -> Vec<(String, String, String)> {
        config_logic::principals_sorted(&self.config)
    }

    fn operators_sorted(&self) -> Vec<(String, bool)> {
        config_logic::operators_sorted(&self.config)
    }

    fn webhooks_list(&self) -> Vec<(String, String, String)> {
        config_logic::webhooks_list(&self.config)
    }

    // -- Rendering -----------------------------------------------------------

    fn render_sub_tabs(&self, area: Rect, frame: &mut Frame, theme: &Theme) {
        let titles: Vec<Line<'_>> = SubTab::ALL
            .iter()
            .enumerate()
            .map(|(i, tab)| {
                let label = format!("{} {}", i + 1, tab.label());
                let style = if *tab == self.active_tab {
                    theme.subtab_active
                } else {
                    theme.subtab_inactive
                };
                Line::from(Span::styled(label, style))
            })
            .collect();
        let tabs = Tabs::new(titles)
            .divider(Span::styled(" · ", theme.dim))
            .select(self.active_tab.index());
        frame.render_widget(tabs, area);
    }

    fn render_overview(&self, area: Rect, frame: &mut Frame, theme: &Theme) {
        let (main_area, input_area) = if self.config_set_input.is_some() {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(1), Constraint::Length(3)])
                .split(area);
            (chunks[0], Some(chunks[1]))
        } else {
            (area, None)
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(theme.content_border_type)
            .border_style(theme.border_active)
            .title(" Overview ");
        let inner = block.inner(main_area);
        frame.render_widget(block, main_area);
        if inner.width == 0 || inner.height == 0 {
            return;
        }

        let mut lines: Vec<Line<'_>> = Vec::with_capacity(24);

        // First-launch prompt.
        if self.config_file_path().is_none() {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "  No configuration found.",
                theme.status_warn,
            )));
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "  Press [i] to initialize a new LatchGate project.",
                theme.header,
            )));
            lines.push(Line::from(Span::styled(
                "  This runs the setup wizard: pick a preset, scaffold config and manifests.",
                theme.dim,
            )));
            lines.push(Line::default());
        } else {
            let kw = 16;
            let source_label = format!("{}", self.config.source);
            lines.push(widgets::key_value_line(
                "  Source:       ",
                Span::raw(source_label),
                kw,
                theme,
            ));
            let path_label = self
                .config_file_path()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "(no config file)".into());
            lines.push(widgets::key_value_line(
                "  Config file:  ",
                Span::raw(path_label),
                kw,
                theme,
            ));
            lines.push(widgets::key_value_line(
                "  Manifests:    ",
                Span::raw(&self.config.manifests_dir),
                kw,
                theme,
            ));
            lines.push(widgets::key_value_line(
                "  Providers:    ",
                Span::raw(&self.config.wasm_providers_dir),
                kw,
                theme,
            ));

            let transport = if self.config.listener.unsafe_expose_http {
                self.config
                    .listener
                    .listen_http_addr
                    .map(|a| format!("TCP {a}"))
                    .unwrap_or_else(|| "TCP (no address)".into())
            } else {
                format!("UDS {}", self.config.listener.listen_uds_path)
            };
            lines.push(widgets::key_value_line(
                "  Transport:    ",
                Span::raw(transport),
                kw,
                theme,
            ));
            let redis_label = self
                .config
                .storage
                .redis_url
                .as_deref()
                .unwrap_or("(not configured — using SQLite)");
            lines.push(widgets::key_value_line(
                "  Redis:        ",
                Span::raw(redis_label),
                kw,
                theme,
            ));
            let opa_label = self.config.policy.opa_url.as_deref().unwrap_or("embedded");
            lines.push(widgets::key_value_line(
                "  OPA:          ",
                Span::raw(opa_label),
                kw,
                theme,
            ));
            lines.push(widgets::key_value_line(
                "  Log level:    ",
                Span::raw(&self.config.logging.level),
                kw,
                theme,
            ));

            lines.push(Line::default());
        } // end else (config exists)

        // Doctor.
        if self.doctor_running {
            let braille = ['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷'];
            let ch = braille[self.tick_count % braille.len()];
            lines.push(Line::from(Span::styled(
                format!("  Doctor: running {ch}"),
                theme.status_warn,
            )));
        } else if let Some(ref checks) = self.doctor_results {
            let ok = checks
                .iter()
                .filter(|c| c.severity == DiagnosticSeverity::Ok)
                .count();
            let skip = checks
                .iter()
                .filter(|c| c.severity == DiagnosticSeverity::Skip)
                .count();
            let warn = checks
                .iter()
                .filter(|c| c.severity == DiagnosticSeverity::Warn)
                .count();
            let err = checks
                .iter()
                .filter(|c| c.severity == DiagnosticSeverity::Error)
                .count();
            let total = checks.len();

            // Summary bar with pass ratio.
            let passed = ok + skip;
            let bar_width = 20usize;
            let filled = if total > 0 {
                (passed * bar_width) / total
            } else {
                bar_width
            };
            let bar: String = "█".repeat(filled) + &"░".repeat(bar_width.saturating_sub(filled));
            let bar_style = if err > 0 {
                theme.status_error
            } else if warn > 0 {
                theme.status_warn
            } else {
                theme.status_ok
            };
            lines.push(Line::from(vec![
                Span::styled("  Doctor  ", theme.header),
                Span::styled(bar, bar_style),
                Span::styled(format!("  {passed}/{total} passed"), bar_style),
            ]));
            lines.push(Line::from(vec![
                Span::styled("          ", theme.dim),
                Span::styled(format!("● {ok} ok"), theme.status_ok),
                Span::raw("  "),
                Span::styled(format!("○ {skip} skip"), theme.dim),
                Span::raw("  "),
                Span::styled(format!("⚠ {warn} warn"), theme.status_warn),
                Span::raw("  "),
                Span::styled(format!("✗ {err} error"), theme.status_error),
            ]));
            lines.push(Line::default());

            // Group checks by section for visual hierarchy.
            let mut current_section = String::new();
            for c in checks {
                if c.section != current_section {
                    current_section.clone_from(&c.section);
                    lines.push(Line::from(vec![
                        Span::styled("  ── ", theme.separator),
                        Span::styled(current_section.clone(), theme.header),
                        Span::styled(" ─────────────────────────────", theme.separator),
                    ]));
                }
                let sym = match c.severity {
                    DiagnosticSeverity::Ok => Span::styled("    ● ", theme.status_ok),
                    DiagnosticSeverity::Skip => Span::styled("    ○ ", theme.dim),
                    DiagnosticSeverity::Warn => Span::styled("    ⚠ ", theme.status_warn),
                    DiagnosticSeverity::Error => Span::styled("    ✗ ", theme.status_error),
                };
                lines.push(Line::from(vec![
                    sym,
                    Span::raw(format!("{:<24} ", c.name)),
                    Span::styled(&c.message, theme.dim),
                ]));
            }
        } else {
            lines.push(Line::from(Span::styled(
                "  Doctor: press [d] to run checks",
                theme.dim,
            )));
        }

        let scroll = self.overview_scroll.min(lines.len().saturating_sub(1));
        let visible: Vec<Line<'_>> = lines.into_iter().skip(scroll).collect();
        frame.render_widget(
            Paragraph::new(Text::from(visible)).wrap(Wrap { trim: false }),
            inner,
        );

        if let Some(ia) = input_area {
            if let Some(ref fi) = self.config_set_input {
                fi.input.render(ia, frame, theme);
            }
        }
    }

    fn render_principals(&self, area: Rect, frame: &mut Frame, theme: &Theme) {
        let items = self.principals_sorted();

        let has_input = self.principal_input.is_some()
            || self.policy_grant_input.is_some()
            || self.policy_revoke_input.is_some();

        let (body_area, input_area) = if has_input {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(1), Constraint::Length(3)])
                .split(area);
            (chunks[0], Some(chunks[1]))
        } else {
            (area, None)
        };

        // Two-panel: principal list (left), detail + policy (right).
        let panels = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Min(0)])
            .split(body_area);

        // -- Left panel: peercred principal list --------------------------------

        let title = format!(" Principals ({}) ", items.len());
        let Some(inner) = widgets::begin_active_panel(frame, panels[0], title, theme) else {
            return;
        };

        let header = Row::new(vec!["  UID", "Name", "Scopes"]).style(theme.header);
        let widths = [
            Constraint::Length(10),
            Constraint::Length(14),
            Constraint::Min(10),
        ];

        let rows: Vec<Row<'_>> = items
            .iter()
            .enumerate()
            .map(|(i, (uid, name, scopes))| {
                let marker = if i == self.principal_selected {
                    "▸ "
                } else {
                    "  "
                };
                let style = if i == self.principal_selected {
                    theme.selected.add_modifier(Modifier::BOLD)
                } else {
                    ratatui::style::Style::default()
                };
                Row::new(vec![
                    Line::from(Span::styled(format!("{marker}{uid}"), style)),
                    Line::from(Span::styled(name.as_str(), style)),
                    Line::from(Span::styled(scopes.as_str(), theme.dim)),
                ])
            })
            .collect();

        frame.render_widget(
            ScrollableTable::new(rows, widths)
                .header(header)
                .selected(self.principal_selected)
                .empty(EmptyState::new("No principals configured.", theme).hint("[a] to add")),
            inner,
        );

        // -- Right panel: policy detail for selected principal ------------------

        self.render_principal_policy(panels[1], frame, theme, &items);

        // -- Input overlay (bottom) ---------------------------------------------

        if let Some(ia) = input_area {
            if let Some(ref fi) = self.principal_input {
                fi.input.render(ia, frame, theme);
            } else if let Some(ref pi) = self.policy_grant_input {
                pi.input.render(ia, frame, theme);
            } else if let Some(ref pi) = self.policy_revoke_input {
                pi.input.render(ia, frame, theme);
            }
        }
    }

    /// Right detail panel showing identity info and policy grants for the
    /// selected principal. Interactive: supports focus, scroll, and action
    /// selection for direct grant/revoke.
    fn render_principal_policy(
        &self,
        area: Rect,
        frame: &mut Frame,
        theme: &Theme,
        items: &[(String, String, String)],
    ) {
        let selected = items.get(self.principal_selected);
        let principal_label = selected.map(|(_, n, _)| n.as_str()).unwrap_or("(none)");
        let title = format!(" {principal_label} ");

        let border_style = if self.policy_detail_focus {
            theme.border_active
        } else {
            theme.border
        };
        let Some(inner) = widgets::begin_panel(frame, area, title, border_style, theme) else {
            return;
        };

        let mut lines: Vec<Line<'_>> = Vec::with_capacity(24);

        // Identity section.
        if let Some((uid, _name, scopes)) = selected {
            lines.push(widgets::key_value_line(
                "UID:     ",
                Span::raw(uid.as_str()),
                9,
                theme,
            ));
            lines.push(widgets::key_value_line(
                "Scopes:  ",
                Span::styled(scopes.as_str(), theme.dim),
                9,
                theme,
            ));
            lines.push(Line::default());
        }

        // Policy section — actions granted to this principal.
        if !self.policy_version.is_empty() {
            lines.push(widgets::key_value_line(
                "Policy:  ",
                Span::styled(&self.policy_version, theme.dim),
                9,
                theme,
            ));
        }

        let principal_actions = self.policy_actions_for(principal_label);
        let wildcard_actions = self.policy_actions_for("*");
        // Track where the first action item starts so we can auto-scroll.
        let mut action_start_line: usize = 0;

        if principal_actions.is_empty() && wildcard_actions.is_empty() {
            lines.push(Line::from(Span::styled("  No actions granted.", theme.dim)));
        } else {
            if !principal_actions.is_empty() {
                lines.push(Line::from(Span::styled(
                    format!("Granted actions ({}):", principal_actions.len()),
                    theme.header,
                )));
                action_start_line = lines.len();
                for (i, action) in principal_actions.iter().enumerate() {
                    let is_sel = self.policy_detail_focus && i == self.policy_detail_selected;
                    let marker = if is_sel { "  ▸ " } else { "    " };
                    let style = if is_sel {
                        theme.selected.add_modifier(Modifier::BOLD)
                    } else {
                        ratatui::style::Style::default()
                    };
                    lines.push(Line::from(Span::styled(format!("{marker}{action}"), style)));
                }
            }

            // Wildcard grants (apply to everyone).
            if !wildcard_actions.is_empty() && principal_label != "*" {
                lines.push(Line::default());
                lines.push(Line::from(Span::styled(
                    format!("Via wildcard * ({}):", wildcard_actions.len()),
                    theme.dim,
                )));
                for action in &wildcard_actions {
                    lines.push(Line::from(Span::styled(format!("    {action}"), theme.dim)));
                }
            }
        }

        // Focus hint at the bottom.
        if self.policy_detail_focus && !principal_actions.is_empty() {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "[↑↓]select  [x]revoke  [h/Esc]back",
                theme.key_hint,
            )));
        }

        // Auto-scroll: keep selected action visible within the viewport.
        let viewport = inner.height as usize;
        let selected_line = action_start_line + self.policy_detail_selected;
        let scroll = if !self.policy_detail_focus || viewport == 0 {
            0
        } else if selected_line >= viewport {
            (selected_line + 1).saturating_sub(viewport)
        } else {
            0
        };
        let visible: Vec<Line<'_>> = lines.into_iter().skip(scroll).collect();
        frame.render_widget(
            Paragraph::new(Text::from(visible)).wrap(Wrap { trim: false }),
            inner,
        );
    }

    /// Extract allowed actions for a principal from the cached policy ACL.
    fn policy_actions_for(&self, principal: &str) -> Vec<String> {
        config_logic::policy_actions_for(&self.policy_acl, principal)
    }

    fn render_operators(&self, area: Rect, frame: &mut Frame, theme: &Theme) {
        let items = self.operators_sorted();

        let (list_area, input_area) = if self.operator_input.is_some() {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(1), Constraint::Length(3)])
                .split(area);
            (chunks[0], Some(chunks[1]))
        } else {
            (area, None)
        };

        let title = format!(" Operators ({}) ", items.len());
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(theme.content_border_type)
            .border_style(theme.border_active)
            .title(title);

        let inner = block.inner(list_area);
        frame.render_widget(block, list_area);

        if inner.width == 0 || inner.height == 0 {
            return;
        }

        let header = Row::new(vec!["  Name", "Auth"]).style(theme.header);
        let widths = [Constraint::Min(16), Constraint::Length(14)];

        let rows: Vec<Row<'_>> = items
            .iter()
            .enumerate()
            .map(|(i, (name, has_dpop))| {
                let marker = if i == self.operator_selected {
                    "▸ "
                } else {
                    "  "
                };
                let style = if i == self.operator_selected {
                    theme.selected.add_modifier(Modifier::BOLD)
                } else {
                    ratatui::style::Style::default()
                };
                let dpop = if *has_dpop {
                    " 🔑 DPoP"
                } else {
                    " ⚠ no DPoP"
                };
                Row::new(vec![
                    Line::from(Span::styled(format!("{marker}{name}"), style)),
                    Line::from(Span::styled(dpop, theme.dim)),
                ])
            })
            .collect();

        frame.render_widget(
            ScrollableTable::new(rows, widths)
                .header(header)
                .selected(self.operator_selected)
                .empty(EmptyState::new("No operators configured.", theme).hint("[a] to add")),
            inner,
        );

        // Show last-added operator info below the table.
        if let Some((ref api_key, ref key_path)) = self.last_added_operator {
            let info_y = inner.bottom().min(list_area.bottom().saturating_sub(3));
            if info_y + 2 < list_area.bottom() {
                let info_area = Rect::new(inner.x, info_y, inner.width, 3);
                let info_lines = vec![
                    Line::from(Span::styled("  Last added:", theme.header)),
                    Line::from(vec![
                        Span::styled("  API key:  ", theme.dim),
                        Span::raw(api_key.as_str()),
                    ]),
                    Line::from(vec![
                        Span::styled("  Key file: ", theme.dim),
                        Span::raw(key_path.as_str()),
                    ]),
                ];
                frame.render_widget(Paragraph::new(info_lines), info_area);
            }
        }

        if let Some(ia) = input_area {
            if let Some(ref input) = self.operator_input {
                input.render(ia, frame, theme);
            }
        }
    }

    fn render_webhooks(&self, area: Rect, frame: &mut Frame, theme: &Theme) {
        let items = self.webhooks_list();

        let (list_area, input_area) = if self.webhook_input.is_some() {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(1), Constraint::Length(3)])
                .split(area);
            (chunks[0], Some(chunks[1]))
        } else {
            (area, None)
        };

        let title = format!(" Webhooks ({}) ", items.len());
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(theme.content_border_type)
            .border_style(theme.border_active)
            .title(title);

        let inner = block.inner(list_area);
        frame.render_widget(block, list_area);

        if inner.width == 0 || inner.height == 0 {
            return;
        }

        let header = Row::new(vec!["  Name", "URL", "Format"]).style(theme.header);
        let widths = [
            Constraint::Length(18),
            Constraint::Min(20),
            Constraint::Length(10),
        ];

        let rows: Vec<Row<'_>> = items
            .iter()
            .enumerate()
            .map(|(i, (name, url, format))| {
                let marker = if i == self.webhook_selected {
                    "▸ "
                } else {
                    "  "
                };
                let style = if i == self.webhook_selected {
                    theme.selected.add_modifier(Modifier::BOLD)
                } else {
                    ratatui::style::Style::default()
                };
                Row::new(vec![
                    Line::from(Span::styled(format!("{marker}{name}"), style)),
                    Line::from(Span::styled(format!("=> {url}"), theme.dim)),
                    Line::from(Span::styled(format.as_str(), theme.dim)),
                ])
            })
            .collect();

        frame.render_widget(
            ScrollableTable::new(rows, widths)
                .header(header)
                .selected(self.webhook_selected)
                .empty(EmptyState::new("No webhooks configured.", theme).hint("[a] to add")),
            inner,
        );

        if let Some(ia) = input_area {
            if let Some(ref fi) = self.webhook_input {
                fi.input.render(ia, frame, theme);
            }
        }
    }

    // -- Key handling per sub-tab --------------------------------------------

    fn handle_overview_key(&mut self, key: KeyEvent) -> ScreenAction {
        // Config set input mode.
        if let Some(mut fi) = self.config_set_input.take() {
            return match fi.input.handle_key(key) {
                InputAction::Cancel => ScreenAction::EndInput,
                InputAction::Continue => {
                    self.config_set_input = Some(fi);
                    ScreenAction::Noop
                }
                InputAction::Submit(val) => {
                    let mut form = fi.form;
                    match form.advance(&val) {
                        FormResult::NextPrompt(prompt) => {
                            self.config_set_input = Some(FormInput {
                                form,
                                input: TextInput::new(prompt, FORM_MAX_LEN),
                            });
                            ScreenAction::Noop
                        }
                        FormResult::Complete => {
                            let Some(params) = form.into_params(&val) else {
                                return ScreenAction::Noop;
                            };
                            self.pending_action = Some(PendingSetup::SetConfig {
                                key: params.key,
                                value: params.value,
                            });
                            ScreenAction::AsyncAction
                        }
                        FormResult::Invalid(msg) => ScreenAction::Flash(FlashMessage::error(msg)),
                        FormResult::Cancelled => ScreenAction::EndInput,
                    }
                }
            };
        }

        match key.code {
            KeyCode::Char('d') if !self.doctor_running => {
                self.doctor_running = true;
                self.pending_action = Some(PendingSetup::Doctor);
                ScreenAction::AsyncAction
            }
            KeyCode::Char('e') => {
                if let Some(path) = self.config_file_path() {
                    ScreenAction::SuspendForEditor(path)
                } else {
                    ScreenAction::Flash(FlashMessage::error("No config file to edit"))
                }
            }
            // Init project (first-launch or re-init).
            KeyCode::Char('i') => ScreenAction::RunInit,
            // Start gate (Docker deps + server).
            KeyCode::Char('u') => ScreenAction::GateUp,
            // Set config value.
            KeyCode::Char('s') if self.config_file_path().is_some() => {
                let form = KeyValueForm::config_set();
                let prompt = form.prompt();
                self.config_set_input = Some(FormInput {
                    form,
                    input: TextInput::new(prompt, FORM_MAX_LEN),
                });
                ScreenAction::BeginInput
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.overview_scroll = self.overview_scroll.saturating_sub(1);
                ScreenAction::Noop
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let max = self.overview_line_count();
                if self.overview_scroll < max {
                    self.overview_scroll += 1;
                }
                ScreenAction::Noop
            }
            _ => ScreenAction::Noop,
        }
    }

    fn handle_principals_key(&mut self, key: KeyEvent) -> ScreenAction {
        // Principal add form.
        if let Some(mut fi) = self.principal_input.take() {
            return match fi.input.handle_key(key) {
                InputAction::Cancel => ScreenAction::EndInput,
                InputAction::Continue => {
                    self.principal_input = Some(fi);
                    ScreenAction::Noop
                }
                InputAction::Submit(val) => {
                    let mut form = fi.form;
                    match form.advance(&val) {
                        FormResult::NextPrompt(prompt) => {
                            self.principal_input = Some(FormInput {
                                form,
                                input: TextInput::new(prompt, FORM_MAX_LEN),
                            });
                            ScreenAction::Noop
                        }
                        FormResult::Complete => {
                            let Some(params) = form.into_params(&val) else {
                                return ScreenAction::Noop;
                            };
                            self.pending_action = Some(PendingSetup::AddPrincipal {
                                uid: params.uid,
                                name: params.name,
                                scopes: params.scopes,
                            });
                            ScreenAction::AsyncAction
                        }
                        FormResult::Invalid(msg) => ScreenAction::Flash(FlashMessage::error(msg)),
                        FormResult::Cancelled => ScreenAction::EndInput,
                    }
                }
            };
        }

        // Policy grant input.
        if let Some(mut pi) = self.policy_grant_input.take() {
            return match pi.input.handle_key(key) {
                InputAction::Submit(action) => {
                    let action = action.trim().to_string();
                    if action.is_empty() {
                        return ScreenAction::EndInput;
                    }
                    self.policy_pending = Some(PendingSetup::PolicyGrant {
                        principal: pi.principal,
                        action,
                    });
                    ScreenAction::AsyncAction
                }
                InputAction::Cancel => ScreenAction::EndInput,
                InputAction::Continue => {
                    self.policy_grant_input = Some(pi);
                    ScreenAction::Noop
                }
            };
        }

        // Policy revoke input.
        if let Some(mut pi) = self.policy_revoke_input.take() {
            return match pi.input.handle_key(key) {
                InputAction::Submit(action) => {
                    let action = action.trim().to_string();
                    if action.is_empty() {
                        return ScreenAction::EndInput;
                    }
                    self.policy_pending = Some(PendingSetup::PolicyRevoke {
                        principal: pi.principal,
                        action,
                    });
                    ScreenAction::AsyncAction
                }
                InputAction::Cancel => ScreenAction::EndInput,
                InputAction::Continue => {
                    self.policy_revoke_input = Some(pi);
                    ScreenAction::Noop
                }
            };
        }

        // Confirm remove.
        if self.principal_removing {
            if key.code == KeyCode::Char('y') {
                self.principal_removing = false;
                let items = self.principals_sorted();
                if let Some((uid_str, _, _)) = items.get(self.principal_selected) {
                    if let Ok(uid) = uid_str.parse::<u32>() {
                        self.pending_action = Some(PendingSetup::RemovePrincipal { uid });
                        return ScreenAction::AsyncAction;
                    }
                }
            }
            self.principal_removing = false;
            return ScreenAction::EndInput;
        }

        match key.code {
            // Focus right panel: l moves to the action list.
            KeyCode::Char('l') if !self.policy_detail_focus => {
                let items = self.principals_sorted();
                let principal_label = items
                    .get(self.principal_selected)
                    .map(|(_, n, _)| n.as_str())
                    .unwrap_or("");
                let actions = self.policy_actions_for(principal_label);
                if !actions.is_empty() {
                    self.policy_detail_focus = true;
                    self.policy_detail_selected = 0;
                    self.policy_detail_scroll = 0;
                }
                ScreenAction::Noop
            }
            KeyCode::Char('h') | KeyCode::Esc if self.policy_detail_focus => {
                self.policy_detail_focus = false;
                ScreenAction::Noop
            }
            // Right-panel navigation when focused.
            KeyCode::Up | KeyCode::Char('k') if self.policy_detail_focus => {
                self.policy_detail_selected = self.policy_detail_selected.saturating_sub(1);
                ScreenAction::Noop
            }
            KeyCode::Down | KeyCode::Char('j') if self.policy_detail_focus => {
                let items = self.principals_sorted();
                let principal_label = items
                    .get(self.principal_selected)
                    .map(|(_, n, _)| n.as_str())
                    .unwrap_or("");
                let actions = self.policy_actions_for(principal_label);
                if self.policy_detail_selected + 1 < actions.len() {
                    self.policy_detail_selected += 1;
                }
                ScreenAction::Noop
            }
            // Direct revoke from the right panel: x on selected action.
            KeyCode::Char('x') if self.policy_detail_focus => {
                let items = self.principals_sorted();
                let principal_label = items
                    .get(self.principal_selected)
                    .map(|(_, n, _)| n.clone())
                    .unwrap_or_default();
                let actions = self.policy_actions_for(&principal_label);
                if let Some(action) = actions.get(self.policy_detail_selected) {
                    self.policy_pending = Some(PendingSetup::PolicyRevoke {
                        principal: principal_label,
                        action: action.clone(),
                    });
                    self.policy_detail_focus = false;
                    return ScreenAction::AsyncAction;
                }
                ScreenAction::Noop
            }
            // Left-panel navigation (original behavior when not focused right).
            KeyCode::Up | KeyCode::Char('k') => {
                config_logic::cursor_up(&mut self.principal_selected);
                // Reset right-panel state on left-panel navigation.
                self.policy_detail_selected = 0;
                self.policy_detail_scroll = 0;
                ScreenAction::Noop
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let len = self.principals_sorted().len();
                config_logic::cursor_down(&mut self.principal_selected, len);
                self.policy_detail_selected = 0;
                self.policy_detail_scroll = 0;
                ScreenAction::Noop
            }
            // Identity: add peercred principal.
            KeyCode::Char('a') if !self.policy_detail_focus => {
                let form = PrincipalForm::Uid;
                let prompt = form.prompt();
                self.principal_input = Some(FormInput {
                    form,
                    input: TextInput::new(prompt, FORM_MAX_LEN),
                });
                ScreenAction::BeginInput
            }
            // Identity: remove peercred principal.
            KeyCode::Char('r')
                if !self.policy_detail_focus && !self.principals_sorted().is_empty() =>
            {
                self.principal_removing = true;
                ScreenAction::BeginInput
            }
            // Policy: grant action to selected principal.
            KeyCode::Char('g') if !self.policy_detail_focus => {
                let items = self.principals_sorted();
                if let Some((_, name, _)) = items.get(self.principal_selected) {
                    self.policy_grant_input = Some(PolicyInput {
                        principal: name.clone(),
                        input: TextInput::new(
                            " Grant action ID (Enter to submit, Esc to cancel) ",
                            128,
                        ),
                    });
                    ScreenAction::BeginInput
                } else {
                    ScreenAction::Noop
                }
            }
            // Policy: revoke action from selected principal (text input).
            KeyCode::Char('x') if !self.policy_detail_focus => {
                let items = self.principals_sorted();
                if let Some((_, name, _)) = items.get(self.principal_selected) {
                    self.policy_revoke_input = Some(PolicyInput {
                        principal: name.clone(),
                        input: TextInput::new(
                            " Revoke action ID (Enter to submit, Esc to cancel) ",
                            128,
                        ),
                    });
                    ScreenAction::BeginInput
                } else {
                    ScreenAction::Noop
                }
            }
            _ => ScreenAction::Noop,
        }
    }

    fn handle_operators_key(&mut self, key: KeyEvent) -> ScreenAction {
        if let Some(ref mut input) = self.operator_input {
            return match input.handle_key(key) {
                InputAction::Cancel => {
                    self.operator_input = None;
                    ScreenAction::EndInput
                }
                InputAction::Continue => ScreenAction::Noop,
                InputAction::Submit(name) => {
                    let name = name.trim().to_string();
                    self.operator_input = None;
                    if name.is_empty() {
                        return ScreenAction::EndInput;
                    }
                    self.pending_action = Some(PendingSetup::AddOperator { name });
                    ScreenAction::AsyncAction
                }
            };
        }

        if self.operator_removing {
            if key.code == KeyCode::Char('y') {
                self.operator_removing = false;
                let items = self.operators_sorted();
                if let Some((name, _)) = items.get(self.operator_selected) {
                    self.pending_action = Some(PendingSetup::RemoveOperator { name: name.clone() });
                    return ScreenAction::AsyncAction;
                }
            }
            self.operator_removing = false;
            return ScreenAction::EndInput;
        }

        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                config_logic::cursor_up(&mut self.operator_selected);
                ScreenAction::Noop
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let len = self.operators_sorted().len();
                config_logic::cursor_down(&mut self.operator_selected, len);
                ScreenAction::Noop
            }
            KeyCode::Char('a') => {
                self.operator_input = Some(TextInput::new(" Operator name (Enter/Esc) ", 64));
                ScreenAction::BeginInput
            }
            KeyCode::Char('r') if !self.operators_sorted().is_empty() => {
                self.operator_removing = true;
                ScreenAction::BeginInput
            }
            _ => ScreenAction::Noop,
        }
    }

    fn handle_webhooks_key(&mut self, key: KeyEvent) -> ScreenAction {
        if let Some(mut fi) = self.webhook_input.take() {
            return match fi.input.handle_key(key) {
                InputAction::Cancel => ScreenAction::EndInput,
                InputAction::Continue => {
                    self.webhook_input = Some(fi);
                    ScreenAction::Noop
                }
                InputAction::Submit(val) => {
                    let mut form = fi.form;
                    match form.advance(&val) {
                        FormResult::NextPrompt(prompt) => {
                            self.webhook_input = Some(FormInput {
                                form,
                                input: TextInput::new(prompt, FORM_MAX_LEN),
                            });
                            ScreenAction::Noop
                        }
                        FormResult::Complete => {
                            let Some(params) = form.into_params(&val) else {
                                return ScreenAction::Noop;
                            };
                            self.pending_action = Some(PendingSetup::AddWebhook {
                                name: params.name,
                                url: params.url,
                                events: params.events,
                                format: params.format,
                            });
                            ScreenAction::AsyncAction
                        }
                        FormResult::Invalid(msg) => ScreenAction::Flash(FlashMessage::error(msg)),
                        FormResult::Cancelled => ScreenAction::EndInput,
                    }
                }
            };
        }

        if self.webhook_removing {
            if key.code == KeyCode::Char('y') {
                self.webhook_removing = false;
                let items = self.webhooks_list();
                if let Some((name, _, _)) = items.get(self.webhook_selected) {
                    self.pending_action = Some(PendingSetup::RemoveWebhook { name: name.clone() });
                    return ScreenAction::AsyncAction;
                }
            }
            self.webhook_removing = false;
            return ScreenAction::EndInput;
        }

        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                config_logic::cursor_up(&mut self.webhook_selected);
                ScreenAction::Noop
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let len = self.webhooks_list().len();
                config_logic::cursor_down(&mut self.webhook_selected, len);
                ScreenAction::Noop
            }
            KeyCode::Char('a') => {
                let form = WebhookForm::Name;
                let prompt = form.prompt();
                self.webhook_input = Some(FormInput {
                    form,
                    input: TextInput::new(prompt, FORM_MAX_LEN),
                });
                ScreenAction::BeginInput
            }
            KeyCode::Char('r') if !self.webhooks_list().is_empty() => {
                self.webhook_removing = true;
                ScreenAction::BeginInput
            }
            KeyCode::Char('t') if !self.webhooks_list().is_empty() && !self.webhook_testing => {
                let items = self.webhooks_list();
                if let Some((name, _, _)) = items.get(self.webhook_selected) {
                    self.webhook_testing = true;
                    self.pending_action = Some(PendingSetup::TestWebhook { name: name.clone() });
                    ScreenAction::AsyncAction
                } else {
                    ScreenAction::Noop
                }
            }
            _ => ScreenAction::Noop,
        }
    }

    fn render_secrets(&self, area: Rect, frame: &mut Frame, theme: &Theme) {
        let sops_in_config = self.config.secrets.sops_secrets_file.is_some();
        let sops_on_disk = !sops_in_config && self.sops_available();

        let (list_area, input_area) = if self.secrets_input.is_some() {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(1), Constraint::Length(3)])
                .split(area);
            (chunks[0], Some(chunks[1]))
        } else {
            (area, None)
        };

        let title = format!(" Secrets ({}) ", self.secrets_list.len());
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(theme.content_border_type)
            .border_style(theme.border_active)
            .title(title);
        let inner = block.inner(list_area);
        frame.render_widget(block, list_area);
        if inner.width == 0 || inner.height == 0 {
            return;
        }

        if !sops_in_config && !sops_on_disk {
            // Check for half-initialized state first.
            if let Some(detail) = self.sops_half_state() {
                let lines: Vec<Line<'_>> = vec![
                    Line::from(Span::styled(
                        "  ⚠ SOPS half-initialized — one file is missing:",
                        theme.status_warn,
                    )),
                    Line::from(Span::styled(format!("    {detail}"), theme.dim)),
                    Line::from(""),
                    Line::from(Span::styled(
                        "  [f] force re-initialize (overwrites existing SOPS files)",
                        theme.status_warn,
                    )),
                    Line::from(Span::styled(
                        "  Or resolve manually and press [i] to link.",
                        theme.dim,
                    )),
                ];
                if self.secrets_initializing {
                    let mut l = lines;
                    l.push(Line::from(Span::styled("  Re-initializing…", theme.dim)));
                    frame.render_widget(Paragraph::new(Text::from(l)), inner);
                } else {
                    frame.render_widget(Paragraph::new(Text::from(lines)), inner);
                }
            } else {
                // No config, no files — fresh setup needed.
                let mut lines: Vec<Line<'_>> = vec![Line::from(Span::styled(
                    "  SOPS not initialized. Press [i] to set up encrypted secrets.",
                    theme.status_warn,
                ))];
                if self.secrets_initializing {
                    lines.push(Line::from(Span::styled("  Initializing…", theme.dim)));
                }
                frame.render_widget(Paragraph::new(Text::from(lines)), inner);

                if self.secrets_initializing && inner.height > 1 {
                    let spinner_area = Rect::new(inner.x + 16, inner.y + 1, 1, 1);
                    frame.render_widget(Spinner::new(self.tick_count, theme), spinner_area);
                }
            }
        } else if sops_on_disk {
            // Files exist but config doesn't reference them — re-link.
            let mut lines: Vec<Line<'_>> = vec![Line::from(Span::styled(
                "  SOPS files found on disk. Press [i] to link existing secrets.",
                theme.status_warn,
            ))];
            if self.secrets_initializing {
                lines.push(Line::from(Span::styled("  Linking…", theme.dim)));
            }
            frame.render_widget(Paragraph::new(Text::from(lines)), inner);

            if self.secrets_initializing && inner.height > 1 {
                let spinner_area = Rect::new(inner.x + 12, inner.y + 1, 1, 1);
                frame.render_widget(Spinner::new(self.tick_count, theme), spinner_area);
            }
        } else if !self.secrets_fetched {
            frame.render_widget(Paragraph::new(Span::styled("  Loading…", theme.dim)), inner);
            // Spinner next to loading text.
            if inner.width > 12 {
                let spinner_area = Rect::new(inner.x + 12, inner.y, 1, 1);
                frame.render_widget(Spinner::new(self.tick_count, theme), spinner_area);
            }
        } else {
            let header = Row::new(vec!["  Key", "Status", "Required by"]).style(theme.header);
            let widths = [
                Constraint::Min(16),
                Constraint::Length(12),
                Constraint::Min(12),
            ];

            let rows: Vec<Row<'_>> = self
                .secrets_list
                .iter()
                .enumerate()
                .map(|(i, entry)| {
                    let marker = if i == self.secrets_selected {
                        "▸ "
                    } else {
                        "  "
                    };
                    let style = if i == self.secrets_selected {
                        theme.selected.add_modifier(Modifier::BOLD)
                    } else {
                        ratatui::style::Style::default()
                    };
                    let status = if entry.is_set {
                        Span::styled("● set", theme.status_ok)
                    } else {
                        Span::styled("○ missing", theme.status_warn)
                    };
                    let deps = if entry.required_by.is_empty() {
                        String::new()
                    } else {
                        entry.required_by.join(", ")
                    };
                    Row::new(vec![
                        Line::from(Span::styled(format!("{marker}{}", entry.key), style)),
                        Line::from(status),
                        Line::from(Span::styled(deps, theme.dim)),
                    ])
                })
                .collect();

            frame.render_widget(
                ScrollableTable::new(rows, widths)
                    .header(header)
                    .selected(self.secrets_selected)
                    .empty(EmptyState::new("No secrets set.", theme).hint("[s] to add a secret")),
                inner,
            );
        }

        if let Some(ia) = input_area {
            if let Some(ref fi) = self.secrets_input {
                fi.input.render(ia, frame, theme);
            }
        }
    }

    fn handle_secrets_key(&mut self, key: KeyEvent) -> ScreenAction {
        if let Some(mut fi) = self.secrets_input.take() {
            return match fi.input.handle_key(key) {
                InputAction::Cancel => ScreenAction::EndInput,
                InputAction::Continue => {
                    self.secrets_input = Some(fi);
                    ScreenAction::Noop
                }
                InputAction::Submit(val) => {
                    let mut form = fi.form;
                    match form.advance(&val) {
                        FormResult::NextPrompt(prompt) => {
                            self.secrets_input = Some(FormInput {
                                form,
                                input: TextInput::new(prompt, FORM_MAX_LEN),
                            });
                            ScreenAction::Noop
                        }
                        FormResult::Complete => {
                            let Some(params) = form.into_params(&val) else {
                                return ScreenAction::Noop;
                            };
                            self.pending_action = Some(PendingSetup::SecretsSet {
                                key: params.key,
                                value: params.value,
                            });
                            ScreenAction::AsyncAction
                        }
                        FormResult::Invalid(msg) => ScreenAction::Flash(FlashMessage::error(msg)),
                        FormResult::Cancelled => ScreenAction::EndInput,
                    }
                }
            };
        }

        if self.secrets_removing {
            if key.code == KeyCode::Char('y') {
                self.secrets_removing = false;
                if let Some(entry) = self.secrets_list.get(self.secrets_selected) {
                    self.pending_action = Some(PendingSetup::SecretsRemove {
                        key: entry.key.clone(),
                    });
                    return ScreenAction::AsyncAction;
                }
            }
            self.secrets_removing = false;
            return ScreenAction::EndInput;
        }

        let sops_in_config = self.config.secrets.sops_secrets_file.is_some();

        match key.code {
            // Init or re-link SOPS.
            KeyCode::Char('i') if !sops_in_config && !self.secrets_initializing => {
                self.secrets_initializing = true;
                self.pending_action = Some(PendingSetup::SecretsInit);
                ScreenAction::AsyncAction
            }
            // Force re-initialize — recovers from half-initialized state.
            KeyCode::Char('f') if !sops_in_config && !self.secrets_initializing => {
                self.secrets_initializing = true;
                self.pending_action = Some(PendingSetup::SecretsForceInit);
                ScreenAction::AsyncAction
            }
            // Set secret.
            KeyCode::Char('s') if sops_in_config => {
                let form = KeyValueForm::secrets_set();
                let prompt = form.prompt();
                self.secrets_input = Some(FormInput {
                    form,
                    input: TextInput::new(prompt, FORM_MAX_LEN),
                });
                ScreenAction::BeginInput
            }
            // Remove secret.
            KeyCode::Char('r') if sops_in_config && !self.secrets_list.is_empty() => {
                self.secrets_removing = true;
                ScreenAction::BeginInput
            }
            KeyCode::Up | KeyCode::Char('k') => {
                config_logic::cursor_up(&mut self.secrets_selected);
                ScreenAction::Noop
            }
            KeyCode::Down | KeyCode::Char('j') => {
                config_logic::cursor_down(&mut self.secrets_selected, self.secrets_list.len());
                ScreenAction::Noop
            }
            _ => ScreenAction::Noop,
        }
    }

    // -- Presets tab -----------------------------------------------------------

    fn render_presets(&self, area: Rect, frame: &mut Frame, theme: &Theme) {
        if let Some(ref preset) = self.preset {
            self.render_preset_builder(preset, area, frame, theme);
            return;
        }

        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(theme.content_border_type)
            .border_style(theme.border_active)
            .title(format!(" Presets ({}) ", self.preset_list.len()));
        let inner = block.inner(area);
        frame.render_widget(block, area);
        if inner.width == 0 || inner.height == 0 {
            return;
        }

        if !self.preset_list_loaded {
            frame.render_widget(Paragraph::new(Span::styled("  Loading…", theme.dim)), inner);
            return;
        }

        if self.preset_list.is_empty() {
            let lines = vec![
                Line::from(Span::styled("  No presets found.", theme.dim)),
                Line::default(),
                Line::from(Span::styled(
                    "  [p] Start preset builder",
                    ratatui::style::Style::default(),
                )),
            ];
            frame.render_widget(
                Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false }),
                inner,
            );
            return;
        }

        // Activation confirmation is now handled by the overlay in the
        // TuiScreen render method — no inline rendering needed here.

        let header = Row::new(vec!["  Name", "Manifests", "Grant", "Source"]).style(theme.header);
        let widths = [
            Constraint::Min(18),
            Constraint::Length(16),
            Constraint::Length(20),
            Constraint::Length(10),
        ];

        let rows: Vec<Row<'_>> = self
            .preset_list
            .iter()
            .enumerate()
            .map(|(i, entry)| {
                let base = if i == self.preset_selected {
                    theme.selected.add_modifier(Modifier::BOLD)
                } else {
                    ratatui::style::Style::default()
                };
                let marker = if i == self.preset_selected {
                    "▸ "
                } else {
                    "  "
                };
                Row::new(vec![
                    Line::from(Span::styled(format!("{marker}{}", entry.preset.name), base)),
                    Line::from(Span::styled(entry.preset.manifests.to_toml_value(), base)),
                    Line::from(Span::styled(
                        entry.preset.wildcard_grant.to_toml_value().to_string(),
                        base,
                    )),
                    Line::from(Span::styled(entry.source.label().to_string(), base)),
                ])
            })
            .collect();

        frame.render_widget(
            ScrollableTable::new(rows, widths)
                .header(header)
                .selected(self.preset_selected),
            inner,
        );
    }

    fn render_preset_builder(
        &self,
        preset: &PresetStep,
        area: Rect,
        frame: &mut Frame,
        theme: &Theme,
    ) {
        let (content_area, input_area) = match preset {
            PresetStep::Name { .. } | PresetStep::Description { .. } => {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Min(1), Constraint::Length(3)])
                    .split(area);
                (chunks[0], Some(chunks[1]))
            }
            _ => (area, None),
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(theme.content_border_type)
            .border_style(theme.border_active)
            .title(" Preset Builder ");
        let inner = block.inner(content_area);
        frame.render_widget(block, content_area);
        if inner.width == 0 || inner.height == 0 {
            return;
        }

        let mut lines: Vec<Line<'_>> = Vec::with_capacity(32);
        match preset {
            PresetStep::SelectActions { available, cursor } => {
                let selected_count = available.iter().filter(|(_, on)| *on).count();
                lines.push(Line::from(Span::styled(
                    format!("  Select actions ({selected_count} selected)"),
                    theme.header,
                )));
                lines.push(Line::from(Span::styled(
                    "  [Space] toggle  [Enter] proceed  [Esc] cancel",
                    theme.dim,
                )));
                lines.push(Line::default());
                for (i, (id, on)) in available.iter().enumerate() {
                    let marker = if i == *cursor { "▸ " } else { "  " };
                    let check = if *on { "[×] " } else { "[ ] " };
                    let style = if i == *cursor {
                        theme.selected
                    } else {
                        ratatui::style::Style::default()
                    };
                    lines.push(Line::from(Span::styled(
                        format!("{marker}{check}{id}"),
                        style,
                    )));
                }
            }
            PresetStep::Grant { cursor, .. } => {
                lines.push(Line::from(Span::styled(
                    "  Wildcard grant level",
                    theme.header,
                )));
                lines.push(Line::default());
                for (i, (_, desc)) in WILDCARD_GRANTS.iter().enumerate() {
                    let marker = if i == *cursor { "  ▸ " } else { "    " };
                    let style = if i == *cursor {
                        theme.selected.add_modifier(Modifier::BOLD)
                    } else {
                        ratatui::style::Style::default()
                    };
                    lines.push(Line::from(Span::styled(format!("{marker}{desc}"), style)));
                }
                lines.push(Line::default());
                lines.push(Line::from(Span::styled(
                    "  [↑↓] select  [Enter] confirm  [Esc] cancel",
                    theme.dim,
                )));
            }
            PresetStep::Name { .. } => {
                lines.push(Line::from(Span::styled("  Preset name", theme.header)));
                lines.push(Line::from(Span::styled(
                    "  Alphanumeric, hyphens, underscores.",
                    theme.dim,
                )));
            }
            PresetStep::Description { .. } => {
                lines.push(Line::from(Span::styled(
                    "  Preset description",
                    theme.header,
                )));
                lines.push(Line::from(Span::styled(
                    "  One-line summary of this preset.",
                    theme.dim,
                )));
            }
        }

        frame.render_widget(
            Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false }),
            inner,
        );
        if let Some(ia) = input_area {
            match preset {
                PresetStep::Name { ref input, .. } | PresetStep::Description { ref input, .. } => {
                    input.render(ia, frame, theme);
                }
                _ => {}
            }
        }
    }

    fn handle_presets_key(&mut self, key: KeyEvent) -> ScreenAction {
        // If the preset builder is active, delegate to it.
        if let Some(preset) = self.preset.take() {
            return self.handle_preset_builder_key(preset, key);
        }

        // Activation confirmation.
        if self.preset_activating {
            match key.code {
                KeyCode::Char('y') => {
                    self.preset_activating = false;
                    if let Some(entry) = self.preset_list.get(self.preset_selected) {
                        let plan = crate::InitPlan {
                            preset: entry.preset.clone(),
                            location: crate::InstallLocation::Project,
                            include_examples: false,
                            force: true,
                            identity: if self.config.identity.provider
                                == latchgate_config::IdentityProviderKind::Peercred
                            {
                                crate::IdentityChoice::Peercred
                            } else {
                                crate::IdentityChoice::None
                            },
                            signing: if self.config.signing.receipt_signing_key_path.is_some() {
                                crate::SigningChoice::Persistent
                            } else {
                                crate::SigningChoice::Ephemeral
                            },
                        };
                        self.pending_action = Some(PendingSetup::ActivatePreset { plan });
                        return ScreenAction::AsyncAction;
                    }
                }
                KeyCode::Char('n') | KeyCode::Esc => {
                    self.preset_activating = false;
                    return ScreenAction::EndInput;
                }
                _ => {}
            }
            return ScreenAction::Noop;
        }

        match key.code {
            // Navigate.
            KeyCode::Up | KeyCode::Char('k') => {
                if self.preset_selected > 0 {
                    self.preset_selected -= 1;
                }
                ScreenAction::Noop
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.preset_selected + 1 < self.preset_list.len() {
                    self.preset_selected += 1;
                }
                ScreenAction::Noop
            }
            // Activate selected preset.
            KeyCode::Char('a') if !self.preset_list.is_empty() => {
                self.preset_activating = true;
                ScreenAction::BeginInput
            }
            // Export builder.
            KeyCode::Char('p') => match self.setup.list_manifests() {
                Ok(infos) => {
                    if infos.is_empty() {
                        return ScreenAction::Flash(FlashMessage::error(
                            "No manifests found — nothing to include in a preset",
                        ));
                    }
                    let available: Vec<(String, bool)> = infos
                        .into_iter()
                        .map(|info| (info.action_id, false))
                        .collect();
                    self.preset = Some(PresetStep::SelectActions {
                        available,
                        cursor: 0,
                    });
                    ScreenAction::BeginInput
                }
                Err(e) => ScreenAction::Flash(FlashMessage::error(format!("Manifests: {e}"))),
            },
            _ => ScreenAction::Noop,
        }
    }

    fn handle_preset_builder_key(&mut self, preset: PresetStep, key: KeyEvent) -> ScreenAction {
        match preset {
            PresetStep::SelectActions {
                mut available,
                mut cursor,
            } => match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    cursor = cursor.saturating_sub(1);
                    self.preset = Some(PresetStep::SelectActions { available, cursor });
                    ScreenAction::Noop
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if cursor + 1 < available.len() {
                        cursor += 1;
                    }
                    self.preset = Some(PresetStep::SelectActions { available, cursor });
                    ScreenAction::Noop
                }
                KeyCode::Char(' ') => {
                    if let Some(entry) = available.get_mut(cursor) {
                        entry.1 = !entry.1;
                    }
                    self.preset = Some(PresetStep::SelectActions { available, cursor });
                    ScreenAction::Noop
                }
                KeyCode::Enter => {
                    let any_selected = available.iter().any(|(_, on)| *on);
                    if !any_selected {
                        self.preset = Some(PresetStep::SelectActions { available, cursor });
                        return ScreenAction::Flash(FlashMessage::error(
                            "Select at least one action for the preset",
                        ));
                    }
                    let action_ids: Vec<String> = available
                        .into_iter()
                        .filter(|(_, on)| *on)
                        .map(|(id, _)| id)
                        .collect();
                    self.preset = Some(PresetStep::Grant {
                        action_ids,
                        cursor: 0,
                    });
                    ScreenAction::Noop
                }
                KeyCode::Esc => ScreenAction::EndInput,
                _ => {
                    self.preset = Some(PresetStep::SelectActions { available, cursor });
                    ScreenAction::Noop
                }
            },

            PresetStep::Grant {
                action_ids,
                mut cursor,
            } => match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    cursor = cursor.saturating_sub(1);
                    self.preset = Some(PresetStep::Grant { action_ids, cursor });
                    ScreenAction::Noop
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if cursor + 1 < WILDCARD_GRANTS.len() {
                        cursor += 1;
                    }
                    self.preset = Some(PresetStep::Grant { action_ids, cursor });
                    ScreenAction::Noop
                }
                KeyCode::Enter => {
                    let grant = WILDCARD_GRANTS[cursor].0.to_string();
                    self.preset = Some(PresetStep::Name {
                        action_ids,
                        grant,
                        input: TextInput::new(" Preset name (Enter/Esc) ", 64),
                    });
                    ScreenAction::Noop
                }
                KeyCode::Esc => ScreenAction::EndInput,
                _ => {
                    self.preset = Some(PresetStep::Grant { action_ids, cursor });
                    ScreenAction::Noop
                }
            },

            PresetStep::Name {
                action_ids,
                grant,
                mut input,
            } => match input.handle_key(key) {
                InputAction::Cancel => ScreenAction::EndInput,
                InputAction::Continue => {
                    self.preset = Some(PresetStep::Name {
                        action_ids,
                        grant,
                        input,
                    });
                    ScreenAction::Noop
                }
                InputAction::Submit(name) => {
                    let name = name.trim().to_string();
                    if name.is_empty() {
                        return ScreenAction::EndInput;
                    }
                    self.preset = Some(PresetStep::Description {
                        action_ids,
                        grant,
                        name,
                        input: TextInput::new(" Description (Enter/Esc) ", FORM_MAX_LEN),
                    });
                    ScreenAction::Noop
                }
            },

            PresetStep::Description {
                action_ids,
                grant,
                name,
                mut input,
            } => match input.handle_key(key) {
                InputAction::Cancel => ScreenAction::EndInput,
                InputAction::Continue => {
                    self.preset = Some(PresetStep::Description {
                        action_ids,
                        grant,
                        name,
                        input,
                    });
                    ScreenAction::Noop
                }
                InputAction::Submit(description) => {
                    let description = description.trim().to_string();
                    if description.is_empty() {
                        return ScreenAction::EndInput;
                    }
                    self.pending_action = Some(PendingSetup::ExportPreset {
                        name,
                        description,
                        action_ids,
                        wildcard_grant: grant,
                    });
                    ScreenAction::AsyncAction
                }
            },
        }
    }
}

impl TuiScreen for ConfigScreen {
    fn render(&self, area: Rect, frame: &mut Frame, theme: &Theme) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Min(0)])
            .split(area);

        self.render_sub_tabs(chunks[0], frame, theme);

        match self.active_tab {
            SubTab::Overview => self.render_overview(chunks[1], frame, theme),
            SubTab::Principals => self.render_principals(chunks[1], frame, theme),
            SubTab::Operators => self.render_operators(chunks[1], frame, theme),
            SubTab::Webhooks => self.render_webhooks(chunks[1], frame, theme),
            SubTab::Secrets => self.render_secrets(chunks[1], frame, theme),
            SubTab::Presets => self.render_presets(chunks[1], frame, theme),
        }

        // Persistent confirm overlays for removal states — these survive
        // past flash expiry so the operator always sees what's pending.
        if self.principal_removing {
            widgets::render_confirm_dialog(area, frame, theme, "Remove this principal?");
        } else if self.operator_removing {
            widgets::render_confirm_dialog(area, frame, theme, "Remove this operator?");
        } else if self.webhook_removing {
            widgets::render_confirm_dialog(area, frame, theme, "Remove this webhook?");
        } else if self.secrets_removing {
            widgets::render_confirm_dialog(area, frame, theme, "Remove this secret?");
        } else if self.preset_activating {
            if let Some(entry) = self.preset_list.get(self.preset_selected) {
                let q = format!(
                    "Activate preset '{}'? This overwrites manifests.",
                    entry.preset.name
                );
                widgets::render_confirm_dialog(area, frame, theme, &q);
            }
        }
    }

    fn handle_key(&mut self, key: KeyEvent, _theme: &Theme) -> ScreenAction {
        // Sub-tab navigation (when not in input mode).
        if !self.is_in_input() {
            match key.code {
                KeyCode::Left | KeyCode::Char('H') => {
                    self.policy_detail_focus = false;
                    self.active_tab = self.active_tab.prev();
                    return ScreenAction::Noop;
                }
                KeyCode::Right | KeyCode::Char('L') => {
                    self.policy_detail_focus = false;
                    self.active_tab = self.active_tab.next();
                    return ScreenAction::Noop;
                }
                KeyCode::Char(c @ '1'..='6') => {
                    self.policy_detail_focus = false;
                    if let Some(tab) = SubTab::from_digit(c) {
                        self.active_tab = tab;
                    }
                    return ScreenAction::Noop;
                }
                _ => {}
            }
        }

        match self.active_tab {
            SubTab::Overview => self.handle_overview_key(key),
            SubTab::Principals => self.handle_principals_key(key),
            SubTab::Operators => self.handle_operators_key(key),
            SubTab::Webhooks => self.handle_webhooks_key(key),
            SubTab::Secrets => self.handle_secrets_key(key),
            SubTab::Presets => self.handle_presets_key(key),
        }
    }

    fn handle_action<'a>(
        &'a mut self,
        client: &'a GateClient,
        auth: &'a OperatorAuth,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<FlashMessage>> + Send + 'a>>
    {
        Box::pin(async move {
            // Policy mutations use the gate client, not SetupOps.
            if let Some(mutation) = self.policy_pending.take() {
                return match mutation {
                    PendingSetup::PolicyGrant { principal, action } => {
                        match client
                            .policy_grant(auth, &principal, &[action.as_str()])
                            .await
                        {
                            Ok(resp) => {
                                self.policy_fetched = false; // force refresh
                                let v = resp["policy_version"].as_str().unwrap_or("?");
                                Some(FlashMessage::success(format!(
                                    "\u{2713} Granted {action} to {principal} (policy {v})"
                                )))
                            }
                            Err(e) => Some(FlashMessage::error(format!("Grant failed: {e}"))),
                        }
                    }
                    PendingSetup::PolicyRevoke { principal, action } => {
                        match client
                            .policy_revoke(auth, &principal, &[action.as_str()])
                            .await
                        {
                            Ok(resp) => {
                                self.policy_fetched = false;
                                let v = resp["policy_version"].as_str().unwrap_or("?");
                                Some(FlashMessage::success(format!(
                                    "\u{2713} Revoked {action} from {principal} (policy {v})"
                                )))
                            }
                            Err(e) => Some(FlashMessage::error(format!("Revoke failed: {e}"))),
                        }
                    }
                    _ => None,
                };
            }

            let action = self.pending_action.take()?;
            match action {
                PendingSetup::Doctor => {
                    let checks = self.doctor.run(self.config.clone()).await;
                    let err_count = checks
                        .iter()
                        .filter(|c| c.severity == DiagnosticSeverity::Error)
                        .count();
                    self.doctor_results = Some(checks);
                    self.doctor_running = false;
                    if err_count > 0 {
                        Some(FlashMessage::error(format!(
                            "Doctor: {err_count} error(s) found"
                        )))
                    } else {
                        Some(FlashMessage::success("Doctor: all checks passed"))
                    }
                }
                PendingSetup::SetConfig { key, value } => {
                    match self.setup.set_config(&key, &value) {
                        Ok(cfg) => {
                            self.config = cfg;
                            Some(FlashMessage::success(format!("✓ Set {key}")))
                        }
                        Err(e) => Some(FlashMessage::error(e)),
                    }
                }
                PendingSetup::AddPrincipal { uid, name, scopes } => {
                    match self.setup.add_principal(uid, &name, &scopes, None) {
                        Ok(cfg) => {
                            self.config = cfg;
                            Some(FlashMessage::success(format!(
                                "✓ Added principal {name} (UID {uid})"
                            )))
                        }
                        Err(e) => Some(FlashMessage::error(e)),
                    }
                }
                PendingSetup::RemovePrincipal { uid } => match self.setup.remove_principal(uid) {
                    Ok(cfg) => {
                        self.config = cfg;
                        Some(FlashMessage::success(format!(
                            "✓ Removed principal UID {uid}"
                        )))
                    }
                    Err(e) => Some(FlashMessage::error(e)),
                },
                PendingSetup::AddOperator { name } => match self.setup.add_operator(&name) {
                    Ok((cfg, api_key, key_path)) => {
                        self.config = cfg;
                        self.last_added_operator = Some((api_key, key_path));
                        Some(FlashMessage::success(format!(
                            "✓ Added operator {name} (key shown below)"
                        )))
                    }
                    Err(e) => Some(FlashMessage::error(e)),
                },
                PendingSetup::RemoveOperator { name } => match self.setup.remove_operator(&name) {
                    Ok(cfg) => {
                        self.config = cfg;
                        self.last_added_operator = None;
                        Some(FlashMessage::success(format!("✓ Removed operator {name}")))
                    }
                    Err(e) => Some(FlashMessage::error(e)),
                },
                PendingSetup::AddWebhook {
                    name,
                    url,
                    events,
                    format,
                } => match self.setup.add_webhook(&name, &url, &events, &format) {
                    Ok((cfg, secret)) => {
                        self.config = cfg;
                        // Show abbreviated secret — full value in `latchgate config show`.
                        let short = if secret.len() > 20 {
                            format!("{}…", &secret[..20])
                        } else {
                            secret.clone()
                        };
                        Some(FlashMessage::success(format!(
                            "✓ Added webhook {name}  (secret: {short})"
                        )))
                    }
                    Err(e) => Some(FlashMessage::error(e)),
                },
                PendingSetup::RemoveWebhook { name } => match self.setup.remove_webhook(&name) {
                    Ok(cfg) => {
                        self.config = cfg;
                        Some(FlashMessage::success(format!("✓ Removed webhook {name}")))
                    }
                    Err(e) => Some(FlashMessage::error(e)),
                },
                PendingSetup::TestWebhook { name } => {
                    let result = self.setup.test_webhook(&name, &self.config).await;
                    self.webhook_testing = false;
                    if result.ok {
                        Some(FlashMessage::success(format!(
                            "✓ {} — delivered in {}ms",
                            result.endpoint_name, result.elapsed_ms,
                        )))
                    } else {
                        Some(FlashMessage::error(format!(
                            "✗ {} — {}",
                            result.endpoint_name,
                            result.error.as_deref().unwrap_or("delivery failed"),
                        )))
                    }
                }
                PendingSetup::SecretsInit => {
                    self.secrets_initializing = false;
                    match self.setup.secrets_init(false) {
                        Ok(cfg) => {
                            self.config = cfg;
                            self.secrets_fetched = false;
                            Some(FlashMessage::success(
                                "✓ SOPS initialized — secrets encryption ready",
                            ))
                        }
                        Err(e) => Some(FlashMessage::error(e)),
                    }
                }
                PendingSetup::SecretsForceInit => {
                    self.secrets_initializing = false;
                    match self.setup.secrets_init(true) {
                        Ok(cfg) => {
                            self.config = cfg;
                            self.secrets_fetched = false;
                            Some(FlashMessage::success(
                                "✓ SOPS re-initialized — previous encrypted data overwritten",
                            ))
                        }
                        Err(e) => Some(FlashMessage::error(e)),
                    }
                }
                PendingSetup::SecretsSet { key, value } => {
                    match self.setup.secrets_set(&key, &value) {
                        Ok(()) => {
                            self.secrets_fetched = false;
                            Some(FlashMessage::success(format!("✓ Secret {key} set")))
                        }
                        Err(e) => Some(FlashMessage::error(e)),
                    }
                }
                PendingSetup::SecretsRemove { key } => match self.setup.secrets_remove(&key) {
                    Ok(()) => {
                        self.secrets_fetched = false;
                        Some(FlashMessage::success(format!("✓ Secret {key} removed")))
                    }
                    Err(e) => Some(FlashMessage::error(e)),
                },
                PendingSetup::ExportPreset {
                    name,
                    description,
                    action_ids,
                    wildcard_grant,
                } => {
                    self.preset = None;
                    match self.setup.export_preset(
                        &name,
                        &description,
                        &action_ids,
                        &wildcard_grant,
                    ) {
                        Ok(path) => {
                            self.preset_list_loaded = false;
                            Some(FlashMessage::success(format!(
                                "✓ Preset {name} => {}",
                                path.display()
                            )))
                        }
                        Err(e) => Some(FlashMessage::error(e)),
                    }
                }
                PendingSetup::ActivatePreset { plan } => {
                    let name = plan.preset.name.clone();
                    match self.setup.execute_init(&plan) {
                        Ok(cfg) => {
                            self.config = cfg;
                            self.preset_list_loaded = false;
                            self.restart_requested = true;
                            Some(FlashMessage::success(format!(
                                "✓ Preset '{name}' activated — restarting gate"
                            )))
                        }
                        Err(e) => Some(FlashMessage::error(format!(
                            "Preset activation failed: {e}"
                        ))),
                    }
                }
                // Policy mutations are routed via `self.policy_pending`.
                PendingSetup::PolicyGrant { .. } | PendingSetup::PolicyRevoke { .. } => None,
            }
        })
    }

    fn tick<'a>(
        &'a mut self,
        client: &'a GateClient,
        auth: &'a OperatorAuth,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async {
            self.tick_count = self.tick_count.wrapping_add(1);

            // Fetch policy ACL when Principals tab is active.
            if self.active_tab == SubTab::Principals
                && (!self.policy_fetched || self.tick_count.is_multiple_of(10))
            {
                if let Ok(resp) = client.policy_show(auth, None).await {
                    self.policy_version = resp["policy_version"].as_str().unwrap_or("").to_string();
                    self.policy_acl = resp
                        .get("acl")
                        .cloned()
                        .unwrap_or(serde_json::Value::Object(Default::default()));
                    self.policy_fetched = true;

                    // Clamp right-panel selection to prevent stale index
                    // after the action list changes (e.g. revoke).
                    if self.policy_detail_focus {
                        let items = self.principals_sorted();
                        let principal = items
                            .get(self.principal_selected)
                            .map(|(_, n, _)| n.as_str())
                            .unwrap_or("");
                        let actions = config_logic::policy_actions_for(&self.policy_acl, principal);
                        if actions.is_empty() {
                            self.policy_detail_focus = false;
                            self.policy_detail_selected = 0;
                        } else if self.policy_detail_selected >= actions.len() {
                            self.policy_detail_selected = actions.len().saturating_sub(1);
                        }
                    }
                }
            }

            // Fetch secrets list when tab is active and not yet loaded.
            if self.active_tab == SubTab::Secrets
                && !self.secrets_fetched
                && self.config.secrets.sops_secrets_file.is_some()
            {
                if let Ok(entries) = self.setup.secrets_list() {
                    self.secrets_list = entries;
                }
                self.secrets_fetched = true;
            }

            // Load presets list when tab is active and not yet loaded.
            if self.active_tab == SubTab::Presets && !self.preset_list_loaded {
                self.preset_list = self.setup.list_presets();
                self.preset_list_loaded = true;
                if self.preset_selected >= self.preset_list.len() && !self.preset_list.is_empty() {
                    self.preset_selected = self.preset_list.len() - 1;
                }
            }
        })
    }

    fn tab_label(&self) -> &'static str {
        "Setup"
    }

    fn is_modal(&self) -> bool {
        self.is_in_input()
    }

    fn needs_confirm_input(&self) -> bool {
        self.principal_removing
            || self.operator_removing
            || self.webhook_removing
            || self.secrets_removing
            || self.preset_activating
    }

    fn update_config(&mut self, config: &latchgate_config::Config) {
        self.config = config.clone();
        self.doctor_results = None;
        self.secrets_fetched = false;
        self.secrets_list.clear();
        self.preset_list_loaded = false;
        self.policy_fetched = false;
        self.policy_detail_focus = false;
        self.policy_detail_selected = 0;
        self.policy_detail_scroll = 0;
    }

    fn take_restart_request(&mut self) -> bool {
        std::mem::take(&mut self.restart_requested)
    }

    fn status_hint(&self) -> &str {
        if self.preset.is_some() {
            return "[↑↓]navigate  [Space]toggle  [Enter]proceed  [Esc]cancel";
        }
        match self.active_tab {
            SubTab::Overview => "[i]nit  [u]p  [s]et config  [d]octor  [e]dit  [←=>]sub-tab",
            SubTab::Principals => {
                if self.policy_detail_focus {
                    "[↑↓]select  [x]revoke  [h/Esc]back  [←→]sub-tab"
                } else {
                    "[a]dd  [r]emove  [g]rant  [x]revoke  [l]focus actions  [←→]sub-tab  [↑↓]navigate"
                }
            }
            SubTab::Operators => "[a]dd  [r]emove  [←=>]sub-tab  [↑↓]navigate",
            SubTab::Webhooks => "[a]dd  [r]emove  [t]est  [←=>]sub-tab  [↑↓]navigate",
            SubTab::Secrets => "[i]nit  [s]et  [r]emove  [←=>]sub-tab  [↑↓]navigate",
            SubTab::Presets => {
                if self.preset_activating {
                    "[y]confirm  [n/Esc]cancel"
                } else if self.preset_list.is_empty() {
                    "[p]export builder  [←=>]sub-tab"
                } else {
                    "[↑↓]navigate  [a]ctivate  [p]export builder  [←=>]sub-tab"
                }
            }
        }
    }

    fn help_keys(&self) -> &'static [(&'static str, &'static str)] {
        &[
            ("\u{2190}/H", "Previous sub-tab"),
            ("\u{2192}/L", "Next sub-tab"),
            ("1-6", "Jump to sub-tab"),
            ("a", "Add item (Principals/Operators/Webhooks)"),
            ("r", "Remove selected item"),
            ("g", "Grant action to principal (Principals tab)"),
            ("x", "Revoke action from principal (Principals tab)"),
            ("l", "Focus action list (Principals tab)"),
            ("h/Esc", "Return to principal list (Principals tab)"),
            ("t", "Test selected webhook (Webhooks tab)"),
            ("d", "Run doctor (Overview tab)"),
            ("e", "Open config in $EDITOR (Overview tab)"),
            ("u", "Start gate via `up` (Overview tab)"),
            ("p", "Build custom preset (Presets tab)"),
        ]
    }
}
