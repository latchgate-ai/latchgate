//! Screen 3 — Actions.
//!
//! Registry browser, manifest editor, and new-action creation wizard.
//! Left pane lists all registered actions; right pane shows detail (browse),
//! an editable field list (edit), or the creation wizard (create).
//!
//! Browse mode fetches data from the running gate via `GateClient`.
//! Edit mode loads the manifest from disk via `SetupOps::read_manifest()`
//! and writes back via `SetupOps::write_manifest()` on save.
//! Create mode walks through a short wizard to build a valid ActionSpec
//! skeleton, then transitions to edit mode for fine-tuning.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Paragraph, Row, Wrap};
use ratatui::Frame;
use serde_json::Value;

use latchgate_client::{ClientError, GateClient, OperatorAuth};
use latchgate_core::{FsOperation, RiskLevel, SecretDecl, VerifierKind};
use latchgate_registry::manifest::{EgressConfig, FsConfig, IoConfig, TemplateConfig};
use latchgate_registry::ActionSpec;

use super::formatting::{join_str_array, truncate};
use super::input::{FlashMessage, InputAction, TextInput};
use super::screen::{ScreenAction, TuiScreen};
use super::theme::Theme;
use super::widgets::{self, EmptyState, ScrollableTable, Spinner};
use super::SetupOps;

// Constants

const FORM_MAX_LEN: usize = 256;

/// Wall-clock timeout after which a pending action that has not appeared in
/// the gate registry is considered stale.  Surfaces a diagnostic pointing at
/// a `manifests_dir` mismatch rather than leaving the "pending" marker
/// visible indefinitely.
const PENDING_ACTION_STALE_SECS: u64 = 30;

const RISK_LEVELS: &[RiskLevel] = &[
    RiskLevel::Low,
    RiskLevel::Medium,
    RiskLevel::High,
    RiskLevel::Critical,
];

// Edit-mode types

/// Identifiers for editable fields, computed per-manifest based on its type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EditField {
    RiskLevel,
    Fuel,
    MemoryMb,
    TimeoutSeconds,
    MaxIoCalls,
    MaxRequestBytes,
    MaxResponseBytes,
    EgressDomains,
    FsAllowedPaths,
    FsDeniedPaths,
    Secrets,
}

impl EditField {
    fn label(self) -> &'static str {
        match self {
            Self::RiskLevel => "Risk Level",
            Self::Fuel => "Fuel",
            Self::MemoryMb => "Memory (MB)",
            Self::TimeoutSeconds => "Timeout (s)",
            Self::MaxIoCalls => "Max IO Calls",
            Self::MaxRequestBytes => "Max Request (B)",
            Self::MaxResponseBytes => "Max Response (B)",
            Self::EgressDomains => "Allowed Domains",
            Self::FsAllowedPaths => "Allowed Paths",
            Self::FsDeniedPaths => "Denied Paths",
            Self::Secrets => "Secrets",
        }
    }

    fn is_list(self) -> bool {
        matches!(
            self,
            Self::EgressDomains | Self::FsAllowedPaths | Self::FsDeniedPaths | Self::Secrets
        )
    }
}

/// Compute the editable fields for a given manifest.
fn editable_fields(spec: &ActionSpec) -> Vec<EditField> {
    let mut fields = vec![
        EditField::RiskLevel,
        EditField::Fuel,
        EditField::MemoryMb,
        EditField::TimeoutSeconds,
        EditField::MaxIoCalls,
        EditField::MaxRequestBytes,
        EditField::MaxResponseBytes,
    ];
    if spec.egress.profile == "proxy_allowlist" {
        fields.push(EditField::EgressDomains);
    }
    if spec.fs.is_some() {
        fields.push(EditField::FsAllowedPaths);
        fields.push(EditField::FsDeniedPaths);
    }
    fields.push(EditField::Secrets);
    fields
}

/// Active sub-editor within a field.
enum FieldEditor {
    /// Text input for numeric fields.
    Numeric(TextInput),
    /// Text input for adding an item to a list field.
    ListAdd(TextInput),
}

/// In-memory editing state for a single manifest.
struct EditState {
    spec: ActionSpec,
    fields: Vec<EditField>,
    field_cursor: usize,
    /// Sub-cursor for items within a list field.
    list_cursor: usize,
    /// Active sub-editor, if any.
    editor: Option<FieldEditor>,
    /// Confirmation pending for removing a list item.
    removing: bool,
    /// Confirmation pending for discarding unsaved changes.
    confirm_discard: bool,
    dirty: bool,
}

impl EditState {
    fn new(spec: ActionSpec) -> Self {
        let fields = editable_fields(&spec);
        Self {
            spec,
            fields,
            field_cursor: 0,
            list_cursor: 0,
            editor: None,
            removing: false,
            confirm_discard: false,
            dirty: false,
        }
    }

    fn current_field(&self) -> Option<EditField> {
        self.fields.get(self.field_cursor).copied()
    }

    /// Get the list items for the current list field.
    fn list_items(&self) -> Vec<String> {
        match self.current_field() {
            Some(EditField::EgressDomains) => self.spec.egress.allowed_domains.clone(),
            Some(EditField::FsAllowedPaths) => self
                .spec
                .fs
                .as_ref()
                .map_or_else(Vec::new, |f| f.allowed_paths.clone()),
            Some(EditField::FsDeniedPaths) => self
                .spec
                .fs
                .as_ref()
                .map_or_else(Vec::new, |f| f.denied_paths.clone()),
            Some(EditField::Secrets) => self
                .spec
                .secrets
                .iter()
                .map(|s| {
                    if s.required {
                        format!("{} (required)", s.name)
                    } else {
                        s.name.to_string()
                    }
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Get the display value for a scalar field.
    fn field_value(&self, field: EditField) -> String {
        match field {
            EditField::RiskLevel => self.spec.risk_level.as_str().to_string(),
            EditField::Fuel => self.spec.resource_limits.fuel.to_string(),
            EditField::MemoryMb => self.spec.resource_limits.memory_mb.to_string(),
            EditField::TimeoutSeconds => self.spec.resource_limits.timeout_seconds.to_string(),
            EditField::MaxIoCalls => self.spec.resource_limits.max_io_calls.to_string(),
            EditField::MaxRequestBytes => self.spec.io.max_request_bytes.to_string(),
            EditField::MaxResponseBytes => self.spec.io.max_response_bytes.to_string(),
            EditField::EgressDomains => {
                let n = self.spec.egress.allowed_domains.len();
                format!("{n} domain(s)")
            }
            EditField::FsAllowedPaths => {
                let n = self.spec.fs.as_ref().map_or(0, |f| f.allowed_paths.len());
                format!("{n} path(s)")
            }
            EditField::FsDeniedPaths => {
                let n = self.spec.fs.as_ref().map_or(0, |f| f.denied_paths.len());
                format!("{n} path(s)")
            }
            EditField::Secrets => {
                let n = self.spec.secrets.len();
                format!("{n} secret(s)")
            }
        }
    }

    /// Apply a numeric value to the current field.
    fn apply_numeric(&mut self, raw: &str) -> Result<(), String> {
        let field = self.current_field().ok_or("no field selected")?;
        match field {
            EditField::Fuel => {
                self.spec.resource_limits.fuel =
                    raw.parse().map_err(|_| "invalid number".to_string())?;
            }
            EditField::MemoryMb => {
                self.spec.resource_limits.memory_mb =
                    raw.parse().map_err(|_| "invalid number".to_string())?;
            }
            EditField::TimeoutSeconds => {
                self.spec.resource_limits.timeout_seconds =
                    raw.parse().map_err(|_| "invalid number".to_string())?;
            }
            EditField::MaxIoCalls => {
                self.spec.resource_limits.max_io_calls =
                    raw.parse().map_err(|_| "invalid number".to_string())?;
            }
            EditField::MaxRequestBytes => {
                self.spec.io.max_request_bytes =
                    raw.parse().map_err(|_| "invalid number".to_string())?;
            }
            EditField::MaxResponseBytes => {
                self.spec.io.max_response_bytes =
                    raw.parse().map_err(|_| "invalid number".to_string())?;
            }
            _ => return Err("field is not numeric".into()),
        }
        self.dirty = true;
        Ok(())
    }

    /// Add an item to the current list field.
    fn list_add(&mut self, value: String) {
        match self.current_field() {
            Some(EditField::EgressDomains) => {
                self.spec.egress.allowed_domains.push(value);
            }
            Some(EditField::FsAllowedPaths) => {
                if let Some(ref mut fs) = self.spec.fs {
                    fs.allowed_paths.push(value);
                }
            }
            Some(EditField::FsDeniedPaths) => {
                if let Some(ref mut fs) = self.spec.fs {
                    fs.denied_paths.push(value);
                }
            }
            Some(EditField::Secrets) => {
                self.spec.secrets.push(SecretDecl {
                    name: Arc::from(value.as_str()),
                    required: false,
                });
            }
            _ => return,
        }
        self.dirty = true;
    }

    /// Remove the item at `list_cursor` from the current list field.
    fn list_remove(&mut self) {
        let idx = self.list_cursor;
        let removed = match self.current_field() {
            Some(EditField::EgressDomains) => {
                if idx < self.spec.egress.allowed_domains.len() {
                    self.spec.egress.allowed_domains.remove(idx);
                    true
                } else {
                    false
                }
            }
            Some(EditField::FsAllowedPaths) => {
                if let Some(ref mut fs) = self.spec.fs {
                    if idx < fs.allowed_paths.len() {
                        fs.allowed_paths.remove(idx);
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            Some(EditField::FsDeniedPaths) => {
                if let Some(ref mut fs) = self.spec.fs {
                    if idx < fs.denied_paths.len() {
                        fs.denied_paths.remove(idx);
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            Some(EditField::Secrets) => {
                if idx < self.spec.secrets.len() {
                    self.spec.secrets.remove(idx);
                    true
                } else {
                    false
                }
            }
            _ => return,
        };
        if !removed {
            return;
        }
        self.dirty = true;
        // Clamp cursor.
        let len = self.list_items().len();
        if self.list_cursor >= len && len > 0 {
            self.list_cursor = len - 1;
        }
    }

    /// Cycle risk level to the next value.
    fn cycle_risk(&mut self) {
        let idx = RISK_LEVELS
            .iter()
            .position(|&r| r == self.spec.risk_level)
            .unwrap_or(0);
        self.spec.risk_level = RISK_LEVELS[(idx + 1) % RISK_LEVELS.len()];
        self.dirty = true;
    }
}

/// Async action pending execution.
enum PendingEdit {
    Save { spec: Box<ActionSpec> },
}

// Creation wizard types

/// Provider presets for the creation wizard.
const HTTP_METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE", "PATCH"];

/// Multi-step wizard state for creating a new action manifest.
enum CreateStep {
    /// Step 1: enter action_id.
    ActionId(TextInput),
    /// Step 2: select provider type.
    ProviderType { action_id: String, cursor: usize },
    /// Step 3a (HTTP): select HTTP method.
    HttpMethod { action_id: String, cursor: usize },
    /// Step 3b (HTTP): enter URL template.
    HttpUrl {
        action_id: String,
        method: String,
        input: TextInput,
    },
    /// Step 3a (FS): select allowed operations.
    FsOps { action_id: String, cursor: usize },
}

/// Labels for ProviderType selection.
const PROVIDER_TYPES: &[(&str, &str)] = &[
    ("builtin:http_api", "HTTP API (template-based)"),
    ("builtin:fs", "Filesystem (read/write/delete)"),
];

/// Labels for FS operation presets.
const FS_OP_PRESETS: &[(&str, &[FsOperation])] = &[
    ("Read only", &[FsOperation::Read]),
    (
        "Read + Write",
        &[
            FsOperation::Read,
            FsOperation::Create,
            FsOperation::Overwrite,
        ],
    ),
    (
        "Full (read/write/delete)",
        &[
            FsOperation::Read,
            FsOperation::Create,
            FsOperation::Overwrite,
            FsOperation::Delete,
        ],
    ),
];

/// Build a valid HTTP API action skeleton.
fn build_http_spec(action_id: String, method: String, url_template: String) -> ActionSpec {
    let mut spec = ActionSpec {
        action_id,
        version: "1.0.0".into(),
        provider_module_digest: "builtin:http_api".into(),
        provider_source: None,
        required_imports: vec!["latchgate:io/http".into(), "latchgate:io/log".into()],
        resource_limits: Default::default(),
        verifier_kind: VerifierKind::HttpStatus,
        verification_config: None,
        io: IoConfig::default(),
        egress: EgressConfig {
            profile: "proxy_allowlist".into(),
            allowed_domains: Vec::new(),
            allowed_methods: Vec::new(),
        },
        secrets: Vec::new(),
        risk_level: RiskLevel::Low,
        declared_side_effects: vec![if method == "GET" {
            "http_read".into()
        } else {
            "http_write".into()
        }],
        required_scopes: vec!["tools:call".into()],
        database_config: None,
        template: Some(TemplateConfig {
            method,
            url_template,
            headers: HashMap::new(),
            body_template: None,
        }),
        tags: Vec::new(),
        fs: None,
        database_mode: None,
        secret_names: Vec::new(),
        content_digest: String::new(),
    };
    spec.finalize_digest();
    spec
}

/// Build a valid FS action skeleton.
fn build_fs_spec(action_id: String, ops: Vec<FsOperation>) -> ActionSpec {
    let has_write = ops
        .iter()
        .any(|o| matches!(o, FsOperation::Create | FsOperation::Overwrite));
    let has_delete = ops.iter().any(|o| matches!(o, FsOperation::Delete));

    let mut effects = Vec::new();
    if ops.contains(&FsOperation::Read) {
        effects.push("fs_read".into());
    }
    if has_write {
        effects.push("fs_write".into());
    }
    if has_delete {
        effects.push("fs_delete".into());
    }

    let mut spec = ActionSpec {
        action_id,
        version: "1.0.0".into(),
        provider_module_digest: "builtin:fs".into(),
        provider_source: None,
        required_imports: vec!["latchgate:io/fs".into(), "latchgate:io/log".into()],
        resource_limits: Default::default(),
        verifier_kind: VerifierKind::FsHash,
        verification_config: None,
        io: IoConfig::default(),
        egress: EgressConfig::default(), // None — fs has no network
        secrets: Vec::new(),
        risk_level: if has_delete {
            RiskLevel::High
        } else if has_write {
            RiskLevel::Medium
        } else {
            RiskLevel::Low
        },
        declared_side_effects: effects,
        required_scopes: vec!["tools:call".into()],
        database_config: None,
        template: None,
        tags: Vec::new(),
        fs: Some(FsConfig {
            allowed_operations: ops,
            allowed_paths: Vec::new(),
            denied_paths: vec!["**/.git/**".into()],
            max_file_bytes: 10 * 1024 * 1024,
            compiled_allowed: Vec::new(),
            compiled_denied: Vec::new(),
        }),
        database_mode: None,
        secret_names: Vec::new(),
        content_digest: String::new(),
    };
    spec.finalize_digest();
    spec
}

// Preset builder types

// Pending-action tracking

/// An action ID that was saved to disk but has not yet appeared in the
/// running gate's registry.  The `added_at` timestamp drives the stale-
/// action diagnostic: if the action does not resolve within
/// [`PENDING_ACTION_STALE_SECS`] of a successful registry fetch, the most
/// likely cause is a `manifests_dir` mismatch.
struct PendingAction {
    action_id: String,
    added_at: Instant,
}

// ActionsScreen

pub(crate) struct ActionsScreen {
    // -- Browse state --------------------------------------------------------
    actions: Vec<Value>,
    selected: usize,
    detail: Option<Value>,
    error: Option<String>,
    fetched: bool,
    needs_refresh: bool,
    tick_count: usize,

    // -- Edit / create state ----------------------------------------------------
    setup: Arc<dyn SetupOps>,
    edit: Option<EditState>,
    create: Option<CreateStep>,
    pending_edit: Option<PendingEdit>,
    /// Action IDs saved to disk but not yet loaded by the gate (requires reload).
    pending_actions: Vec<PendingAction>,
    /// After save/create, seek the cursor to this action on the next list fetch.
    select_after_refresh: Option<String>,

    // -- Diagnostics -----------------------------------------------------------
    /// Cached manifests-dir consistency warning.  Populated once at construction
    /// and refreshed on config changes — filesystem comparison, not hot-path.
    manifests_dir_warning: Option<String>,
}

impl ActionsScreen {
    pub fn new(setup: Arc<dyn SetupOps>) -> Self {
        let manifests_dir_warning = setup.check_manifests_dir_consistency();
        Self {
            actions: Vec::new(),
            selected: 0,
            detail: None,
            error: None,
            fetched: false,
            needs_refresh: false,
            tick_count: 0,
            setup,
            edit: None,
            create: None,
            pending_edit: None,
            pending_actions: Vec::new(),
            select_after_refresh: None,
            manifests_dir_warning,
        }
    }

    fn selected_action_id(&self) -> Option<&str> {
        self.actions
            .get(self.selected)
            .and_then(|a| a["action_id"].as_str())
    }

    /// Whether any saved actions are still waiting for a gate restart.
    fn has_unresolved_pending(&self) -> bool {
        self.pending_actions.iter().any(|p| {
            !self
                .actions
                .iter()
                .any(|a| a["action_id"].as_str() == Some(p.action_id.as_str()))
        })
    }

    /// Reconcile pending actions against the live registry.
    ///
    /// - **Resolved** entries (now in the live list) are discarded.
    /// - **Stale** entries (past [`PENDING_ACTION_STALE_SECS`]) are discarded
    ///   with a diagnostic surfaced in `self.error`.
    /// - All other entries are retained.
    fn reconcile_pending_actions(&mut self) {
        let now = Instant::now();
        let stale = Duration::from_secs(PENDING_ACTION_STALE_SECS);
        let mut stale_msg: Option<String> = None;

        self.pending_actions.retain(|p| {
            let resolved = self
                .actions
                .iter()
                .any(|a| a["action_id"].as_str() == Some(p.action_id.as_str()));
            if resolved {
                return false;
            }
            if now.duration_since(p.added_at) > stale {
                stale_msg = Some(format!(
                    "Action '{}' was saved but did not appear in the gate \
                     registry after restart. Check that manifests_dir matches \
                     the directory the gate loads from.",
                    p.action_id,
                ));
                return false;
            }
            true
        });

        if let Some(msg) = stale_msg {
            self.error = Some(msg);
        }
    }

    // -- Browse rendering ----------------------------------------------------

    fn render_list(&self, area: Rect, frame: &mut Frame, theme: &Theme) {
        let pending_count = self
            .pending_actions
            .iter()
            .filter(|p| {
                !self
                    .actions
                    .iter()
                    .any(|a| a["action_id"].as_str() == Some(p.action_id.as_str()))
            })
            .count();
        let total = self.actions.len() + pending_count;
        let title = if pending_count > 0 {
            format!(" Actions ({total}, {pending_count} pending — [R] reload) ")
        } else {
            format!(" Actions ({total}) ")
        };
        let Some(inner) = widgets::begin_active_panel(frame, area, title, theme) else {
            return;
        };

        let header = Row::new(vec!["  Action", "Risk"]).style(theme.header);
        let widths = [Constraint::Min(20), Constraint::Length(6)];

        let mut rows: Vec<Row<'_>> = self
            .actions
            .iter()
            .enumerate()
            .map(|(i, a)| {
                let action_id = a["action_id"].as_str().unwrap_or("-");
                let risk = a["risk_level"].as_str().unwrap_or("?");

                let base = if i == self.selected {
                    theme.selected.add_modifier(Modifier::BOLD)
                } else {
                    ratatui::style::Style::default()
                };

                let marker = if i == self.selected { "▸ " } else { "  " };

                Row::new(vec![
                    Line::from(Span::styled(
                        format!("{marker}{}", truncate(action_id, 20)),
                        base,
                    )),
                    Line::from(widgets::risk_badge(risk, theme)),
                ])
            })
            .collect();

        // Append pending actions not yet in the live list.
        for p in &self.pending_actions {
            let already_live = self
                .actions
                .iter()
                .any(|a| a["action_id"].as_str() == Some(p.action_id.as_str()));
            if !already_live {
                rows.push(Row::new(vec![
                    Line::from(Span::styled(
                        format!("  {} (pending restart)", truncate(&p.action_id, 14)),
                        theme.dim,
                    )),
                    Line::from(Span::styled("—", theme.dim)),
                ]));
            }
        }

        frame.render_widget(
            ScrollableTable::new(rows, widths)
                .header(header)
                .selected(self.selected)
                .empty(EmptyState::new("No actions registered.", theme).hint("[r] to refresh")),
            inner,
        );
    }

    fn render_detail(&self, area: Rect, frame: &mut Frame, theme: &Theme) {
        let Some(inner) = widgets::begin_detail_panel(frame, area, " Detail ", theme) else {
            return;
        };

        let Some(detail) = &self.detail else {
            let msg = if self.actions.is_empty() {
                "No actions registered."
            } else {
                "Loading…"
            };
            frame.render_widget(Paragraph::new(msg).style(theme.dim), inner);
            if self.detail.is_none() && !self.actions.is_empty() {
                let offset = msg.chars().count() as u16 + 1;
                if inner.width > offset {
                    let spinner_area = Rect::new(inner.x + offset, inner.y, 1, 1);
                    frame.render_widget(Spinner::new(self.tick_count, theme), spinner_area);
                }
            }
            return;
        };

        let kw = 11;
        let mut lines: Vec<Line<'_>> = Vec::with_capacity(20);

        lines.push(widgets::key_value_line(
            "Action:    ",
            Span::raw(detail["action_id"].as_str().unwrap_or("-")),
            kw,
            theme,
        ));
        lines.push(widgets::key_value_line(
            "Version:   ",
            Span::raw(detail["version"].as_str().unwrap_or("-")),
            kw,
            theme,
        ));

        let risk = detail["risk_level"].as_str().unwrap_or("?");
        lines.push(widgets::key_value_line(
            "Risk:      ",
            widgets::risk_badge(risk, theme),
            kw,
            theme,
        ));

        if let Some(digest) = detail["provider_module_digest"].as_str() {
            let short = if digest.len() > 16 {
                format!("{}…", &digest[..16])
            } else {
                digest.to_string()
            };
            lines.push(widgets::key_value_line(
                "Digest:    ",
                Span::styled(short, theme.dim),
                kw,
                theme,
            ));
        }

        lines.push(Line::default());

        if let Some(rl) = detail.get("resource_limits") {
            lines.push(Line::from(Span::styled("Resource limits:", theme.header)));
            if let Some(fuel) = rl["fuel"].as_u64() {
                lines.push(Line::from(format!("  Fuel:       {fuel}")));
            }
            if let Some(mem) = rl["memory_mb"].as_u64() {
                lines.push(Line::from(format!("  Memory:     {mem} MB")));
            }
            if let Some(timeout) = rl["timeout_seconds"].as_u64() {
                lines.push(Line::from(format!("  Timeout:    {timeout}s")));
            }
            if let Some(io) = rl["max_io_calls"].as_u64() {
                lines.push(Line::from(format!("  Max IO:     {io}")));
            }
        }

        if let Some(io) = detail.get("io") {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled("IO:", theme.header)));
            if let Some(req) = io["max_request_bytes"].as_u64() {
                lines.push(Line::from(format!("  Max request:  {req} bytes")));
            }
            if let Some(resp) = io["max_response_bytes"].as_u64() {
                lines.push(Line::from(format!("  Max response: {resp} bytes")));
            }
            let has_req_schema = io["has_request_schema"].as_bool().unwrap_or(false);
            let has_resp_schema = io["has_response_schema"].as_bool().unwrap_or(false);
            lines.push(Line::from(format!(
                "  Schemas:      req={}, resp={}",
                if has_req_schema { "yes" } else { "no" },
                if has_resp_schema { "yes" } else { "no" },
            )));
        }

        if let Some(egress) = detail.get("egress") {
            if !egress.is_null() {
                lines.push(Line::default());
                lines.push(Line::from(Span::styled("Egress:", theme.header)));

                if let Some(domains) = egress["allowed_domains"].as_array() {
                    let list = join_str_array(domains);
                    lines.push(Line::from(format!(
                        "  Domains: {}",
                        if list.is_empty() { "(none)" } else { &list }
                    )));
                }
                if let Some(cidrs) = egress["allowed_cidrs"].as_array() {
                    let list = join_str_array(cidrs);
                    if !list.is_empty() {
                        lines.push(Line::from(format!("  CIDRs:   {list}")));
                    }
                }
            }
        }

        if let Some(effects) = detail["declared_side_effects"].as_array() {
            if !effects.is_empty() {
                lines.push(Line::default());
                lines.push(Line::from(vec![
                    Span::styled("Side effects: ", theme.header),
                    Span::raw(join_str_array(effects)),
                ]));
            }
        }

        if let Some(db) = detail.get("database") {
            if !db.is_null() {
                lines.push(Line::default());
                lines.push(Line::from(Span::styled("Database:", theme.header)));
                if let Some(mode) = db["mode"].as_str() {
                    lines.push(Line::from(format!("  Mode: {mode}")));
                }
                if let Some(stmts) = db["statements"].as_array() {
                    lines.push(Line::from(format!("  Statements: {}", stmts.len())));
                }
            }
        }

        if let Some(ref err) = self.error {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(err.as_str(), theme.status_error)));
        }

        if let Some(ref warn) = self.manifests_dir_warning {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                format!("⚠ {warn}"),
                theme.status_warn,
            )));
        }

        frame.render_widget(
            Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false }),
            inner,
        );
    }

    // -- Wizard rendering ------------------------------------------------------

    fn render_wizard(&self, area: Rect, frame: &mut Frame, theme: &Theme) {
        let create = match &self.create {
            Some(c) => c,
            None => return,
        };

        let (content_area, input_area) = match create {
            CreateStep::ActionId(_) | CreateStep::HttpUrl { .. } => {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Min(1), Constraint::Length(3)])
                    .split(area);
                (chunks[0], Some(chunks[1]))
            }
            _ => (area, None),
        };

        let Some(inner) = widgets::begin_active_panel(frame, content_area, " New Action ", theme)
        else {
            return;
        };

        let mut lines: Vec<Line<'_>> = Vec::with_capacity(16);

        match create {
            CreateStep::ActionId(_) => {
                lines.push(Line::from(Span::styled(
                    "  Step 1: Action ID",
                    theme.header,
                )));
                lines.push(Line::default());
                lines.push(Line::from(Span::styled(
                    "  Enter a unique identifier (e.g. github_read, slack_post).",
                    theme.dim,
                )));
                lines.push(Line::from(Span::styled(
                    "  Allowed: [a-zA-Z0-9_-]",
                    theme.dim,
                )));
            }
            CreateStep::ProviderType { cursor, .. } => {
                lines.push(Line::from(Span::styled(
                    "  Step 2: Provider Type",
                    theme.header,
                )));
                lines.push(Line::default());
                for (i, (_, desc)) in PROVIDER_TYPES.iter().enumerate() {
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
            CreateStep::HttpMethod { cursor, .. } => {
                lines.push(Line::from(Span::styled(
                    "  Step 3: HTTP Method",
                    theme.header,
                )));
                lines.push(Line::default());
                for (i, method) in HTTP_METHODS.iter().enumerate() {
                    let marker = if i == *cursor { "  ▸ " } else { "    " };
                    let style = if i == *cursor {
                        theme.selected.add_modifier(Modifier::BOLD)
                    } else {
                        ratatui::style::Style::default()
                    };
                    lines.push(Line::from(Span::styled(format!("{marker}{method}"), style)));
                }
                lines.push(Line::default());
                lines.push(Line::from(Span::styled(
                    "  [↑↓] select  [Enter] confirm  [Esc] cancel",
                    theme.dim,
                )));
            }
            CreateStep::HttpUrl { .. } => {
                lines.push(Line::from(Span::styled(
                    "  Step 4: URL Template",
                    theme.header,
                )));
                lines.push(Line::default());
                lines.push(Line::from(Span::styled(
                    "  Use {{var}} for placeholders resolved from the request body.",
                    theme.dim,
                )));
                lines.push(Line::from(Span::styled(
                    "  Example: https://api.github.com/repos/{{owner}}/{{repo}}",
                    theme.dim,
                )));
            }
            CreateStep::FsOps { cursor, .. } => {
                lines.push(Line::from(Span::styled(
                    "  Step 3: Filesystem Operations",
                    theme.header,
                )));
                lines.push(Line::default());
                for (i, (label, _)) in FS_OP_PRESETS.iter().enumerate() {
                    let marker = if i == *cursor { "  ▸ " } else { "    " };
                    let style = if i == *cursor {
                        theme.selected.add_modifier(Modifier::BOLD)
                    } else {
                        ratatui::style::Style::default()
                    };
                    lines.push(Line::from(Span::styled(format!("{marker}{label}"), style)));
                }
                lines.push(Line::default());
                lines.push(Line::from(Span::styled(
                    "  [↑↓] select  [Enter] confirm  [Esc] cancel",
                    theme.dim,
                )));
            }
        }

        frame.render_widget(
            Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false }),
            inner,
        );

        // Render text input when applicable.
        if let Some(ia) = input_area {
            match create {
                CreateStep::ActionId(ref input) => input.render(ia, frame, theme),
                CreateStep::HttpUrl { ref input, .. } => input.render(ia, frame, theme),
                _ => {}
            }
        }
    }

    // -- Edit rendering ------------------------------------------------------

    fn render_editor(&self, area: Rect, frame: &mut Frame, theme: &Theme) {
        let edit = match &self.edit {
            Some(e) => e,
            None => return,
        };

        // Split: field list on top, input area at bottom (when active).
        let (fields_area, input_area) = if edit.editor.is_some() {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(1), Constraint::Length(3)])
                .split(area);
            (chunks[0], Some(chunks[1]))
        } else {
            (area, None)
        };

        let dirty_marker = if edit.dirty { " ● " } else { "" };
        let title = if edit.dirty {
            format!(
                " Edit: {} {dirty_marker}— [s] save  [Esc] discard ",
                truncate(&edit.spec.action_id, 24)
            )
        } else {
            format!(" Edit: {} ", truncate(&edit.spec.action_id, 24))
        };
        let Some(inner) = widgets::begin_active_panel(frame, fields_area, title, theme) else {
            return;
        };

        let mut lines: Vec<Line<'_>> = Vec::with_capacity(32);

        // Header.
        lines.push(Line::from(vec![
            Span::styled("  Action:  ", theme.dim),
            Span::raw(edit.spec.action_id.as_str()),
            Span::styled("  v", theme.dim),
            Span::raw(&*edit.spec.version),
        ]));
        lines.push(Line::from(vec![
            Span::styled("  Provider: ", theme.dim),
            Span::styled(truncate(&edit.spec.provider_module_digest, 30), theme.dim),
        ]));
        lines.push(Line::default());

        // Editable fields.
        for (i, &field) in edit.fields.iter().enumerate() {
            let is_selected = i == edit.field_cursor;
            let marker = if is_selected { "▸ " } else { "  " };
            let style = if is_selected {
                theme.selected.add_modifier(Modifier::BOLD)
            } else {
                ratatui::style::Style::default()
            };

            if field.is_list() && is_selected {
                // Render list field header.
                lines.push(Line::from(Span::styled(
                    format!("{marker}{:<20}", field.label()),
                    style,
                )));

                // Render list items with sub-cursor.
                let items = edit.list_items();
                if items.is_empty() {
                    lines.push(Line::from(Span::styled("    (empty)", theme.dim)));
                } else {
                    for (j, item) in items.iter().enumerate() {
                        let sub_marker = if j == edit.list_cursor {
                            "  ▹ "
                        } else {
                            "    "
                        };
                        let sub_style = if j == edit.list_cursor {
                            theme.selected
                        } else {
                            theme.dim
                        };
                        lines.push(Line::from(Span::styled(
                            format!("{sub_marker}{}", truncate(item, 40)),
                            sub_style,
                        )));
                    }
                }
            } else {
                // Render scalar or collapsed list field.
                let value = edit.field_value(field);
                let hint = match field {
                    EditField::RiskLevel => "  (Enter: cycle)",
                    _ if field.is_list() => "  (Enter: expand)",
                    _ => "",
                };
                lines.push(Line::from(vec![
                    Span::styled(format!("{marker}{:<20}", field.label()), style),
                    Span::raw(value),
                    Span::styled(hint, theme.dim),
                ]));
            }
        }

        frame.render_widget(
            Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false }),
            inner,
        );

        // Render sub-editor input.
        if let Some(ia) = input_area {
            if let Some(ref editor) = edit.editor {
                match editor {
                    FieldEditor::Numeric(input) | FieldEditor::ListAdd(input) => {
                        input.render(ia, frame, theme);
                    }
                }
            }
        }
    }

    // -- Key handling: creation wizard ---------------------------------------

    fn handle_create_key(&mut self, key: KeyEvent) -> ScreenAction {
        let create = match self.create.take() {
            Some(c) => c,
            None => return ScreenAction::Noop,
        };

        match create {
            CreateStep::ActionId(mut input) => match input.handle_key(key) {
                InputAction::Cancel => ScreenAction::EndInput,
                InputAction::Continue => {
                    self.create = Some(CreateStep::ActionId(input));
                    ScreenAction::Noop
                }
                InputAction::Submit(val) => {
                    let action_id = val.trim().to_string();
                    if action_id.is_empty() {
                        return ScreenAction::EndInput;
                    }
                    // Basic format check (full validation happens on save).
                    if !action_id
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                    {
                        self.create = None;
                        return ScreenAction::Flash(FlashMessage::error(
                            "Invalid action_id: only [a-zA-Z0-9_-] allowed",
                        ));
                    }
                    self.create = Some(CreateStep::ProviderType {
                        action_id,
                        cursor: 0,
                    });
                    ScreenAction::Noop
                }
            },

            CreateStep::ProviderType {
                action_id,
                mut cursor,
            } => match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    cursor = cursor.saturating_sub(1);
                    self.create = Some(CreateStep::ProviderType { action_id, cursor });
                    ScreenAction::Noop
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if cursor + 1 < PROVIDER_TYPES.len() {
                        cursor += 1;
                    }
                    self.create = Some(CreateStep::ProviderType { action_id, cursor });
                    ScreenAction::Noop
                }
                KeyCode::Enter => {
                    if cursor == 0 {
                        // HTTP API => select method.
                        self.create = Some(CreateStep::HttpMethod {
                            action_id,
                            cursor: 0,
                        });
                    } else {
                        // FS => select operations.
                        self.create = Some(CreateStep::FsOps {
                            action_id,
                            cursor: 0,
                        });
                    }
                    ScreenAction::Noop
                }
                KeyCode::Esc => ScreenAction::EndInput,
                _ => {
                    self.create = Some(CreateStep::ProviderType { action_id, cursor });
                    ScreenAction::Noop
                }
            },

            CreateStep::HttpMethod {
                action_id,
                mut cursor,
            } => match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    cursor = cursor.saturating_sub(1);
                    self.create = Some(CreateStep::HttpMethod { action_id, cursor });
                    ScreenAction::Noop
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if cursor + 1 < HTTP_METHODS.len() {
                        cursor += 1;
                    }
                    self.create = Some(CreateStep::HttpMethod { action_id, cursor });
                    ScreenAction::Noop
                }
                KeyCode::Enter => {
                    let method = HTTP_METHODS[cursor].to_string();
                    self.create = Some(CreateStep::HttpUrl {
                        action_id,
                        method,
                        input: TextInput::new(" URL template (Enter/Esc) ", FORM_MAX_LEN),
                    });
                    ScreenAction::Noop
                }
                KeyCode::Esc => ScreenAction::EndInput,
                _ => {
                    self.create = Some(CreateStep::HttpMethod { action_id, cursor });
                    ScreenAction::Noop
                }
            },

            CreateStep::HttpUrl {
                action_id,
                method,
                mut input,
            } => match input.handle_key(key) {
                InputAction::Cancel => ScreenAction::EndInput,
                InputAction::Continue => {
                    self.create = Some(CreateStep::HttpUrl {
                        action_id,
                        method,
                        input,
                    });
                    ScreenAction::Noop
                }
                InputAction::Submit(url) => {
                    let url = url.trim().to_string();
                    if url.is_empty() {
                        return ScreenAction::EndInput;
                    }
                    let spec = build_http_spec(action_id, method, url);
                    self.edit = Some(EditState::new(spec));
                    // Enter edit mode under input lock so global keys (q, 1-8)
                    // cannot quit or navigate away and discard the new action.
                    ScreenAction::BeginInput
                }
            },

            CreateStep::FsOps {
                action_id,
                mut cursor,
            } => match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    cursor = cursor.saturating_sub(1);
                    self.create = Some(CreateStep::FsOps { action_id, cursor });
                    ScreenAction::Noop
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if cursor + 1 < FS_OP_PRESETS.len() {
                        cursor += 1;
                    }
                    self.create = Some(CreateStep::FsOps { action_id, cursor });
                    ScreenAction::Noop
                }
                KeyCode::Enter => {
                    let ops = FS_OP_PRESETS[cursor].1.to_vec();
                    let spec = build_fs_spec(action_id, ops);
                    self.edit = Some(EditState::new(spec));
                    // Enter edit mode under input lock so global keys (q, 1-8)
                    // cannot quit or navigate away and discard the new action.
                    ScreenAction::BeginInput
                }
                KeyCode::Esc => ScreenAction::EndInput,
                _ => {
                    self.create = Some(CreateStep::FsOps { action_id, cursor });
                    ScreenAction::Noop
                }
            },
        }
    }

    // -- Key handling: browse mode -------------------------------------------

    fn handle_browse_key(&mut self, key: KeyEvent) -> ScreenAction {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                if !self.actions.is_empty() && self.selected > 0 {
                    self.selected -= 1;
                    self.detail = None;
                }
                ScreenAction::Noop
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected + 1 < self.actions.len() {
                    self.selected += 1;
                    self.detail = None;
                }
                ScreenAction::Noop
            }
            KeyCode::Char('r') => {
                self.needs_refresh = true;
                self.detail = None;
                ScreenAction::Noop
            }
            KeyCode::Char('e') => {
                let Some(action_id) = self.selected_action_id().map(str::to_string) else {
                    return ScreenAction::Noop;
                };
                match self.setup.read_manifest(&action_id) {
                    Ok(spec) => {
                        self.edit = Some(EditState::new(spec));
                        ScreenAction::BeginInput
                    }
                    Err(e) => ScreenAction::Flash(FlashMessage::error(format!("Cannot edit: {e}"))),
                }
            }
            KeyCode::Char('n') => {
                self.create = Some(CreateStep::ActionId(TextInput::new(
                    " Action ID (Enter/Esc) ",
                    128,
                )));
                ScreenAction::BeginInput
            }
            KeyCode::Char('R') if self.has_unresolved_pending() => {
                // Pending markers are reconciled in `tick` after the gate
                // reloads; clearing here would erase them if the reload fails.
                ScreenAction::GateReload
            }
            _ => ScreenAction::Noop,
        }
    }

    // -- Key handling: edit mode (field navigation) ---------------------------

    fn handle_edit_key(&mut self, key: KeyEvent) -> ScreenAction {
        if self.edit.is_none() {
            return ScreenAction::Noop;
        }

        // Delegate to sub-editor if active.
        if self.edit.as_ref().is_some_and(|e| e.editor.is_some()) {
            return self.handle_field_input_key(key);
        }

        // Delegate to discard confirmation.
        if self.edit.as_ref().is_some_and(|e| e.confirm_discard) {
            if key.code == KeyCode::Char('y') {
                self.edit = None;
                return ScreenAction::EndInput;
            }
            if let Some(ref mut edit) = self.edit {
                edit.confirm_discard = false;
            }
            return ScreenAction::Noop;
        }

        // Delegate to remove confirmation.
        if self.edit.as_ref().is_some_and(|e| e.removing) {
            if let Some(ref mut edit) = self.edit {
                if key.code == KeyCode::Char('y') {
                    edit.list_remove();
                }
                edit.removing = false;
            }
            return ScreenAction::Noop;
        }

        // Safe to hold a long-lived borrow now — no more branches that
        // need to drop-and-reborrow self.edit.
        let edit = match &mut self.edit {
            Some(e) => e,
            None => return ScreenAction::Noop,
        };

        let current = edit.current_field();
        let on_list = current.is_some_and(|f| f.is_list());
        let list_len = if on_list { edit.list_items().len() } else { 0 };

        match key.code {
            // Field navigation.
            KeyCode::Up | KeyCode::Char('k') => {
                if on_list && edit.list_cursor > 0 {
                    edit.list_cursor = edit.list_cursor.saturating_sub(1);
                } else if (!on_list || edit.list_cursor == 0) && edit.field_cursor > 0 {
                    edit.field_cursor -= 1;
                    edit.list_cursor = 0;
                }
                ScreenAction::Noop
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if on_list && edit.list_cursor + 1 < list_len {
                    edit.list_cursor += 1;
                } else if edit.field_cursor + 1 < edit.fields.len() {
                    edit.field_cursor += 1;
                    edit.list_cursor = 0;
                }
                ScreenAction::Noop
            }

            // Activate field editor.
            KeyCode::Enter => {
                let Some(field) = current else {
                    return ScreenAction::Noop;
                };
                match field {
                    EditField::RiskLevel => {
                        edit.cycle_risk();
                        ScreenAction::Noop
                    }
                    f if f.is_list() => {
                        // Lists are already expanded — Enter does nothing
                        // at the list level. Use [a] and [d] instead.
                        ScreenAction::Noop
                    }
                    _ => {
                        // Open numeric editor pre-filled with current value.
                        let current_val = edit.field_value(field);
                        let input = TextInput::with_initial(
                            &format!(" {} (Enter/Esc) ", field.label()),
                            FORM_MAX_LEN,
                            &current_val,
                        );
                        edit.editor = Some(FieldEditor::Numeric(input));
                        ScreenAction::Noop
                    }
                }
            }

            // List operations.
            KeyCode::Char('a') if on_list => {
                let label = match current {
                    Some(EditField::EgressDomains) => " Domain (Enter/Esc) ",
                    Some(EditField::FsAllowedPaths) => " Path pattern (Enter/Esc) ",
                    Some(EditField::FsDeniedPaths) => " Deny pattern (Enter/Esc) ",
                    Some(EditField::Secrets) => " Secret name (Enter/Esc) ",
                    Some(_) => " Value (Enter/Esc) ",
                    None => return ScreenAction::Noop,
                };
                edit.editor = Some(FieldEditor::ListAdd(TextInput::new(label, FORM_MAX_LEN)));
                ScreenAction::Noop
            }
            KeyCode::Char('d') if on_list && list_len > 0 => {
                edit.removing = true;
                ScreenAction::Flash(FlashMessage::info(
                    "Press [y] to confirm removal, any other key to cancel",
                ))
            }

            // Save.
            KeyCode::Char('s') if edit.dirty => {
                let spec = edit.spec.clone();
                self.pending_edit = Some(PendingEdit::Save {
                    spec: Box::new(spec),
                });
                ScreenAction::AsyncAction
            }

            // Discard + exit edit mode (confirm if dirty).
            KeyCode::Esc => {
                if edit.dirty {
                    edit.confirm_discard = true;
                    ScreenAction::Flash(FlashMessage::info(
                        "Unsaved changes — press [y] to discard, any other key to keep editing",
                    ))
                } else {
                    self.edit = None;
                    ScreenAction::EndInput
                }
            }

            _ => ScreenAction::Noop,
        }
    }

    // -- Key handling: sub-editor (TextInput active) -------------------------

    fn handle_field_input_key(&mut self, key: KeyEvent) -> ScreenAction {
        let edit = match &mut self.edit {
            Some(e) => e,
            None => return ScreenAction::Noop,
        };

        let editor = match &mut edit.editor {
            Some(e) => e,
            None => return ScreenAction::Noop,
        };

        match editor {
            FieldEditor::Numeric(ref mut input) => match input.handle_key(key) {
                InputAction::Cancel => {
                    edit.editor = None;
                    ScreenAction::Noop
                }
                InputAction::Continue => ScreenAction::Noop,
                InputAction::Submit(val) => {
                    edit.editor = None;
                    match edit.apply_numeric(val.trim()) {
                        Ok(()) => ScreenAction::Noop,
                        Err(e) => ScreenAction::Flash(FlashMessage::error(e)),
                    }
                }
            },
            FieldEditor::ListAdd(ref mut input) => match input.handle_key(key) {
                InputAction::Cancel => {
                    edit.editor = None;
                    ScreenAction::Noop
                }
                InputAction::Continue => ScreenAction::Noop,
                InputAction::Submit(val) => {
                    edit.editor = None;
                    let val = val.trim().to_string();
                    if !val.is_empty() {
                        edit.list_add(val);
                    }
                    ScreenAction::Noop
                }
            },
        }
    }
}

// TuiScreen

impl TuiScreen for ActionsScreen {
    fn render(&self, area: Rect, frame: &mut Frame, theme: &Theme) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(35), Constraint::Min(0)])
            .split(area);

        self.render_list(chunks[0], frame, theme);

        if self.create.is_some() {
            self.render_wizard(chunks[1], frame, theme);
        } else if self.edit.is_some() {
            self.render_editor(chunks[1], frame, theme);
        } else {
            self.render_detail(chunks[1], frame, theme);
        }

        // Persistent overlays for confirmation states that outlive the flash.
        if let Some(ref edit) = self.edit {
            if edit.confirm_discard {
                widgets::render_confirm_dialog(area, frame, theme, "Discard unsaved changes?");
            } else if edit.removing {
                widgets::render_confirm_dialog(area, frame, theme, "Remove this item?");
            }
        }
    }

    fn handle_key(&mut self, key: KeyEvent, _theme: &Theme) -> ScreenAction {
        if self.create.is_some() {
            self.handle_create_key(key)
        } else if self.edit.is_some() {
            self.handle_edit_key(key)
        } else {
            self.handle_browse_key(key)
        }
    }

    fn handle_action<'a>(
        &'a mut self,
        client: &'a GateClient,
        auth: &'a OperatorAuth,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<FlashMessage>> + Send + 'a>>
    {
        Box::pin(async move {
            let action = self.pending_edit.take()?;
            match action {
                PendingEdit::Save { spec } => match self.setup.write_manifest(&spec) {
                    Ok(_path) => {
                        let action_id = spec.action_id.clone();
                        if !self
                            .pending_actions
                            .iter()
                            .any(|p| p.action_id == action_id)
                        {
                            self.pending_actions.push(PendingAction {
                                action_id: action_id.clone(),
                                added_at: Instant::now(),
                            });
                        }
                        self.edit = None;
                        self.needs_refresh = true;
                        self.detail = None;
                        self.select_after_refresh = Some(action_id.clone());

                        // Hot-reload the gate inline so the new manifest is
                        // picked up immediately, without a manual `R` press.
                        match client.admin_reload(auth).await {
                            Ok(resp) => {
                                self.needs_refresh = true;
                                let n = resp["actions"].as_u64().unwrap_or(0);
                                Some(FlashMessage::success(format!(
                                    "✓ Saved {action_id} — reloaded ({n} actions)"
                                )))
                            }
                            Err(e) => Some(FlashMessage::success(format!(
                                "✓ Saved {action_id} (reload failed: {e} — press R to retry)"
                            ))),
                        }
                    }
                    Err(e) => Some(FlashMessage::error(e)),
                },
            }
        })
    }

    fn tick<'a>(
        &'a mut self,
        client: &'a GateClient,
        _auth: &'a OperatorAuth,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            self.tick_count = self.tick_count.wrapping_add(1);

            // Skip API fetch while in edit, create, or preset mode.
            if self.edit.is_some() || self.create.is_some() {
                return;
            }

            // Fetch action list (once, or on explicit refresh).
            if !self.fetched || self.needs_refresh {
                match client.list_actions().await {
                    Ok(list) => {
                        let prev_count = self.actions.len();
                        self.actions = list;
                        self.error = None;
                        self.fetched = true;
                        self.needs_refresh = false;

                        // Discard resolved entries; surface stale ones.
                        self.reconcile_pending_actions();

                        if self.actions.is_empty() {
                            self.selected = 0;
                            self.detail = None;
                            self.select_after_refresh = None;
                            return;
                        }

                        // After save/create, seek the cursor to the target action.
                        if let Some(target) = self.select_after_refresh.take() {
                            if let Some(idx) = self
                                .actions
                                .iter()
                                .position(|a| a["action_id"].as_str() == Some(target.as_str()))
                            {
                                self.selected = idx;
                                self.detail = None;
                            }
                        }

                        if self.selected >= self.actions.len() {
                            self.selected = self.actions.len() - 1;
                        }
                        if self.actions.len() != prev_count {
                            self.detail = None;
                        }
                    }
                    Err(ClientError::NotReachable(msg)) => {
                        self.error = Some(format!("Gate unreachable: {msg}"));
                        return;
                    }
                    Err(ClientError::Http { status: 404, .. }) => {
                        self.actions.clear();
                        self.selected = 0;
                        self.detail = None;
                        self.error = None;
                        self.fetched = true;
                        self.needs_refresh = false;
                        return;
                    }
                    Err(e) => {
                        self.error = Some(format!("Error: {e}"));
                        return;
                    }
                }
            }

            // Fetch detail for the selected action.
            if self.detail.is_none() {
                if let Some(id) = self.selected_action_id().map(str::to_string) {
                    match client.get_action(&id).await {
                        Ok(d) => self.detail = Some(d),
                        Err(e) => {
                            self.error = Some(format!("Detail: {e}"));
                        }
                    }
                }
            }
        })
    }

    fn tab_label(&self) -> &'static str {
        "Actions"
    }

    fn update_config(&mut self, _config: &latchgate_config::Config) {
        self.manifests_dir_warning = self.setup.check_manifests_dir_consistency();
    }

    fn needs_confirm_input(&self) -> bool {
        self.edit
            .as_ref()
            .is_some_and(|e| e.confirm_discard || e.removing)
    }

    fn is_modal(&self) -> bool {
        // The edit and create screens are modal input surfaces: while either
        // is open they own *all* key input, including digits and Tab. Routing
        // those keys to the screen (rather than global navigation) is what
        // keeps a keystroke aimed at a field from leaking out to tab
        // navigation. `Esc` is handled before this gate in `app.rs` and always
        // exits cleanly, so the user is never trapped.
        self.edit.is_some() || self.create.is_some()
    }

    fn status_hint(&self) -> &str {
        if self.create.is_some() {
            return "[↑↓]select  [Enter]confirm  [Esc]cancel";
        }
        if let Some(ref edit) = self.edit {
            if edit.editor.is_some() {
                return "[Enter]submit  [Esc]cancel";
            }
            if edit.dirty {
                if edit.current_field().is_some_and(|f| f.is_list()) {
                    return "[↑↓]navigate  [a]dd  [d]elete  [s]ave  [Esc]discard";
                }
                return "[↑↓]navigate  [Enter]edit  [s]ave  [Esc]discard";
            }
            if edit.current_field().is_some_and(|f| f.is_list()) {
                return "[↑↓]navigate  [a]dd  [d]elete  [Esc]close";
            }
            return "[↑↓]navigate  [Enter]edit  [Esc]close";
        }
        if self.has_unresolved_pending() {
            return "[↑↓/jk]navigate  [e]dit  [n]ew  [r]efresh  [R]reload";
        }
        "[↑↓/jk]navigate  [e]dit  [n]ew  [r]efresh"
    }

    fn help_keys(&self) -> &'static [(&'static str, &'static str)] {
        if self.create.is_some() {
            &[
                ("↑/k", "Previous option"),
                ("↓/j", "Next option"),
                ("Enter", "Confirm selection"),
                ("Esc", "Cancel wizard"),
            ]
        } else if self.edit.is_some() {
            &[
                ("↑/k", "Previous field / list item"),
                ("↓/j", "Next field / list item"),
                ("Enter", "Edit field / cycle risk level"),
                ("a", "Add item (list fields)"),
                ("d", "Delete item (list fields)"),
                ("s", "Save changes to disk"),
                ("Esc", "Discard and close editor"),
            ]
        } else if self.has_unresolved_pending() {
            &[
                ("↑/k", "Move cursor up"),
                ("↓/j", "Move cursor down"),
                ("e", "Edit selected action manifest"),
                ("n", "Create new action"),
                ("r", "Refresh action list"),
                ("R", "Restart gate to apply pending"),
            ]
        } else {
            &[
                ("↑/k", "Move cursor up"),
                ("↓/j", "Move cursor down"),
                ("e", "Edit selected action manifest"),
                ("n", "Create new action"),
                ("r", "Refresh action list"),
            ]
        }
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use latchgate_core::{FsOperation, RiskLevel};

    // -- Helpers -------------------------------------------------------------

    /// Minimal HTTP action spec for testing.
    fn http_spec() -> ActionSpec {
        build_http_spec(
            "test_http".into(),
            "POST".into(),
            "https://api.example.com/{{id}}".into(),
        )
    }

    /// Minimal FS action spec for testing.
    fn fs_spec_rw() -> ActionSpec {
        build_fs_spec(
            "test_fs".into(),
            vec![
                FsOperation::Read,
                FsOperation::Create,
                FsOperation::Overwrite,
            ],
        )
    }

    // -- editable_fields -----------------------------------------------------

    #[test]
    fn editable_fields_http_proxy_includes_egress_domains() {
        let spec = http_spec();
        assert_eq!(spec.egress.profile, "proxy_allowlist");
        let fields = editable_fields(&spec);
        assert!(fields.contains(&EditField::EgressDomains));
        assert!(!fields.contains(&EditField::FsAllowedPaths));
        assert!(!fields.contains(&EditField::FsDeniedPaths));
    }

    #[test]
    fn editable_fields_fs_includes_paths_excludes_egress() {
        let spec = fs_spec_rw();
        let fields = editable_fields(&spec);
        assert!(fields.contains(&EditField::FsAllowedPaths));
        assert!(fields.contains(&EditField::FsDeniedPaths));
        assert!(!fields.contains(&EditField::EgressDomains));
    }

    #[test]
    fn editable_fields_always_includes_common_fields() {
        for spec in [http_spec(), fs_spec_rw()] {
            let fields = editable_fields(&spec);
            assert!(fields.contains(&EditField::RiskLevel));
            assert!(fields.contains(&EditField::Fuel));
            assert!(fields.contains(&EditField::TimeoutSeconds));
            assert!(fields.contains(&EditField::Secrets));
        }
    }

    // -- EditState: apply_numeric --------------------------------------------

    #[test]
    fn apply_numeric_updates_fuel() {
        let mut state = EditState::new(http_spec());
        state.field_cursor = state
            .fields
            .iter()
            .position(|f| *f == EditField::Fuel)
            .unwrap();
        state.apply_numeric("5000").unwrap();
        assert_eq!(state.spec.resource_limits.fuel, 5000);
        assert!(state.dirty);
    }

    #[test]
    fn apply_numeric_updates_timeout() {
        let mut state = EditState::new(http_spec());
        state.field_cursor = state
            .fields
            .iter()
            .position(|f| *f == EditField::TimeoutSeconds)
            .unwrap();
        state.apply_numeric("120").unwrap();
        assert_eq!(state.spec.resource_limits.timeout_seconds, 120);
    }

    #[test]
    fn apply_numeric_updates_io_limits() {
        let mut state = EditState::new(http_spec());
        state.field_cursor = state
            .fields
            .iter()
            .position(|f| *f == EditField::MaxRequestBytes)
            .unwrap();
        state.apply_numeric("32768").unwrap();
        assert_eq!(state.spec.io.max_request_bytes, 32768);
    }

    #[test]
    fn apply_numeric_rejects_non_number() {
        let mut state = EditState::new(http_spec());
        state.field_cursor = state
            .fields
            .iter()
            .position(|f| *f == EditField::Fuel)
            .unwrap();
        assert!(state.apply_numeric("not_a_number").is_err());
        assert!(!state.dirty);
    }

    #[test]
    fn apply_numeric_rejects_list_field() {
        let mut state = EditState::new(http_spec());
        state.field_cursor = state
            .fields
            .iter()
            .position(|f| *f == EditField::EgressDomains)
            .unwrap();
        assert!(state.apply_numeric("42").is_err());
    }

    // -- EditState: cycle_risk -----------------------------------------------

    #[test]
    fn cycle_risk_advances_through_all_levels() {
        let mut state = EditState::new(http_spec());
        assert_eq!(state.spec.risk_level, RiskLevel::Low);

        state.cycle_risk();
        assert_eq!(state.spec.risk_level, RiskLevel::Medium);

        state.cycle_risk();
        assert_eq!(state.spec.risk_level, RiskLevel::High);

        state.cycle_risk();
        assert_eq!(state.spec.risk_level, RiskLevel::Critical);

        state.cycle_risk();
        assert_eq!(state.spec.risk_level, RiskLevel::Low);

        assert!(state.dirty);
    }

    // -- EditState: list operations ------------------------------------------

    #[test]
    fn list_add_egress_domain() {
        let mut state = EditState::new(http_spec());
        state.field_cursor = state
            .fields
            .iter()
            .position(|f| *f == EditField::EgressDomains)
            .unwrap();
        assert!(state.list_items().is_empty());

        state.list_add("api.example.com".into());
        state.list_add("cdn.example.com".into());

        assert_eq!(state.spec.egress.allowed_domains.len(), 2);
        assert_eq!(state.spec.egress.allowed_domains[0], "api.example.com");
        assert!(state.dirty);
    }

    #[test]
    fn list_add_fs_paths() {
        let mut state = EditState::new(fs_spec_rw());
        state.field_cursor = state
            .fields
            .iter()
            .position(|f| *f == EditField::FsAllowedPaths)
            .unwrap();

        state.list_add("/home/user/**".into());
        assert_eq!(state.spec.fs.as_ref().unwrap().allowed_paths.len(), 1);
    }

    #[test]
    fn list_add_secrets() {
        let mut state = EditState::new(http_spec());
        state.field_cursor = state
            .fields
            .iter()
            .position(|f| *f == EditField::Secrets)
            .unwrap();

        state.list_add("API_KEY".into());
        assert_eq!(state.spec.secrets.len(), 1);
        assert_eq!(&*state.spec.secrets[0].name, "API_KEY");
        assert!(!state.spec.secrets[0].required);
    }

    #[test]
    fn list_remove_clamps_cursor() {
        let mut state = EditState::new(http_spec());
        state.field_cursor = state
            .fields
            .iter()
            .position(|f| *f == EditField::EgressDomains)
            .unwrap();
        state.list_add("a.com".into());
        state.list_add("b.com".into());
        state.list_cursor = 1;

        state.list_remove();

        assert_eq!(state.spec.egress.allowed_domains.len(), 1);
        assert_eq!(state.list_cursor, 0);
    }

    #[test]
    fn list_remove_empty_is_noop() {
        let mut state = EditState::new(http_spec());
        state.field_cursor = state
            .fields
            .iter()
            .position(|f| *f == EditField::EgressDomains)
            .unwrap();
        state.dirty = false;

        state.list_remove(); // no items — should not panic or set dirty

        assert!(!state.dirty);
    }

    #[test]
    fn list_remove_denied_paths() {
        let mut state = EditState::new(fs_spec_rw());
        state.field_cursor = state
            .fields
            .iter()
            .position(|f| *f == EditField::FsDeniedPaths)
            .unwrap();
        // fs_spec_rw starts with "**/.git/**" in denied_paths.
        assert_eq!(state.list_items().len(), 1);

        state.list_cursor = 0;
        state.list_remove();

        assert!(state.spec.fs.as_ref().unwrap().denied_paths.is_empty());
    }

    // -- EditState: field_value display --------------------------------------

    #[test]
    fn field_value_scalar_formats_correctly() {
        let state = EditState::new(http_spec());
        assert_eq!(state.field_value(EditField::RiskLevel), "low");
        // Default fuel from ResourceLimits::default().
        let fuel_str = state.field_value(EditField::Fuel);
        assert!(fuel_str.parse::<u64>().is_ok());
    }

    #[test]
    fn field_value_list_shows_count() {
        let mut state = EditState::new(http_spec());
        state.spec.egress.allowed_domains = vec!["a.com".into(), "b.com".into()];
        assert_eq!(state.field_value(EditField::EgressDomains), "2 domain(s)");
    }

    // -- EditState: confirm_discard ------------------------------------------

    #[test]
    fn confirm_discard_starts_false() {
        let state = EditState::new(http_spec());
        assert!(!state.confirm_discard);
    }

    // -- build_http_spec -----------------------------------------------------

    #[test]
    fn build_http_spec_get_has_read_effect() {
        let spec = build_http_spec(
            "github_read".into(),
            "GET".into(),
            "https://api.github.com/repos/{{owner}}/{{repo}}".into(),
        );
        assert_eq!(spec.risk_level, RiskLevel::Low);
        assert_eq!(spec.egress.profile, "proxy_allowlist");
        assert!(spec.declared_side_effects.contains(&"http_read".into()));
        assert!(!spec.declared_side_effects.contains(&"http_write".into()));
        assert!(spec.template.is_some());
        let tpl = spec.template.unwrap();
        assert_eq!(tpl.method, "GET");
        assert!(tpl.url_template.contains("{{owner}}"));
    }

    #[test]
    fn build_http_spec_post_has_write_effect() {
        let spec = build_http_spec(
            "slack_post".into(),
            "POST".into(),
            "https://slack.com/api/chat.postMessage".into(),
        );
        assert!(spec.declared_side_effects.contains(&"http_write".into()));
        assert!(!spec.declared_side_effects.contains(&"http_read".into()));
    }

    #[test]
    fn build_http_spec_has_required_fields() {
        let spec = http_spec();
        assert_eq!(&*spec.provider_module_digest, "builtin:http_api");
        assert!(spec.required_imports.contains(&"latchgate:io/http".into()));
        assert!(spec.required_scopes.contains(&"tools:call".into()));
        assert!(spec.fs.is_none());
    }

    // -- build_fs_spec -------------------------------------------------------

    #[test]
    fn build_fs_spec_read_only_is_low_risk() {
        let spec = build_fs_spec("fs_read".into(), vec![FsOperation::Read]);
        assert_eq!(spec.risk_level, RiskLevel::Low);
        assert!(spec.declared_side_effects.contains(&"fs_read".into()));
        assert!(!spec.declared_side_effects.contains(&"fs_write".into()));
        assert_eq!(spec.egress.profile, "none");
    }

    #[test]
    fn build_fs_spec_write_is_medium_risk() {
        let spec = build_fs_spec(
            "fs_write".into(),
            vec![
                FsOperation::Read,
                FsOperation::Create,
                FsOperation::Overwrite,
            ],
        );
        assert_eq!(spec.risk_level, RiskLevel::Medium);
        assert!(spec.declared_side_effects.contains(&"fs_write".into()));
    }

    #[test]
    fn build_fs_spec_delete_is_high_risk() {
        let spec = build_fs_spec(
            "fs_full".into(),
            vec![
                FsOperation::Read,
                FsOperation::Create,
                FsOperation::Overwrite,
                FsOperation::Delete,
            ],
        );
        assert_eq!(spec.risk_level, RiskLevel::High);
        assert!(spec.declared_side_effects.contains(&"fs_delete".into()));
    }

    #[test]
    fn build_fs_spec_has_default_denied_paths() {
        let spec = build_fs_spec("fs_any".into(), vec![FsOperation::Read]);
        let fs = spec.fs.unwrap();
        assert!(fs.denied_paths.contains(&"**/.git/**".into()));
    }

    #[test]
    fn build_fs_spec_has_required_fields() {
        let spec = build_fs_spec("fs_any".into(), vec![FsOperation::Read]);
        assert_eq!(&*spec.provider_module_digest, "builtin:fs");
        assert!(spec.required_imports.contains(&"latchgate:io/fs".into()));
        assert!(spec.template.is_none());
    }

    // -- Pending-action reconciliation ---------------------------------------

    use serde_json::json;

    /// `SetupOps` stub: every method is unreachable. These tests exercise
    /// only the in-memory pending/live reconciliation, which never touches
    /// the filesystem.
    struct UnusedSetup;

    macro_rules! unreachable_setup {
        ($($sig:tt)*) => {
            $($sig)* { unreachable!("SetupOps must not be called in this test") }
        };
    }

    impl SetupOps for UnusedSetup {
        unreachable_setup!(fn set_config(&self, _: &str, _: &str) -> Result<latchgate_config::Config, String>);
        unreachable_setup!(fn add_principal(&self, _: u32, _: &str, _: &str, _: Option<&str>) -> Result<latchgate_config::Config, String>);
        unreachable_setup!(fn remove_principal(&self, _: u32) -> Result<latchgate_config::Config, String>);
        unreachable_setup!(fn add_operator(&self, _: &str) -> Result<(latchgate_config::Config, String, String), String>);
        unreachable_setup!(fn remove_operator(&self, _: &str) -> Result<latchgate_config::Config, String>);
        unreachable_setup!(fn add_webhook(&self, _: &str, _: &str, _: &str, _: &str) -> Result<(latchgate_config::Config, String), String>);
        unreachable_setup!(fn remove_webhook(&self, _: &str) -> Result<latchgate_config::Config, String>);
        unreachable_setup!(fn test_webhook(&self, _: &str, _: &latchgate_config::Config) -> std::pin::Pin<Box<dyn std::future::Future<Output = crate::WebhookTestResult> + Send>>);
        unreachable_setup!(fn execute_init(&self, _: &crate::InitPlan) -> Result<latchgate_config::Config, String>);
        unreachable_setup!(fn secrets_init(&self, _: bool) -> Result<latchgate_config::Config, String>);
        unreachable_setup!(fn secrets_set(&self, _: &str, _: &str) -> Result<(), String>);
        unreachable_setup!(fn secrets_list(&self) -> Result<Vec<crate::SecretEntry>, String>);
        unreachable_setup!(fn secrets_remove(&self, _: &str) -> Result<(), String>);
        unreachable_setup!(fn list_manifests(&self) -> Result<Vec<crate::ManifestInfo>, String>);
        unreachable_setup!(fn read_manifest(&self, _: &str) -> Result<latchgate_registry::ActionSpec, String>);
        unreachable_setup!(fn write_manifest(&self, _: &latchgate_registry::ActionSpec) -> Result<std::path::PathBuf, String>);
        unreachable_setup!(fn export_preset(&self, _: &str, _: &str, _: &[String], _: &str) -> Result<std::path::PathBuf, String>);
        unreachable_setup!(fn list_presets(&self) -> Vec<crate::PresetListEntry>);
        fn check_manifests_dir_consistency(&self) -> Option<String> {
            None
        }
    }

    fn screen() -> ActionsScreen {
        ActionsScreen::new(Arc::new(UnusedSetup))
    }

    fn live(id: &str) -> Value {
        json!({ "action_id": id, "risk_level": "low" })
    }

    /// Fresh pending action — `added_at` is now, well within the stale threshold.
    fn pending(id: &str) -> PendingAction {
        PendingAction {
            action_id: id.into(),
            added_at: Instant::now(),
        }
    }

    /// Pending action whose timestamp is past [`PENDING_ACTION_STALE_SECS`].
    fn stale_pending(id: &str) -> PendingAction {
        PendingAction {
            action_id: id.into(),
            added_at: Instant::now() - Duration::from_secs(PENDING_ACTION_STALE_SECS + 1),
        }
    }

    #[test]
    fn pending_marker_survives_until_action_goes_live() {
        let mut s = screen();
        s.pending_actions = vec![pending("new_action")];

        // Gate has not yet reloaded: the action is still unresolved.
        s.actions = vec![live("existing")];
        assert!(s.has_unresolved_pending());

        // Gate reloads and now serves the action: reconciliation drops it.
        s.actions = vec![live("existing"), live("new_action")];
        s.reconcile_pending_actions();
        assert!(!s.has_unresolved_pending());
        assert!(s.pending_actions.is_empty());
        assert!(s.error.is_none());
    }

    #[test]
    fn pending_marker_persists_when_reload_fails() {
        let mut s = screen();
        s.pending_actions = vec![pending("new_action")];
        // A failed restart leaves the live list unchanged; the marker must
        // remain so the operator still sees the unapplied action.
        s.actions = vec![live("existing")];
        assert!(s.has_unresolved_pending());
    }

    #[test]
    fn no_pending_means_no_unresolved() {
        let mut s = screen();
        s.actions = vec![live("a"), live("b")];
        assert!(!s.has_unresolved_pending());
    }

    #[test]
    fn stale_pending_action_surfaces_error() {
        let mut s = screen();
        s.pending_actions = vec![stale_pending("vanished_action")];
        s.actions = vec![live("existing")];

        s.reconcile_pending_actions();

        // Stale entry is removed and a diagnostic is surfaced.
        assert!(s.pending_actions.is_empty());
        let err = s.error.as_ref().expect("expected stale-action diagnostic");
        assert!(err.contains("vanished_action"));
        assert!(err.contains("manifests_dir"));
    }

    #[test]
    fn fresh_pending_action_survives_reconciliation() {
        let mut s = screen();
        s.pending_actions = vec![pending("still_waiting")];
        s.actions = vec![live("existing")];

        s.reconcile_pending_actions();

        // Fresh entry survives — no error.
        assert_eq!(s.pending_actions.len(), 1);
        assert!(s.error.is_none());
    }

    // -- Modal input gating --------------------------------------------------

    #[test]
    fn not_modal_when_no_edit_or_create() {
        let s = screen();
        assert!(!s.is_modal());
    }

    #[test]
    fn modal_while_create_is_open() {
        let mut s = screen();
        s.create = Some(CreateStep::ActionId(TextInput::new("action_id", 64)));
        assert!(s.is_modal());
    }

    #[test]
    fn modal_at_edit_field_list_level() {
        // The regression case: the edit screen is open but at the field-list
        // level — no field editor open and the buffer is not dirty. A digit
        // typed here must be captured by the modal, not leak to global tab
        // navigation, so the screen must report as modal.
        let mut s = screen();
        let edit = EditState::new(http_spec());
        assert!(!edit.dirty, "fresh edit must not be dirty");
        assert!(edit.editor.is_none(), "fresh edit must have no open editor");
        s.edit = Some(edit);
        assert!(s.is_modal());
    }
}
