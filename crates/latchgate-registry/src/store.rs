//! In-memory action registry: manifest lookup, digest verification, and
//! pre-compiled JSON Schema validators.
//!
//! The `RegistryStore` loads action manifests from YAML files at startup,
//! resolves their I/O schema paths, and pre-compiles JSON Schema validators.
//! All mutations happen at load time — the store is immutable during request
//! processing.
//!
//! # Security properties
//!
//! - **Fail-closed on unknown actions**: `get_action() returns `None` for
//!   unregistered action IDs. The caller (Gate pipeline) MUST deny.
//! - **Digest verification**: `verify_digest()` returns a [`TrustVerdict`]
//!   that the Gate enforces. Mismatch or missing entry = DENY.
//!   startup without reloading the store. This prevents TOCTOU attacks
//! - **Pre-compiled schemas**: JSON Schemas are compiled once at startup.
//!   The hot path uses `&Validator` — zero per-request parsing cost.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use serde_json::Value;
use tracing::{info, trace, warn};

use crate::schema::{compile_schema, SchemaError, ValidationLimits};

use crate::manifest::{ActionSpec, ManifestError};
use latchgate_core::TrustVerdict;

/// Errors from loading the registry store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("manifests directory not found: {path}")]
    DirNotFound { path: String },

    #[error("failed to read manifests directory: {0}")]
    ReadDir(#[source] std::io::Error),

    #[error("failed to load manifest '{path}': {source}")]
    LoadManifest {
        path: String,
        #[source]
        source: ManifestError,
    },

    #[error("duplicate action_id '{action_id}' in manifests: '{first}' and '{second}'")]
    DuplicateActionId {
        action_id: String,
        first: String,
        second: String,
    },

    #[error("failed to read schema file '{path}': {source}")]
    SchemaIo {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse schema JSON '{path}': {source}")]
    SchemaJson {
        path: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("failed to compile schema '{path}': {reason}")]
    SchemaCompile { path: String, reason: String },

    #[error("path traversal rejected: {path} escapes {root}")]
    PathTraversal { path: String, root: String },
}

/// A manifest that was skipped during lenient directory loading.
///
/// Returned by [`RegistryBuilder::add_dir_lenient`] for each YAML file
/// that could not be parsed or whose schemas could not be compiled.
/// Security-critical failures (path traversal, duplicate IDs) still
/// cause a hard error even in lenient mode.
#[derive(Debug)]
pub struct SkippedManifest {
    /// Filesystem path of the skipped file.
    pub path: String,
    /// Human-readable reason the manifest was skipped.
    pub reason: String,
}

/// Pre-compiled JSON Schema validators for a action's request and response.
///
/// Compiled once at startup from the schema files declared in the manifest's
/// `io.request_schema` / `io.response_schema` fields. If a manifest omits a
/// schema path, the corresponding validator is `None`.
///
/// SECURITY: validators are compiled at startup. If compilation fails, the
/// store load fails entirely (fail-closed — no action runs without a valid
/// schema if one is declared).
pub struct ActionSchemas {
    pub request: Option<jsonschema::Validator>,
    pub response: Option<jsonschema::Validator>,
    /// Raw request JSON Schema value, retained for API/MCP exposure.
    ///
    /// The compiled 'request' validator is used for enforcement; this value
    /// is returned verbatim by GET /v1/actions/{id}/schema/request so that
    /// the MCP adapter can populate MCP inputSchema fields without needing
    /// filesystem access to the schema files.
    pub request_schema_json: Option<serde_json::Value>,
}

impl std::fmt::Debug for ActionSchemas {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActionSchemas")
            .field("request", &self.request.as_ref().map(|_| "Validator(...)"))
            .field(
                "response",
                &self.response.as_ref().map(|_| "Validator(...)"),
            )
            .field(
                "request_schema_json",
                &self.request_schema_json.as_ref().map(|_| "Value(...)"),
            )
            .finish()
    }
}

/// Immutable, in-memory action manifest store with pre-compiled schemas.
///
/// Built once at startup from a directory of YAML manifests. Provides O(1)
/// lookups by action ID for the Gate pipeline hot path. JSON Schemas are
/// compiled during loading — the hot path pays zero compilation cost.
#[derive(Debug)]
pub struct RegistryStore {
    actions: HashMap<String, ActionSpec>,
    schemas: HashMap<String, ActionSchemas>,
    provenance: HashMap<String, SourceKind>,
    /// Maps action_id => on-disk file path for manifests loaded from directories.
    /// Embedded manifests are excluded (they have no editable file path).
    /// Used by the TUI to locate manifests for editing and write-back.
    source_files: HashMap<String, std::path::PathBuf>,
    override_count: usize,
}

/// Where an action was loaded from. Used by `config resources` and
/// override logging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceKind {
    Embedded,
    Dir(std::path::PathBuf),
}

impl std::fmt::Display for SourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Embedded => write!(f, "embedded"),
            Self::Dir(p) => write!(f, "{}", p.display()),
        }
    }
}

/// Builds a [`RegistryStore`] by merging sources in order.
///
/// Later sources win by `action_id`. Every override of an existing action
/// emits a WARN log — the operator always knows when a built-in is shadowed.
///
/// ```text
/// 1. Embedded   — built into the binary (66 default actions)
/// 2. User dir   — ~/.config/latchgate/manifests/ (user overrides)
/// 3. Project dir — .latchgate/manifests/ (project-local overrides)
/// ```
#[derive(Debug)]
pub struct RegistryBuilder {
    actions: HashMap<String, ActionSpec>,
    schemas: HashMap<String, ActionSchemas>,
    provenance: HashMap<String, SourceKind>,
    source_files: HashMap<String, String>,
    override_count: usize,
}

impl Default for RegistryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RegistryBuilder {
    pub fn new() -> Self {
        Self {
            actions: HashMap::new(),
            schemas: HashMap::new(),
            provenance: HashMap::new(),
            source_files: HashMap::new(),
            override_count: 0,
        }
    }

    /// Add embedded manifests (YAML text loaded from the binary).
    ///
    /// Schema resolution uses inline schemas only — file-path schemas in
    /// embedded manifests will fail with a clear error.
    pub fn add_embedded(
        mut self,
        manifests: impl Iterator<Item = (&'static str, &'static str)>,
    ) -> Result<Self, StoreError> {
        for (filename, yaml) in manifests {
            let manifest = ActionSpec::from_yaml(yaml).map_err(|e| StoreError::LoadManifest {
                path: format!("embedded:{filename}"),
                source: e,
            })?;

            let action_id = manifest.action_id.clone();

            // Embedded manifests are the baseline — duplicates within
            // embedded are a build-time bug.
            if let Some(prev) = self.source_files.get(&action_id) {
                return Err(StoreError::DuplicateActionId {
                    action_id,
                    first: prev.clone(),
                    second: format!("embedded:{filename}"),
                });
            }

            let action_schemas = compile_action_schemas(Path::new(""), &manifest)?;

            self.source_files
                .insert(action_id.clone(), format!("embedded:{filename}"));
            self.schemas.insert(action_id.clone(), action_schemas);
            self.provenance
                .insert(action_id.clone(), SourceKind::Embedded);
            self.actions.insert(action_id, manifest);
        }

        info!(
            count = self.actions.len(),
            "registry: embedded manifests loaded"
        );
        Ok(self)
    }

    /// Add manifests from a directory. Actions with the same `action_id` as
    /// an existing entry override it — a WARN is emitted for each override.
    ///
    /// Skips silently if the directory does not exist (user may not have
    /// custom manifests).
    pub fn add_dir(mut self, dir: &Path) -> Result<Self, StoreError> {
        if !dir.exists() {
            info!(path = %dir.display(), "manifests directory does not exist, skipping");
            return Ok(self);
        }
        if !dir.is_dir() {
            return Err(StoreError::DirNotFound {
                path: dir.display().to_string(),
            });
        }

        let entries = std::fs::read_dir(dir).map_err(StoreError::ReadDir)?;
        let source = SourceKind::Dir(dir.to_path_buf());
        let mut count = 0usize;
        let mut overrides = 0usize;

        for entry in entries {
            let entry = entry.map_err(StoreError::ReadDir)?;
            let path = entry.path();

            let is_yaml = path
                .extension()
                .map(|ext| ext == "yaml" || ext == "yml")
                .unwrap_or(false);
            if !is_yaml {
                continue;
            }

            latchgate_core::paths::ensure_contained(dir, &path).map_err(|_| {
                StoreError::PathTraversal {
                    path: path.display().to_string(),
                    root: dir.display().to_string(),
                }
            })?;

            let manifest = ActionSpec::from_file(&path).map_err(|e| StoreError::LoadManifest {
                path: path.display().to_string(),
                source: e,
            })?;

            let action_id = manifest.action_id.clone();
            let file_str = path.display().to_string();

            // Within the same directory, duplicates are still an error.
            if let Some(prev) = self.source_files.get(&action_id) {
                if prev.starts_with(&format!("{}:", dir.display()))
                    || (self.provenance.get(&action_id) == Some(&source))
                {
                    return Err(StoreError::DuplicateActionId {
                        action_id,
                        first: prev.clone(),
                        second: file_str,
                    });
                }
            }

            // Cross-source override: log and replace.
            if let Some(prev_source) = self.provenance.get(&action_id) {
                // Suppress warning when the user manifest is identical to the
                // embedded one (common after `latchgate init` extracts built-in
                // manifests to disk). Compare via `serde_json::to_value` for
                // structural equality — `to_string` is ordering-sensitive and
                // fails on structs containing HashMap fields.
                let is_identical = self.actions.get(&action_id).is_some_and(|existing| {
                    match (
                        serde_json::to_value(existing),
                        serde_json::to_value(&manifest),
                    ) {
                        (Ok(a), Ok(b)) => a == b,
                        _ => false,
                    }
                });

                if is_identical {
                    trace!(
                        action_id = %action_id,
                        "user manifest identical to embedded — no override"
                    );
                } else {
                    warn!(
                        action_id = %action_id,
                        previous_source = %prev_source,
                        new_source = %dir.display(),
                        "action manifest overridden — built-in shadowed by user manifest"
                    );
                    overrides += 1;
                    self.override_count += 1;
                }
            }

            let manifest_dir = path.parent().unwrap_or(dir);
            let action_schemas = compile_action_schemas(manifest_dir, &manifest)?;

            self.source_files.insert(action_id.clone(), file_str);
            self.schemas.insert(action_id.clone(), action_schemas);
            self.provenance.insert(action_id.clone(), source.clone());
            self.actions.insert(action_id, manifest);
            count += 1;
        }

        info!(
            dir = %dir.display(),
            loaded = count,
            overrides,
            "registry: directory manifests merged"
        );
        Ok(self)
    }

    /// Load manifests from a directory, skipping files that fail to parse or
    /// whose schemas fail to compile.
    ///
    /// Intended for **dev posture only** — keeps one bad manifest from taking
    /// down the entire registry during iteration. Production posture should
    /// use [`add_dir`](Self::add_dir) which fails hard on any error.
    ///
    /// # Security
    ///
    /// Path-traversal and duplicate-ID violations still return hard errors.
    /// Only content-level failures (YAML parse, schema I/O, schema
    /// compilation) are treated as soft skips.
    pub fn add_dir_lenient(
        mut self,
        dir: &Path,
    ) -> Result<(Self, Vec<SkippedManifest>), StoreError> {
        if !dir.exists() {
            info!(path = %dir.display(), "manifests directory does not exist, skipping");
            return Ok((self, Vec::new()));
        }
        if !dir.is_dir() {
            return Err(StoreError::DirNotFound {
                path: dir.display().to_string(),
            });
        }

        let entries = std::fs::read_dir(dir).map_err(StoreError::ReadDir)?;
        let source = SourceKind::Dir(dir.to_path_buf());
        let mut count = 0usize;
        let mut overrides = 0usize;
        let mut skipped = Vec::new();

        for entry in entries {
            let entry = entry.map_err(StoreError::ReadDir)?;
            let path = entry.path();

            let is_yaml = path
                .extension()
                .map(|ext| ext == "yaml" || ext == "yml")
                .unwrap_or(false);
            if !is_yaml {
                continue;
            }

            // Security: path traversal is always a hard error.
            latchgate_core::paths::ensure_contained(dir, &path).map_err(|_| {
                StoreError::PathTraversal {
                    path: path.display().to_string(),
                    root: dir.display().to_string(),
                }
            })?;

            let manifest = match ActionSpec::from_file(&path) {
                Ok(m) => m,
                Err(e) => {
                    warn!(
                        path = %path.display(),
                        error = %e,
                        "skipping malformed manifest (dev mode)"
                    );
                    skipped.push(SkippedManifest {
                        path: path.display().to_string(),
                        reason: e.to_string(),
                    });
                    continue;
                }
            };

            let action_id = manifest.action_id.clone();
            let file_str = path.display().to_string();

            // Security: duplicate IDs within the same directory are always
            // a hard error — they indicate a config conflict.
            if let Some(prev) = self.source_files.get(&action_id) {
                if prev.starts_with(&format!("{}:", dir.display()))
                    || (self.provenance.get(&action_id) == Some(&source))
                {
                    return Err(StoreError::DuplicateActionId {
                        action_id,
                        first: prev.clone(),
                        second: file_str,
                    });
                }
            }

            // Cross-source override handling (same as add_dir).
            if let Some(prev_source) = self.provenance.get(&action_id) {
                let is_identical = self.actions.get(&action_id).is_some_and(|existing| {
                    match (
                        serde_json::to_value(existing),
                        serde_json::to_value(&manifest),
                    ) {
                        (Ok(a), Ok(b)) => a == b,
                        _ => false,
                    }
                });

                if is_identical {
                    trace!(
                        action_id = %action_id,
                        "user manifest identical to embedded — no override"
                    );
                } else {
                    warn!(
                        action_id = %action_id,
                        previous_source = %prev_source,
                        new_source = %dir.display(),
                        "action manifest overridden — built-in shadowed by user manifest"
                    );
                    overrides += 1;
                    self.override_count += 1;
                }
            }

            let manifest_dir = path.parent().unwrap_or(dir);
            let action_schemas = match compile_action_schemas(manifest_dir, &manifest) {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        action_id = %action_id,
                        path = %path.display(),
                        error = %e,
                        "skipping manifest with schema errors (dev mode)"
                    );
                    skipped.push(SkippedManifest {
                        path: path.display().to_string(),
                        reason: e.to_string(),
                    });
                    continue;
                }
            };

            self.source_files.insert(action_id.clone(), file_str);
            self.schemas.insert(action_id.clone(), action_schemas);
            self.provenance.insert(action_id.clone(), source.clone());
            self.actions.insert(action_id, manifest);
            count += 1;
        }

        info!(
            dir = %dir.display(),
            loaded = count,
            skipped = skipped.len(),
            overrides,
            "registry: directory manifests merged (lenient)"
        );
        Ok((self, skipped))
    }

    /// Finalize into an immutable [`RegistryStore`].
    pub fn build(self) -> RegistryStore {
        info!(
            total = self.actions.len(),
            overrides = self.override_count,
            "registry build complete"
        );

        // Retain only on-disk file paths (not "embedded:..." entries).
        let source_files: HashMap<String, std::path::PathBuf> = self
            .source_files
            .into_iter()
            .filter(|(_, path)| !path.starts_with("embedded:"))
            .map(|(id, path)| (id, std::path::PathBuf::from(path)))
            .collect();

        RegistryStore {
            actions: self.actions,
            schemas: self.schemas,
            provenance: self.provenance,
            source_files,
            override_count: self.override_count,
        }
    }
}

impl RegistryStore {
    /// Create an empty store. Useful for tests.
    pub fn empty() -> Self {
        Self {
            actions: HashMap::new(),
            schemas: HashMap::new(),
            provenance: HashMap::new(),
            source_files: HashMap::new(),
            override_count: 0,
        }
    }

    /// Load all `.yaml` / `.yml` manifests from a directory.
    ///
    /// For each manifest, resolves `io.request_schema` / `io.response_schema`
    /// paths relative to the manifest file's parent directory, reads the JSON,
    /// and pre-compiles a `jsonschema::Validator`.
    ///
    /// Rejects duplicate `action_id` values across files — each action must have
    /// exactly one manifest. Non-YAML files are silently skipped.
    ///
    /// Returns an error if:
    /// - The directory does not exist or is unreadable.
    /// - Any YAML file fails to parse or validate.
    /// - Two manifests declare the same `action_id`.
    /// - A declared schema file cannot be read, parsed, or compiled.
    pub fn load_from_dir(dir: &Path) -> Result<Self, StoreError> {
        if !dir.is_dir() {
            return Err(StoreError::DirNotFound {
                path: dir.display().to_string(),
            });
        }

        let entries = std::fs::read_dir(dir).map_err(StoreError::ReadDir)?;

        let mut actions = HashMap::new();
        let mut schemas = HashMap::new();
        // Track which file defined each action_id for duplicate diagnostics.
        let mut source_files: HashMap<String, String> = HashMap::new();

        for entry in entries {
            let entry = entry.map_err(StoreError::ReadDir)?;
            let path = entry.path();

            // Skip non-YAML files.
            let is_yaml = path
                .extension()
                .map(|ext| ext == "yaml" || ext == "yml")
                .unwrap_or(false);
            if !is_yaml {
                continue;
            }

            let manifest = ActionSpec::from_file(&path).map_err(|e| StoreError::LoadManifest {
                path: path.display().to_string(),
                source: e,
            })?;

            let action_id = manifest.action_id.clone();
            let file_str = path.display().to_string();

            // SECURITY: duplicate action_id would allow one manifest to shadow
            // another, potentially bypassing digest verification.
            if let Some(first_file) = source_files.get(&action_id) {
                return Err(StoreError::DuplicateActionId {
                    action_id,
                    first: first_file.clone(),
                    second: file_str,
                });
            }

            // Pre-compile schemas declared in the manifest.
            let manifest_dir = path.parent().unwrap_or(dir);
            let action_schemas = compile_action_schemas(manifest_dir, &manifest)?;

            source_files.insert(action_id.clone(), file_str);
            schemas.insert(action_id.clone(), action_schemas);
            actions.insert(action_id, manifest);
        }

        info!(count = actions.len(), dir = %dir.display(), "registry loaded (with schemas)");
        let disk_source_files = source_files
            .into_iter()
            .map(|(id, path)| (id, std::path::PathBuf::from(path)))
            .collect();
        Ok(Self {
            actions,
            schemas,
            provenance: HashMap::new(),
            source_files: disk_source_files,
            override_count: 0,
        })
    }

    /// Look up an action manifest by ID. Returns `None` for unknown actions.
    ///
    /// SECURITY: the caller MUST deny requests for unknown actions. A `None`
    /// return is not "action not found, try later" — it means "action is not
    /// registered and execution is forbidden".
    pub fn get_action(&self, action_id: &str) -> Option<&ActionSpec> {
        self.actions.get(action_id)
    }

    /// Get the pre-compiled request schema validator for an action.
    ///
    /// Returns `None` if the action has no request schema declared, or if the
    /// action is not registered at all.
    pub fn get_request_validator(&self, action_id: &str) -> Option<&jsonschema::Validator> {
        self.schemas.get(action_id).and_then(|s| s.request.as_ref())
    }

    /// Get the pre-compiled response schema validator for an action.
    ///
    /// Returns `None` if the action has no response schema declared, or if the
    /// action is not registered at all.
    pub fn get_response_validator(&self, action_id: &str) -> Option<&jsonschema::Validator> {
        self.schemas
            .get(action_id)
            .and_then(|s| s.response.as_ref())
    }

    /// Get the raw request JSON Schema for an action, if one was declared.
    ///
    /// Returns the parsed schema value for exposure via the API (e.g.
    /// GET /v1/actions/{id}/schema/request). Returns None if the action has
    /// no declared request schema.
    pub fn get_request_schema_json(&self, action_id: &str) -> Option<&serde_json::Value> {
        self.schemas
            .get(action_id)
            .and_then(|s| s.request_schema_json.as_ref())
    }

    /// Get the pre-compiled schemas for an action.
    pub fn get_schemas(&self, action_id: &str) -> Option<&ActionSchemas> {
        self.schemas.get(action_id)
    }

    /// Validate an action request body against pre-compiled schemas and limits.
    ///
    /// This is the high-level entry point for the Gate pipeline. It:
    /// 1. Looks up the manifest (fail-closed if not found).
    /// 2. Builds `ValidationLimits` from the manifest's `io` config.
    /// 3. Runs `validate_request()` with the pre-compiled validator.
    ///
    /// Returns `Ok(())` if no request schema is declared (validation is optional).
    pub fn validate_action_request(
        &self,
        action_id: &str,
        body: &Value,
    ) -> Result<(), SchemaError> {
        let manifest = self
            .actions
            .get(action_id)
            .ok_or_else(|| SchemaError::NotFound {
                action_id: action_id.to_string(),
            })?;

        let limits = ValidationLimits {
            max_bytes: manifest.io.max_request_bytes,
            ..ValidationLimits::default()
        };

        match self.get_request_validator(action_id) {
            Some(validator) => crate::schema::validate_request(validator, body, &limits),
            None => {
                // No schema declared — still enforce limits (size/depth/items).
                crate::schema::validate_request_limits_only(body, &limits)
            }
        }
    }

    /// Validate an action response body against pre-compiled schemas and limits.
    ///
    /// Enforces the action contract envelope (`{"ok": bool, ...}`) regardless
    /// of whether a response schema is declared.
    pub fn validate_action_response(
        &self,
        action_id: &str,
        body: &Value,
    ) -> Result<(), SchemaError> {
        let manifest = self
            .actions
            .get(action_id)
            .ok_or_else(|| SchemaError::NotFound {
                action_id: action_id.to_string(),
            })?;

        let limits = ValidationLimits {
            max_bytes: manifest.io.max_response_bytes,
            ..ValidationLimits::default()
        };

        let validator = self.get_response_validator(action_id);
        crate::schema::validate_response(validator, body, &limits)
    }

    /// Verify an image digest against the trust allowlist.
    ///
    /// Returns a [`TrustVerdict`] — a data type. The Gate pipeline converts
    /// non-ok verdicts to [`latchgate_core::TrustError`] for enforcement.
    ///
    /// For `builtin:` providers, trust is implicit (the operator controls
    /// the server binary) — always returns `DigestOk`.
    pub fn verify_digest(&self, action_id: &str, actual_digest: &str) -> TrustVerdict {
        match self.actions.get(action_id) {
            None => {
                warn!(action_id, "trust check: action not registered");
                TrustVerdict::NotRegistered
            }
            Some(manifest) if manifest.provider_module_digest.starts_with("builtin:") => {
                // SECURITY: builtin providers are compiled into the server
                // binary. Trust is established by the operator deploying
                // a known server image — no content-addressed digest check.
                TrustVerdict::DigestOk
            }
            Some(manifest) if *manifest.provider_module_digest == *actual_digest => {
                TrustVerdict::DigestOk
            }
            Some(manifest) => {
                warn!(
                    action_id,
                    expected = %manifest.provider_module_digest,
                    actual = %actual_digest,
                    "trust check: digest mismatch"
                );
                TrustVerdict::DigestMismatch {
                    expected: Arc::clone(&manifest.provider_module_digest),
                    actual: Arc::from(actual_digest),
                }
            }
        }
    }

    /// List all registered action IDs (sorted for deterministic output).
    pub fn list_action_ids(&self) -> Vec<&str> {
        let mut ids: Vec<&str> = self.actions.keys().map(|s| s.as_str()).collect();
        ids.sort_unstable();
        ids
    }

    /// Return all manifests (sorted by action_id for deterministic output).
    pub fn list_actions(&self) -> Vec<&ActionSpec> {
        let mut actions_list: Vec<&ActionSpec> = self.actions.values().collect();
        actions_list.sort_by_key(|t| &t.action_id);
        actions_list
    }

    /// Number of registered actions.
    pub fn len(&self) -> usize {
        self.actions.len()
    }

    /// Returns `true` if no actions are registered.
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    /// Look up provenance for a single action.
    pub fn provenance_for(&self, action_id: &str) -> Option<&SourceKind> {
        self.provenance.get(action_id)
    }

    /// Iterate over provenance entries: `(action_id, source_kind)`.
    pub fn provenance_iter(&self) -> impl Iterator<Item = (&str, &SourceKind)> + '_ {
        self.provenance
            .iter()
            .map(|(id, source)| (id.as_str(), source))
    }

    /// Get the on-disk file path for a manifest loaded from a directory.
    ///
    /// Returns `None` for embedded manifests that were not overridden by a
    /// directory source (i.e. manifests with no editable file on disk).
    pub fn source_file(&self, action_id: &str) -> Option<&std::path::Path> {
        self.source_files.get(action_id).map(|p| p.as_path())
    }

    /// Iterate over on-disk manifest file paths: `(action_id, path)`.
    pub fn source_files_iter(&self) -> impl Iterator<Item = (&str, &std::path::Path)> + '_ {
        self.source_files
            .iter()
            .map(|(id, path)| (id.as_str(), path.as_path()))
    }

    /// Number of actions that were overridden during the multi-source merge.
    pub fn override_count(&self) -> usize {
        self.override_count
    }

    /// Start a new [`RegistryBuilder`] for multi-source merge loading.
    pub fn builder() -> RegistryBuilder {
        RegistryBuilder::new()
    }
}

/// Resolve schemas from a manifest and compile them into validators.
///
/// Schemas can be either file paths (resolved relative to the manifest
/// directory) or inline JSON Schema objects embedded in the YAML.
///
/// SECURITY: fail-closed — if a declared schema cannot be read or compiled,
/// the entire store load fails. No action runs with a broken schema.
fn compile_action_schemas(
    manifest_dir: &Path,
    manifest: &ActionSpec,
) -> Result<ActionSchemas, StoreError> {
    let (request, request_schema_json) = match &manifest.io.request_schema {
        Some(schema_ref) => {
            let (validator, raw) = resolve_and_compile_schema(
                manifest_dir,
                schema_ref,
                &manifest.action_id,
                "request",
            )?;
            (Some(validator), Some(raw))
        }
        None => (None, None),
    };

    let response = match &manifest.io.response_schema {
        Some(schema_ref) => {
            let (validator, _) = resolve_and_compile_schema(
                manifest_dir,
                schema_ref,
                &manifest.action_id,
                "response",
            )?;
            Some(validator)
        }
        None => None,
    };

    Ok(ActionSchemas {
        request,
        response,
        request_schema_json,
    })
}

/// Resolve an [`IoSchema`] (file path or inline) and compile it.
///
/// Returns both the compiled validator and the raw JSON value.
fn resolve_and_compile_schema(
    manifest_dir: &Path,
    schema_ref: &crate::manifest::IoSchema,
    action_id: &str,
    schema_kind: &str,
) -> Result<(jsonschema::Validator, Value), StoreError> {
    match schema_ref {
        crate::manifest::IoSchema::Path(rel_path) => {
            load_and_compile_schema_with_raw(manifest_dir, rel_path)
        }
        crate::manifest::IoSchema::Inline(value) => {
            let validator = compile_schema(value).map_err(|e| StoreError::SchemaCompile {
                path: format!("inline:{action_id}:{schema_kind}"),
                reason: e.to_string(),
            })?;
            Ok((validator, value.clone()))
        }
    }
}

/// Read a JSON file, return both the compiled validator and the raw Value.
///
/// The raw Value is stored in ActionSchemas for API/MCP exposure without
/// requiring filesystem access at request time.
fn load_and_compile_schema_with_raw(
    base_dir: &Path,
    rel_path: &str,
) -> Result<(jsonschema::Validator, Value), StoreError> {
    if Path::new(rel_path)
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(StoreError::PathTraversal {
            path: rel_path.to_string(),
            root: base_dir.display().to_string(),
        });
    }

    let abs_path = base_dir.join(rel_path);
    let canonical = abs_path.canonicalize().map_err(|e| StoreError::SchemaIo {
        path: abs_path.display().to_string(),
        source: e,
    })?;

    let canonical_root = base_dir.canonicalize().map_err(|e| StoreError::SchemaIo {
        path: base_dir.display().to_string(),
        source: e,
    })?;
    if !canonical.starts_with(&canonical_root) {
        return Err(StoreError::PathTraversal {
            path: canonical.display().to_string(),
            root: canonical_root.display().to_string(),
        });
    }

    let contents = std::fs::read_to_string(&canonical).map_err(|e| StoreError::SchemaIo {
        path: canonical.display().to_string(),
        source: e,
    })?;

    let schema_value: Value =
        serde_json::from_str(&contents).map_err(|e| StoreError::SchemaJson {
            path: canonical.display().to_string(),
            source: e,
        })?;

    let validator = compile_schema(&schema_value).map_err(|e| StoreError::SchemaCompile {
        path: canonical.display().to_string(),
        reason: e.to_string(),
    })?;

    Ok((validator, schema_value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const VALID_DIGEST: &str =
        "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
    const OTHER_DIGEST: &str =
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    fn sample_yaml(action_id: &str, digest: &str) -> String {
        format!(
            r#"
action_id: "{action_id}"
version: "1.0.0"
provider_module_digest: "{digest}"
"#
        )
    }

    fn sample_yaml_with_schemas(action_id: &str, digest: &str) -> String {
        format!(
            r#"
action_id: "{action_id}"
version: "1.0.0"
provider_module_digest: "{digest}"
io:
  request_schema: "schemas/{action_id}_request.json"
  response_schema: "schemas/{action_id}_response.json"
  max_request_bytes: 32768
  max_response_bytes: 65536
"#
        )
    }

    /// Minimal valid JSON Schema.
    fn minimal_request_schema() -> &'static str {
        r#"{
  "type": "object",
  "properties": {
    "url": { "type": "string" }
  },
  "required": ["url"],
  "additionalProperties": false
}"#
    }

    fn minimal_response_schema() -> &'static str {
        r#"{
  "type": "object",
  "properties": {
    "ok": { "type": "boolean" },
    "data": { "type": "object" }
  },
  "required": ["ok"]
}"#
    }

    /// Create a temp dir with YAML manifest files and return the path.
    fn create_manifest_dir(manifests: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (filename, content) in manifests {
            let path = dir.path().join(filename);
            fs::write(&path, content).unwrap();
        }
        dir
    }

    /// Create a temp dir with YAML manifests and JSON schema files.
    fn create_manifest_dir_with_schemas(
        manifests: &[(&str, &str)],
        schemas: &[(&str, &str)],
    ) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (filename, content) in manifests {
            let path = dir.path().join(filename);
            fs::write(&path, content).unwrap();
        }
        // Create schemas/ subdirectory.
        let schema_dir = dir.path().join("schemas");
        fs::create_dir_all(&schema_dir).unwrap();
        for (filename, content) in schemas {
            let path = schema_dir.join(filename);
            fs::write(&path, content).unwrap();
        }
        dir
    }

    // -- Empty store --

    #[test]
    fn empty_store_has_no_actions() {
        let store = RegistryStore::empty();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        assert!(store.list_action_ids().is_empty());
    }

    #[test]
    fn empty_store_get_returns_none() {
        let store = RegistryStore::empty();
        assert!(store.get_action("anything").is_none());
    }

    #[test]
    fn empty_store_verify_digest_returns_not_registered() {
        let store = RegistryStore::empty();
        assert_eq!(
            store.verify_digest("anything", VALID_DIGEST),
            TrustVerdict::NotRegistered
        );
    }

    // -- Loading from directory --

    #[test]
    fn load_from_dir_with_valid_manifests() {
        let dir = create_manifest_dir(&[
            ("http_fetch.yaml", &sample_yaml("http_fetch", VALID_DIGEST)),
            ("file_write.yml", &sample_yaml("file_write", OTHER_DIGEST)),
        ]);

        let store = RegistryStore::load_from_dir(dir.path()).unwrap();
        assert_eq!(store.len(), 2);
        assert!(store.get_action("http_fetch").is_some());
        assert!(store.get_action("file_write").is_some());
    }

    #[test]
    fn load_skips_non_yaml_files() {
        let dir = create_manifest_dir(&[
            ("tool.yaml", &sample_yaml("my_tool", VALID_DIGEST)),
            ("readme.md", "# Not a manifest"),
            ("notes.txt", "some notes"),
        ]);

        let store = RegistryStore::load_from_dir(dir.path()).unwrap();
        assert_eq!(store.len(), 1);
        assert!(store.get_action("my_tool").is_some());
    }

    #[test]
    fn load_empty_dir_returns_empty_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = RegistryStore::load_from_dir(dir.path()).unwrap();
        assert!(store.is_empty());
    }

    #[test]
    fn load_nonexistent_dir_returns_error() {
        let err = RegistryStore::load_from_dir(Path::new("/nonexistent/path")).unwrap_err();
        assert!(matches!(err, StoreError::DirNotFound { .. }));
    }

    #[test]
    fn load_rejects_invalid_manifest() {
        let dir = create_manifest_dir(&[("bad.yaml", "not: [valid: manifest")]);

        let err = RegistryStore::load_from_dir(dir.path()).unwrap_err();
        assert!(matches!(err, StoreError::LoadManifest { .. }));
    }

    #[test]
    fn load_rejects_duplicate_action_id() {
        let dir = create_manifest_dir(&[
            ("tool_a.yaml", &sample_yaml("same_id", VALID_DIGEST)),
            ("tool_b.yaml", &sample_yaml("same_id", OTHER_DIGEST)),
        ]);

        let err = RegistryStore::load_from_dir(dir.path()).unwrap_err();
        assert!(matches!(err, StoreError::DuplicateActionId { .. }));
        assert!(err.to_string().contains("same_id"));
    }

    // -- Digest verification --

    #[test]
    fn verify_digest_ok_when_matching() {
        let dir = create_manifest_dir(&[("t.yaml", &sample_yaml("tool_a", VALID_DIGEST))]);
        let store = RegistryStore::load_from_dir(dir.path()).unwrap();

        assert_eq!(
            store.verify_digest("tool_a", VALID_DIGEST),
            TrustVerdict::DigestOk
        );
    }

    #[test]
    fn verify_digest_mismatch_when_different() {
        let dir = create_manifest_dir(&[("t.yaml", &sample_yaml("tool_a", VALID_DIGEST))]);
        let store = RegistryStore::load_from_dir(dir.path()).unwrap();

        let verdict = store.verify_digest("tool_a", OTHER_DIGEST);
        assert!(matches!(verdict, TrustVerdict::DigestMismatch { .. }));
        if let TrustVerdict::DigestMismatch { expected, actual } = verdict {
            assert_eq!(&*expected, VALID_DIGEST);
            assert_eq!(&*actual, OTHER_DIGEST);
        }
    }

    #[test]
    fn verify_digest_not_registered_for_unknown_action() {
        let dir = create_manifest_dir(&[("t.yaml", &sample_yaml("known", VALID_DIGEST))]);
        let store = RegistryStore::load_from_dir(dir.path()).unwrap();

        assert_eq!(
            store.verify_digest("unknown", VALID_DIGEST),
            TrustVerdict::NotRegistered
        );
    }

    // -- Listing --

    #[test]
    fn list_action_ids_sorted() {
        let dir = create_manifest_dir(&[
            ("z.yaml", &sample_yaml("zebra", VALID_DIGEST)),
            ("a.yaml", &sample_yaml("alpha", OTHER_DIGEST)),
        ]);
        let store = RegistryStore::load_from_dir(dir.path()).unwrap();

        assert_eq!(store.list_action_ids(), vec!["alpha", "zebra"]);
    }

    #[test]
    fn list_actions_sorted_by_id() {
        let dir = create_manifest_dir(&[
            ("z.yaml", &sample_yaml("zebra", VALID_DIGEST)),
            ("a.yaml", &sample_yaml("alpha", OTHER_DIGEST)),
        ]);
        let store = RegistryStore::load_from_dir(dir.path()).unwrap();

        let actions = store.list_actions();
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0].action_id, "alpha");
        assert_eq!(actions[1].action_id, "zebra");
    }

    // -- get_action --

    #[test]
    fn get_action_returns_correct_manifest() {
        let dir = create_manifest_dir(&[
            ("a.yaml", &sample_yaml("alpha", VALID_DIGEST)),
            ("b.yaml", &sample_yaml("beta", OTHER_DIGEST)),
        ]);
        let store = RegistryStore::load_from_dir(dir.path()).unwrap();

        let action = store.get_action("beta").unwrap();
        assert_eq!(action.action_id, "beta");
        assert_eq!(&*action.provider_module_digest, OTHER_DIGEST);
    }

    #[test]
    fn get_action_returns_none_for_unknown() {
        let dir = create_manifest_dir(&[("a.yaml", &sample_yaml("alpha", VALID_DIGEST))]);
        let store = RegistryStore::load_from_dir(dir.path()).unwrap();

        assert!(store.get_action("nonexistent").is_none());
    }

    // -- Schema compilation --

    #[test]
    fn load_compiles_schemas_when_declared() {
        let dir = create_manifest_dir_with_schemas(
            &[(
                "fetch.yaml",
                &sample_yaml_with_schemas("fetch", VALID_DIGEST),
            )],
            &[
                ("fetch_request.json", minimal_request_schema()),
                ("fetch_response.json", minimal_response_schema()),
            ],
        );

        let store = RegistryStore::load_from_dir(dir.path()).unwrap();
        assert!(store.get_request_validator("fetch").is_some());
        assert!(store.get_response_validator("fetch").is_some());
    }

    #[test]
    fn no_validators_when_no_schemas_declared() {
        let dir = create_manifest_dir(&[("tool.yaml", &sample_yaml("my_tool", VALID_DIGEST))]);

        let store = RegistryStore::load_from_dir(dir.path()).unwrap();
        assert!(store.get_request_validator("my_tool").is_none());
        assert!(store.get_response_validator("my_tool").is_none());
    }

    #[test]
    fn load_fails_when_schema_file_missing() {
        let dir = create_manifest_dir(&[(
            "fetch.yaml",
            &sample_yaml_with_schemas("fetch", VALID_DIGEST),
        )]);
        // No schemas/ directory created — schema files don't exist.

        let err = RegistryStore::load_from_dir(dir.path()).unwrap_err();
        assert!(matches!(err, StoreError::SchemaIo { .. }));
    }

    #[test]
    fn load_fails_when_schema_json_invalid() {
        let dir = create_manifest_dir_with_schemas(
            &[(
                "fetch.yaml",
                &sample_yaml_with_schemas("fetch", VALID_DIGEST),
            )],
            &[
                ("fetch_request.json", "NOT VALID JSON {{{"),
                ("fetch_response.json", minimal_response_schema()),
            ],
        );

        let err = RegistryStore::load_from_dir(dir.path()).unwrap_err();
        assert!(matches!(err, StoreError::SchemaJson { .. }));
    }

    #[test]
    fn get_schemas_returns_struct() {
        let dir = create_manifest_dir_with_schemas(
            &[(
                "fetch.yaml",
                &sample_yaml_with_schemas("fetch", VALID_DIGEST),
            )],
            &[
                ("fetch_request.json", minimal_request_schema()),
                ("fetch_response.json", minimal_response_schema()),
            ],
        );

        let store = RegistryStore::load_from_dir(dir.path()).unwrap();
        let schemas = store.get_schemas("fetch").unwrap();
        assert!(schemas.request.is_some());
        assert!(schemas.response.is_some());
    }

    #[test]
    fn get_schemas_returns_none_for_unknown_action() {
        let store = RegistryStore::empty();
        assert!(store.get_schemas("nonexistent").is_none());
    }

    // -- High-level validation --

    #[test]
    fn validate_action_request_passes_valid_body() {
        let dir = create_manifest_dir_with_schemas(
            &[(
                "fetch.yaml",
                &sample_yaml_with_schemas("fetch", VALID_DIGEST),
            )],
            &[
                ("fetch_request.json", minimal_request_schema()),
                ("fetch_response.json", minimal_response_schema()),
            ],
        );
        let store = RegistryStore::load_from_dir(dir.path()).unwrap();

        let body = serde_json::json!({"url": "https://example.com"});
        store.validate_action_request("fetch", &body).unwrap();
    }

    #[test]
    fn validate_action_request_rejects_invalid_body() {
        let dir = create_manifest_dir_with_schemas(
            &[(
                "fetch.yaml",
                &sample_yaml_with_schemas("fetch", VALID_DIGEST),
            )],
            &[
                ("fetch_request.json", minimal_request_schema()),
                ("fetch_response.json", minimal_response_schema()),
            ],
        );
        let store = RegistryStore::load_from_dir(dir.path()).unwrap();

        // Missing required "url" field.
        let body = serde_json::json!({"method": "GET"});
        let err = store.validate_action_request("fetch", &body).unwrap_err();
        assert!(matches!(err, SchemaError::ValidationFailed { .. }));
    }

    #[test]
    fn validate_action_request_rejects_extra_field() {
        let dir = create_manifest_dir_with_schemas(
            &[(
                "fetch.yaml",
                &sample_yaml_with_schemas("fetch", VALID_DIGEST),
            )],
            &[
                ("fetch_request.json", minimal_request_schema()),
                ("fetch_response.json", minimal_response_schema()),
            ],
        );
        let store = RegistryStore::load_from_dir(dir.path()).unwrap();

        // Extra field blocked by additionalProperties: false.
        let body = serde_json::json!({"url": "https://example.com", "evil": true});
        let err = store.validate_action_request("fetch", &body).unwrap_err();
        assert!(matches!(err, SchemaError::ValidationFailed { .. }));
    }

    #[test]
    fn validate_action_request_unknown_action_returns_not_found() {
        let store = RegistryStore::empty();
        let body = serde_json::json!({"url": "https://example.com"});
        let err = store.validate_action_request("ghost", &body).unwrap_err();
        assert!(matches!(err, SchemaError::NotFound { .. }));
    }

    #[test]
    fn validate_action_request_no_schema_still_enforces_limits() {
        let dir = create_manifest_dir(&[("tool.yaml", &sample_yaml("my_tool", VALID_DIGEST))]);
        let store = RegistryStore::load_from_dir(dir.path()).unwrap();

        // Small valid body — should pass (no schema, limits only).
        let body = serde_json::json!({"anything": "goes"});
        store.validate_action_request("my_tool", &body).unwrap();
    }

    #[test]
    fn validate_action_request_no_schema_rejects_oversized_body() {
        let dir = create_manifest_dir(&[("tool.yaml", &sample_yaml("my_tool", VALID_DIGEST))]);
        let store = RegistryStore::load_from_dir(dir.path()).unwrap();

        // Default max_request_bytes is 64KB — build a body that exceeds it.
        let big_value = "x".repeat(70_000);
        let body = serde_json::json!({"payload": big_value});
        let err = store.validate_action_request("my_tool", &body).unwrap_err();
        assert!(matches!(err, SchemaError::TooLarge { .. }));
    }

    #[test]
    fn validate_action_response_passes_valid_envelope() {
        let dir = create_manifest_dir_with_schemas(
            &[(
                "fetch.yaml",
                &sample_yaml_with_schemas("fetch", VALID_DIGEST),
            )],
            &[
                ("fetch_request.json", minimal_request_schema()),
                ("fetch_response.json", minimal_response_schema()),
            ],
        );
        let store = RegistryStore::load_from_dir(dir.path()).unwrap();

        let body = serde_json::json!({"ok": true, "data": {"status": 200}});
        store.validate_action_response("fetch", &body).unwrap();
    }

    #[test]
    fn validate_action_response_rejects_missing_ok_field() {
        let dir = create_manifest_dir_with_schemas(
            &[(
                "fetch.yaml",
                &sample_yaml_with_schemas("fetch", VALID_DIGEST),
            )],
            &[
                ("fetch_request.json", minimal_request_schema()),
                ("fetch_response.json", minimal_response_schema()),
            ],
        );
        let store = RegistryStore::load_from_dir(dir.path()).unwrap();

        let body = serde_json::json!({"data": {"status": 200}});
        let err = store.validate_action_response("fetch", &body).unwrap_err();
        assert!(matches!(err, SchemaError::ValidationFailed { .. }));
    }

    // -- Debug impl --

    #[test]
    fn action_schemas_debug_does_not_expose_internals() {
        let schemas = ActionSchemas {
            request: None,
            response: None,
            request_schema_json: None,
        };
        let debug = format!("{schemas:?}");
        assert!(debug.contains("ActionSchemas"));
        assert!(!debug.contains("jsonschema"));
    }

    // -- Builtin provider support --

    fn builtin_yaml_with_inline_schema(action_id: &str) -> String {
        format!(
            r#"
action_id: "{action_id}"
version: "1.0.0"
provider_module_digest: "builtin:http_api"
template:
  method: GET
  url_template: "https://api.github.com/{{{{path}}}}"
  headers:
    Accept: "application/vnd.github.v3+json"
io:
  request_schema:
    type: object
    properties:
      path:
        type: string
    required:
      - path
  max_request_bytes: 4096
  max_response_bytes: 1048576
egress:
  profile: "proxy_allowlist"
  allowed_domains:
    - "api.github.com"
risk_level: "low"
verifier_kind: http_status
declared_side_effects:
  - "http_read"
"#
        )
    }

    #[test]
    fn load_builtin_manifest_with_inline_schema() {
        let dir = create_manifest_dir(&[(
            "github_read.yaml",
            &builtin_yaml_with_inline_schema("github_read"),
        )]);

        let store = RegistryStore::load_from_dir(dir.path()).unwrap();
        assert_eq!(store.len(), 1);
        assert!(store.get_action("github_read").is_some());

        let action = store.get_action("github_read").unwrap();
        assert_eq!(&*action.provider_module_digest, "builtin:http_api");
        assert!(action.template.is_some());

        // Inline schema should be compiled.
        assert!(store.get_request_validator("github_read").is_some());
        // Raw schema JSON should be available for API exposure.
        let schema_json = store
            .get_request_schema_json("github_read")
            .expect("inline schema JSON should be stored");
        assert_eq!(schema_json["type"], "object");
    }

    #[test]
    fn verify_digest_builtin_always_ok() {
        let dir = create_manifest_dir(&[(
            "github_read.yaml",
            &builtin_yaml_with_inline_schema("github_read"),
        )]);
        let store = RegistryStore::load_from_dir(dir.path()).unwrap();

        // For builtin providers, any actual_digest should return DigestOk
        // because trust is implicit.
        assert_eq!(
            store.verify_digest("github_read", "sha256:doesnotmatter"),
            TrustVerdict::DigestOk
        );
        assert_eq!(
            store.verify_digest("github_read", "builtin:http_api"),
            TrustVerdict::DigestOk
        );
    }

    #[test]
    fn validate_request_with_inline_schema() {
        let dir = create_manifest_dir(&[(
            "github_read.yaml",
            &builtin_yaml_with_inline_schema("github_read"),
        )]);
        let store = RegistryStore::load_from_dir(dir.path()).unwrap();

        // Valid request.
        let body = serde_json::json!({"path": "repos/torvalds/linux"});
        store.validate_action_request("github_read", &body).unwrap();

        // Missing required field.
        let bad = serde_json::json!({"wrong": "field"});
        let err = store
            .validate_action_request("github_read", &bad)
            .unwrap_err();
        assert!(matches!(err, SchemaError::ValidationFailed { .. }));
    }

    #[test]
    fn mixed_builtin_and_digest_manifests_load() {
        let dir = create_manifest_dir(&[
            (
                "github_read.yaml",
                &builtin_yaml_with_inline_schema("github_read"),
            ),
            ("http_fetch.yaml", &sample_yaml("http_fetch", VALID_DIGEST)),
        ]);
        let store = RegistryStore::load_from_dir(dir.path()).unwrap();
        assert_eq!(store.len(), 2);

        // Digest-based action: normal verification.
        assert_eq!(
            store.verify_digest("http_fetch", VALID_DIGEST),
            TrustVerdict::DigestOk
        );
        assert!(matches!(
            store.verify_digest("http_fetch", OTHER_DIGEST),
            TrustVerdict::DigestMismatch { .. }
        ));

        // Builtin action: always ok.
        assert_eq!(
            store.verify_digest("github_read", "anything"),
            TrustVerdict::DigestOk
        );
    }

    // Egress-proxy coverage wiring
    //
    // `latchgate_api::server::serve` composes two public APIs at startup
    // to enforce defence-in-depth egress control:
    //
    //   1. `RegistryStore::list_actions()` =>
    //      `ActionSpec::egress_profile()` yields the per-action egress
    //      shape.
    //   2. `Config::validate_egress_proxy_coverage()` reports when
    //      actions declare `EgressProfile::ProxyAllowlist` but
    //      `egress_proxy_url` is absent — the kernel emits a startup
    //      warning and proceeds with kernel-only enforcement.
    //
    // Each endpoint has its own unit suite — profile parsing here, the
    // validator in `latchgate-core/src/config.rs`. The glue between
    // them is not covered anywhere else. A silent change to the
    // iteration shape, profile parsing, or action_id borrowing could
    // break the production `serve()` guarantee without tripping any
    // existing test. The two tests below close that gap by driving the
    // full wiring from on-disk YAML through to the final validation.
    //
    // SECURITY: the kernel's per-call sink allowlist and the egress
    // proxy's per-packet enforcement are intentionally redundant.
    // Running without the proxy collapses defence-in-depth to a single
    // layer; the kernel emits a startup warning in that configuration.

    fn proxy_allowlist_yaml(action_id: &str) -> String {
        format!(
            r#"
action_id: "{action_id}"
version: "1.0.0"
provider_module_digest: "{VALID_DIGEST}"
egress:
  profile: "proxy_allowlist"
  allowed_domains:
    - "api.example.com"
"#
        )
    }

    /// Mirrors the registry-to-config glue in
    /// `latchgate_api::server::serve`. Any change to the shape of that
    /// wiring (e.g. a new filter, a different accessor) must be
    /// reflected here so this test continues to exercise the production
    /// path.
    fn collect_action_egress_profiles(
        registry: &RegistryStore,
    ) -> Vec<(String, latchgate_core::EgressProfile)> {
        registry
            .list_actions()
            .into_iter()
            .filter_map(|spec| {
                spec.egress_profile()
                    .ok()
                    .map(|profile| (spec.action_id.clone(), profile))
            })
            .collect()
    }

    #[test]
    fn production_startup_reports_kernel_only_for_proxy_allowlist_without_egress_proxy() {
        use latchgate_config::{Config, EgressCoverageResult, SecurityPosture};

        let dir = create_manifest_dir(&[
            ("fetcher.yaml", &proxy_allowlist_yaml("fetcher")),
            ("poster.yaml", &proxy_allowlist_yaml("poster")),
            // Co-existing no-egress manifest must not surface in the
            // violation list.
            ("offline.yaml", &sample_yaml("offline", OTHER_DIGEST)),
        ]);

        let registry = RegistryStore::load_from_dir(dir.path()).expect("load registry");
        assert_eq!(registry.len(), 3, "all three manifests must load");

        let config = Config {
            posture: SecurityPosture::default(),
            egress: latchgate_config::EgressConfig {
                egress_proxy_url: None,
                ..Default::default()
            },
            ..Config::default()
        };

        let profiles = collect_action_egress_profiles(&registry);
        let result = config.validate_egress_proxy_coverage(
            profiles.iter().map(|(id, p)| (id.as_str(), p.clone())),
        );

        match result {
            EgressCoverageResult::KernelOnly { mut actions } => {
                // Registry iteration is HashMap-backed; order not stable.
                actions.sort();
                assert_eq!(
                    actions,
                    vec!["fetcher".to_string(), "poster".to_string()],
                    "only proxy_allowlist actions must appear; \
                     'offline' declares egress=none and must not"
                );
            }
            other => panic!("expected KernelOnly, got {other:?}"),
        }
    }

    #[test]
    fn production_startup_accepts_proxy_allowlist_with_egress_proxy() {
        use latchgate_config::{Config, EgressCoverageResult, SecurityPosture};

        let dir = create_manifest_dir(&[("fetcher.yaml", &proxy_allowlist_yaml("fetcher"))]);

        let registry = RegistryStore::load_from_dir(dir.path()).expect("load registry");

        let config = Config {
            posture: SecurityPosture::default(),
            egress: latchgate_config::EgressConfig {
                egress_proxy_url: Some("http://egress-proxy.internal:3128".into()),
                ..Default::default()
            },
            ..Config::default()
        };

        let profiles = collect_action_egress_profiles(&registry);
        assert_eq!(
            config.validate_egress_proxy_coverage(
                profiles.iter().map(|(id, p)| (id.as_str(), p.clone()))
            ),
            EgressCoverageResult::Covered,
            "proxy_allowlist with configured egress_proxy_url must report Covered",
        );
    }

    // -- RegistryBuilder -------------------------------------------------

    #[test]
    fn builder_loads_embedded() {
        let manifests = [
            ("a.yaml", sample_yaml("action_a", VALID_DIGEST)),
            ("b.yaml", sample_yaml("action_b", OTHER_DIGEST)),
        ];
        let iter = manifests.iter().map(|(f, y)| (*f, y.as_str()));

        // Leak to get 'static — acceptable in tests.
        let pairs: Vec<(&'static str, &'static str)> = iter
            .map(|(f, y)| {
                let f: &'static str = Box::leak(f.to_string().into_boxed_str());
                let y: &'static str = Box::leak(y.to_string().into_boxed_str());
                (f, y)
            })
            .collect();

        let store = RegistryStore::builder()
            .add_embedded(pairs.into_iter())
            .unwrap()
            .build();

        assert_eq!(store.len(), 2);
        assert!(store.get_action("action_a").is_some());
        assert!(store.get_action("action_b").is_some());
        assert_eq!(
            store.provenance_for("action_a"),
            Some(&SourceKind::Embedded)
        );
    }

    #[test]
    fn builder_dir_overrides_embedded() {
        let manifests = [("a.yaml", sample_yaml("action_a", VALID_DIGEST))];
        let pairs: Vec<(&'static str, &'static str)> = manifests
            .iter()
            .map(|(f, y)| {
                let f: &'static str = Box::leak(f.to_string().into_boxed_str());
                let y: &'static str = Box::leak(y.to_string().into_boxed_str());
                (f, y)
            })
            .collect();

        let dir = create_manifest_dir(&[("action_a.yaml", &sample_yaml("action_a", OTHER_DIGEST))]);

        let store = RegistryStore::builder()
            .add_embedded(pairs.into_iter())
            .unwrap()
            .add_dir(dir.path())
            .unwrap()
            .build();

        assert_eq!(store.len(), 1);
        let action = store.get_action("action_a").unwrap();
        assert_eq!(&*action.provider_module_digest, OTHER_DIGEST);
        assert_eq!(
            store.provenance_for("action_a"),
            Some(&SourceKind::Dir(dir.path().to_path_buf()))
        );
    }

    #[test]
    fn builder_dir_adds_new_actions() {
        let manifests = [("a.yaml", sample_yaml("action_a", VALID_DIGEST))];
        let pairs: Vec<(&'static str, &'static str)> = manifests
            .iter()
            .map(|(f, y)| {
                let f: &'static str = Box::leak(f.to_string().into_boxed_str());
                let y: &'static str = Box::leak(y.to_string().into_boxed_str());
                (f, y)
            })
            .collect();

        let dir =
            create_manifest_dir(&[("custom.yaml", &sample_yaml("custom_action", OTHER_DIGEST))]);

        let store = RegistryStore::builder()
            .add_embedded(pairs.into_iter())
            .unwrap()
            .add_dir(dir.path())
            .unwrap()
            .build();

        assert_eq!(store.len(), 2);
        assert!(store.get_action("action_a").is_some());
        assert!(store.get_action("custom_action").is_some());
    }

    #[test]
    fn builder_skips_nonexistent_dir() {
        let store = RegistryStore::builder()
            .add_dir(Path::new("/nonexistent/manifests"))
            .unwrap()
            .build();

        assert!(store.is_empty());
    }

    #[test]
    fn builder_rejects_duplicate_within_embedded() {
        let manifests = [
            ("a.yaml", sample_yaml("dup", VALID_DIGEST)),
            ("b.yaml", sample_yaml("dup", OTHER_DIGEST)),
        ];
        let pairs: Vec<(&'static str, &'static str)> = manifests
            .iter()
            .map(|(f, y)| {
                let f: &'static str = Box::leak(f.to_string().into_boxed_str());
                let y: &'static str = Box::leak(y.to_string().into_boxed_str());
                (f, y)
            })
            .collect();

        let err = RegistryStore::builder()
            .add_embedded(pairs.into_iter())
            .unwrap_err();
        assert!(matches!(err, StoreError::DuplicateActionId { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn builder_rejects_symlink_escaping_manifest_dir() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();

        let external_yaml = outside.path().join("evil.yaml");
        fs::write(&external_yaml, sample_yaml("evil", VALID_DIGEST)).unwrap();

        let link = root.path().join("evil.yaml");
        std::os::unix::fs::symlink(&external_yaml, &link).unwrap();

        let err = RegistryStore::builder().add_dir(root.path()).unwrap_err();
        assert!(
            matches!(err, StoreError::PathTraversal { .. }),
            "expected PathTraversal, got: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn builder_rejects_schema_path_traversal() {
        let dir = tempfile::tempdir().unwrap();

        let outside = tempfile::tempdir().unwrap();
        let secret = outside.path().join("secret.json");
        fs::write(&secret, minimal_request_schema()).unwrap();

        let rel = format!(
            "../../{}/secret.json",
            outside.path().file_name().unwrap().to_str().unwrap()
        );
        let yaml = format!(
            "action_id: \"traversal_test\"\nversion: \"1.0.0\"\nprovider_module_digest: \"{VALID_DIGEST}\"\nio:\n  request_schema: \"{rel}\"\n"
        );
        fs::write(dir.path().join("t.yaml"), &yaml).unwrap();

        let err = RegistryStore::builder().add_dir(dir.path()).unwrap_err();
        assert!(
            matches!(err, StoreError::PathTraversal { .. }),
            "expected PathTraversal, got: {err}"
        );
    }
}
