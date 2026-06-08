//! ActionSpec validation and content digest computation.
//!
//! Cross-field invariants enforced at parse time. Every constraint is a
//! single `require!` invocation — adding a new rule is a one-liner.

use crate::manifest_types::*;

use latchgate_core::{EgressProfile, RiskLevel, VerifierKind};

/// Fail-fast validation: require `condition` or return
/// `ManifestError::Validation` with a `format!`-style reason.
///
/// Every manifest constraint is one `require!` invocation. Adding a new
/// cross-field rule is a one-liner; the macro handles error construction.
macro_rules! require {
    ($cond:expr, $reason:literal) => {
        if !($cond) {
            return Err(ManifestError::Validation { reason: $reason.into() });
        }
    };
    ($cond:expr, $($arg:tt)*) => {
        if !($cond) {
            return Err(ManifestError::Validation { reason: format!($($arg)*) });
        }
    };
}

impl ActionSpec {
    /// Compute a SHA-256 content-addressable digest of the action definition.
    ///
    /// Covers all security-relevant fields including template configuration.
    /// Called once at construction; the result is cached in
    /// [`content_digest`](Self::content_digest).
    pub(crate) fn compute_digest(&self) -> String {
        use sha2::{Digest, Sha256};

        let mut h = Sha256::new();
        h.update(b"latchgate-action-v1:");
        h.update(self.action_id.as_bytes());
        h.update(b"|");
        h.update(self.version.as_bytes());
        h.update(b"|");
        h.update(self.provider_module_digest.as_bytes());
        h.update(b"|");
        for import in &self.required_imports {
            h.update(import.as_bytes());
            h.update(b",");
        }
        h.update(b"|");
        let rl = serde_json::to_string(&self.resource_limits).unwrap_or_default();
        h.update(rl.as_bytes());
        h.update(b"|");
        let vk = serde_json::to_string(&self.verifier_kind).unwrap_or_default();
        h.update(vk.as_bytes());
        h.update(b"|");
        let rl_str = serde_json::to_string(&self.risk_level).unwrap_or_default();
        h.update(rl_str.as_bytes());
        h.update(b"|");
        for secret in &self.secrets {
            h.update(secret.name.as_bytes());
            h.update(b",");
        }
        h.update(b"|");
        for target in &self.declared_side_effects {
            h.update(target.as_bytes());
            h.update(b",");
        }
        h.update(b"|");
        let egress = serde_json::to_string(&self.egress).unwrap_or_default();
        h.update(egress.as_bytes());
        h.update(b"|");
        for scope in &self.required_scopes {
            h.update(scope.as_bytes());
            h.update(b",");
        }
        h.update(b"|");
        let pc = serde_json::to_string(&self.database_config).unwrap_or_default();
        h.update(pc.as_bytes());
        h.update(b"|");
        let tmpl = serde_json::to_string(&self.template).unwrap_or_default();
        h.update(tmpl.as_bytes());
        h.update(b"|");
        let fs = serde_json::to_string(&self.fs).unwrap_or_default();
        h.update(fs.as_bytes());
        latchgate_core::crypto::sha256_hex(h.finalize())
    }

    /// Validate manifest invariants that serde alone cannot enforce.
    ///
    /// Each constraint is a single `require!` invocation. Adding a new
    /// cross-field rule is one line; the macro handles error wrapping.
    pub(crate) fn validate(&self) -> Result<(), ManifestError> {
        // ── action_id ──────────────────────────────────────────────────
        const MAX_ACTION_ID_LEN: usize = 128;
        require!(!self.action_id.is_empty(), "action_id must not be empty");
        require!(
            self.action_id.len() <= MAX_ACTION_ID_LEN,
            "action_id '{}' exceeds maximum length of {MAX_ACTION_ID_LEN} characters",
            self.action_id
        );
        require!(
            self.action_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'),
            "action_id '{}' contains invalid characters; only [a-zA-Z0-9_-] are permitted",
            self.action_id
        );

        // ── provider_module_digest ─────────────────────────────────────
        // SECURITY: parse validates the digest format (sha256:<hex> or builtin:<name>).
        let provider = ProviderModule::parse(&self.provider_module_digest)?;

        // ── required_imports ───────────────────────────────────────────
        for import in &self.required_imports {
            require!(
                import.starts_with("latchgate:io/"),
                "required_imports must start with 'latchgate:io/' (got '{import}')"
            );
        }

        // ── resource_limits ────────────────────────────────────────────
        self.resource_limits.validate()?;

        // ── egress ─────────────────────────────────────────────────────
        // SECURITY: validate egress config is a known profile.
        self.egress.to_profile()?;

        // SECURITY: validate egress allowed_domains entries at parse time.
        // Manifests are operator-authored, code-reviewed artifacts, so the
        // manifest validator is structurally strict (well-formed labels,
        // valid wildcard syntax, no *.com) but does not reject localhost or
        // private IPs — runtime SSRF checks provide defense-in-depth.
        for domain in &self.egress.allowed_domains {
            latchgate_core::net::validate_manifest_domain_entry(domain).map_err(|e| {
                ManifestError::Validation {
                    reason: format!("egress.allowed_domains entry '{domain}' is invalid: {e}"),
                }
            })?;
        }

        // ── required_scopes ────────────────────────────────────────────
        // SECURITY: every action must require the base execution capability.
        require!(
            !self.required_scopes.is_empty(),
            "required_scopes must not be empty; \
             every action must require at least \"tools:call\""
        );
        require!(
            self.required_scopes
                .iter()
                .any(|s| s.as_ref() == "tools:call"),
            "required_scopes must include \"tools:call\" \
             (base execution capability — cannot be omitted)"
        );
        for scope in &self.required_scopes {
            validate_scope_format(scope).map_err(|reason| ManifestError::Validation { reason })?;
        }

        // ── template ───────────────────────────────────────────────────
        // SECURITY: template actions MUST use a builtin provider — they share the
        // same trusted WASM binary and the kernel resolves templates before dispatch.
        if let Some(ref template) = self.template {
            template.validate()?;
            require!(
                provider.is_builtin(),
                "template actions must use 'builtin:<name>' provider_module_digest (got '{}')",
                self.provider_module_digest
            );
        }

        // ── risk level constraints ─────────────────────────────────────
        // SECURITY: high/critical actions require independent verification.
        let is_high_risk = matches!(self.risk_level, RiskLevel::High | RiskLevel::Critical);
        if is_high_risk {
            require!(
                !matches!(self.verifier_kind, VerifierKind::None),
                "high/critical action '{}' must declare a verifier_kind (got 'none')",
                self.action_id
            );
            // Filesystem actions are exempt — they verify via host-observed
            // SHA-256 hashes, not response body inspection.
            require!(
                self.io.response_schema.is_some() || self.fs.is_some(),
                "high/critical action '{}' must declare io.response_schema",
                self.action_id
            );
            // A bare 2xx check does not confirm which resource was affected.
            if matches!(self.verifier_kind, VerifierKind::HttpStatus) {
                let has_write = self
                    .declared_side_effects
                    .iter()
                    .any(|e| !e.ends_with("_read"));
                let has_required_fields = self
                    .verification_config
                    .as_deref()
                    .and_then(|vc| vc.get("required_fields"))
                    .and_then(|rf| rf.as_array())
                    .is_some_and(|arr| !arr.is_empty());
                require!(
                    !has_write || has_required_fields,
                    "high/critical write action '{}' uses http_status verifier \
                     without verification_config.required_fields — a bare 2xx \
                     check is insufficient for destructive or financial operations",
                    self.action_id
                );
            }
        }

        // ── filesystem config ──────────────────────────────────────────
        // SECURITY: filesystem provider configuration validation.
        if let Some(ref fs) = self.fs {
            require!(
                matches!(provider, ProviderModule::Builtin(ref s) if s == "builtin:fs"),
                "action '{}' has fs config but provider_module_digest is '{}'; \
                 fs actions must use 'builtin:fs'",
                self.action_id,
                self.provider_module_digest
            );
            // Filesystem authority is the gate's own UID — no per-action credentials.
            require!(
                self.secrets.is_empty(),
                "action '{}' has fs config with non-empty secrets; \
                 fs actions do not use secrets (filesystem authority is the gate's own UID)",
                self.action_id
            );
            // The WASM fs provider has no networking capability.
            require!(
                matches!(self.egress.to_profile()?, EgressProfile::None),
                "action '{}' has fs config with non-None egress; \
                 fs providers have no network capability",
                self.action_id
            );
            require!(
                !fs.allowed_operations.is_empty(),
                "action '{}' fs.allowed_operations must not be empty",
                self.action_id
            );
            require!(
                fs.max_file_bytes > 0,
                "action '{}' fs.max_file_bytes must be > 0",
                self.action_id
            );
            require!(
                matches!(self.verifier_kind, VerifierKind::FsHash),
                "action '{}' has fs config but verifier_kind is '{}'; \
                 fs actions must use 'fs_hash'",
                self.action_id,
                self.verifier_kind
            );
        }

        Ok(())
    }

    /// Make the validation logic available for external callers that construct
    /// or modify an [`ActionSpec`] programmatically (e.g. TUI manifest editor).
    ///
    /// `from_yaml()` calls this automatically after deserialization; callers
    /// that build an `ActionSpec` by mutating fields should call `validate()`
    /// explicitly before persisting.
    pub fn validate_spec(&self) -> Result<(), ManifestError> {
        self.validate()
    }
}
