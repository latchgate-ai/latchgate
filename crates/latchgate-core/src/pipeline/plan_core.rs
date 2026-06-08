//! `ExecutionPlanCore` — shared security-binding fields between
//! `ApprovedExecutionPlan` and `ExecutionGrant`.
//!
//! # Why this type exists
//!
//! Both `ApprovedExecutionPlan` (operator-reviewed immutable snapshot) and
//! `ExecutionGrant` (signed runtime authorization) bind the same fundamental
//! execution parameters: which action, which module, which targets, which
//! secrets, which egress profile, when it expires. Before this type existed,
//! each struct defined these fields independently, with independent hash
//! coverage. Adding a security-relevant field to one without the other
//! created a binding gap — the exact class of divergence the plan-hash
//! system is designed to prevent.
//!
//! `ExecutionPlanCore` makes the shared field set explicit and provides a
//! single [`hash_into`](ExecutionPlanCore::hash_into) method that both
//! hash functions call. The compiler enforces coverage: a new field on the
//! core requires updating `hash_into`, and both consumers inherit the
//! change automatically.
//!
//! # Serialization
//!
//! Both parent structs embed this type with `#[serde(flatten)]`, keeping
//! the JSON representation flat (no nested `"core": {...}` wrapper).

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::plan_hash::PlanHasher;
use crate::EgressProfile;

/// Security-binding fields shared between `ApprovedExecutionPlan` and
/// `ExecutionGrant`.
///
/// SECURITY: every field here affects what gets executed, what targets are
/// contacted, what secrets are injected, or when authorization expires.
/// [`hash_into`](Self::hash_into) MUST cover every field. Adding a field
/// without hashing it is a binding gap.
#[must_use = "execution plan cores bind security-relevant parameters — dropping one loses the binding"]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionPlanCore {
    /// Action identifier from the registry.
    pub action_id: Arc<str>,

    /// Content-addressable digest of the action definition.
    pub action_digest: Arc<str>,

    /// SHA-256 digest of the `.wasm` provider module.
    ///
    /// SECURITY: pins the exact binary that will execute. A module swap
    /// after approval or grant issuance is detected because the hash
    /// will not match.
    pub provider_module_digest: Arc<str>,

    /// SHA-256 of the canonicalized (JCS) request body.
    pub request_hash: Arc<str>,

    /// OPA policy bundle version that produced the authorization decision.
    ///
    /// `None` when no OPA policy is configured (the plan captures the
    /// absence). Grants resolve `None` to a sentinel before construction,
    /// so grant-side this is always `Some`.
    pub policy_version: Option<Arc<str>>,

    /// Targets (sinks) approved for this execution.
    ///
    /// SECURITY: the host I/O layer MUST NOT write to targets outside
    /// this list.
    ///
    /// `Arc<str>` elements: each clone is a refcount bump, not a heap
    /// allocation. These values are forwarded into `RunTask`, `HostState`,
    /// `AuditEvent`, and `RequestContext` — four consumers per request.
    pub approved_targets: Vec<Arc<str>>,

    /// Secret names approved for release to the host I/O layer.
    ///
    /// SECURITY: only these secrets may be injected at execution time.
    ///
    /// `Arc<str>` elements for the same per-clone savings as `approved_targets`.
    pub approved_secrets: Vec<Arc<str>>,

    /// Network egress profile approved for this execution.
    pub approved_egress: EgressProfile,

    /// When this authorization expires. After this time, the plan or
    /// grant MUST NOT be used.
    pub expires_at: DateTime<Utc>,
}

impl ExecutionPlanCore {
    /// Hash all fields into the provided `PlanHasher`.
    ///
    /// Called by both `ApprovedExecutionPlan::compute_hash` and
    /// `ExecutionGrant::compute_plan_hash` to ensure identical coverage
    /// of the shared field set. Each caller adds its own type-specific
    /// fields before or after this call.
    ///
    /// SECURITY: this method MUST hash every field on `ExecutionPlanCore`.
    /// The field order is part of the hash contract — do not reorder
    /// without bumping the version prefix on all callers.
    pub fn hash_into(&self, h: &mut PlanHasher) {
        // Action identity.
        h.hash_str(&self.action_id);
        h.hash_str(&self.action_digest);
        h.hash_str(&self.provider_module_digest);

        // Request binding.
        h.hash_str(&self.request_hash);

        // Policy context.
        h.hash_optional_tagged(b"pv:", self.policy_version.as_deref());

        // Permissions.
        h.hash_string_list(&self.approved_targets);
        h.hash_string_list(&self.approved_secrets);
        h.hash_json(&self.approved_egress);

        // Expiry.
        h.hash_datetime(&self.expires_at);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_core() -> ExecutionPlanCore {
        ExecutionPlanCore {
            action_id: "http_fetch".into(),
            action_digest: "sha256:aabb".into(),
            provider_module_digest: "sha256:ccdd".into(),
            request_hash: "sha256:eeff".into(),
            policy_version: Some("v1".into()),
            approved_targets: vec!["api.github.com".into()],
            approved_secrets: vec!["TOKEN".into()],
            approved_egress: EgressProfile::None,
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
        }
    }

    #[test]
    fn hash_into_is_deterministic() {
        let core = sample_core();
        let mut h1 = PlanHasher::new(b"test:");
        core.hash_into(&mut h1);
        let mut h2 = PlanHasher::new(b"test:");
        core.hash_into(&mut h2);
        assert_eq!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn hash_changes_when_action_id_changes() {
        let c1 = sample_core();
        let mut c2 = c1.clone();
        c2.action_id = "db_query".into();
        let mut h1 = PlanHasher::new(b"test:");
        c1.hash_into(&mut h1);
        let mut h2 = PlanHasher::new(b"test:");
        c2.hash_into(&mut h2);
        assert_ne!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn hash_changes_when_targets_change() {
        let c1 = sample_core();
        let mut c2 = c1.clone();
        c2.approved_targets.push("evil.com".into());
        let mut h1 = PlanHasher::new(b"test:");
        c1.hash_into(&mut h1);
        let mut h2 = PlanHasher::new(b"test:");
        c2.hash_into(&mut h2);
        assert_ne!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn hash_changes_when_policy_version_changes() {
        let c1 = sample_core();
        let mut c2 = c1.clone();
        c2.policy_version = None;
        let mut h1 = PlanHasher::new(b"test:");
        c1.hash_into(&mut h1);
        let mut h2 = PlanHasher::new(b"test:");
        c2.hash_into(&mut h2);
        assert_ne!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn hash_changes_when_expires_at_changes() {
        let c1 = sample_core();
        let mut c2 = c1.clone();
        c2.expires_at += chrono::Duration::hours(1);
        let mut h1 = PlanHasher::new(b"test:");
        c1.hash_into(&mut h1);
        let mut h2 = PlanHasher::new(b"test:");
        c2.hash_into(&mut h2);
        assert_ne!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn hash_changes_when_egress_changes() {
        let c1 = sample_core();
        let mut c2 = c1.clone();
        c2.approved_egress = EgressProfile::ProxyAllowlist {
            allowed_domains: vec!["evil.com".into()],
        };
        let mut h1 = PlanHasher::new(b"test:");
        c1.hash_into(&mut h1);
        let mut h2 = PlanHasher::new(b"test:");
        c2.hash_into(&mut h2);
        assert_ne!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn hash_changes_when_secrets_change() {
        let c1 = sample_core();
        let mut c2 = c1.clone();
        c2.approved_secrets.push("STOLEN".into());
        let mut h1 = PlanHasher::new(b"test:");
        c1.hash_into(&mut h1);
        let mut h2 = PlanHasher::new(b"test:");
        c2.hash_into(&mut h2);
        assert_ne!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn serialization_roundtrips() {
        let core = sample_core();
        let json = serde_json::to_string(&core).unwrap();
        let parsed: ExecutionPlanCore = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, core);
    }
}
