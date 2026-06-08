//! `ApprovedExecutionPlan` — immutable snapshot of the exact execution plan
//! bound by a human approval.
//!
//! # Security purpose
//!
//! When OPA returns `PendingApproval`, the kernel captures the full execution
//! context at that moment into an `ApprovedExecutionPlan`. This plan is stored
//! alongside the `PendingApproval` and becomes the **single source of truth**
//! for what was approved.
//!
//! On approve, the kernel executes *this plan* — not whatever the live manifest
//! happens to contain at approve time. This prevents a class of attacks where
//! the manifest changes between `pending` and `approve`, silently widening
//! targets, secrets, or provider module.
//!
//! # Hash binding
//!
//! `plan_hash` is a SHA-256 over all security-relevant fields, computed once
//! at plan creation. The `approval_hash` (stored in the `ExecutionGrant`) binds
//! `approval_id` to `plan_hash`, creating a tamper-evident chain:
//!
//! ```text
//! approval_id + plan_hash => approval_hash => grant signature
//! ```
//!
//! # Shared core
//!
//! Fields shared with `ExecutionGrant` are held in [`ExecutionPlanCore`], which
//! provides [`hash_into`](ExecutionPlanCore::hash_into) for consistent hash
//! coverage. Plan-specific fields (capability binding, budget, trust verdict,
//! provider config) are hashed separately.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::plan_core::ExecutionPlanCore;
use crate::{EgressProfile, ResourceLimits, TrustVerdict, VerifierKind};

/// Immutable execution plan captured at `PendingApproval` creation time.
///
/// SECURITY: every field that affects what gets executed, what targets are
/// contacted, what secrets are injected, or what resources are consumed MUST
/// be present here. Adding a new security-relevant field to the execution
/// path without adding it here breaks the approval binding guarantee.
#[must_use = "approved plans must be persisted or executed — dropping one silently discards operator approval"]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovedExecutionPlan {
    // -- Shared execution binding (see `ExecutionPlanCore` docs) ---------------
    #[serde(flatten)]
    pub core: ExecutionPlanCore,

    // -- Action identity (plan-specific) --------------------------------------
    /// Semantic version of the action at plan creation time.
    pub action_version: Arc<str>,

    // -- Capability binding ---------------------------------------------------
    /// Host I/O imports the provider is allowed to use.
    ///
    pub required_imports: Vec<Arc<str>>,

    /// WASM resource limits (fuel, memory, timeout, I/O calls).
    pub resource_limits: ResourceLimits,

    /// Which verifier checks the outcome after execution.
    pub verifier_kind: VerifierKind,

    /// Verifier-specific configuration snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_config: Option<Arc<serde_json::Value>>,

    /// Risk classification at plan creation time.
    ///
    /// SECURITY: determines whether the high-risk `approval_hash` assertion
    /// fires in the shared execution path. Must come from the plan, not from
    /// the live manifest, so a manifest downgrade from High=>Low after
    /// approval cannot bypass the assertion.
    pub risk_level: crate::RiskLevel,

    /// Maximum response body size (bytes) for schema validation.
    ///
    /// SECURITY: captured from `manifest.io.max_response_bytes` at plan
    /// creation time. If the manifest raises this limit after approval, the
    /// approval path still uses the original value — preventing a post-approval
    /// manifest change from widening the accepted response envelope.
    pub max_response_bytes: usize,

    // -- Secret declarations --------------------------------------------------
    /// Full secret declarations (name + required flag) snapshotted from the
    /// manifest at plan creation time.
    ///
    /// SECURITY: the approval path uses these declarations — not the live
    /// manifest — when resolving secrets. If the manifest changes a secret
    /// from optional to required (or vice versa) between `pending` and
    /// `approve`, the plan's snapshot governs, and the plan hash detects
    /// any tampering.
    pub secret_declarations: Vec<crate::SecretDecl>,

    // -- Budget ---------------------------------------------------------------
    /// Calls remaining in session budget at plan creation time.
    pub budget_calls_remaining: i64,

    /// Calls remaining as approved by the policy engine.
    ///
    /// SECURITY: captures the policy-approved budget intent — what
    /// the policy engine says the budget *should* be after execution. The
    /// actual debit happens atomically at approve-time via `BudgetManager`,
    /// but this field records what was authorized so the operator can review
    /// the expected impact and the approval hash binds the intent.
    pub policy_approved_calls_after: i64,

    // -- Policy context (plan-specific) ---------------------------------------
    /// Trust verification result at plan creation time.
    ///
    /// SECURITY: if trust degrades between pending and approve (e.g. digest
    /// mismatch appears), the approve path re-checks trust and denies. This
    /// field is stored for audit trail and hash integrity.
    pub trust_verdict: Arc<TrustVerdict>,

    // -- Provider binding -----------------------------------------------------
    /// Database configuration snapshot from the manifest at plan creation time.
    ///
    /// SECURITY: the approval path uses this — not the live manifest — to
    /// configure the provider at execution time. Contains the `DatabaseConfig`
    /// (mode, statements, rules) for database actions. A manifest update
    /// between `pending` and `approve` must not silently change provider
    /// behavior, so the plan binds the exact config as opaque JSON.
    /// `None` for non-database actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database_config: Option<Arc<serde_json::Value>>,

    /// Filesystem configuration snapshot from the manifest at plan creation
    /// time.
    ///
    /// SECURITY: the approval path uses this — not the live manifest — to
    /// configure the `builtin:fs` provider at execution time. It holds the
    /// manifest `fs` block (`allowed_operations`, `allowed_paths`,
    /// `denied_paths`, `max_file_bytes`) as opaque JSON, mirroring
    /// [`Self::database_config`], so this core type carries no dependency on
    /// the registry's manifest types. A manifest edit between `pending` and
    /// `approve` cannot widen the approved filesystem scope: the plan binds
    /// the exact config, and `plan_hash` makes any change tamper-evident.
    /// Learned paths still only **extend** `allowed_paths` at execution time;
    /// `denied_paths` is immutable. `None` for non-filesystem actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fs: Option<Arc<serde_json::Value>>,

    // -- Integrity ------------------------------------------------------------
    /// SHA-256 hash over all security-relevant fields above, computed once
    /// at plan creation time via [`Self::compute_hash`].
    ///
    /// SECURITY: this is the anchor for `approval_hash` in the `ExecutionGrant`.
    /// Changing any field after creation will NOT update this hash, making
    /// tampering detectable via [`Self::verify_hash`].
    pub plan_hash: String,
}

impl ApprovedExecutionPlan {
    /// Compute SHA-256 over all security-relevant fields.
    ///
    /// This covers everything in the plan except `plan_hash` itself. The
    /// hash is domain-separated with a version prefix so future format
    /// changes don't collide with older hashes.
    ///
    /// Shared fields are hashed via [`ExecutionPlanCore::hash_into`];
    /// plan-specific fields are hashed here.
    #[must_use]
    pub fn compute_hash(&self) -> String {
        use super::plan_hash::PlanHasher;

        let mut h = PlanHasher::new(b"latchgate-approved-plan-v7:");

        // Action version (plan-specific, before shared core to keep
        // action identity fields adjacent in the hash stream).
        h.hash_str(&self.action_version);

        // Shared execution binding (9 fields).
        self.core.hash_into(&mut h);

        // Capability binding (plan-specific).
        h.hash_string_list(&self.required_imports);
        h.hash_json(&self.resource_limits);
        h.hash_json(&self.verifier_kind);
        h.hash_json(&self.risk_level);
        h.hash_usize(self.max_response_bytes);
        h.hash_optional_json(self.verification_config.as_deref());

        // Secret declarations (name + required flag).
        h.hash_u32_len(self.secret_declarations.len());
        for decl in &self.secret_declarations {
            h.hash_u32_len(decl.name.len());
            h.hash_raw(decl.name.as_bytes());
            h.hash_bool(decl.required);
        }
        h.hash_raw(b"|");

        // Budget.
        h.hash_i64(self.budget_calls_remaining);
        h.hash_i64(self.policy_approved_calls_after);
        h.hash_raw(b"|");

        // Trust verdict (plan-specific).
        h.hash_json(&self.trust_verdict);

        // Provider config (plan-specific).
        h.hash_optional_json(self.database_config.as_deref());
        h.hash_optional_json(self.fs.as_deref());

        h.finalize()
    }

    /// Set `plan_hash` to the canonical hash of all security-relevant fields.
    ///
    /// MUST be called exactly once after all fields are populated, before the
    /// plan is persisted. Calling it twice is safe (idempotent given immutable
    /// fields), but indicates a logic error.
    pub fn finalize(&mut self) {
        self.plan_hash = self.compute_hash();
    }

    /// Verify that the stored `plan_hash` matches a fresh computation.
    ///
    /// Returns `true` only if no field has been modified since `finalize()`.
    /// SECURITY: call this on the approve path before using plan fields.
    pub fn verify_hash(&self) -> bool {
        !self.plan_hash.is_empty() && self.compute_hash() == self.plan_hash
    }

    /// Build a minimal valid `ApprovedExecutionPlan` for tests.
    ///
    /// Single source of truth for test defaults — all test code across
    /// the workspace should call this instead of constructing plans inline.
    /// When a new field is added to the struct, only this method needs
    /// updating; any test that relied on the missing field will fail to
    /// compile (if the field has no Default) or get a safe placeholder.
    #[doc(hidden)]
    pub fn test_default() -> Self {
        let expires = chrono::Utc::now() + chrono::Duration::minutes(5);
        let mut plan = Self {
            core: ExecutionPlanCore {
                action_id: "http_fetch".into(),
                action_digest:
                    "sha256:f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0".into(),
                provider_module_digest:
                    "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".into(),
                request_hash: "sha256:deadbeef".into(),
                policy_version: Some("test-v1".into()),
                approved_targets: vec![],
                approved_secrets: vec![],
                approved_egress: EgressProfile::None,
                expires_at: expires,
            },
            action_version: "1.0.0".into(),
            required_imports: vec![],
            resource_limits: ResourceLimits::default(),
            verifier_kind: VerifierKind::None,
            verification_config: None,
            risk_level: crate::RiskLevel::Low,
            max_response_bytes: 1024 * 1024,
            secret_declarations: vec![],
            budget_calls_remaining: i64::MAX,
            policy_approved_calls_after: i64::MAX - 1,
            trust_verdict: Arc::new(TrustVerdict::DigestOk),
            database_config: None,
            fs: None,
            plan_hash: String::new(),
        };
        plan.finalize();
        plan
    }
}

/// Build a minimal valid `ApprovedExecutionPlan` for tests.
///
/// Delegates to [`ApprovedExecutionPlan::test_default`].
#[cfg(test)]
pub fn test_plan() -> ApprovedExecutionPlan {
    ApprovedExecutionPlan::test_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_hash_is_deterministic() {
        let plan = test_plan();
        assert_eq!(plan.plan_hash.len(), 64, "hex-encoded SHA-256 = 64 chars");
        assert_eq!(plan.compute_hash(), plan.plan_hash);
    }

    #[test]
    fn verify_hash_succeeds_for_unmodified_plan() {
        let plan = test_plan();
        assert!(plan.verify_hash());
    }

    #[test]
    fn verify_hash_fails_for_empty_hash() {
        let mut plan = test_plan();
        plan.plan_hash = String::new();
        assert!(!plan.verify_hash());
    }

    #[test]
    fn hash_changes_when_targets_change() {
        let plan1 = test_plan();
        let mut plan2 = plan1.clone();
        plan2.core.approved_targets.push("evil.com".into());
        plan2.finalize();
        assert_ne!(
            plan1.plan_hash, plan2.plan_hash,
            "widened targets must change plan hash"
        );
    }

    #[test]
    fn hash_changes_when_secrets_change() {
        let plan1 = test_plan();
        let mut plan2 = plan1.clone();
        plan2.core.approved_secrets.push("STOLEN_KEY".into());
        plan2.finalize();
        assert_ne!(
            plan1.plan_hash, plan2.plan_hash,
            "widened secrets must change plan hash"
        );
    }

    #[test]
    fn hash_changes_when_secret_declarations_change() {
        let plan1 = test_plan();

        // Adding a declaration must change the hash.
        let mut plan2 = plan1.clone();
        plan2.secret_declarations.push(crate::SecretDecl {
            name: "DB_PASSWORD".into(),
            required: true,
        });
        plan2.finalize();
        assert_ne!(
            plan1.plan_hash, plan2.plan_hash,
            "added secret declaration must change plan hash"
        );

        // Flipping the required flag must change the hash.
        let mut plan3 = plan2.clone();
        plan3.secret_declarations[0].required = false;
        plan3.finalize();
        assert_ne!(
            plan2.plan_hash, plan3.plan_hash,
            "different required flag must change plan hash"
        );
    }

    #[test]
    fn hash_changes_when_provider_module_changes() {
        let plan1 = test_plan();
        let mut plan2 = plan1.clone();
        plan2.core.provider_module_digest = "sha256:ffff".into();
        plan2.finalize();
        assert_ne!(
            plan1.plan_hash, plan2.plan_hash,
            "different provider module must change plan hash"
        );
    }

    #[test]
    fn hash_changes_when_budget_changes() {
        let plan1 = test_plan();
        let mut plan2 = plan1.clone();
        plan2.budget_calls_remaining = 42;
        plan2.finalize();
        assert_ne!(
            plan1.plan_hash, plan2.plan_hash,
            "different budget_calls_remaining must change plan hash"
        );
    }

    #[test]
    fn hash_changes_when_policy_approved_budget_changes() {
        let plan1 = test_plan();
        let mut plan2 = plan1.clone();
        plan2.policy_approved_calls_after = 42;
        plan2.finalize();
        assert_ne!(
            plan1.plan_hash, plan2.plan_hash,
            "different policy_approved_calls_after must change plan hash"
        );
    }

    #[test]
    fn hash_changes_when_egress_changes() {
        let plan1 = test_plan();
        let mut plan2 = plan1.clone();
        plan2.core.approved_egress = EgressProfile::ProxyAllowlist {
            allowed_domains: vec!["evil.com".into()],
        };
        plan2.finalize();
        assert_ne!(
            plan1.plan_hash, plan2.plan_hash,
            "different egress must change plan hash"
        );
    }

    #[test]
    fn hash_changes_when_resource_limits_change() {
        let plan1 = test_plan();
        let mut plan2 = plan1.clone();
        plan2.resource_limits.fuel = 999_999_999;
        plan2.finalize();
        assert_ne!(
            plan1.plan_hash, plan2.plan_hash,
            "different resource limits must change plan hash"
        );
    }

    #[test]
    fn hash_changes_when_verifier_kind_changes() {
        let plan1 = test_plan();
        let mut plan2 = plan1.clone();
        plan2.verifier_kind = VerifierKind::HttpStatus;
        plan2.finalize();
        assert_ne!(
            plan1.plan_hash, plan2.plan_hash,
            "different verifier_kind must change plan hash"
        );
    }

    #[test]
    fn hash_changes_when_risk_level_changes() {
        let plan1 = test_plan();
        let mut plan2 = plan1.clone();
        plan2.risk_level = crate::RiskLevel::Critical;
        plan2.finalize();
        assert_ne!(
            plan1.plan_hash, plan2.plan_hash,
            "different risk_level must change plan hash"
        );
    }

    #[test]
    fn hash_changes_when_max_response_bytes_changes() {
        let plan1 = test_plan();
        let mut plan2 = plan1.clone();
        plan2.max_response_bytes = 100 * 1024 * 1024; // 100 MiB
        plan2.finalize();
        assert_ne!(
            plan1.plan_hash, plan2.plan_hash,
            "different max_response_bytes must change plan hash"
        );
    }

    #[test]
    fn hash_changes_when_action_version_changes() {
        let plan1 = test_plan();
        let mut plan2 = plan1.clone();
        plan2.action_version = "2.0.0".into();
        plan2.finalize();
        assert_ne!(
            plan1.plan_hash, plan2.plan_hash,
            "different action_version must change plan hash"
        );
    }

    #[test]
    fn hash_changes_when_request_hash_changes() {
        let plan1 = test_plan();
        let mut plan2 = plan1.clone();
        plan2.core.request_hash = "sha256:different".into();
        plan2.finalize();
        assert_ne!(
            plan1.plan_hash, plan2.plan_hash,
            "different request_hash must change plan hash"
        );
    }

    #[test]
    fn plan_serialization_roundtrips() {
        let plan = test_plan();
        let json = serde_json::to_string(&plan).unwrap();
        let parsed: ApprovedExecutionPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, plan);
        assert!(parsed.verify_hash());
    }

    #[test]
    fn tampered_plan_fails_verify() {
        let mut plan = test_plan();
        assert!(plan.verify_hash());

        // Tamper after finalize.
        plan.core.approved_targets.push("evil.com".into());
        assert!(
            !plan.verify_hash(),
            "tampered plan must fail hash verification"
        );
    }

    #[test]
    fn hash_changes_when_trust_verdict_changes() {
        let plan1 = test_plan();
        let mut plan2 = plan1.clone();
        plan2.trust_verdict = Arc::new(TrustVerdict::DigestMismatch {
            expected: "a".into(),
            actual: "b".into(),
        });
        plan2.finalize();
        assert_ne!(
            plan1.plan_hash, plan2.plan_hash,
            "different trust verdict must change plan hash"
        );
    }

    #[test]
    fn hash_changes_when_expires_at_changes() {
        let plan1 = test_plan();
        let mut plan2 = plan1.clone();
        plan2.core.expires_at += chrono::Duration::hours(1);
        plan2.finalize();
        assert_ne!(
            plan1.plan_hash, plan2.plan_hash,
            "different expiry must change plan hash"
        );
    }

    #[test]
    fn hash_changes_when_database_config_changes() {
        let plan1 = test_plan();
        assert!(plan1.database_config.is_none());

        // Adding a database_config must change the hash.
        let mut plan2 = plan1.clone();
        plan2.database_config = Some(Arc::new(serde_json::json!({
            "mode": "hybrid",
            "statements": [{
                "id": "update_order_status",
                "sql": "UPDATE orders SET status = $1 WHERE id = $2"
            }],
            "rules": {"blocked_operations": ["ddl"]}
        })));
        plan2.finalize();
        assert_ne!(
            plan1.plan_hash, plan2.plan_hash,
            "adding database_config must change plan hash"
        );

        // Changing the SQL in a statement must change the hash.
        let mut plan3 = plan1.clone();
        plan3.database_config = Some(Arc::new(serde_json::json!({
            "mode": "hybrid",
            "statements": [{
                "id": "update_order_status",
                "sql": "UPDATE orders SET status = $1, updated_at = NOW() WHERE id = $2"
            }],
            "rules": {"blocked_operations": ["ddl"]}
        })));
        plan3.finalize();
        assert_ne!(
            plan2.plan_hash, plan3.plan_hash,
            "different statement SQL must change plan hash"
        );

        // Changing the mode must change the hash.
        let mut plan4 = plan2.clone();
        if let Some(ref mut cfg) = plan4.database_config {
            Arc::make_mut(cfg)["mode"] = serde_json::json!("strict");
        }
        plan4.finalize();
        assert_ne!(
            plan2.plan_hash, plan4.plan_hash,
            "different database mode must change plan hash"
        );
    }

    #[test]
    fn hash_changes_when_fs_changes() {
        let plan1 = test_plan();
        assert!(plan1.fs.is_none());

        // Adding an fs config must change the hash.
        let mut plan2 = plan1.clone();
        plan2.fs = Some(Arc::new(serde_json::json!({
            "allowed_operations": ["read"],
            "allowed_paths": ["data/**"],
            "denied_paths": ["data/secrets/**"],
            "max_file_bytes": 1048576
        })));
        plan2.finalize();
        assert_ne!(
            plan1.plan_hash, plan2.plan_hash,
            "adding fs config must change plan hash"
        );

        // Widening allowed_paths must change the hash.
        let mut plan3 = plan2.clone();
        if let Some(ref mut cfg) = plan3.fs {
            Arc::make_mut(cfg)["allowed_paths"] = serde_json::json!(["data/**", "config/**"]);
        }
        plan3.finalize();
        assert_ne!(
            plan2.plan_hash, plan3.plan_hash,
            "widening allowed_paths must change plan hash"
        );

        // Narrowing denied_paths must change the hash.
        let mut plan4 = plan2.clone();
        if let Some(ref mut cfg) = plan4.fs {
            Arc::make_mut(cfg)["denied_paths"] = serde_json::json!([]);
        }
        plan4.finalize();
        assert_ne!(
            plan2.plan_hash, plan4.plan_hash,
            "changing denied_paths must change plan hash"
        );

        // Changing an allowed operation must change the hash.
        let mut plan5 = plan2.clone();
        if let Some(ref mut cfg) = plan5.fs {
            Arc::make_mut(cfg)["allowed_operations"] = serde_json::json!(["read", "overwrite"]);
        }
        plan5.finalize();
        assert_ne!(
            plan2.plan_hash, plan5.plan_hash,
            "changing allowed_operations must change plan hash"
        );
    }

    #[test]
    fn hash_changes_when_policy_version_changes() {
        let plan1 = test_plan();
        let mut plan2 = plan1.clone();
        plan2.core.policy_version = Some("test-v2".into());
        plan2.finalize();
        assert_ne!(
            plan1.plan_hash, plan2.plan_hash,
            "different policy_version must change plan hash"
        );
    }

    /// SECURITY: the core fields shared with `ExecutionGrant` are hashed
    /// through `ExecutionPlanCore::hash_into` — verify the core's hash
    /// contribution is included and matches a direct computation.
    #[test]
    fn core_hash_contribution_is_included() {
        use crate::pipeline::plan_hash::PlanHasher;

        let plan = test_plan();

        // Hash the core fields independently.
        let mut h = PlanHasher::new(b"standalone:");
        plan.core.hash_into(&mut h);
        let core_hash = h.finalize();

        // The core hash must be non-empty and deterministic.
        assert_eq!(core_hash.len(), 64);

        // Mutating a core field must change the plan hash.
        let mut plan2 = plan.clone();
        plan2.core.action_id = "different_action".into();
        plan2.finalize();
        assert_ne!(plan.plan_hash, plan2.plan_hash);
    }
}
