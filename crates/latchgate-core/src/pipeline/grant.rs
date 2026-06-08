//! `ExecutionGrant` - the short-lived, signed authorization artifact.
//!
//! Issued by the kernel after identity, policy, approval, and budget checks
//! pass. The grant binds one exact execution plan: the action, its digest,
//! the approved targets, secrets, egress, and budget reservation.
//!
//! # Shared core
//!
//! Fields shared with `ApprovedExecutionPlan` are held in
//! [`ExecutionPlanCore`], which provides [`hash_into`](ExecutionPlanCore::hash_into)
//! for consistent hash coverage. Grant-specific fields (operator identity,
//! signatures, revocation) are hashed separately.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::plan_core::ExecutionPlanCore;
use crate::types::GrantId;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BudgetReservation {
    pub calls_before: i64,
    pub calls_after: i64,
}

/// Short-lived authorization binding one exact execution plan.
///
/// The kernel issues a grant after all pre-dispatch checks pass. The
/// WasmRuntime receives the grant as its authority to act.
#[must_use = "grants represent authorized execution — dropping one silently skips dispatch"]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionGrant {
    /// Unique grant identifier. Correlates grant -> receipt -> evidence.
    pub grant_id: GrantId,

    /// Authenticated principal (from the Lease JWT `sub` claim).
    pub subject: Arc<str>,

    /// Sender key binding (`cnf.jkt` thumbprint from the DPoP proof).
    pub sender_binding: Arc<str>,

    /// Shared execution binding (action, targets, secrets, egress, expiry).
    #[serde(flatten)]
    pub core: ExecutionPlanCore,

    /// Budget reservation snapshot at issuance time.
    pub budget_reservation: BudgetReservation,

    /// Operator identity that approved the execution, if approval was required.
    ///
    /// `None` when policy auto-allowed the execution (no human in the loop).
    /// When present, this is the `operator_id` resolved from the named
    /// `[operator_credentials]` table — never a shared anonymous key.
    ///
    /// Included in `compute_plan_hash()` so that operator identity is
    /// integrity-bound into the approval chain and cannot be silently changed
    /// after the fact.
    pub approved_by: Option<Arc<str>>,

    /// JWK thumbprint of the operator's DPoP key (sender-constrained binding).
    ///
    /// `None` when policy auto-allowed the execution or when operator used
    /// bearer-only auth (dev mode). When present, this cryptographically
    /// proves which key the operator controlled at approval time.
    ///
    /// SECURITY: included in `compute_plan_hash()` and covered by the
    /// grant signature. Without this, `approved_by` gives attribution
    /// (operator name) but not non-repudiation (cryptographic proof).
    /// `operator_binding` gives both.
    pub operator_binding: Option<Arc<str>>,

    /// Hash over the exact plan that was human-approved, if approval was
    /// required. None when policy auto-allowed the execution.
    pub approval_hash: Option<Arc<str>>,

    /// When the grant was issued.
    pub issued_at: DateTime<Utc>,

    /// Monotonic epoch for revocation.
    pub revocation_epoch: u64,

    /// Ed25519 signature over `compute_signable_hash()`, hex-encoded.
    ///
    /// Binds the entire grant to the kernel's signing key. Without this,
    /// any process with access to the grant struct could forge or mutate
    /// fields (subject, targets, secrets, epoch) before dispatch.
    ///
    /// Signed immediately after construction; verified immediately before
    /// provider dispatch. Unsigned grants are rejected — fail-closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_signature: Option<String>,

    /// Key identifier of the signer that produced `grant_signature`.
    ///
    /// Allows key rotation without breaking in-flight grants: the verifier
    /// checks `kid` to select the correct public key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_signing_key_id: Option<String>,
}

impl ExecutionGrant {
    #[must_use]
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.core.expires_at
    }

    #[must_use]
    pub fn is_valid(&self, now: DateTime<Utc>, current_epoch: u64) -> bool {
        !self.is_expired(now) && self.revocation_epoch >= current_epoch
    }

    /// Compute the canonical hash of the execution plan bound by this grant.
    ///
    /// Uses `PlanHasher` for consistent
    /// hashing patterns shared with `ApprovedExecutionPlan::compute_hash`.
    /// Shared fields are hashed via [`ExecutionPlanCore::hash_into`];
    /// grant-specific fields are hashed here.
    ///
    /// SECURITY: every grant field that affects what gets executed, what
    /// targets are contacted, or what secrets are injected MUST be hashed
    /// here. A missing field means tampering goes undetected through the
    /// signature chain (`compute_plan_hash` => `compute_signable_hash` =>
    /// `sign`/`verify_signature`).
    #[must_use]
    pub fn compute_plan_hash(&self) -> String {
        use super::plan_hash::PlanHasher;

        let mut h = PlanHasher::new(b"latchgate-grant-plan-v3:");

        // Shared execution binding (9 fields).
        self.core.hash_into(&mut h);

        // Operator identity binding (grant-specific).
        h.hash_optional_tagged(b"approved_by:", self.approved_by.as_deref());
        h.hash_optional_tagged(b"operator_binding:", self.operator_binding.as_deref());

        h.finalize()
    }

    /// Compute a SHA-256 hash over ALL security-relevant fields of the grant.
    ///
    /// This is the value that gets signed. It covers everything in
    /// `compute_plan_hash()` plus identity, grant_id, timestamps, and
    /// revocation epoch — fields that `plan_hash` deliberately excludes
    /// because they change between issuance and verification.
    #[must_use]
    pub fn compute_signable_hash(&self) -> String {
        use sha2::{Digest, Sha256};

        let plan_hash = self.compute_plan_hash();

        let mut hasher = Sha256::new();
        hasher.update(b"latchgate-grant-v1:");
        hasher.update(self.grant_id.as_str().as_bytes());
        hasher.update(b":");
        hasher.update(self.subject.as_bytes());
        hasher.update(b":");
        hasher.update(self.sender_binding.as_bytes());
        hasher.update(b":");
        hasher.update(plan_hash.as_bytes());
        hasher.update(b":");
        hasher.update(self.issued_at.to_rfc3339().as_bytes());
        hasher.update(b":");
        hasher.update(self.core.expires_at.to_rfc3339().as_bytes());
        hasher.update(b":");
        hasher.update(self.revocation_epoch.to_le_bytes());
        if let Some(ref ah) = self.approval_hash {
            hasher.update(b":approval_hash:");
            hasher.update(ah.as_bytes());
        }
        hex::encode(hasher.finalize())
    }

    /// Compute the approval hash that binds a human approval to an execution
    /// plan.
    ///
    /// SECURITY: this cryptographically ties `approval_id` to the exact plan
    /// that was approved. If any plan field changes between approval and
    /// execution (e.g. manifest update, policy change), the hash will differ,
    /// and downstream validation can detect the divergence.
    #[must_use]
    pub fn compute_approval_hash(approval_id: &str, plan_hash: &str) -> Arc<str> {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(b"latchgate-approval-v1:");
        hasher.update(approval_id.as_bytes());
        hasher.update(b":");
        hasher.update(plan_hash.as_bytes());
        Arc::from(hex::encode(hasher.finalize()))
    }
}

/// Authenticated caller identity bound into every [`ExecutionGrant`].
///
/// Grouping `subject` and `sender_binding` into a struct prevents silent
/// parameter swaps at `ExecutionGrantBuilder::new` call sites — both are
/// `Arc<str>`-typed and adjacent, so swapping them would compile but produce
/// a grant bound to the wrong principal.
#[derive(Debug)]
pub struct GrantIdentity {
    /// Authenticated principal (from the Lease JWT `sub` claim).
    pub subject: Arc<str>,
    /// Sender key binding (JWK thumbprint from the DPoP proof `cnf.jkt`).
    pub sender_binding: Arc<str>,
}

/// Centralised construction of [`ExecutionGrant`].
///
/// The grant is a signed artifact whose security depends on every field being
/// set correctly. Two kernel paths produce grants — the auto-allow path
/// (policy-approved, no human) and the approval path (operator-confirmed).
/// They differ only in three fields: `approved_by`, `operator_binding`, and
/// `approval_hash`. Building both sites with a shared builder keeps the two
/// paths identical by construction.
///
/// Required fields are passed to [`Self::new`] (identity, shared
/// [`ExecutionPlanCore`], budget, timing). Approval bindings are applied
/// through chainable setters. `GrantBuilderExt::build_and_sign` is the single
/// finalisation step.
#[must_use = "builder must be consumed via build() or build_and_sign()"]
pub struct ExecutionGrantBuilder {
    grant_id: GrantId,
    subject: Arc<str>,
    sender_binding: Arc<str>,
    core: ExecutionPlanCore,
    budget_reservation: BudgetReservation,
    issued_at: DateTime<Utc>,
    revocation_epoch: u64,

    // Approval-path bindings — all default to None for the auto-allow path.
    approved_by: Option<Arc<str>>,
    operator_binding: Option<Arc<str>>,
    approval_binding: Option<ApprovalBinding>,
}

/// Inputs for computing `approval_hash` during builder finalisation.
struct ApprovalBinding {
    approval_id: Arc<str>,
    plan_hash: Arc<str>,
}

impl ExecutionGrantBuilder {
    /// Construct a builder with all fields required on every grant.
    ///
    /// The auto-allow path calls this and finalises immediately; the approval
    /// path chains [`Self::approved_by`], [`Self::operator_binding`], and
    /// [`Self::with_approval_for`] before finalising.
    pub fn new(
        grant_id: GrantId,
        identity: GrantIdentity,
        core: ExecutionPlanCore,
        budget_reservation: BudgetReservation,
        issued_at: DateTime<Utc>,
        revocation_epoch: u64,
    ) -> Self {
        Self {
            grant_id,
            subject: identity.subject,
            sender_binding: identity.sender_binding,
            core,
            budget_reservation,
            issued_at,
            revocation_epoch,
            approved_by: None,
            operator_binding: None,
            approval_binding: None,
        }
    }

    /// Record which operator approved this grant.
    ///
    /// Auto-allow grants omit this. Approval grants set it to the resolved
    /// `operator_id` from `[operator_credentials]`.
    pub fn approved_by(mut self, operator_id: impl Into<Arc<str>>) -> Self {
        self.approved_by = Some(operator_id.into());
        self
    }

    /// Record the operator's DPoP key thumbprint (sender binding).
    ///
    /// Pass `None` explicitly for operators authenticated without DPoP (dev
    /// mode). Pass `Some(thumbprint)` for the production case — the empty
    /// string from the API layer is normalised to `None` by the caller.
    pub fn operator_binding(mut self, binding: Option<Arc<str>>) -> Self {
        self.operator_binding = binding;
        self
    }

    /// Bind this grant to a specific approval. `GrantBuilderExt::build_and_sign` will
    /// compute `approval_hash = compute_approval_hash(approval_id, plan_hash)`.
    ///
    /// SECURITY: callers MUST pass the `plan_hash` stored alongside the
    /// pending approval — not a freshly recomputed hash from the live
    /// manifest. The stored hash is what the operator reviewed; using it
    /// here is how plan tampering between approval and execution is
    /// detected.
    pub fn with_approval_for(
        mut self,
        approval_id: impl Into<Arc<str>>,
        plan_hash: impl Into<Arc<str>>,
    ) -> Self {
        self.approval_binding = Some(ApprovalBinding {
            approval_id: approval_id.into(),
            plan_hash: plan_hash.into(),
        });
        self
    }

    /// Assemble the grant and compute `approval_hash` if an approval binding
    /// was configured. Returns an **unsigned** grant.
    ///
    /// SECURITY: the returned grant has no signature. Callers MUST sign it
    /// via `GrantExt::sign` before dispatch. Unsigned
    /// grants are rejected at verification — fail-closed.
    pub fn build(self) -> ExecutionGrant {
        let approval_hash = self
            .approval_binding
            .as_ref()
            .map(|b| ExecutionGrant::compute_approval_hash(&b.approval_id, &b.plan_hash));

        ExecutionGrant {
            grant_id: self.grant_id,
            subject: self.subject,
            sender_binding: self.sender_binding,
            core: self.core,
            budget_reservation: self.budget_reservation,
            approved_by: self.approved_by,
            operator_binding: self.operator_binding,
            approval_hash,
            issued_at: self.issued_at,
            revocation_epoch: self.revocation_epoch,
            grant_signature: None,
            grant_signing_key_id: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EgressProfile;
    use chrono::Duration;

    fn sample_core(expires_at: chrono::DateTime<chrono::Utc>) -> ExecutionPlanCore {
        ExecutionPlanCore {
            action_id: "http_fetch".into(),
            action_digest: "sha256:aabbccdd".into(),
            provider_module_digest:
                "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".into(),
            request_hash: "sha256:deadbeef".into(),
            policy_version: Some("2026-03-01".into()),
            approved_targets: vec!["api.github.com".into()],
            approved_secrets: vec!["GITHUB_TOKEN".into()],
            approved_egress: EgressProfile::ProxyAllowlist {
                allowed_domains: vec!["api.github.com".into()],
            },
            expires_at,
        }
    }

    fn sample_grant(expires_in: Duration) -> ExecutionGrant {
        let now = chrono::Utc::now();
        ExecutionGrant {
            grant_id: crate::types::GrantId::new(),
            subject: "agent@example.com".into(),
            sender_binding: "thumb-abc123".into(),
            core: sample_core(now + expires_in),
            budget_reservation: BudgetReservation {
                calls_before: 5,
                calls_after: 6,
            },
            approval_hash: None,
            approved_by: None,
            operator_binding: None,
            issued_at: now,
            revocation_epoch: 1,
            grant_signature: None,
            grant_signing_key_id: None,
        }
    }

    #[test]
    fn fresh_grant_is_valid() {
        let grant = sample_grant(Duration::seconds(60));
        assert!(grant.is_valid(chrono::Utc::now(), 1));
    }

    #[test]
    fn expired_grant_is_invalid() {
        let grant = sample_grant(Duration::seconds(-1));
        assert!(grant.is_expired(chrono::Utc::now()));
        assert!(!grant.is_valid(chrono::Utc::now(), 1));
    }

    #[test]
    fn revoked_grant_is_invalid() {
        let grant = sample_grant(Duration::seconds(60));
        assert!(!grant.is_valid(chrono::Utc::now(), 999));
    }

    #[test]
    fn plan_hash_is_deterministic() {
        let grant = sample_grant(Duration::seconds(60));
        assert_eq!(grant.compute_plan_hash(), grant.compute_plan_hash());
    }

    #[test]
    fn signable_hash_is_deterministic() {
        let grant = sample_grant(Duration::seconds(60));
        assert_eq!(grant.compute_signable_hash(), grant.compute_signable_hash());
    }

    #[test]
    fn signable_hash_differs_from_plan_hash() {
        let grant = sample_grant(Duration::seconds(60));
        assert_ne!(grant.compute_plan_hash(), grant.compute_signable_hash());
    }

    #[test]
    fn approval_hash_is_deterministic() {
        let h1 = ExecutionGrant::compute_approval_hash("ap-1", "plan-hash-1");
        let h2 = ExecutionGrant::compute_approval_hash("ap-1", "plan-hash-1");
        assert_eq!(h1, h2);
    }

    #[test]
    fn approval_hash_changes_with_approval_id() {
        let h1 = ExecutionGrant::compute_approval_hash("ap-1", "plan-hash-1");
        let h2 = ExecutionGrant::compute_approval_hash("ap-2", "plan-hash-1");
        assert_ne!(h1, h2);
    }

    #[test]
    fn build_returns_unsigned_grant() {
        let now = chrono::Utc::now();
        let grant = ExecutionGrantBuilder::new(
            crate::types::GrantId::new(),
            GrantIdentity {
                subject: "agent@test".into(),
                sender_binding: "thumb".into(),
            },
            sample_core(now + Duration::seconds(60)),
            BudgetReservation {
                calls_before: 1,
                calls_after: 2,
            },
            now,
            1,
        )
        .build();

        assert!(grant.grant_signature.is_none());
        assert!(grant.grant_signing_key_id.is_none());
    }

    #[test]
    fn build_with_approval_computes_hash() {
        let now = chrono::Utc::now();
        let grant = ExecutionGrantBuilder::new(
            crate::types::GrantId::new(),
            GrantIdentity {
                subject: "agent@test".into(),
                sender_binding: "thumb".into(),
            },
            sample_core(now + Duration::seconds(60)),
            BudgetReservation {
                calls_before: 1,
                calls_after: 2,
            },
            now,
            1,
        )
        .approved_by("alice")
        .with_approval_for("ap-1", "plan-hash-1")
        .build();

        assert!(grant.approval_hash.is_some());
        assert_eq!(grant.approved_by.as_deref(), Some("alice"));
    }
}
