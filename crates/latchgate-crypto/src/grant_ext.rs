//! Extension trait adding Ed25519 signing to [`ExecutionGrant`].
//!

use latchgate_core::ExecutionGrant;

use crate::grant_signer::{GrantSigner, GrantVerifyingKeyStore};

/// Ed25519 signing and verification for [`ExecutionGrant`].
pub trait GrantExt {
    /// Sign the grant using the provided Ed25519 signer.
    ///
    /// Must be called immediately after grant construction, before any
    /// other code can observe or modify the grant. Sets `grant_signature`
    /// and `grant_signing_key_id`.
    fn sign(&mut self, signer: &GrantSigner);

    /// Verify the grant's Ed25519 signature against a historical key store.
    ///
    /// Returns `true` only if:
    /// - `grant_signature` is present
    /// - `grant_signing_key_id` is found in the key store
    /// - the signature verifies against `compute_signable_hash()`
    ///
    /// Returns `false` in all other cases — fail-closed.
    fn verify_signature(&self, key_store: &GrantVerifyingKeyStore) -> bool;
}

impl GrantExt for ExecutionGrant {
    fn sign(&mut self, signer: &GrantSigner) {
        let signable = self.compute_signable_hash();
        self.grant_signing_key_id = Some(signer.kid());
        self.grant_signature = Some(signer.sign(&signable));
    }

    fn verify_signature(&self, key_store: &GrantVerifyingKeyStore) -> bool {
        match (&self.grant_signature, &self.grant_signing_key_id) {
            (Some(sig), Some(kid)) => {
                let signable = self.compute_signable_hash();
                match key_store.verify_by_kid(kid, &signable, sig) {
                    Ok(valid) => valid,
                    Err(_) => {
                        tracing::error!(
                            kid = %kid,
                            "grant signing key id not found in verifying key store"
                        );
                        false
                    }
                }
            }
            _ => false,
        }
    }
}

/// Extension trait adding `build_and_sign` to `ExecutionGrantBuilder`.
///
pub trait GrantBuilderExt {
    /// Assemble the grant and sign it with the provided signer.
    ///
    /// This is the only supported production finalisation path —
    /// unsigned grants are rejected at dispatch (fail-closed).
    fn build_and_sign(self, signer: &GrantSigner) -> ExecutionGrant;
}

impl GrantBuilderExt for latchgate_core::ExecutionGrantBuilder {
    fn build_and_sign(self, signer: &GrantSigner) -> ExecutionGrant {
        let mut grant = self.build();
        grant.sign(signer);
        grant
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use latchgate_core::{
        types::GrantId, BudgetReservation, EgressProfile, ExecutionGrantBuilder, ExecutionPlanCore,
        GrantIdentity,
    };

    fn sample_core() -> ExecutionPlanCore {
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
            expires_at: Utc::now() + Duration::seconds(60),
        }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let signer = GrantSigner::generate();
        let mut store = GrantVerifyingKeyStore::empty();
        store.register(&signer);

        let mut grant = ExecutionGrantBuilder::new(
            GrantId::new(),
            GrantIdentity {
                subject: "agent@test".into(),
                sender_binding: "thumb-abc".into(),
            },
            sample_core(),
            BudgetReservation {
                calls_before: 5,
                calls_after: 6,
            },
            Utc::now(),
            1,
        )
        .build();

        grant.sign(&signer);
        assert!(grant.verify_signature(&store));
    }

    #[test]
    fn build_and_sign_convenience() {
        let signer = GrantSigner::generate();
        let mut store = GrantVerifyingKeyStore::empty();
        store.register(&signer);

        let grant = ExecutionGrantBuilder::new(
            GrantId::new(),
            GrantIdentity {
                subject: "agent@test".into(),
                sender_binding: "thumb-abc".into(),
            },
            sample_core(),
            BudgetReservation {
                calls_before: 5,
                calls_after: 6,
            },
            Utc::now(),
            1,
        )
        .build_and_sign(&signer);

        assert!(grant.grant_signature.is_some());
        assert!(grant.verify_signature(&store));
    }

    #[test]
    fn unsigned_grant_fails_verification() {
        let signer = GrantSigner::generate();
        let mut store = GrantVerifyingKeyStore::empty();
        store.register(&signer);

        let grant = ExecutionGrantBuilder::new(
            GrantId::new(),
            GrantIdentity {
                subject: "agent@test".into(),
                sender_binding: "thumb-abc".into(),
            },
            sample_core(),
            BudgetReservation {
                calls_before: 5,
                calls_after: 6,
            },
            Utc::now(),
            1,
        )
        .build();

        assert!(!grant.verify_signature(&store));
    }
}
