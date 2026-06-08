//! Compile-time embedded OPA policy.
//!
//! Binary installs (brew, cargo-binstall) do not ship `policies/opa/`.
//! This module embeds the Rego policy at compile time so that
//! `latchgate init` can extract a working policy without the source tree.

/// The Rego policy file, embedded at compile time.
///
/// Path is relative to `crates/latchgate-cli/Cargo.toml`.
pub const POLICY_REGO: &str = include_str!("../../../definitions/policies/opa/latchgate.rego");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_rego_is_valid() {
        assert!(
            POLICY_REGO.contains("package latchgate"),
            "embedded latchgate.rego missing 'package latchgate' declaration"
        );
    }

    #[test]
    fn embedded_rego_references_acl_schema() {
        assert!(
            POLICY_REGO.contains("data.acl"),
            "Rego policy must reference data.acl — init generates this structure"
        );
        assert!(
            POLICY_REGO.contains("allowed_actions"),
            "Rego policy must reference allowed_actions — init generates this field"
        );
        assert!(
            POLICY_REGO.contains("allowed_sinks"),
            "Rego policy must reference allowed_sinks — init generates this field"
        );
    }
}
