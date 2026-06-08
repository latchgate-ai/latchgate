//! Config validation checks.

use latchgate_config::Config;

use super::Check;

pub(super) fn check_config_file(config: &Config) -> Check {
    if config.listener.public_base_url.is_empty() {
        Check::warn(
            "public_base_url",
            "not set — DPoP htu validation will fail. Set in latchgate.toml.",
        )
    } else {
        Check::ok("public_base_url", &config.listener.public_base_url)
    }
}

/// Verify operator credentials are present and have DPoP binding in production.
///
/// SECURITY: in production, every operator MUST have `dpop_jkt` for
/// proof-of-possession binding. Bearer-only credentials (no `dpop_jkt`) mean
/// a stolen API key grants full operator access with no cryptographic binding
/// to a private key.
pub(super) fn check_operator_credentials(config: &Config) -> Check {
    if config.operator_credentials.is_empty() {
        if config.dev_mode() {
            return Check::warn("operator_creds", "none configured (dev mode)");
        }
        return Check::error(
            "operator_creds",
            "no operator credentials configured — run: latchgate config add-operator --name <n>",
        );
    }

    let total = config.operator_credentials.len();
    let missing_jkt: Vec<&str> = config
        .operator_credentials
        .iter()
        .filter(|(_, cred)| cred.dpop_jkt.is_none())
        .map(|(name, _)| name.as_str())
        .collect();

    if missing_jkt.is_empty() {
        Check::ok(
            "operator_creds",
            format!("{total} operator(s) — all have DPoP binding"),
        )
    } else if config.dev_mode() {
        Check::warn(
            "operator_creds",
            format!(
                "{total} operator(s) — {} without dpop_jkt (dev only): {}",
                missing_jkt.len(),
                missing_jkt.join(", "),
            ),
        )
    } else {
        Check::error(
            "operator_creds",
            format!(
                "operator(s) missing dpop_jkt (required in production): {}",
                missing_jkt.join(", "),
            ),
        )
    }
}

/// Verify persistent signing key paths are configured in production.
///
/// SECURITY: without persistent signing keys, receipts and grants are signed
/// with ephemeral keys that are lost on restart. This makes all previously
/// issued receipts unverifiable — acceptable in dev, unacceptable in prod.
pub(super) fn check_signing_keys(config: &Config) -> Check {
    let receipt = config.signing.receipt_signing_key_path.is_some();
    let grant = config.signing.grant_signing_key_path.is_some();

    if receipt && grant {
        Check::ok("signing_keys", "receipt + grant key paths configured")
    } else if config.dev_mode() {
        Check::skip(
            "signing_keys",
            "skipped (dev) — ephemeral keys, receipts unverifiable after restart",
        )
    } else {
        let mut missing = Vec::new();
        if !receipt {
            missing.push("receipt_signing_key_path");
        }
        if !grant {
            missing.push("grant_signing_key_path");
        }
        Check::error(
            "signing_keys",
            format!(
                "missing: {} — run: latchgate init --force",
                missing.join(", "),
            ),
        )
    }
}
