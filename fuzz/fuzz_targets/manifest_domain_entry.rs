#![no_main]
//! Fuzz the egress allowlist parser: `validate_manifest_domain_entry`.
//!
//! Properties tested:
//! - No panics on arbitrary input.
//! - Idempotence: re-validating accepted output returns the same string.
//! - Lowercase: accepted output is ASCII-lowercased.
//! - Wildcard differential: if a wildcard suffix passes
//!   `is_safe_wildcard_suffix`, the strict `validate_domain_entry` must also
//!   accept it (no classification desync).

use libfuzzer_sys::fuzz_target;
use latchgate_core::net::is_safe_wildcard_suffix;
use latchgate_core::{validate_domain_entry, validate_manifest_domain_entry};

fuzz_target!(|data: &str| {
    let result = validate_manifest_domain_entry(data);

    let Ok(ref normalized) = result else {
        return;
    };

    // Property: lowercase.
    assert!(
        normalized.chars().all(|c| !c.is_ascii_uppercase()),
        "accepted output must be ASCII-lowercased: {normalized}",
    );

    // Property: idempotence.
    let re = validate_manifest_domain_entry(normalized);
    match re {
        Ok(ref re_normalized) => assert_eq!(
            re_normalized, normalized,
            "re-validation must be idempotent for: {normalized}",
        ),
        Err(e) => panic!("re-validation rejected its own output {normalized}: {e}"),
    }

    // Property: wildcard differential.
    if let Some(suffix) = normalized.strip_prefix("*.") {
        if is_safe_wildcard_suffix(suffix) {
            let strict = validate_domain_entry(normalized, false);
            assert!(
                strict.is_ok(),
                "safe wildcard rejected by strict validator: {normalized}",
            );
        }
    }
});
