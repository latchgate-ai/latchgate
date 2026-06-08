//! Network security primitives: SSRF protection, private IP detection,
//! domain validation, and egress allowlist matching.
//!
//! Implementation is split across [`ip`] (IP/SSRF), [`domain`]
//! (domain validation), and [`egress`] (egress matching). This module
//! re-exports the full public API.

mod domain;
mod egress;
mod ip;

pub use domain::{
    is_safe_wildcard_suffix, validate_domain_entry, validate_manifest_domain_entry,
    DomainValidationError,
};
pub use egress::{
    domain_in_allowlist, find_matching_entry, host_matches_allowlist_lower, lowercase_allowlist,
    parse_host_from_url,
};
pub use ip::{is_private_ip, resolve_and_check_ssrf, SsrfCheckOptions, SsrfError};
