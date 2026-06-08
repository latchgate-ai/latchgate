#![no_main]
//! Fuzz the host extraction feeding allowlist matching: `parse_host_from_url`.
//!
//! A parser/connector desync here is an SSRF primitive.
//!
//! Properties tested:
//! - No panics on arbitrary input.
//! - Result is lowercase ASCII.
//! - Result is non-empty.
//! - Idempotence: `parse_host_from_url(result)` returns `result` or `None`.

use libfuzzer_sys::fuzz_target;
use latchgate_core::parse_host_from_url;

fuzz_target!(|data: &str| {
    let Some(host) = parse_host_from_url(data) else {
        return;
    };

    // Property: non-empty.
    assert!(!host.is_empty(), "extracted host must not be empty");

    // Property: lowercase.
    assert!(
        host.chars().all(|c| !c.is_ascii_uppercase()),
        "extracted host must be lowercase: {host}",
    );

    // Property: idempotence.
    // Feeding the extracted host back must either reproduce the same host
    // or return None (it may lack the scheme required for URL parsing).
    if let Some(re_host) = parse_host_from_url(&host) {
        assert_eq!(
            host, re_host,
            "parse_host_from_url must be idempotent: {data} -> {host} -> {re_host}",
        );
    }
});
