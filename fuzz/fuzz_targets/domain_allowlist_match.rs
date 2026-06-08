#![no_main]
//! Fuzz the runtime egress gate: `domain_in_allowlist`.
//!
//! Properties tested:
//! - No panics on arbitrary domain + allowlist combinations.
//! - Differential: `domain_in_allowlist(d, list)` must equal
//!   `host_matches_allowlist_lower(d.lower, lowercase_allowlist(list))`.
//! - Case-insensitivity: result is identical regardless of domain casing.

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use latchgate_core::domain_in_allowlist;
use latchgate_core::net::{host_matches_allowlist_lower, lowercase_allowlist};

#[derive(Debug)]
struct FuzzInput {
    domain: String,
    allowlist: Vec<String>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let domain: String = u.arbitrary()?;
        let len = u.int_in_range(0..=16_u8)?;
        let allowlist = (0..len)
            .map(|_| u.arbitrary())
            .collect::<arbitrary::Result<Vec<String>>>()?;
        Ok(Self { domain, allowlist })
    }
}

fuzz_target!(|input: FuzzInput| {
    let result = domain_in_allowlist(&input.domain, &input.allowlist);

    // Property: differential.
    let lowered_list = lowercase_allowlist(&input.allowlist);
    let lowered_domain = input.domain.to_ascii_lowercase();
    let expected = host_matches_allowlist_lower(&lowered_domain, &lowered_list);
    assert_eq!(
        result, expected,
        "domain_in_allowlist vs host_matches_allowlist_lower desync \
         for domain={:?}, allowlist={:?}",
        input.domain, input.allowlist,
    );

    // Property: case-insensitivity.
    let upper_result = domain_in_allowlist(
        &input.domain.to_ascii_uppercase(),
        &input.allowlist,
    );
    assert_eq!(
        result, upper_result,
        "domain_in_allowlist must be case-insensitive for: {:?}",
        input.domain,
    );
});
