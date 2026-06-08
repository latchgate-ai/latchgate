#![no_main]
//! Fuzz the SSRF defense: `is_private_ip`.
//!
//! A false negative leaks cloud metadata.
//!
//! Properties tested:
//! - No panics on any valid IP address.
//! - IPv4-mapped-IPv6 invariant: `is_private_ip(::ffff:V4)` ==
//!   `is_private_ip(V4)`.

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use latchgate_core::is_private_ip;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug)]
enum FuzzAddr {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl<'a> Arbitrary<'a> for FuzzAddr {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        if u.arbitrary::<bool>()? {
            Ok(Self::V4(u.arbitrary()?))
        } else {
            Ok(Self::V6(u.arbitrary()?))
        }
    }
}

fuzz_target!(|addr: FuzzAddr| {
    match addr {
        FuzzAddr::V4(octets) => {
            let v4 = Ipv4Addr::from(octets);
            let v4_result = is_private_ip(IpAddr::V4(v4));

            // Property: IPv4-mapped-IPv6 invariant.
            let mapped = v4.to_ipv6_mapped();
            let v6_result = is_private_ip(IpAddr::V6(mapped));
            assert_eq!(
                v4_result, v6_result,
                "is_private_ip({v4}) = {v4_result}, \
                 is_private_ip(::ffff:{v4}) = {v6_result}",
            );
        }
        FuzzAddr::V6(octets) => {
            let v6 = Ipv6Addr::from(octets);
            let _ = is_private_ip(IpAddr::V6(v6));

            // If this is an IPv4-mapped address, verify the invariant
            // from the v6 side as well.
            if let Some(v4) = v6.to_ipv4_mapped() {
                let v4_result = is_private_ip(IpAddr::V4(v4));
                let v6_result = is_private_ip(IpAddr::V6(v6));
                assert_eq!(
                    v4_result, v6_result,
                    "mapped invariant violated for {v6} (inner {v4})",
                );
            }
        }
    }
});
