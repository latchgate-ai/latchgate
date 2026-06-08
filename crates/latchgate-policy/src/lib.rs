#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
//! Policy decision engine for LatchGate.
//!
//! This crate owns the pure-function policy evaluation boundary: given a
//! [`PolicyInput`], produce a [`PolicyDecision`]. It contains no persistent
//! state — approvals and budgets live in `latchgate-state`.
//!

pub(crate) mod embedded;
pub(crate) mod policy;

pub use policy::{
    PolicyAction, PolicyClient, PolicyDecision, PolicyError, PolicyIdentity, PolicyInput,
    PolicyRequest, PolicyResolution,
};
