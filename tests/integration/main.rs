//! Integration tests — require Redis + OPA.
//!
//! Run via: `cargo test --test integration`
//! Prerequisites: `make dev` or `docker compose up redis opa`

#[allow(dead_code)]
mod harness;

mod approval;
mod e2e;
mod evidence;
mod resilience;
