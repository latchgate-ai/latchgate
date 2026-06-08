//! LatchGate stress tests and benchmarks.
//!
//! This crate provides criterion benchmarks for the three latency-sensitive
//! hot paths (DPoP verify, policy eval, WASM instantiation) and a vegeta
//! load test script for manual use.
