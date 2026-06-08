//! Per-endpoint rate limit configuration.

use serde::Deserialize;

/// Token bucket rate limits (requests per second).
#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitsConfig {
    /// Operator write endpoints (create/revoke credentials).
    #[serde(default = "default_op_write")]
    pub operator_write_rps: u32,
    /// Operator read endpoints (list, status).
    #[serde(default = "default_op_read")]
    pub operator_read_rps: u32,
    /// Lease issuance endpoint.
    #[serde(default = "default_lease")]
    pub lease_rps: u32,
    /// Execute path — per authenticated session.
    #[serde(default = "default_exec_session")]
    pub execute_rps_per_session: u32,
    /// Execute path — anonymous (no parseable session).
    #[serde(default = "default_exec_anon")]
    pub execute_rps_anonymous: u32,
}

fn default_op_write() -> u32 {
    20
}
fn default_op_read() -> u32 {
    100
}
fn default_lease() -> u32 {
    50
}
fn default_exec_session() -> u32 {
    20
}
fn default_exec_anon() -> u32 {
    5
}

impl Default for RateLimitsConfig {
    fn default() -> Self {
        Self {
            operator_write_rps: 20,
            operator_read_rps: 100,
            lease_rps: 50,
            execute_rps_per_session: 20,
            execute_rps_anonymous: 5,
        }
    }
}
