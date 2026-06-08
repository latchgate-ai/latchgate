//! Policy engine configuration (OPA / embedded regorus).

use serde::Deserialize;

/// Policy evaluation configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyConfig {
    /// OPA HTTP URL. Present => external OPA, absent => embedded regorus.
    #[serde(default)]
    pub opa_url: Option<String>,

    /// Default Lease TTL in seconds.
    /// Short TTLs limit blast radius of stolen Leases.
    #[serde(default = "default_lease_ttl")]
    pub lease_ttl_seconds: u64,
}

fn default_lease_ttl() -> u64 {
    300
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            opa_url: None,
            lease_ttl_seconds: 300,
        }
    }
}
