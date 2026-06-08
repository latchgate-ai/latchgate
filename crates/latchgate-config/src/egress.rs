//! Egress control configuration (proxy, allowlists).

use serde::Deserialize;

/// Egress proxy and domain allowlist configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct EgressConfig {
    /// Forward proxy URL for defense-in-depth egress control.
    #[serde(default)]
    pub egress_proxy_url: Option<String>,

    /// Runtime narrowing — intersects with manifest `allowed_domains`.
    #[serde(default)]
    pub egress_runtime_allowlist: Option<Vec<String>>,

    /// Path for live Squid-format allowlist file.
    #[serde(default)]
    pub egress_live_allowlist_path: Option<String>,

    /// Command to reload the proxy after allowlist update.
    #[serde(default)]
    pub egress_reload_command: Option<String>,
}
