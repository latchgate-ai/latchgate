//! Listener transport configuration (UDS, TCP, TLS, public URL).

use std::net::SocketAddr;

use serde::Deserialize;

/// Transport configuration for client and admin endpoints.
#[derive(Debug, Clone, Deserialize)]
pub struct ListenerConfig {
    /// UDS path for the primary (client-facing) socket.
    /// SECURITY: UDS limits access to processes with filesystem access.
    #[serde(default = "default_uds_path")]
    pub listen_uds_path: String,

    /// UDS path for the admin-facing socket.
    /// SECURITY: must be owned by a group that excludes agent processes.
    #[serde(default = "default_admin_uds_path")]
    pub listen_admin_uds_path: String,

    /// Optional TCP listen address. Requires `unsafe_expose_http = true`.
    pub listen_http_addr: Option<SocketAddr>,

    /// Optional TCP listen address for admin endpoints.
    ///
    /// Requires either `unsafe_expose_http = true` (plain HTTP) or all
    /// three `admin_tls_*` fields (mTLS). When mTLS is configured, the
    /// `unsafe_expose_http` flag is not required — TLS makes TCP safe
    /// to expose.
    pub listen_admin_http_addr: Option<SocketAddr>,

    /// Opt in to TCP/HTTP exposure. Default: false.
    /// SECURITY: exposing TCP widens the attack surface beyond UDS.
    #[serde(default)]
    pub unsafe_expose_http: bool,

    /// PEM-encoded server certificate path for admin mTLS.
    ///
    /// SECURITY: must be a certificate signed by the same CA whose
    /// public cert is in `admin_tls_ca`. Presented to connecting clients
    /// during the TLS handshake.
    pub admin_tls_cert: Option<String>,

    /// PEM-encoded server private key path for admin mTLS.
    ///
    /// SECURITY: must be readable only by the LatchGate process (chmod
    /// 0o600). Corresponds to the public key in `admin_tls_cert`.
    pub admin_tls_key: Option<String>,

    /// PEM-encoded CA certificate path for admin mTLS client verification.
    ///
    /// SECURITY: connecting clients must present a certificate signed by
    /// this CA. This is the mutual-authentication anchor — without it,
    /// any TCP client can reach the admin API.
    pub admin_tls_ca: Option<String>,

    /// Public base URL for DPoP `htu` verification.
    /// SECURITY: must NOT be derived from Host/X-Forwarded headers.
    #[serde(default = "default_public_base_url")]
    pub public_base_url: String,

    /// Optional allowlist of client certificate SHA-256 fingerprints
    /// (lowercase hex, 64 characters) permitted on the admin mTLS
    /// listener. When set, connections whose client cert fingerprint is
    /// not in this list are rejected immediately after the TLS handshake
    /// — before any HTTP request is processed.
    ///
    /// When absent (`None`), any client cert signed by the configured CA
    /// is accepted (the CA trust anchor is the sole identity gate).
    ///
    /// SECURITY: without this, all certificates issued by the admin CA
    /// are equivalent — a compromised operator cert cannot be revoked
    /// without rotating the CA. This field provides per-certificate
    /// revocation by omission.
    #[serde(default)]
    pub admin_tls_allowed_fingerprints: Option<Vec<String>>,
}

impl ListenerConfig {
    /// Returns `true` when all three admin TLS fields are configured.
    ///
    /// SECURITY: partial configuration (1 or 2 of 3 fields set) is caught
    /// by `Config::validate_listen` as a hard startup error. This helper
    /// only returns `true` when the full mTLS triple is present.
    pub fn admin_tls_configured(&self) -> bool {
        self.admin_tls_cert.is_some() && self.admin_tls_key.is_some() && self.admin_tls_ca.is_some()
    }

    /// Returns the number of `admin_tls_*` fields that are `Some`.
    ///
    /// Used by validation to detect partial configuration (1 or 2 of 3).
    pub(crate) fn admin_tls_field_count(&self) -> usize {
        [
            self.admin_tls_cert.is_some(),
            self.admin_tls_key.is_some(),
            self.admin_tls_ca.is_some(),
        ]
        .iter()
        .filter(|&&v| v)
        .count()
    }
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            listen_uds_path: latchgate_core::paths::default_uds_path()
                .to_string_lossy()
                .into_owned(),
            listen_admin_uds_path: latchgate_core::paths::default_admin_uds_path()
                .to_string_lossy()
                .into_owned(),
            listen_http_addr: None,
            listen_admin_http_addr: None,
            unsafe_expose_http: false,
            admin_tls_cert: None,
            admin_tls_key: None,
            admin_tls_ca: None,
            public_base_url: "http://localhost:3000".to_string(),
            admin_tls_allowed_fingerprints: None,
        }
    }
}

fn default_uds_path() -> String {
    latchgate_core::paths::default_uds_path()
        .to_string_lossy()
        .into_owned()
}

fn default_admin_uds_path() -> String {
    latchgate_core::paths::default_admin_uds_path()
        .to_string_lossy()
        .into_owned()
}

fn default_public_base_url() -> String {
    "http://localhost:3000".to_string()
}
