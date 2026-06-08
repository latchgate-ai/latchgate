//! Caller identity verification for lease issuance.
//!
//! # Problem
//!
//! `POST /v1/leases` is the authentication bootstrapping endpoint — it issues
//! the Lease JWT that subsequent pipeline calls rely on. But the endpoint
//! itself needs to know *who* is requesting the lease. Without an identity
//! layer, any process with socket access can obtain a lease with arbitrary
//! (format-valid) scopes. DPoP binds the lease to a key, but says nothing
//! about the caller's real identity.
//!
//! # Design
//!
//! The [`IdentityProvider`] trait abstracts caller authentication at lease
//! issuance time. Implementations verify the caller through transport-level
//! or token-level mechanisms and return a [`VerifiedIdentity`] containing
//! the authenticated principal and the maximum scopes the caller is permitted
//! to request.
//!
//! The lease endpoint intersects the caller's requested scopes with
//! `VerifiedIdentity::max_scopes` — a caller cannot escalate beyond what
//! the identity layer grants.
//!
//! # Implementations
//!
//! | Provider | Transport | Mechanism | Use case |
//! |----------|-----------|-----------|----------|
//! | [`peercred::PeerCredProvider`] | UDS | `SO_PEERCRED` uid=>principal mapping | Single-host, containers |
//! | (future) `OidcProvider` | Any | IdP-issued JWT verification | Enterprise, multi-tenant |
//! | (future) `MtlsProvider` | TLS | x509 / SPIFFE SVID | Service mesh |
//! | [`NoneProvider`] | Any | Accept all (dev only) | Local dev, testing |

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub mod peercred;

// Re-export config types from core so consumers can import from one place.
pub use latchgate_config::{
    IdentityConfig, IdentityProviderKind, PeercredConfig, PeercredPrincipal,
};

/// Authenticated caller identity, returned by an [`IdentityProvider`].
///
/// The lease endpoint uses this to:
/// - set `sub` in the Lease JWT to `principal` (server-controlled, not client-asserted)
/// - intersect requested scopes with `max_scopes` (least-privilege)
/// - record `identity_method` in audit events for forensic attribution
#[must_use = "verified identities must be used for authorization — dropping one bypasses identity checks"]
#[derive(Debug, Clone)]
pub struct VerifiedIdentity {
    /// Authenticated principal identifier.
    ///
    /// This becomes the `sub` claim in the Lease JWT and the `principal`
    /// in all downstream audit events.
    pub principal: String,

    /// Maximum scopes this identity is allowed to request.
    ///
    /// The lease endpoint intersects the client's requested scopes with
    /// this set: `issued_scopes = requested ∩ max_scopes`.
    pub max_scopes: Vec<String>,

    /// Human-readable label for the authentication method.
    pub identity_method: &'static str,

    /// Owner/responsible person for this agent (e.g. `"alice@company.com"`).
    pub owner: Option<String>,
}

/// Errors from caller identity verification.
///
/// Mapped to HTTP responses at the API boundary:
/// - `Unauthenticated` => 401 (caller must authenticate)
/// - `Forbidden` => 403 (identity known but not permitted)
/// - `ProviderUnavailable` => 503 (transient; retry with backoff)
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// Caller could not be identified. No identity evidence was presented,
    /// or the presented evidence was invalid.
    #[error("unauthenticated: {reason}")]
    Unauthenticated { reason: String },

    /// Caller identity is known but not authorized for lease issuance.
    /// Example: uid is not in the peercred principal map.
    #[error("forbidden: {reason}")]
    Forbidden { reason: String },

    /// The identity provider's backing service is unavailable.
    /// SECURITY: fail-closed — lease issuance must be denied.
    #[error("identity provider unavailable: {reason}")]
    ProviderUnavailable { reason: String },
}

/// Transport-level metadata extracted at connection time.
///
/// Carried as an axum request extension. Each transport (UDS, TCP+TLS)
/// populates the fields it can provide. Identity providers read the
/// fields they need and ignore the rest.
#[derive(Debug, Clone, Default)]
pub struct ConnectionContext {
    /// Unix peer credentials (uid, gid, pid) from `SO_PEERCRED`.
    ///
    /// Available only on UDS connections. Populated by the UDS listener
    /// middleware before the request enters axum routing.
    #[cfg(unix)]
    pub peer_cred: Option<PeerCred>,

    /// Bearer token from the `Authorization` header.
    ///
    /// Used by token-based identity providers (OIDC, bootstrap tokens).
    /// Extracted by the lease handler from request headers.
    pub bearer_token: Option<Arc<str>>,

    /// TLS client certificate SHA-256 fingerprint (hex-encoded).
    ///
    /// Populated once per TLS connection by the admin mTLS listener.
    pub client_cert_fingerprint: Option<Arc<str>>,
}

/// Unix peer credentials from `SO_PEERCRED` / `getpeereid`.
///
/// On Linux, obtained via `getsockopt(SO_PEERCRED)`. On macOS, via
/// `getpeereid(2)`. The kernel guarantees these values — they cannot
/// be forged by the peer process.
#[cfg(unix)]
#[derive(Debug, Clone, Copy)]
pub struct PeerCred {
    /// Effective UID of the peer process.
    pub uid: u32,
    /// Effective GID of the peer process.
    pub gid: u32,
    /// PID of the peer process (Linux only; not stable across restarts).
    pub pid: Option<u32>,
}

/// Verifies caller identity at lease issuance time.
///
/// # Contract
///
/// - `authenticate` is called once per `POST /v1/leases` request.
/// - On success, returns [`VerifiedIdentity`] with the authenticated
///   principal and maximum permitted scopes.
/// - On failure, returns [`IdentityError`]. The lease endpoint maps
///   this to an HTTP error and denies issuance. **Fail-closed.**
/// - Implementations must be `Send + Sync + 'static` (shared via `Arc`).
/// - Implementations must not block the tokio runtime. CPU-heavy work
///   (e.g. JWT signature verification) should use `spawn_blocking`.
pub trait IdentityProvider: Send + Sync + 'static {
    /// Authenticate the caller and return their verified identity.
    fn authenticate<'a>(
        &'a self,
        ctx: &'a ConnectionContext,
    ) -> Pin<Box<dyn Future<Output = Result<VerifiedIdentity, IdentityError>> + Send + 'a>>;
}

/// Identity provider that accepts all callers without verification.
///
/// **SECURITY: dev/test only.** Every caller gets a synthetic principal
/// (`"dev:anonymous"`) and unrestricted scopes. The lease audit event
/// records `identity_method: "none"` so production audits can detect
/// misconfiguration.
pub struct NoneProvider;

impl IdentityProvider for NoneProvider {
    fn authenticate<'a>(
        &'a self,
        _ctx: &'a ConnectionContext,
    ) -> Pin<Box<dyn Future<Output = Result<VerifiedIdentity, IdentityError>> + Send + 'a>> {
        Box::pin(async {
            Ok(VerifiedIdentity {
                principal: "dev:anonymous".to_string(),
                max_scopes: vec![], // empty = unrestricted
                identity_method: "none",
                owner: None,
            })
        })
    }
}

/// Build an [`IdentityProvider`] from configuration.
///
/// Called once at server startup. The returned provider is shared via
/// `Arc<dyn IdentityProvider>` in `AppState`.
pub fn build_identity_provider(config: &IdentityConfig) -> Box<dyn IdentityProvider> {
    match config.provider {
        IdentityProviderKind::Peercred => {
            Box::new(peercred::PeerCredProvider::new(config.peercred.clone()))
        }
        IdentityProviderKind::None => Box::new(NoneProvider),
    }
}

/// Compute the effective scopes for a lease: `requested ∩ max_scopes`.
///
/// If `max_scopes` is empty, all requested scopes are permitted (used by
/// [`NoneProvider`] in dev mode). Otherwise, only scopes present in both
/// `requested` and `max_scopes` are returned.
///
/// Returns `Err` if the intersection is empty and `max_scopes` is non-empty
/// — the caller requested scopes they're not permitted to have.
pub fn intersect_scopes(
    requested: &[String],
    max_scopes: &[String],
) -> Result<Vec<String>, IdentityError> {
    // Unrestricted: identity provider allows any scope.
    if max_scopes.is_empty() {
        return Ok(requested.to_vec());
    }

    let effective: Vec<String> = requested
        .iter()
        .filter(|s| max_scopes.contains(s))
        .cloned()
        .collect();

    if effective.is_empty() {
        return Err(IdentityError::Forbidden {
            reason: format!(
                "none of the requested scopes ({requested:?}) are permitted \
                 for this identity (allowed: {max_scopes:?})"
            ),
        });
    }

    Ok(effective)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // -- NoneProvider --

    #[tokio::test]
    async fn none_provider_returns_dev_anonymous() {
        let provider = NoneProvider;
        let ctx = ConnectionContext::default();
        let identity = provider.authenticate(&ctx).await.unwrap();
        assert_eq!(identity.principal, "dev:anonymous");
        assert_eq!(identity.identity_method, "none");
        assert!(identity.max_scopes.is_empty());
    }

    // -- intersect_scopes --

    #[test]
    fn intersect_empty_max_allows_all() {
        let result = intersect_scopes(&["tools:call".into(), "email:send".into()], &[]).unwrap();
        assert_eq!(result, vec!["tools:call", "email:send"]);
    }

    #[test]
    fn intersect_filters_to_allowed() {
        let result = intersect_scopes(
            &[
                "tools:call".into(),
                "email:send".into(),
                "admin:nuke".into(),
            ],
            &["tools:call".into(), "email:send".into()],
        )
        .unwrap();
        assert_eq!(result, vec!["tools:call", "email:send"]);
    }

    #[test]
    fn intersect_rejects_when_no_overlap() {
        let result = intersect_scopes(&["admin:nuke".into()], &["tools:call".into()]);
        assert!(result.is_err());
    }

    #[test]
    fn intersect_subset_ok() {
        let result = intersect_scopes(
            &["tools:call".into()],
            &["tools:call".into(), "email:send".into()],
        )
        .unwrap();
        assert_eq!(result, vec!["tools:call"]);
    }

    // -- IdentityConfig defaults --

    #[test]
    fn default_config_is_none_provider() {
        let config = IdentityConfig::default();
        assert_eq!(config.provider, IdentityProviderKind::None);
    }

    #[test]
    fn peercred_config_deserializes() {
        let toml = r#"
            provider = "peercred"

            [peercred]
            allow_unmapped = false

            [peercred.principals]
            1001 = { principal = "agent-jira", scopes = ["tools:call"] }
            1002 = { principal = "agent-email", scopes = ["tools:call", "email:send"] }
        "#;

        let config: IdentityConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.provider, IdentityProviderKind::Peercred);
        assert!(!config.peercred.allow_unmapped);
        assert_eq!(config.peercred.principals.len(), 2);

        let jira = &config.peercred.principals["1001"];
        assert_eq!(jira.principal, "agent-jira");
        assert_eq!(jira.scopes, vec!["tools:call"]);

        let email = &config.peercred.principals["1002"];
        assert_eq!(email.principal, "agent-email");
        assert_eq!(email.scopes, vec!["tools:call", "email:send"]);
    }

    // -- build_identity_provider --

    #[tokio::test]
    async fn build_none_provider_works() {
        let config = IdentityConfig::default();
        let provider = build_identity_provider(&config);
        let identity = provider
            .authenticate(&ConnectionContext::default())
            .await
            .unwrap();
        assert_eq!(identity.identity_method, "none");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn build_peercred_provider_works() {
        let config = IdentityConfig {
            provider: IdentityProviderKind::Peercred,
            peercred: PeercredConfig {
                principals: HashMap::from([(
                    "1001".to_string(),
                    PeercredPrincipal {
                        principal: "test-agent".to_string(),
                        scopes: vec!["tools:call".into()],
                        owner: None,
                    },
                )]),
                allow_unmapped: false,
            },
        };
        let provider = build_identity_provider(&config);
        // Without peer creds in context, should fail.
        let result = provider.authenticate(&ConnectionContext::default()).await;
        assert!(result.is_err());
    }
}
