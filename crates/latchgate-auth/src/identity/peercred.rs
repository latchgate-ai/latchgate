//! `SO_PEERCRED` identity provider for Unix Domain Socket connections.
//!
//! # How it works
//!
//! When a process connects to a UDS, the kernel makes the peer's effective
//! UID, GID, and PID available via `SO_PEERCRED` (Linux) or `getpeereid`
//! (macOS/BSD). These values are kernel-guaranteed — the peer process
//! cannot forge them.
//!
//! `PeerCredProvider` maps the peer UID to a configured principal and
//! scope set. UIDs not in the mapping are rejected (fail-closed), unless
//! `allow_unmapped` is set (dev only).
//!
//! # Configuration
//!
//! ```toml
//! [identity]
//! provider = "peercred"
//!
//! [identity.peercred]
//! allow_unmapped = false  # SECURITY: must be false in production
//!
//! [identity.peercred.principals]
//! 1001 = { principal = "agent-jira-bot",     scopes = ["tools:call"] }
//! 1002 = { principal = "agent-email-assist",  scopes = ["tools:call", "email:send"] }
//! 0    = { principal = "root-operator",       scopes = ["tools:call", "audit:read"] }
//! ```
//!
//! # Security properties
//!
//! - **Kernel-enforced identity**: UID cannot be forged by the peer.
//! - **Fail-closed**: missing peer creds or unmapped UID => deny.
//! - **Scope restriction**: each UID gets only its configured scopes.
//! - **Stable principal**: UID=>principal mapping is config-driven, not PID-based.
//! - **Audit attribution**: principal name appears in every downstream event.

#[cfg(unix)]
use super::{
    ConnectionContext, IdentityError, IdentityProvider, PeerCred, PeercredConfig, VerifiedIdentity,
};

#[cfg(unix)]
use std::future::Future;
#[cfg(unix)]
use std::pin::Pin;

#[cfg(unix)]
use tracing::{info, warn};

/// `SO_PEERCRED` identity provider.
///
/// Maps Unix UIDs from UDS connections to principals and scope sets.
/// Created once at startup, shared via `Arc<dyn IdentityProvider>`.
#[cfg(unix)]
pub struct PeerCredProvider {
    config: PeercredConfig,
}

#[cfg(unix)]
impl PeerCredProvider {
    /// Create a new `PeerCredProvider` from configuration.
    pub fn new(config: PeercredConfig) -> Self {
        info!(
            mapped_uids = config.principals.len(),
            allow_unmapped = config.allow_unmapped,
            "peercred identity provider initialised"
        );
        Self { config }
    }
}

#[cfg(unix)]
impl IdentityProvider for PeerCredProvider {
    fn authenticate<'a>(
        &'a self,
        ctx: &'a ConnectionContext,
    ) -> Pin<Box<dyn Future<Output = Result<VerifiedIdentity, IdentityError>> + Send + 'a>> {
        Box::pin(async move {
            let cred = ctx.peer_cred.ok_or_else(|| {
                // No peer creds means this isn't a UDS connection (e.g. TCP in dev mode)
                // or the listener didn't extract them. Fail-closed.
                IdentityError::Unauthenticated {
                    reason: "peercred identity provider requires a UDS connection \
                             with SO_PEERCRED; no peer credentials found in \
                             connection context"
                        .into(),
                }
            })?;

            let uid_key = cred.uid.to_string();

            // Look up the UID in the principal map.
            if let Some(entry) = self.config.principals.get(&uid_key) {
                return Ok(VerifiedIdentity {
                    principal: entry.principal.clone(),
                    max_scopes: entry.scopes.clone(),
                    identity_method: "peercred",
                    owner: entry.owner.clone(),
                });
            }

            // UID is not in the map.
            if self.config.allow_unmapped {
                // Dev mode: synthetic principal with unrestricted scopes.
                warn!(
                    uid = cred.uid,
                    gid = cred.gid,
                    pid = ?cred.pid,
                    "peercred: unmapped UID allowed (allow_unmapped=true); \
                     using synthetic principal — NOT FOR PRODUCTION"
                );
                return Ok(VerifiedIdentity {
                    principal: format!("uid:{}", cred.uid),
                    max_scopes: vec![], // unrestricted
                    identity_method: "peercred:unmapped",
                    owner: None,
                });
            }

            // Fail-closed: unknown UID.
            warn!(
                uid = cred.uid,
                gid = cred.gid,
                pid = ?cred.pid,
                "peercred: UID not in principal map and allow_unmapped=false — denying"
            );
            Err(IdentityError::Forbidden {
                reason: format!(
                    "Unix UID {} is not in the peercred principal map; \
                     add an entry to [identity.peercred.principals] in latchgate.toml",
                    cred.uid
                ),
            })
        })
    }
}

/// Extract `PeerCred` from a `tokio::net::UnixStream`.
///
/// Called by the UDS listener after accepting a connection, before the
/// stream is handed to axum. The result is attached to requests as a
/// `ConnectionContext` extension.
///
/// # Platform notes
///
/// - **Linux**: uses `UCred` from `tokio::net::unix::UCred` (wraps `SO_PEERCRED`).
/// - **macOS**: uid/gid from `peer_cred()`, pid not available.
/// - **Other Unix**: may not support peer creds; returns `None`.
#[cfg(unix)]
pub fn extract_peer_cred(stream: &tokio::net::UnixStream) -> Option<PeerCred> {
    match stream.peer_cred() {
        Ok(cred) => Some(PeerCred {
            uid: cred.uid(),
            gid: cred.gid(),
            pid: cred.pid().map(|p| p as u32),
        }),
        Err(e) => {
            warn!(error = %e, "failed to extract SO_PEERCRED from UDS connection");
            None
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use super::super::PeercredPrincipal;

    fn test_config() -> PeercredConfig {
        PeercredConfig {
            principals: HashMap::from([
                (
                    "1001".to_string(),
                    PeercredPrincipal {
                        principal: "agent-jira".to_string(),
                        scopes: vec!["tools:call".into()],
                        owner: Some("alice@company.com".to_string()),
                    },
                ),
                (
                    "1002".to_string(),
                    PeercredPrincipal {
                        principal: "agent-email".to_string(),
                        scopes: vec!["tools:call".into(), "email:send".into()],
                        owner: Some("bob@company.com".to_string()),
                    },
                ),
                (
                    "0".to_string(),
                    PeercredPrincipal {
                        principal: "root-operator".to_string(),
                        scopes: vec!["tools:call".into(), "audit:read".into()],
                        owner: None,
                    },
                ),
            ]),
            allow_unmapped: false,
        }
    }

    fn ctx_with_uid(uid: u32) -> ConnectionContext {
        ConnectionContext {
            peer_cred: Some(PeerCred {
                uid,
                gid: uid,
                pid: Some(12345),
            }),
            bearer_token: None,
            client_cert_fingerprint: None,
        }
    }

    // -- Happy path --

    #[tokio::test]
    async fn mapped_uid_returns_correct_principal() {
        let provider = PeerCredProvider::new(test_config());
        let identity = provider.authenticate(&ctx_with_uid(1001)).await.unwrap();
        assert_eq!(identity.principal, "agent-jira");
        assert_eq!(identity.max_scopes, vec!["tools:call"]);
        assert_eq!(identity.identity_method, "peercred");
    }

    #[tokio::test]
    async fn mapped_uid_with_multiple_scopes() {
        let provider = PeerCredProvider::new(test_config());
        let identity = provider.authenticate(&ctx_with_uid(1002)).await.unwrap();
        assert_eq!(identity.principal, "agent-email");
        assert_eq!(identity.max_scopes, vec!["tools:call", "email:send"]);
    }

    #[tokio::test]
    async fn root_uid_maps_correctly() {
        let provider = PeerCredProvider::new(test_config());
        let identity = provider.authenticate(&ctx_with_uid(0)).await.unwrap();
        assert_eq!(identity.principal, "root-operator");
    }

    // -- Owner propagation --

    #[tokio::test]
    async fn owner_propagated_from_config() {
        let provider = PeerCredProvider::new(test_config());
        let identity = provider.authenticate(&ctx_with_uid(1001)).await.unwrap();
        assert_eq!(
            identity.owner.as_deref(),
            Some("alice@company.com"),
            "owner must propagate from PeercredPrincipal to VerifiedIdentity"
        );
    }

    #[tokio::test]
    async fn owner_none_when_not_configured() {
        let provider = PeerCredProvider::new(test_config());
        // UID 0 (root-operator) has owner: None in test_config.
        let identity = provider.authenticate(&ctx_with_uid(0)).await.unwrap();
        assert!(
            identity.owner.is_none(),
            "owner must be None when not configured in PeercredPrincipal"
        );
    }

    #[tokio::test]
    async fn owner_none_for_unmapped_uid() {
        let mut config = test_config();
        config.allow_unmapped = true;
        let provider = PeerCredProvider::new(config);
        let identity = provider.authenticate(&ctx_with_uid(9999)).await.unwrap();
        assert!(
            identity.owner.is_none(),
            "unmapped UIDs cannot have an owner"
        );
    }

    // -- Fail-closed: unmapped UID --

    #[tokio::test]
    async fn unmapped_uid_denied_when_allow_unmapped_false() {
        let provider = PeerCredProvider::new(test_config());
        let result = provider.authenticate(&ctx_with_uid(9999)).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, IdentityError::Forbidden { .. }),
            "unmapped UID must produce Forbidden, got: {err}"
        );
    }

    #[tokio::test]
    async fn unmapped_uid_allowed_in_dev_mode() {
        let mut config = test_config();
        config.allow_unmapped = true;
        let provider = PeerCredProvider::new(config);
        let identity = provider.authenticate(&ctx_with_uid(9999)).await.unwrap();
        assert_eq!(identity.principal, "uid:9999");
        assert!(identity.max_scopes.is_empty(), "unmapped = unrestricted");
        assert_eq!(identity.identity_method, "peercred:unmapped");
    }

    // -- Fail-closed: no peer creds --

    #[tokio::test]
    async fn no_peer_creds_returns_unauthenticated() {
        let provider = PeerCredProvider::new(test_config());
        let ctx = ConnectionContext::default();
        let result = provider.authenticate(&ctx).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            IdentityError::Unauthenticated { .. }
        ));
    }

    // -- Empty principal map --

    #[tokio::test]
    async fn empty_principal_map_denies_all() {
        let config = PeercredConfig {
            principals: HashMap::new(),
            allow_unmapped: false,
        };
        let provider = PeerCredProvider::new(config);
        let result = provider.authenticate(&ctx_with_uid(1001)).await;
        assert!(matches!(
            result.unwrap_err(),
            IdentityError::Forbidden { .. }
        ));
    }

    // -- extract_peer_cred with real UDS --

    #[tokio::test]
    async fn extract_peer_cred_from_real_uds() {
        let dir = std::env::temp_dir().join(format!(
            "latchgate-peercred-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let sock_path = dir.join("test.sock");

        let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();

        // Spawn a client that connects.
        let path = sock_path.clone();
        let client_handle = tokio::spawn(async move {
            let _stream = tokio::net::UnixStream::connect(&path).await.unwrap();
            // Keep alive briefly.
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });

        let (stream, _addr) = listener.accept().await.unwrap();
        let cred = extract_peer_cred(&stream);
        assert!(cred.is_some(), "must extract peer creds from real UDS");

        let cred = cred.unwrap();
        // The connecting process is this test — uid should be non-zero
        // (unless running as root, which is uncommon in test environments).
        // More importantly, uid and gid must be plausible values.
        assert!(
            cred.uid < 65535 || cred.uid == u32::MAX,
            "peer UID must be a plausible value, got {}",
            cred.uid,
        );

        client_handle.await.unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }
}
