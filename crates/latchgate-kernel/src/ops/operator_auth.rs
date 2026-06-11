//! Operator authentication — single implementation for all admin endpoints.
//!
//! Consolidates operator DPoP proof-of-possession verification into one
//! kernel function. The API layer passes extracted header values; no HTTP
//! framework types cross this boundary.

use crate::{AppState, PipelineError};
use latchgate_auth::{AuthError, OperatorAuthContext, OperatorAuthError};

/// Header values extracted by the transport layer for operator auth.
///
/// The kernel stays transport-agnostic — it never imports `axum::HeaderMap`.
/// The API layer extracts these two headers and passes them here.
pub struct OperatorAuthHeaders<'a> {
    pub authorization: Option<&'a str>,
    pub dpop: Option<&'a str>,
}

/// Verify operator authentication using DPoP proof-of-possession.
///
/// SECURITY: all operator credentials require `dpop_jkt` — enforced at
/// startup by `Config::validate_operator_auth()`. Returns operator context
/// on success; maps all failure modes to typed `PipelineError::Auth`
/// variants so the API layer never needs to import auth error types.
pub async fn verify(
    state: &AppState,
    headers: &OperatorAuthHeaders<'_>,
    request_method: &str,
    request_path: &str,
) -> Result<OperatorAuthContext, PipelineError> {
    let htu = format!(
        "{}{}",
        state.config.listener.public_base_url.trim_end_matches('/'),
        request_path
    );

    let credentials = state.config.effective_operator_credentials();

    latchgate_auth::verify_operator_dpop_auth(
        headers.authorization,
        headers.dpop,
        request_method,
        &htu,
        credentials,
        &state.auth.replay_cache,
        &state.auth.dpop_key_cache,
    )
    .await
    .map_err(|e| match e {
        OperatorAuthError::MissingAuthHeader => PipelineError::Auth(AuthError::MissingHeader {
            name: "Authorization".into(),
        }),
        OperatorAuthError::InvalidScheme => PipelineError::Auth(AuthError::InvalidAuthScheme),
        OperatorAuthError::InvalidToken => PipelineError::Auth(AuthError::InvalidOperatorToken),
        OperatorAuthError::MissingDpopHeader => PipelineError::Auth(AuthError::MissingDpopHeader),
        OperatorAuthError::InvalidDpopProof { kind, reason } => {
            PipelineError::Auth(AuthError::InvalidDPoP { kind, reason })
        }
        OperatorAuthError::KeyBindingFailed => PipelineError::Auth(AuthError::KeyBindingFailed {
            deny_reason: "DPoP proof thumbprint does not match configured dpop_jkt".into(),
        }),
        OperatorAuthError::ReplayDetected { jti } => {
            PipelineError::Auth(AuthError::ReplayDetected { jti })
        }
        OperatorAuthError::NotConfigured => PipelineError::ConfigConstraint {
            reason: "operator authentication not configured; approval endpoints disabled",
        },
        OperatorAuthError::ReplayCacheUnavailable => {
            PipelineError::Auth(AuthError::ReplayCacheUnavailable)
        }
    })
}
