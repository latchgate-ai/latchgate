//! Background scanner that detects expired pending approvals and emits
//! `approval.expired` domain events.
//!
//! Runs as a spawned tokio task. Polls `ApprovalStore::list_approvals` every
//! `SCAN_INTERVAL` and fires a domain event for each newly-expired approval.
//! A `HashSet` of emitted IDs prevents duplicate notifications.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tracing::{debug, warn};

use latchgate_kernel::ops::approvals::ApprovalState;
use latchgate_kernel::AppState;

/// Scan interval. 30 seconds balances timeliness against Redis load.
const SCAN_INTERVAL: Duration = Duration::from_secs(30);

/// Maximum pending approvals to scan per cycle.
const SCAN_LIMIT: usize = 200;

/// Start the expiry scanner as a background task.
///
/// Returns a `JoinHandle` that runs until the process shuts down.
/// The task is purely advisory — panics or errors are logged, never
/// propagated. Webhook delivery failures are handled by the dispatcher.
pub fn spawn_expiry_scanner(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut emitted: HashSet<String> = HashSet::new();

        loop {
            tokio::time::sleep(SCAN_INTERVAL).await;
            scan_once(&state, &mut emitted).await;
        }
    })
}

/// Single scan cycle. Separated for testability.
async fn scan_once(state: &AppState, emitted: &mut HashSet<String>) {
    let approvals = match latchgate_kernel::ops::approvals::list_approvals(
        state,
        Some(ApprovalState::Pending),
        SCAN_LIMIT,
    )
    .await
    {
        Ok(list) => list,
        Err(e) => {
            warn!(error = %e, "expiry scanner: failed to list pending approvals");
            return;
        }
    };

    let now = Utc::now();

    for summary in &approvals {
        if emitted.contains(&summary.approval_id) {
            continue;
        }

        let expires_at = match chrono::DateTime::parse_from_rfc3339(&summary.expires_at) {
            Ok(dt) => dt.with_timezone(&Utc),
            Err(_) => {
                debug!(
                    approval_id = %summary.approval_id,
                    expires_at = %summary.expires_at,
                    "expiry scanner: unparseable expires_at — skipping"
                );
                continue;
            }
        };

        if now >= expires_at {
            state.emit(latchgate_core::DomainEvent::ApprovalExpired {
                approval_id: Arc::from(summary.approval_id.as_str()),
                action_id: Arc::clone(&summary.action_id),
                principal: Arc::clone(&summary.principal),
                owner: summary.owner.clone(),
                created_at: Arc::from(summary.created_at.as_str()),
                expired_at: Arc::from(summary.expires_at.as_str()),
            });
            emitted.insert(summary.approval_id.clone());
            debug!(
                approval_id = %summary.approval_id,
                action_id = %summary.action_id,
                "expiry scanner: emitted approval.expired event"
            );
        }
    }

    // Prune emitted set: remove IDs no longer in the pending list.
    let current_ids: HashSet<&str> = approvals.iter().map(|s| s.approval_id.as_str()).collect();
    emitted.retain(|id| current_ids.contains(id.as_str()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn scan_with_no_pending_approvals_succeeds() {
        let state = crate::test_support::test_state();
        let mut emitted = HashSet::new();
        scan_once(&state, &mut emitted).await;
        assert!(emitted.is_empty());
    }

    #[tokio::test]
    async fn emitted_set_is_pruned_when_approval_disappears() {
        let state = crate::test_support::test_state();
        let mut emitted = HashSet::new();
        emitted.insert("apr_gone".into());
        emitted.insert("apr_also_gone".into());
        scan_once(&state, &mut emitted).await;
        assert!(emitted.is_empty());
    }
}
