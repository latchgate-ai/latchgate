//! In-memory backend for the approval store.
//!
//! Used exclusively in tests. Provides the same state-machine guarantees
//! as the Redis backend (single-claim, outcome-marker blocking, TTL expiry)
//! via `RwLock` serialization instead of Lua scripts.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::RwLock;

use crate::approval_types::*;
use crate::approvals::ApprovalStore;

/// Type alias for the in-memory store.
pub(crate) type InMemoryMap = HashMap<String, (ApprovalRecord, Instant)>;
pub(crate) type InMemoryStore = Arc<RwLock<InMemoryMap>>;

impl ApprovalStore {
    // create_pending

    pub(crate) async fn inmemory_create(
        &self,
        store: &InMemoryStore,
        record: &ApprovalRecord,
    ) -> Result<(), ApprovalError> {
        let mut map = store.write().await;
        let id = &record.payload.approval_id;
        if map.contains_key(id) {
            return Err(ApprovalError::AlreadyExists {
                approval_id: id.clone(),
            });
        }
        map.insert(id.clone(), (record.clone(), Instant::now()));
        Ok(())
    }

    // get_pending

    pub(crate) async fn inmemory_get_pending(
        &self,
        store: &InMemoryStore,
        approval_id: &str,
    ) -> Result<Option<PendingApproval>, ApprovalError> {
        let map = store.read().await;
        match map.get(approval_id) {
            Some((record, created)) => {
                if created.elapsed() >= self.default_ttl {
                    Ok(None)
                } else {
                    Ok(Some(record.payload.clone()))
                }
            }
            None => Ok(None),
        }
    }

    // get_record

    pub(crate) async fn inmemory_get_record(
        store: &InMemoryStore,
        approval_id: &str,
    ) -> Option<ApprovalRecord> {
        let map = store.read().await;
        map.get(approval_id).map(|(r, _)| r.clone())
    }

    // list_approvals

    pub(crate) async fn inmemory_list(
        &self,
        store: &InMemoryStore,
        state_filter: Option<ApprovalState>,
        limit: usize,
    ) -> Result<Vec<ApprovalSummary>, ApprovalError> {
        let map = store.read().await;
        let mut summaries = Vec::new();

        for (_, (record, created)) in map.iter() {
            if !record.effective_state().is_terminal() && created.elapsed() >= self.default_ttl {
                continue;
            }

            let summary = record.to_summary();
            if let Some(filter) = state_filter {
                if summary.state != filter {
                    continue;
                }
            }
            summaries.push(summary);
        }

        summaries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        summaries.truncate(limit);
        Ok(summaries)
    }

    // claim_pending

    pub(crate) async fn inmemory_claim(
        &self,
        store: &InMemoryStore,
        approval_id: &str,
        operator_id: &str,
        claim_token: &str,
        now_millis: i64,
        claimed_at: &str,
    ) -> Result<ClaimedApproval, ApprovalError> {
        let mut map = store.write().await;
        let (record, created) =
            map.get_mut(approval_id)
                .ok_or_else(|| ApprovalError::NotFound {
                    approval_id: approval_id.to_string(),
                })?;

        if created.elapsed() >= self.default_ttl && !record.state.is_terminal() {
            return Err(ApprovalError::NotFound {
                approval_id: approval_id.to_string(),
            });
        }

        validate_claim_transition(
            record.state,
            record.outcome_marker.is_some(),
            record.claim.as_ref().map(|c| c.claim_expires_at_unix),
            now_millis,
            approval_id,
        )?;

        record.state = ApprovalState::Claimed;
        record.claim = Some(ClaimInfo {
            claimed_by: operator_id.to_string(),
            claimed_at: claimed_at.to_string(),
            claim_token: claim_token.to_string(),
            claim_expires_at_unix: now_millis + self.claim_ttl_secs as i64 * 1000,
        });

        Ok(ClaimedApproval {
            pending: record.payload.clone(),
            claim_token: claim_token.to_string(),
            claimed_at: claimed_at.to_string(),
            claimed_by: operator_id.to_string(),
        })
    }

    // write_outcome_marker

    pub(crate) async fn inmemory_write_outcome(
        &self,
        store: &InMemoryStore,
        approval_id: &str,
        claim_token: &str,
        outcome_kind: &str,
        outcome_detail: &str,
        outcome_at: &str,
    ) -> Result<(), ApprovalError> {
        let mut map = store.write().await;
        let (record, _) = map
            .get_mut(approval_id)
            .ok_or_else(|| ApprovalError::NotFound {
                approval_id: approval_id.to_string(),
            })?;

        // Idempotent: if outcome already written, succeed silently.
        if record.outcome_marker.is_some() {
            return Ok(());
        }

        require_claimed_with_token(
            record.state,
            record.claim.as_ref().map(|c| c.claim_token.as_str()),
            claim_token,
            approval_id,
        )?;

        record.outcome_marker = Some(OutcomeMarker {
            kind: outcome_kind.to_string(),
            at: outcome_at.to_string(),
            detail: outcome_detail.to_string(),
        });
        Ok(())
    }

    // complete

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn inmemory_complete(
        &self,
        store: &InMemoryStore,
        approval_id: &str,
        claim_token: &str,
        terminal_state: ApprovalState,
        trace_id: &str,
        completed_at: &str,
        detail_key: &str,
        detail_value: &str,
    ) -> Result<(), ApprovalError> {
        let mut map = store.write().await;
        let (record, _) = map
            .get_mut(approval_id)
            .ok_or_else(|| ApprovalError::NotFound {
                approval_id: approval_id.to_string(),
            })?;

        require_claimed_with_token(
            record.state,
            record.claim.as_ref().map(|c| c.claim_token.as_str()),
            claim_token,
            approval_id,
        )?;

        record.state = terminal_state;
        record.completion = Some(build_completion_info(
            completed_at,
            trace_id,
            detail_key,
            detail_value,
        ));
        Ok(())
    }
}

// Contract tests — InMemory backend

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::approval_contract_tests as contract;
    use crate::approvals::ApprovalStore;

    fn store() -> ApprovalStore {
        ApprovalStore::in_memory_for_tests(Duration::from_secs(300))
    }

    fn store_short_claim() -> ApprovalStore {
        ApprovalStore {
            claim_ttl_secs: 1,
            ..ApprovalStore::in_memory_for_tests(Duration::from_secs(300))
        }
    }

    #[tokio::test]
    async fn contract_create_and_get() {
        contract::create_and_get(&store()).await;
    }

    #[tokio::test]
    async fn contract_get_nonexistent_returns_none() {
        contract::get_nonexistent_returns_none(&store()).await;
    }

    #[tokio::test]
    async fn contract_create_duplicate_returns_already_exists() {
        contract::create_duplicate_returns_already_exists(&store()).await;
    }

    #[tokio::test]
    async fn contract_full_approve_lifecycle() {
        contract::full_approve_lifecycle(&store()).await;
    }

    #[tokio::test]
    async fn contract_full_deny_lifecycle() {
        contract::full_deny_lifecycle(&store()).await;
    }

    #[tokio::test]
    async fn contract_full_failed_lifecycle() {
        contract::full_failed_lifecycle(&store()).await;
    }

    #[tokio::test]
    async fn contract_double_claim_rejected() {
        contract::double_claim_rejected(&store()).await;
    }

    #[tokio::test]
    async fn contract_terminal_state_blocks_reclaim() {
        contract::terminal_state_blocks_reclaim(&store()).await;
    }

    #[tokio::test]
    async fn contract_wrong_claim_token_rejected() {
        contract::wrong_claim_token_rejected(&store()).await;
    }

    #[tokio::test]
    async fn contract_expired_claim_can_be_reclaimed() {
        contract::expired_claim_can_be_reclaimed(&store_short_claim()).await;
    }

    #[tokio::test]
    async fn contract_outcome_marker_blocks_reclaim() {
        contract::outcome_marker_blocks_reclaim(&store_short_claim()).await;
    }

    #[tokio::test]
    async fn contract_outcome_marker_is_idempotent() {
        contract::outcome_marker_is_idempotent(&store()).await;
    }

    #[tokio::test]
    async fn contract_outcome_marker_rejects_wrong_token() {
        contract::outcome_marker_rejects_wrong_token(&store()).await;
    }

    #[tokio::test]
    async fn contract_outcome_marker_rejects_unclaimed() {
        contract::outcome_marker_rejects_unclaimed(&store()).await;
    }

    #[tokio::test]
    async fn contract_get_status_synthesizes_from_outcome_marker() {
        contract::get_status_synthesizes_from_outcome_marker(&store()).await;
    }

    #[tokio::test]
    async fn contract_complete_after_outcome_marker() {
        contract::complete_after_outcome_marker(&store()).await;
    }

    #[tokio::test]
    async fn contract_list_returns_all() {
        contract::list_returns_all(&store()).await;
    }

    #[tokio::test]
    async fn contract_list_filters_by_state() {
        contract::list_filters_by_state(&store()).await;
    }

    #[tokio::test]
    async fn contract_list_respects_limit() {
        contract::list_respects_limit(&store()).await;
    }

    #[tokio::test]
    async fn contract_plan_hash_survives_roundtrip() {
        contract::plan_hash_survives_roundtrip(&store()).await;
    }

    #[tokio::test]
    async fn contract_unresolved_domains_survive_roundtrip() {
        contract::unresolved_domains_survive_roundtrip(&store()).await;
    }

    #[tokio::test]
    async fn contract_unresolved_paths_survive_roundtrip() {
        contract::unresolved_paths_survive_roundtrip(&store()).await;
    }
}
