//! Redis backend for the approval store.
//!
//! State transitions use Lua scripts for atomicity — no GET+SET from Rust.

use std::collections::HashMap;

use tracing::warn;

use crate::approval_types::*;
use crate::approvals::ApprovalStore;

// Key formatting

const KEY_PREFIX: &str = "latch:approval:";

pub(crate) fn approval_key(approval_id: &str) -> String {
    format!("{KEY_PREFIX}{approval_id}")
}

/// Reconstruct an `ApprovalRecord` from flat Redis HASH fields.
fn record_from_hash(
    state: ApprovalState,
    payload: PendingApproval,
    fields: &HashMap<String, String>,
) -> ApprovalRecord {
    let claim = match (fields.get("claimed_by"), fields.get("claimed_at")) {
        (Some(by), Some(at)) => Some(ClaimInfo {
            claimed_by: by.clone(),
            claimed_at: at.clone(),
            // Omit sensitive token in read paths.
            claim_token: String::new(),
            claim_expires_at_unix: fields
                .get("claim_expires_at_unix")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
        }),
        _ => None,
    };

    let outcome_marker = match (
        fields.get("terminal_outcome_kind"),
        fields.get("terminal_outcome_at"),
        fields.get("terminal_outcome_detail"),
    ) {
        (Some(kind), Some(at), Some(detail)) => Some(OutcomeMarker {
            kind: kind.clone(),
            at: at.clone(),
            detail: detail.clone(),
        }),
        _ => None,
    };

    let completion = fields
        .get("completed_at")
        .map(|completed_at| CompletionInfo {
            completed_at: completed_at.clone(),
            trace_id: fields.get("terminal_trace_id").cloned().unwrap_or_default(),
            receipt_id: fields.get("receipt_id").cloned(),
            deny_reason: fields.get("deny_reason").cloned(),
            error_code: fields.get("error_code").cloned(),
        });

    ApprovalRecord {
        state,
        payload,
        claim,
        outcome_marker,
        completion,
    }
}

// Lua scripts

/// Atomic create: set HASH fields + EXPIRE in a single Lua evaluation.
///
/// KEYS[1] = approval hash key
/// ARGV[1] = state string ("pending")
/// ARGV[2] = payload JSON string (raw, never parsed by Lua)
/// ARGV[3] = TTL in seconds
///
/// Returns: "OK"
const LUA_CREATE: &str = r#"
local key = KEYS[1]
if redis.call('EXISTS', key) == 1 then
    return redis.error_reply('ALREADY_EXISTS')
end
redis.call('HSET', key, 'state', ARGV[1], 'payload', ARGV[2])
redis.call('EXPIRE', key, tonumber(ARGV[3]))
return 'OK'
"#;

/// Atomic claim: Pending => Claimed (or re-claim on expired claim).
///
/// Uses Redis HASH. The `payload` field is a raw JSON string that the Lua
/// script never decodes — avoiding cjson precision issues with large numbers.
///
/// KEYS[1] = approval hash key
/// ARGV[1] = operator_id
/// ARGV[2] = claim_token (UUID)
/// ARGV[3] = claim_ttl_secs
/// ARGV[4] = now_unix (seconds)
/// ARGV[5] = claimed_at (ISO 8601)
///
/// Returns: payload JSON string on success.
/// Errors:  NOT_FOUND | ALREADY_CLAIMED | ALREADY_COMPLETED
const LUA_CLAIM: &str = r#"
local key = KEYS[1]
local state = redis.call('HGET', key, 'state')
if not state then
    return redis.error_reply('NOT_FOUND')
end

-- SECURITY (02): check durable outcome marker BEFORE any state logic.
-- If present, this approval has already been executed/denied/failed,
-- even if the main state is still 'claimed' (partial completion failure).
-- This is the primary defense against double-execution.
local outcome = redis.call('HGET', key, 'terminal_outcome_kind')
if outcome then
    return redis.error_reply('ALREADY_COMPLETED')
end

local now = tonumber(ARGV[4])

if state == 'pending' then
    -- ok
elseif state == 'claimed' then
    local expires = tonumber(redis.call('HGET', key, 'claim_expires_at_unix'))
    if expires and now < expires then
        return redis.error_reply('ALREADY_CLAIMED')
    end
    -- Expired claim: allow re-claim (crash recovery)
elseif state == 'approved' or state == 'denied' or state == 'failed' then
    return redis.error_reply('ALREADY_COMPLETED')
else
    return redis.error_reply('ALREADY_COMPLETED')
end

redis.call('HSET', key,
    'state', 'claimed',
    'claimed_by', ARGV[1],
    'claimed_at', ARGV[5],
    'claim_token', ARGV[2],
    'claim_expires_at_unix', tostring(now + tonumber(ARGV[3])))

return redis.call('HGET', key, 'payload')
"#;

/// Atomic complete: Claimed => terminal state (Approved or Denied).
///
/// KEYS[1] = approval hash key
/// ARGV[1] = expected claim_token
/// ARGV[2] = terminal_state ("approved" or "denied" or "failed")
/// ARGV[3] = terminal_trace_id
/// ARGV[4] = completed_at (ISO 8601)
/// ARGV[5] = forensics_ttl_secs
/// ARGV[6] = terminal_detail_key (e.g. "receipt_id", "deny_reason", "error_code")
/// ARGV[7] = terminal_detail_value
///
/// Returns: "OK" on success.
/// Errors:  NOT_FOUND | NOT_CLAIMED | TOKEN_MISMATCH | ALREADY_COMPLETED
const LUA_COMPLETE: &str = r#"
local key = KEYS[1]
local state = redis.call('HGET', key, 'state')
if not state then
    return redis.error_reply('NOT_FOUND')
end

if state ~= 'claimed' then
    if state == 'approved' or state == 'denied' or state == 'failed' then
        return redis.error_reply('ALREADY_COMPLETED')
    end
    return redis.error_reply('NOT_CLAIMED')
end

local stored_token = redis.call('HGET', key, 'claim_token')
if stored_token ~= ARGV[1] then
    return redis.error_reply('TOKEN_MISMATCH')
end

redis.call('HSET', key,
    'state', ARGV[2],
    'completed_at', ARGV[4],
    'terminal_trace_id', ARGV[3])

if ARGV[6] ~= '' and ARGV[7] ~= '' then
    redis.call('HSET', key, ARGV[6], ARGV[7])
end

redis.call('EXPIRE', key, tonumber(ARGV[5]))
return 'OK'
"#;

/// Atomic durable outcome marker write.
///
/// SECURITY (02): written AFTER the side effect occurs but BEFORE the
/// terminal state transition. Once this marker exists in the Redis hash,
/// `LUA_CLAIM` will reject any re-claim attempt — even if the main `state`
/// field is still `claimed` because `LUA_COMPLETE` failed.
///
/// This script is idempotent: if the marker already exists, it returns OK
/// without modification. This allows safe retry after transient failures.
///
/// KEYS[1] = approval hash key
/// ARGV[1] = expected claim_token
/// ARGV[2] = outcome_kind ("approved", "denied", "failed")
/// ARGV[3] = outcome_detail (receipt_id / deny_reason / error_code)
/// ARGV[4] = outcome_at (ISO 8601 timestamp)
///
/// Returns: "OK" on success.
/// Errors:  NOT_FOUND | NOT_CLAIMED | TOKEN_MISMATCH | ALREADY_COMPLETED
const LUA_WRITE_OUTCOME: &str = r#"
local key = KEYS[1]
local state = redis.call('HGET', key, 'state')
if not state then
    return redis.error_reply('NOT_FOUND')
end

-- Idempotent: if outcome marker already written, succeed silently.
local existing = redis.call('HGET', key, 'terminal_outcome_kind')
if existing then
    return 'OK'
end

-- Must be in claimed state (not already transitioned to terminal).
if state ~= 'claimed' then
    if state == 'approved' or state == 'denied' or state == 'failed' then
        return redis.error_reply('ALREADY_COMPLETED')
    end
    return redis.error_reply('NOT_CLAIMED')
end

-- Verify claim ownership.
local stored_token = redis.call('HGET', key, 'claim_token')
if stored_token ~= ARGV[1] then
    return redis.error_reply('TOKEN_MISMATCH')
end

-- Write the durable outcome marker. This is the critical invariant:
-- once these fields exist, LUA_CLAIM rejects all re-claim attempts.
redis.call('HSET', key,
    'terminal_outcome_kind', ARGV[2],
    'terminal_outcome_at', ARGV[4],
    'terminal_outcome_detail', ARGV[3])

return 'OK'
"#;

impl ApprovalStore {
    pub(crate) async fn redis_create(
        &self,
        client: &redis::Client,
        record: &ApprovalRecord,
    ) -> Result<(), ApprovalError> {
        let key = approval_key(&record.payload.approval_id);
        let payload_json = serde_json::to_string(&record.payload)
            .map_err(|e| ApprovalError::DataCorrupted(e.to_string()))?;
        let state_str = record.state.as_str();
        let ttl_secs = self.default_ttl.as_secs().max(1) as i64;
        let mut conn = self.redis_conn(client).await?;

        // Atomic: HSET + EXPIRE in a single Lua evaluation.
        // If the process crashes between these two operations in plain Redis
        // commands, the key lives forever without TTL. The Lua script ensures
        // both happen or neither does.
        let _: String = redis::cmd("EVAL")
            .arg(LUA_CREATE)
            .arg(1)
            .arg(&key)
            .arg(state_str)
            .arg(&payload_json)
            .arg(ttl_secs)
            .query_async(&mut conn)
            .await
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("ALREADY_EXISTS") {
                    return ApprovalError::AlreadyExists {
                        approval_id: record.payload.approval_id.clone(),
                    };
                }
                warn!(approval_id = %record.payload.approval_id, error = %e, "create_pending failed");
                ApprovalError::Unavailable(msg)
            })?;

        Ok(())
    }

    pub(crate) async fn redis_get_record(
        &self,
        client: &redis::Client,
        approval_id: &str,
    ) -> Result<Option<ApprovalRecord>, ApprovalError> {
        let key = approval_key(approval_id);
        let mut conn = self.redis_conn(client).await?;

        let result: HashMap<String, String> = redis::cmd("HGETALL")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .map_err(|e| {
                warn!(approval_id, error = %e, "get_record failed");
                ApprovalError::Unavailable(e.to_string())
            })?;

        if result.is_empty() {
            return Ok(None);
        }

        let state_str = result
            .get("state")
            .ok_or_else(|| ApprovalError::DataCorrupted("missing state field".into()))?;
        let state = ApprovalState::from_db_str(state_str.as_str())
            .ok_or_else(|| ApprovalError::DataCorrupted(format!("unknown state: {state_str}")))?;

        let payload_json = result
            .get("payload")
            .ok_or_else(|| ApprovalError::DataCorrupted("missing payload field".into()))?;
        let payload: PendingApproval = serde_json::from_str(payload_json)
            .map_err(|e| ApprovalError::DataCorrupted(e.to_string()))?;

        Ok(Some(record_from_hash(state, payload, &result)))
    }

    /// Retrieve a pending approval without deserializing the full record.
    ///
    /// Uses `HMGET` to fetch only the `state` and `payload` fields — avoids
    /// the overhead of `HGETALL` (which returns claim, outcome-marker, and
    /// completion fields that are irrelevant for a pending-only read).
    ///
    /// Returns `Ok(None)` if the key does not exist, has expired, or is in
    /// any non-pending state. This is consistent with the InMemory and SQLite
    /// backends which push the state filter into the store.
    pub(crate) async fn redis_get_pending(
        &self,
        client: &redis::Client,
        approval_id: &str,
    ) -> Result<Option<PendingApproval>, ApprovalError> {
        let key = approval_key(approval_id);
        let mut conn = self.redis_conn(client).await?;

        let (state_opt, payload_opt): (Option<String>, Option<String>) = redis::cmd("HMGET")
            .arg(&key)
            .arg("state")
            .arg("payload")
            .query_async(&mut conn)
            .await
            .map_err(|e| {
                warn!(approval_id, error = %e, "get_pending failed");
                ApprovalError::Unavailable(e.to_string())
            })?;

        // Key absent or expired — both fields will be None.
        let (Some(state_str), Some(payload_json)) = (state_opt, payload_opt) else {
            return Ok(None);
        };

        // Only return payload for pending approvals.
        if state_str != "pending" {
            return Ok(None);
        }

        let payload: PendingApproval = serde_json::from_str(&payload_json)
            .map_err(|e| ApprovalError::DataCorrupted(e.to_string()))?;

        Ok(Some(payload))
    }

    /// Retrieve the approval payload regardless of lifecycle state.
    ///
    /// Unlike [`redis_get_pending`](Self::redis_get_pending), this does not
    /// filter by state — the payload is returned for pending, claimed,
    /// approved, denied, and failed records alike.
    pub(crate) async fn redis_get_payload(
        &self,
        client: &redis::Client,
        approval_id: &str,
    ) -> Result<Option<PendingApproval>, ApprovalError> {
        let key = approval_key(approval_id);
        let mut conn = self.redis_conn(client).await?;

        let payload_opt: Option<String> = redis::cmd("HGET")
            .arg(&key)
            .arg("payload")
            .query_async(&mut conn)
            .await
            .map_err(|e| {
                warn!(approval_id, error = %e, "get_payload failed");
                ApprovalError::Unavailable(e.to_string())
            })?;

        let Some(payload_json) = payload_opt else {
            return Ok(None);
        };

        let payload: PendingApproval = serde_json::from_str(&payload_json)
            .map_err(|e| ApprovalError::DataCorrupted(e.to_string()))?;

        Ok(Some(payload))
    }

    /// List approvals via Redis SCAN + pipelined HGETALL.
    ///
    /// SCAN is non-blocking (cursor-based) and avoids the O(N) `KEYS`
    /// command. Each batch of matched keys is fetched in a single pipeline
    /// round-trip. Corrupted or expired-between-scan-and-fetch records
    /// are skipped with a warning — one bad record must not block the
    /// entire list operation.
    ///
    /// Iteration is bounded by `MAX_SCAN_ITERATIONS` to prevent long
    /// tail latency on keyspaces with many expired-but-not-yet-purged keys.
    pub(crate) async fn redis_list_approvals(
        &self,
        client: &redis::Client,
        state_filter: Option<ApprovalState>,
        limit: usize,
    ) -> Result<Vec<ApprovalSummary>, ApprovalError> {
        let mut conn = self.redis_conn(client).await?;
        let mut summaries = Vec::new();
        let mut cursor: u64 = 0;
        let scan_pattern = format!("{KEY_PREFIX}*");

        // Bounds: 50 iterations × COUNT 100 = up to ~5 000 keys examined.
        // Under normal operation (TTL-bounded pending + forensics), total
        // key count is far below this. If the limit is reached, results
        // are partial — acceptable for a list view.
        const MAX_SCAN_ITERATIONS: usize = 50;
        const SCAN_BATCH_SIZE: usize = 100;

        for _ in 0..MAX_SCAN_ITERATIONS {
            let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&scan_pattern)
                .arg("COUNT")
                .arg(SCAN_BATCH_SIZE)
                .query_async(&mut conn)
                .await
                .map_err(|e| ApprovalError::Unavailable(e.to_string()))?;

            if !keys.is_empty() {
                // Pipeline: HGETALL for each key in this SCAN batch.
                let mut pipe = redis::pipe();
                for key in &keys {
                    pipe.cmd("HGETALL").arg(key);
                }
                let batch: Vec<HashMap<String, String>> = pipe
                    .query_async(&mut conn)
                    .await
                    .map_err(|e| ApprovalError::Unavailable(e.to_string()))?;

                for (key, fields) in keys.iter().zip(batch.into_iter()) {
                    if fields.is_empty() {
                        // Key expired between SCAN and HGETALL — normal.
                        continue;
                    }

                    let state = match fields
                        .get("state")
                        .and_then(|s| ApprovalState::from_db_str(s))
                    {
                        Some(s) => s,
                        None => continue,
                    };

                    if let Some(filter) = state_filter {
                        if state != filter {
                            continue;
                        }
                    }

                    let payload_json = match fields.get("payload") {
                        Some(p) => p,
                        None => continue,
                    };

                    let pending: PendingApproval = match serde_json::from_str(payload_json) {
                        Ok(p) => p,
                        Err(e) => {
                            warn!(
                                key = %key,
                                error = %e,
                                "list: skipping corrupted approval record"
                            );
                            continue;
                        }
                    };

                    let record = record_from_hash(state, pending, &fields);
                    summaries.push(record.to_summary());
                }
            }

            cursor = next_cursor;
            if cursor == 0 {
                break; // full iteration complete
            }
        }

        summaries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        summaries.truncate(limit);
        Ok(summaries)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn redis_claim(
        &self,
        client: &redis::Client,
        approval_id: &str,
        operator_id: &str,
        claim_token: &str,
        claim_ttl_secs: u64,
        now_unix: i64,
        claimed_at: &str,
    ) -> Result<ClaimedApproval, ApprovalError> {
        let key = approval_key(approval_id);
        let mut conn = self.redis_conn(client).await?;

        // Lua script returns the raw payload JSON string (never cjson-parsed).
        let result: Result<String, redis::RedisError> = redis::cmd("EVAL")
            .arg(LUA_CLAIM)
            .arg(1)
            .arg(&key)
            .arg(operator_id)
            .arg(claim_token)
            .arg(claim_ttl_secs)
            .arg(now_unix)
            .arg(claimed_at)
            .query_async(&mut conn)
            .await;

        match result {
            Ok(payload_json) => {
                let pending: PendingApproval = serde_json::from_str(&payload_json)
                    .map_err(|e| ApprovalError::DataCorrupted(e.to_string()))?;
                Ok(ClaimedApproval {
                    pending,
                    claim_token: claim_token.to_string(),
                    claimed_at: claimed_at.to_string(),
                    claimed_by: operator_id.to_string(),
                })
            }
            Err(e) => Err(Self::map_lua_error(approval_id, e)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn redis_complete(
        &self,
        client: &redis::Client,
        approval_id: &str,
        claim_token: &str,
        terminal_state: &str,
        trace_id: &str,
        completed_at: &str,
        forensics_ttl_secs: u64,
        detail_key: &str,
        detail_value: &str,
    ) -> Result<(), ApprovalError> {
        let key = approval_key(approval_id);
        let mut conn = self.redis_conn(client).await?;

        let result: Result<String, redis::RedisError> = redis::cmd("EVAL")
            .arg(LUA_COMPLETE)
            .arg(1)
            .arg(&key)
            .arg(claim_token)
            .arg(terminal_state)
            .arg(trace_id)
            .arg(completed_at)
            .arg(forensics_ttl_secs)
            .arg(detail_key)
            .arg(detail_value)
            .query_async(&mut conn)
            .await;

        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(Self::map_lua_error(approval_id, e)),
        }
    }

    /// Write durable outcome marker via Lua script.
    ///
    /// SECURITY (02): this is the Redis-backed implementation of the outcome
    /// marker write. The Lua script is atomic (single EVAL) and idempotent.
    pub(crate) async fn redis_write_outcome(
        &self,
        client: &redis::Client,
        approval_id: &str,
        claim_token: &str,
        outcome_kind: &str,
        outcome_detail: &str,
        outcome_at: &str,
    ) -> Result<(), ApprovalError> {
        let key = approval_key(approval_id);
        let mut conn = self.redis_conn(client).await?;

        let result: Result<String, redis::RedisError> = redis::cmd("EVAL")
            .arg(LUA_WRITE_OUTCOME)
            .arg(1)
            .arg(&key)
            .arg(claim_token)
            .arg(outcome_kind)
            .arg(outcome_detail)
            .arg(outcome_at)
            .query_async(&mut conn)
            .await;

        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(Self::map_lua_error(approval_id, e)),
        }
    }
    fn map_lua_error(approval_id: &str, e: redis::RedisError) -> ApprovalError {
        let msg = e.to_string();
        if msg.contains("NOT_FOUND") {
            ApprovalError::NotFound {
                approval_id: approval_id.to_string(),
            }
        } else if msg.contains("ALREADY_CLAIMED") {
            ApprovalError::AlreadyClaimed {
                approval_id: approval_id.to_string(),
            }
        } else if msg.contains("ALREADY_COMPLETED") {
            ApprovalError::AlreadyCompleted {
                approval_id: approval_id.to_string(),
            }
        } else if msg.contains("NOT_CLAIMED") {
            ApprovalError::NotClaimed {
                approval_id: approval_id.to_string(),
            }
        } else if msg.contains("TOKEN_MISMATCH") {
            ApprovalError::TokenMismatch {
                approval_id: approval_id.to_string(),
            }
        } else {
            ApprovalError::Unavailable(msg)
        }
    }

    pub(crate) async fn redis_conn(
        &self,
        client: &redis::Client,
    ) -> Result<redis::aio::MultiplexedConnection, ApprovalError> {
        client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                warn!(error = %e, "approval store: failed to connect to Redis");
                ApprovalError::Unavailable(e.to_string())
            })
    }
}

// Contract tests — Redis backend

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::approval_contract_tests as contract;
    use crate::approvals::ApprovalStore;

    // Helpers

    fn redis_url() -> String {
        std::env::var("LATCHGATE_REDIS_URL")
            .unwrap_or_else(|_| "redis://:changeme@127.0.0.1:6379".to_string())
    }

    fn redis_available() -> bool {
        std::net::TcpStream::connect_timeout(
            &"127.0.0.1:6379".parse().unwrap(),
            std::time::Duration::from_millis(200),
        )
        .is_ok()
    }

    fn store() -> ApprovalStore {
        ApprovalStore::new(&redis_url(), Duration::from_secs(300)).unwrap()
    }

    fn store_short_claim() -> ApprovalStore {
        ApprovalStore {
            claim_ttl_secs: 1,
            ..store()
        }
    }

    /// Run a contract test, skipping gracefully if Redis is unreachable.
    macro_rules! redis_contract {
        ($name:ident, $store_fn:ident) => {
            #[tokio::test]
            async fn $name() {
                if !redis_available() {
                    eprintln!(
                        "skipping {}: Redis not available on 127.0.0.1:6379",
                        stringify!($name)
                    );
                    return;
                }
                contract::$name(&$store_fn()).await;
            }
        };
    }

    // Contract tests (standard store)

    redis_contract!(create_and_get, store);
    redis_contract!(get_nonexistent_returns_none, store);
    redis_contract!(create_duplicate_returns_already_exists, store);
    redis_contract!(full_approve_lifecycle, store);
    redis_contract!(full_deny_lifecycle, store);
    redis_contract!(full_failed_lifecycle, store);
    redis_contract!(double_claim_rejected, store);
    redis_contract!(terminal_state_blocks_reclaim, store);
    redis_contract!(wrong_claim_token_rejected, store);
    redis_contract!(outcome_marker_is_idempotent, store);
    redis_contract!(outcome_marker_rejects_wrong_token, store);
    redis_contract!(outcome_marker_rejects_unclaimed, store);
    redis_contract!(get_status_synthesizes_from_outcome_marker, store);
    redis_contract!(complete_after_outcome_marker, store);
    redis_contract!(list_returns_all, store);
    redis_contract!(list_filters_by_state, store);
    redis_contract!(list_respects_limit, store);
    redis_contract!(plan_hash_survives_roundtrip, store);
    redis_contract!(unresolved_domains_survive_roundtrip, store);
    redis_contract!(unresolved_paths_survive_roundtrip, store);

    // Contract tests (short claim TTL — needed for expiry/reclaim tests)

    redis_contract!(expired_claim_can_be_reclaimed, store_short_claim);
    redis_contract!(outcome_marker_blocks_reclaim, store_short_claim);
}
