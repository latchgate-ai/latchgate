//! Hot-path benchmarks for latency-sensitive per-request operations.
//!
//! Per-request critical paths currently benchmarked:
//!   1. DPoP proof verification (P-256 ECDSA sign + verify round-trip)
//!   2. Policy evaluation (embedded Rego via regorus)
//!   3. WASM module instantiation (per-call cost for short tasks)
//!   4. Lease token issuance (P-256 JWT signing)
//!   5. JSON Schema request validation (pre-compiled validator)
//!   6. File path glob matching (deny-overrides-allow)
//!   7. Ed25519 grant sign + verify (kid-based lookup)
//!   8. Audit event construction (full builder chain)
//!
//! Run: `cargo bench --package latchgate-stress`
//!
//! CI integration: CodSpeed (simulated CPU) on every push to main and
//! every pull request. Regression detection is automatic.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

// ---------------------------------------------------------------------------
// 1. DPoP proof sign + verify round-trip
// ---------------------------------------------------------------------------

fn bench_dpop_sign_verify(c: &mut Criterion) {
    use latchgate_auth::dpop::verify::verify_dpop_proof;
    use latchgate_auth::dpop::{
        compute_ath, compute_jwk_thumbprint, generate_dpop_keypair, sign_dpop_proof,
    };
    use latchgate_auth::DPoPKeyCache;

    let (sk, pk) = generate_dpop_keypair().unwrap();
    let jkt = compute_jwk_thumbprint(&pk.x, &pk.y).unwrap();
    let htm = "POST";
    let htu = "http://localhost:3000/v1/actions/http_get/execute";
    let lease_jwt = "eyJhbGciOiJFUzI1NiJ9.bench-lease-placeholder";
    let ath = compute_ath(lease_jwt);
    let key_cache = DPoPKeyCache::new();

    c.bench_function("dpop_sign_verify_p256", |b| {
        b.iter(|| {
            let jti = format!("bench-{}", nanos_id());
            let proof = sign_dpop_proof(&sk, htm, htu, &ath, &jti).unwrap();
            let result = verify_dpop_proof(&proof, htm, htu, lease_jwt, &jkt, &key_cache);
            black_box(result)
        })
    });
}

// ---------------------------------------------------------------------------
// 1b. DPoP verify-only with warm key cache (server-side hot path)
// ---------------------------------------------------------------------------

fn bench_dpop_verify_cached(c: &mut Criterion) {
    use latchgate_auth::dpop::verify::verify_dpop_proof;
    use latchgate_auth::dpop::{
        compute_ath, compute_jwk_thumbprint, generate_dpop_keypair, sign_dpop_proof,
    };
    use latchgate_auth::DPoPKeyCache;

    let (sk, pk) = generate_dpop_keypair().unwrap();
    let jkt = compute_jwk_thumbprint(&pk.x, &pk.y).unwrap();
    let htm = "POST";
    let htu = "http://localhost:3000/v1/actions/http_get/execute";
    let lease_jwt = "eyJhbGciOiJFUzI1NiJ9.bench-lease-placeholder";
    let ath = compute_ath(lease_jwt);
    let key_cache = DPoPKeyCache::new();

    // Pre-sign a proof and warm the cache with one verify pass.
    // The proof stays valid for IAT_MAX_AGE_SECS (60 s) — well beyond
    // the benchmark duration. Re-verifying the same proof is correct
    // here: jti replay checking is the caller's responsibility (Redis
    // SETNX), not verify_dpop_proof's.
    let proof = sign_dpop_proof(&sk, htm, htu, &ath, "bench-cached-jti").unwrap();
    verify_dpop_proof(&proof, htm, htu, lease_jwt, &jkt, &key_cache).unwrap();
    assert_eq!(key_cache.len(), 1, "cache must be warm before benchmark");

    // Hot loop: verify only, no signing, warm cache.
    // Measures the actual per-request server-side cost:
    //   JWT split + cache hit (hash lookup) + ECDSA verify + payload validate.
    c.bench_function("dpop_verify_cached_p256", |b| {
        b.iter(|| {
            let result =
                verify_dpop_proof(black_box(&proof), htm, htu, lease_jwt, &jkt, &key_cache);
            black_box(result)
        })
    });
}

// ---------------------------------------------------------------------------
// 2. Embedded policy evaluation (regorus)
// ---------------------------------------------------------------------------

fn bench_policy_eval(c: &mut Criterion) {
    use latchgate_core::{BudgetSnapshot, EgressProfile, RiskLevel, TrustVerdict};
    use latchgate_policy::{
        PolicyAction, PolicyClient, PolicyIdentity, PolicyInput, PolicyRequest, PolicyResolution,
    };
    use std::sync::Arc;

    let rego = latchgate_cli::embedded_policies::POLICY_REGO;

    let data_json = serde_json::json!({
        "policy_version": "bench",
        "acl": {
            "*": {
                "allowed_actions": ["http_get"],
                "allowed_sinks": ["http_read"],
            }
        }
    });
    let data_str = serde_json::to_string(&data_json).unwrap();
    let policy = PolicyClient::embedded(rego, Some(&data_str));

    let scopes: Vec<String> = vec!["tools:call".into()];
    let required_scopes: Vec<Arc<str>> = vec!["tools:call".into()];
    let sinks: Vec<Arc<str>> = vec!["http_read".into()];
    let egress = EgressProfile::None;

    let input = PolicyInput {
        identity: PolicyIdentity {
            principal: "bench-principal".into(),
            session_id: "bench-session".into(),
            scopes: &scopes,
            required_scopes: &required_scopes,
        },
        action: PolicyAction {
            action_id: "http_get".into(),
            action_version: "0.1.0",
            action_risk_level: RiskLevel::Low,
            action_trust_verdict: Arc::new(TrustVerdict::DigestOk),
            action_category: "http",
        },
        request: PolicyRequest {
            request_hash: "deadbeef",
            requested_sinks: &sinks,
            requested_secrets: &[],
            egress_profile: &egress,
            provider_context: None,
            fs_path: None,
        },
        budgets_before: BudgetSnapshot {
            calls_remaining: 1000,
        },
        resolution: PolicyResolution::default(),
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    c.bench_function("policy_eval_embedded_rego", |b| {
        b.iter(|| {
            let result = rt.block_on(policy.evaluate(black_box(&input)));
            black_box(result)
        })
    });
}

// ---------------------------------------------------------------------------
// 3. WASM module instantiation
// ---------------------------------------------------------------------------

fn bench_wasm_instantiation(c: &mut Criterion) {
    use latchgate_providers::WasmRuntime;
    use sha2::{Digest, Sha256};

    let runtime = WasmRuntime::new(4).unwrap();

    let wasm_entry: Option<(&str, &[u8])> = latchgate_cli::embedded_providers::PROVIDERS
        .iter()
        .find(|(name, _)| *name == "http_api")
        .map(|(name, bytes)| (*name, *bytes));

    let Some((_name, wasm_bytes)) = wasm_entry else {
        eprintln!(
            "skipping wasm_instantiation bench: no embedded http_api provider. \
             Run `make providers` first."
        );
        return;
    };

    let digest = format!("sha256:{}", hex::encode(Sha256::digest(wasm_bytes)));

    c.bench_function("wasm_precompile_http_api", |b| {
        b.iter(|| {
            let result = runtime.precompile(black_box(wasm_bytes), black_box(&digest));
            black_box(result)
        })
    });
}

// ---------------------------------------------------------------------------
// 4. Lease token issuance (P-256 JWT)
// ---------------------------------------------------------------------------

fn bench_lease_issuance(c: &mut Criterion) {
    use latchgate_auth::issuer::jwt::{generate_keypair, sign_lease, CnfClaim, LeaseClaims};
    use std::time::{SystemTime, UNIX_EPOCH};

    let (signing_key, _) = generate_keypair().unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let claims = LeaseClaims {
        iss: "latchgate".into(),
        sub: "bench-agent".into(),
        aud: "latchgate".into(),
        exp: now + 300,
        nbf: now - 1,
        iat: now,
        jti: "bench-jti-001".into(),
        session_id: "bench-session".into(),
        scope: vec!["tools:call".into()],
        budgets: None,
        cnf: CnfClaim {
            jkt: "bench-thumbprint".into(),
        },
        owner: None,
    };

    c.bench_function("lease_sign_p256_jwt", |b| {
        b.iter(|| black_box(sign_lease(black_box(&claims), &signing_key)))
    });
}

// ---------------------------------------------------------------------------
// 5. JSON Schema request validation
// ---------------------------------------------------------------------------

fn bench_schema_validation(c: &mut Criterion) {
    use latchgate_registry::schema::{compile_schema, validate_request, ValidationLimits};

    let schema = serde_json::json!({
        "type": "object",
        "properties": {
            "url": { "type": "string", "format": "uri" },
            "method": { "type": "string", "enum": ["GET", "POST", "PUT", "DELETE"] },
            "headers": { "type": "object" }
        },
        "required": ["url", "method"]
    });
    let validator = compile_schema(&schema).unwrap();
    let limits = ValidationLimits::default();

    let payload = serde_json::json!({
        "url": "https://api.example.com/data",
        "method": "GET",
        "headers": { "Authorization": "Bearer tok_123" }
    });

    c.bench_function("schema_validate_request", |b| {
        b.iter(|| black_box(validate_request(&validator, black_box(&payload), &limits)))
    });
}

// ---------------------------------------------------------------------------
// 6. File path glob matching (deny-overrides-allow)
// ---------------------------------------------------------------------------

fn bench_path_evaluation(c: &mut Criterion) {
    use latchgate_core::fs_path::{compile_patterns, evaluate_path};
    use std::path::Path;

    let allowed =
        compile_patterns(["/home/user/projects/**", "/tmp/**", "/var/data/*.csv"]).unwrap();

    let denied =
        compile_patterns(["/home/user/projects/.env", "/tmp/secrets/**", "**/.git/**"]).unwrap();

    // Four paths exercising every PathDecision variant:
    //   [0] Allowed  — matches allow, no deny
    //   [1] Denied   — matches both, deny overrides
    //   [2] Allowed  — matches allow, no deny
    //   [3] NotMatched — no allow match
    let paths = [
        Path::new("/home/user/projects/src/main.rs"),
        Path::new("/home/user/projects/.env"),
        Path::new("/tmp/scratch/output.txt"),
        Path::new("/etc/passwd"),
    ];

    c.bench_function("path_evaluate_glob_4_paths", |b| {
        b.iter(|| {
            for p in &paths {
                black_box(evaluate_path(p, &allowed, &denied));
            }
        })
    });
}

// ---------------------------------------------------------------------------
// 7. Ed25519 grant sign + verify (kid-based lookup)
// ---------------------------------------------------------------------------

fn bench_grant_sign_verify(c: &mut Criterion) {
    // Imported from crate root — grant_signer module is pub(crate).
    use latchgate_crypto::{GrantSigner, GrantVerifyingKeyStore};

    let signer = GrantSigner::generate();
    let mut store = GrantVerifyingKeyStore::empty();
    store.register(&signer);

    let message = "action=http_get&hash=deadbeef&ts=1700000000";

    // kid is derived from the verifying key and is stable for the lifetime of
    // the signer — in production it is resolved once, not per-request.
    let kid = signer.kid();

    c.bench_function("grant_ed25519_sign_verify", |b| {
        b.iter(|| {
            let sig = signer.sign(black_box(message));
            let result = store.verify_by_kid(&kid, message, &sig);
            black_box(result)
        })
    });
}

// ---------------------------------------------------------------------------
// 8. Audit event construction (full builder chain)
// ---------------------------------------------------------------------------

fn bench_audit_event_build(c: &mut Criterion) {
    // Imported from crate root — events module is pub(crate).
    use latchgate_ledger::{AuditEventBuilder, Decision, EventType};
    use std::sync::Arc;

    // In production, action_version arrives as Arc<str> from the registry.
    // Pre-allocate so the hot loop measures clone (refcount bump), not alloc.
    let action_version: Arc<str> = Arc::from("0.1.0");

    c.bench_function("audit_event_build_full", |b| {
        b.iter(|| {
            let event = AuditEventBuilder::new("trace-bench-001", EventType::ActionCall)
                .principal("bench-principal", "bench-session", "bench-jti")
                .identity_method("dpop")
                .action(
                    "http_get",
                    Some(action_version.clone()),
                    "deadbeef",
                    "digest_ok",
                )
                .request("cafebabe", None)
                .risk_level("low")
                .decision(Decision::Allow)
                .build();
            black_box(event)
        })
    });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn nanos_id() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

criterion_group!(
    benches,
    bench_dpop_sign_verify,
    bench_dpop_verify_cached,
    bench_policy_eval,
    bench_wasm_instantiation,
    bench_lease_issuance,
    bench_schema_validation,
    bench_path_evaluation,
    bench_grant_sign_verify,
    bench_audit_event_build,
);
criterion_main!(benches);
