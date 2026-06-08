import { describe, it, expect } from "vitest";
import { MockAgent } from "undici";
import { LatchGateClient } from "../src/client.js";
import {
  LatchGateApprovalRequired,
  LatchGateAuthError,
  LatchGateBudgetExhausted,
  LatchGateDenied,
  LatchGateNotConnected,
  LatchGateUnavailable,
} from "../src/errors.js";

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

const BASE_URL = "http://localhost";
const LEASE_JWT = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhZ2VudDp0ZXN0In0.sig";
const EXPIRES_AT = new Date(Date.now() + 3_600_000).toISOString();
const LEASE_RESPONSE = {
  lease_jwt: LEASE_JWT,
  session_id: "sess-001",
  lease_jti: "jti-001",
  expires_at: EXPIRES_AT,
};

const EXECUTE_OK = {
  trace_id: "trace-001",
  action_id: "http_fetch",
  grant_id: "grant-001",
  receipt_id: "rcpt-001",
  output: { status_code: 200, body: "hello" },
  verification: { outcome: "verified", is_fully_successful: true },
  runtime: { duration_ms: 150, exit_code: 0, fuel_consumed: 100_000 },
};

const RECEIPT_OK = {
  receipt_id: "rcpt-001",
  grant_id: "grant-001",
  provider_module_digest: "sha256:abc",
  provider_receipt: { status: 200 },
  normalized_result: { kind: "success", summary: "HTTP 200 OK" },
  verification_outcome: { status: "verified", evidence: { status_code: 200 } },
  result_hash: "deadbeef".repeat(8),
  started_at: "2026-03-01T12:00:00Z",
  finished_at: "2026-03-01T12:00:00.150Z",
  failure_class: null,
};

// ---------------------------------------------------------------------------
// MockAgent factory
// ---------------------------------------------------------------------------

function makeMock() {
  const mockAgent = new MockAgent({ connections: 1 });
  mockAgent.disableNetConnect();
  const pool = mockAgent.get(BASE_URL);
  return { mockAgent, pool };
}

function makeClient(mockAgent: MockAgent) {
  return new LatchGateClient({ baseUrl: BASE_URL, dispatcher: mockAgent });
}

// ---------------------------------------------------------------------------
// connect()
// ---------------------------------------------------------------------------

describe("connect()", () => {
  it("POSTs to /v1/leases with dpop_jwk, scopes, session_id", async () => {
    const { mockAgent, pool } = makeMock();
    let capturedBody: Record<string, unknown> = {};

    pool
      .intercept({ path: "/v1/leases", method: "POST" })
      .reply(200, (opts) => {
        capturedBody = JSON.parse(opts.body as string) as Record<string, unknown>;
        return LEASE_RESPONSE;
      });

    await makeClient(mockAgent).connect({ agentId: "agent:test" });

    expect(capturedBody["dpop_jwk"]).toMatchObject({ kty: "EC", crv: "P-256" });
    expect(capturedBody["scopes"]).toContain("tools:call");
    // session_id is server-issued — the server generates and returns it in the
    // response; the client must NOT send it in the request body (the server
    // enforces this via deny_unknown_fields and has a dedicated regression test).
    expect(capturedBody["session_id"]).toBeUndefined();
  });

  it("stores the lease JWT", async () => {
    const { mockAgent, pool } = makeMock();
    pool.intercept({ path: "/v1/leases", method: "POST" }).reply(200, LEASE_RESPONSE);

    const client = makeClient(mockAgent);
    await client.connect();
    expect((client as unknown as { leaseJwt: string }).leaseJwt).toBe(LEASE_JWT);
  });

  it("sends budgets when specified", async () => {
    const { mockAgent, pool } = makeMock();
    let capturedBody: Record<string, unknown> = {};

    pool
      .intercept({ path: "/v1/leases", method: "POST" })
      .reply(200, (opts) => {
        capturedBody = JSON.parse(opts.body as string) as Record<string, unknown>;
        return LEASE_RESPONSE;
      });

    await makeClient(mockAgent).connect({ maxCalls: 50, maxCostUsdCents: 1000 });

    const budgets = capturedBody["budgets"] as Record<string, number>;
    expect(budgets["max_calls"]).toBe(50);
    expect(budgets["max_cost_usd_cents"]).toBe(1000);
  });

  it("throws LatchGateDenied on 400", async () => {
    const { mockAgent, pool } = makeMock();
    pool
      .intercept({ path: "/v1/leases", method: "POST" })
      .reply(400, { error: "invalid_request" });

    await expect(makeClient(mockAgent).connect()).rejects.toBeInstanceOf(LatchGateDenied);
  });
});

// ---------------------------------------------------------------------------
// execute() — happy path
// ---------------------------------------------------------------------------

describe("execute()", () => {
  it("returns ActionResult on 200", async () => {
    const { mockAgent, pool } = makeMock();
    pool.intercept({ path: "/v1/leases", method: "POST" }).reply(200, LEASE_RESPONSE);
    pool
      .intercept({ path: "/v1/actions/http_fetch/execute", method: "POST" })
      .reply(200, EXECUTE_OK);

    const client = makeClient(mockAgent);
    await client.connect();
    const result = await client.execute("http_fetch", { url: "https://example.com" });

    expect(result.receiptId).toBe("rcpt-001");
    expect(result.traceId).toBe("trace-001");
    expect(result.grantId).toBe("grant-001");
    expect(result.output).toEqual({ status_code: 200, body: "hello" });
  });

  it("sends Authorization header with DPoP scheme", async () => {
    const { mockAgent, pool } = makeMock();
    let capturedAuth = "";

    pool.intercept({ path: "/v1/leases", method: "POST" }).reply(200, LEASE_RESPONSE);
    pool
      .intercept({ path: "/v1/actions/http_fetch/execute", method: "POST" })
      .reply(200, (opts) => {
        capturedAuth = (opts.headers as Record<string, string>)["Authorization"] ?? "";
        return EXECUTE_OK;
      });

    const client = makeClient(mockAgent);
    await client.connect();
    await client.execute("http_fetch", {});

    expect(capturedAuth).toMatch(/^DPoP /);
    expect(capturedAuth).toContain(LEASE_JWT);
  });

  it("sends DPoP header as 3-part JWT", async () => {
    const { mockAgent, pool } = makeMock();
    let capturedDpop = "";

    pool.intercept({ path: "/v1/leases", method: "POST" }).reply(200, LEASE_RESPONSE);
    pool
      .intercept({ path: "/v1/actions/http_fetch/execute", method: "POST" })
      .reply(200, (opts) => {
        capturedDpop = (opts.headers as Record<string, string>)["DPoP"] ?? "";
        return EXECUTE_OK;
      });

    const client = makeClient(mockAgent);
    await client.connect();
    await client.execute("http_fetch", {});

    expect(capturedDpop.split(".")).toHaveLength(3);
  });

  it("DPoP proof htm is POST", async () => {
    const { mockAgent, pool } = makeMock();
    let capturedDpop = "";

    pool.intercept({ path: "/v1/leases", method: "POST" }).reply(200, LEASE_RESPONSE);
    pool
      .intercept({ path: "/v1/actions/http_fetch/execute", method: "POST" })
      .reply(200, (opts) => {
        capturedDpop = (opts.headers as Record<string, string>)["DPoP"] ?? "";
        return EXECUTE_OK;
      });

    const client = makeClient(mockAgent);
    await client.connect();
    await client.execute("http_fetch", {});

    const payloadB64 = capturedDpop.split(".")[1]!;
    const payload = JSON.parse(
      atob(payloadB64.replaceAll("-", "+").replaceAll("_", "/")),
    ) as Record<string, unknown>;
    expect(payload["htm"]).toBe("POST");
  });
});

// ---------------------------------------------------------------------------
// execute() — error mapping
// ---------------------------------------------------------------------------

describe("execute() errors", () => {
  it("throws LatchGateAuthError on 401", async () => {
    const { mockAgent, pool } = makeMock();
    pool.intercept({ path: "/v1/leases", method: "POST" }).reply(200, LEASE_RESPONSE);
    pool
      .intercept({ path: "/v1/actions/http_fetch/execute", method: "POST" })
      .reply(401, { error: "lease_expired" });

    const client = makeClient(mockAgent);
    await client.connect();
    await expect(client.execute("http_fetch", {})).rejects.toBeInstanceOf(LatchGateAuthError);
  });

  it("throws LatchGateDenied on 403", async () => {
    const { mockAgent, pool } = makeMock();
    pool.intercept({ path: "/v1/leases", method: "POST" }).reply(200, LEASE_RESPONSE);
    pool
      .intercept({ path: "/v1/actions/http_fetch/execute", method: "POST" })
      .reply(403, { error: "policy_denied" });

    const client = makeClient(mockAgent);
    await client.connect();
    await expect(client.execute("http_fetch", {})).rejects.toBeInstanceOf(LatchGateDenied);
  });

  it("throws LatchGateBudgetExhausted on 403 budget_exhausted", async () => {
    const { mockAgent, pool } = makeMock();
    pool.intercept({ path: "/v1/leases", method: "POST" }).reply(200, LEASE_RESPONSE);
    pool
      .intercept({ path: "/v1/actions/http_fetch/execute", method: "POST" })
      .reply(403, { error: "budget_exhausted" });

    const client = makeClient(mockAgent);
    await client.connect();
    await expect(client.execute("http_fetch", {})).rejects.toBeInstanceOf(
      LatchGateBudgetExhausted,
    );
  });

  it("surfaces deny_reason on 403 policy_denied", async () => {
    const { mockAgent, pool } = makeMock();
    pool.intercept({ path: "/v1/leases", method: "POST" }).reply(200, LEASE_RESPONSE);
    pool
      .intercept({ path: "/v1/actions/http_fetch/execute", method: "POST" })
      .reply(403, { error: "policy_denied", deny_reason: "not in ACL" });

    const client = makeClient(mockAgent);
    await client.connect();
    const err = await client.execute("http_fetch", {}).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(LatchGateDenied);
    expect((err as LatchGateDenied).reason).toContain("not in ACL");
  });

  it("does not double schema_violation on 422", async () => {
    const { mockAgent, pool } = makeMock();
    pool.intercept({ path: "/v1/leases", method: "POST" }).reply(200, LEASE_RESPONSE);
    pool
      .intercept({ path: "/v1/actions/http_fetch/execute", method: "POST" })
      .reply(422, { error: "schema_violation" });

    const client = makeClient(mockAgent);
    await client.connect();
    const err = await client.execute("http_fetch", {}).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(LatchGateDenied);
    expect((err as LatchGateDenied).reason).toBe("schema_violation");
  });

  it("appends distinct reason on 422 when present", async () => {
    const { mockAgent, pool } = makeMock();
    pool.intercept({ path: "/v1/leases", method: "POST" }).reply(200, LEASE_RESPONSE);
    pool
      .intercept({ path: "/v1/actions/http_fetch/execute", method: "POST" })
      .reply(422, { error: "schema_violation", reason: "missing field 'url'" });

    const client = makeClient(mockAgent);
    await client.connect();
    const err = await client.execute("http_fetch", {}).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(LatchGateDenied);
    expect((err as LatchGateDenied).reason).toContain("missing field 'url'");
  });

  it("surfaces gate error code in LatchGateAuthError.detail on 401", async () => {
    const { mockAgent, pool } = makeMock();
    pool.intercept({ path: "/v1/leases", method: "POST" }).reply(200, LEASE_RESPONSE);
    pool
      .intercept({ path: "/v1/actions/http_fetch/execute", method: "POST" })
      .reply(401, { error: "lease_expired" });

    const client = makeClient(mockAgent);
    await client.connect();
    const err = await client.execute("http_fetch", {}).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(LatchGateAuthError);
    expect((err as LatchGateAuthError).detail).toBe("lease_expired");
  });

  it("surfaces gate error code in LatchGateUnavailable.detail on 503", async () => {
    const { mockAgent, pool } = makeMock();
    pool.intercept({ path: "/v1/leases", method: "POST" }).reply(200, LEASE_RESPONSE);
    pool
      .intercept({ path: "/v1/actions/http_fetch/execute", method: "POST" })
      .reply(503, { error: "policy_engine_unavailable" });

    const client = makeClient(mockAgent);
    await client.connect();
    const err = await client.execute("http_fetch", {}).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(LatchGateUnavailable);
    expect((err as LatchGateUnavailable).detail).toBe("policy_engine_unavailable");
  });

  it("throws LatchGateApprovalRequired on 202", async () => {
    const { mockAgent, pool } = makeMock();
    pool.intercept({ path: "/v1/leases", method: "POST" }).reply(200, LEASE_RESPONSE);
    pool
      .intercept({ path: "/v1/actions/http_post/execute", method: "POST" })
      .reply(202, { decision: "pending_approval", approval_id: "appr-999" });

    const client = makeClient(mockAgent);
    await client.connect();
    const err = await client.execute("http_post", {}).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(LatchGateApprovalRequired);
    expect((err as LatchGateApprovalRequired).approvalId).toBe("appr-999");
    expect((err as LatchGateApprovalRequired).actionId).toBe("http_post");
  });
});

// ---------------------------------------------------------------------------
// Not connected guard
// ---------------------------------------------------------------------------

describe("LatchGateNotConnected", () => {
  it("thrown from execute() before connect()", async () => {
    const client = new LatchGateClient({ baseUrl: BASE_URL });
    await expect(client.execute("http_fetch", {})).rejects.toBeInstanceOf(LatchGateNotConnected);
  });

  it("thrown from getReceipt() before connect()", async () => {
    const client = new LatchGateClient({ baseUrl: BASE_URL });
    await expect(client.getReceipt("some-id")).rejects.toBeInstanceOf(LatchGateNotConnected);
  });
});

// ---------------------------------------------------------------------------
// Auto-renew
// ---------------------------------------------------------------------------

describe("auto-renew", () => {
  it("renews lease when fewer than 60s remain", async () => {
    const { mockAgent, pool } = makeMock();
    let leaseCallCount = 0;

    pool.intercept({ path: "/v1/leases", method: "POST" }).reply(200, () => {
      leaseCallCount++;
      // Return a lease that expires in 30s — below the 60s threshold.
      return {
        lease_jwt: LEASE_JWT,
        session_id: "sess-renew",
        lease_jti: `jti-renew-${leaseCallCount}`,
        expires_at: new Date(Date.now() + 30_000).toISOString(),
      };
    }).times(2); // expect two calls

    pool
      .intercept({ path: "/v1/actions/http_fetch/execute", method: "POST" })
      .reply(200, EXECUTE_OK);

    const client = makeClient(mockAgent);
    await client.connect();
    expect(leaseCallCount).toBe(1);

    await client.execute("http_fetch", {});
    expect(leaseCallCount).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// getReceipt()
// ---------------------------------------------------------------------------

describe("getReceipt()", () => {
  it("returns ExecutionReceipt on 200", async () => {
    const { mockAgent, pool } = makeMock();
    pool.intercept({ path: "/v1/leases", method: "POST" }).reply(200, LEASE_RESPONSE);
    pool.intercept({ path: "/v1/receipts/rcpt-001", method: "GET" }).reply(200, RECEIPT_OK);

    const client = makeClient(mockAgent);
    await client.connect();
    const receipt = await client.getReceipt("rcpt-001");

    expect(receipt.receiptId).toBe("rcpt-001");
    expect(receipt.grantId).toBe("grant-001");
  });

  it("throws LatchGateDenied on 404", async () => {
    const { mockAgent, pool } = makeMock();
    pool.intercept({ path: "/v1/leases", method: "POST" }).reply(200, LEASE_RESPONSE);
    pool.intercept({ path: "/v1/receipts/missing", method: "GET" }).reply(404, {});

    const client = makeClient(mockAgent);
    await client.connect();
    await expect(client.getReceipt("missing")).rejects.toBeInstanceOf(LatchGateDenied);
  });
});

// ---------------------------------------------------------------------------
// getApprovalStatus()
// ---------------------------------------------------------------------------

describe("getApprovalStatus()", () => {
  it("returns pending with retry hint", async () => {
    const { mockAgent, pool } = makeMock();
    pool.intercept({ path: "/v1/leases", method: "POST" }).reply(200, LEASE_RESPONSE);
    pool
      .intercept({ path: "/v1/approvals/appr-001/poll", method: "GET" })
      .reply(200, { status: "pending", retry_after_seconds: 2 });

    const client = makeClient(mockAgent);
    await client.connect();
    const status = await client.getApprovalStatus("appr-001");

    expect(status.approvalId).toBe("appr-001");
    expect(status.status).toBe("pending");
    expect(status.retryAfterSeconds).toBe(2);
  });

  it("returns approved with receipt_id", async () => {
    const { mockAgent, pool } = makeMock();
    pool.intercept({ path: "/v1/leases", method: "POST" }).reply(200, LEASE_RESPONSE);
    pool
      .intercept({ path: "/v1/approvals/appr-002/poll", method: "GET" })
      .reply(200, { status: "approved", receipt_id: "rcpt-099" });

    const client = makeClient(mockAgent);
    await client.connect();
    const status = await client.getApprovalStatus("appr-002");

    expect(status.status).toBe("approved");
    expect(status.receiptId).toBe("rcpt-099");
    expect(status.approvalId).toBe("appr-002");
  });

  it("returns denied with reason", async () => {
    const { mockAgent, pool } = makeMock();
    pool.intercept({ path: "/v1/leases", method: "POST" }).reply(200, LEASE_RESPONSE);
    pool
      .intercept({ path: "/v1/approvals/appr-003/poll", method: "GET" })
      .reply(200, { status: "denied", reason: "risk too high" });

    const client = makeClient(mockAgent);
    await client.connect();
    const status = await client.getApprovalStatus("appr-003");

    expect(status.status).toBe("denied");
    expect(status.reason).toBe("risk too high");
  });

  it("throws LatchGateDenied on 404", async () => {
    const { mockAgent, pool } = makeMock();
    pool.intercept({ path: "/v1/leases", method: "POST" }).reply(200, LEASE_RESPONSE);
    pool
      .intercept({ path: "/v1/approvals/missing/poll", method: "GET" })
      .reply(404, {});

    const client = makeClient(mockAgent);
    await client.connect();
    await expect(client.getApprovalStatus("missing")).rejects.toBeInstanceOf(LatchGateDenied);
  });
});

// ---------------------------------------------------------------------------
// Session properties
// ---------------------------------------------------------------------------

describe("session properties", () => {
  it("sessionId is null before connect", () => {
    const { mockAgent } = makeMock();
    const client = makeClient(mockAgent);
    expect(client.sessionId).toBeNull();
  });

  it("sessionId is available after connect", async () => {
    const { mockAgent, pool } = makeMock();
    pool.intercept({ path: "/v1/leases", method: "POST" }).reply(200, LEASE_RESPONSE);

    const client = makeClient(mockAgent);
    await client.connect();
    expect(client.sessionId).toBe("sess-001");
  });

  it("leaseJti is available after connect", async () => {
    const { mockAgent, pool } = makeMock();
    pool.intercept({ path: "/v1/leases", method: "POST" }).reply(200, LEASE_RESPONSE);

    const client = makeClient(mockAgent);
    await client.connect();
    expect(client.leaseJti).toBe("jti-001");
  });

  it("properties update on reconnect", async () => {
    const { mockAgent, pool } = makeMock();
    pool.intercept({ path: "/v1/leases", method: "POST" }).reply(200, {
      ...LEASE_RESPONSE,
      session_id: "sess-new",
      lease_jti: "jti-new",
    });

    const client = makeClient(mockAgent);
    await client.connect();
    expect(client.sessionId).toBe("sess-new");
    expect(client.leaseJti).toBe("jti-new");
  });
});

// ---------------------------------------------------------------------------
// Defensive JSON parsing
// ---------------------------------------------------------------------------

describe("defensive JSON parsing", () => {
  it("connect with non-JSON response throws LatchGateTransportError", async () => {
    const { mockAgent, pool } = makeMock();
    pool
      .intercept({ path: "/v1/leases", method: "POST" })
      .reply(200, "<html>proxy error</html>", {
        headers: { "content-type": "text/html" },
      });

    const client = makeClient(mockAgent);
    await expect(client.connect()).rejects.toThrow("invalid JSON");
  });

  it("execute with non-JSON response throws LatchGateTransportError", async () => {
    const { mockAgent, pool } = makeMock();
    pool.intercept({ path: "/v1/leases", method: "POST" }).reply(200, LEASE_RESPONSE);
    pool
      .intercept({ path: "/v1/actions/http_fetch/execute", method: "POST" })
      .reply(200, "not json", {
        headers: { "content-type": "text/plain" },
      });

    const client = makeClient(mockAgent);
    await client.connect();
    await expect(client.execute("http_fetch", {})).rejects.toThrow("invalid JSON");
  });
});
