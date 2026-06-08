/**
 * LatchGate async client.
 *
 * @example
 * ```ts
 * import { LatchGateClient } from "latchgate";
 *
 * // Minimal — reads LATCHGATE_URL from environment:
 * await using client = new LatchGateClient({ agentId: "my-agent" });
 * const result = await client.execute("http_fetch", { url: "https://api.example.com" });
 *
 * // Explicit:
 * await using client = new LatchGateClient({ baseUrl: "http://localhost:3000" });
 * await client.connect({ agentId: "my-agent" });
 * const result = await client.execute("http_fetch", { url: "https://api.example.com" });
 * ```
 *
 * Transport resolution order:
 * 1. `baseUrl` constructor option (TCP)
 * 2. `LATCHGATE_URL` environment variable (TCP)
 * 3. `socket` constructor option (UDS, default: `$XDG_RUNTIME_DIR/latchgate/gate.sock`)
 */

import type { Dispatcher } from "undici";
import { Agent, fetch as undiciFetch } from "undici";

import { computeAth, DPoPKeyPair } from "./crypto.js";
import {
  LatchGateApprovalRequired,
  LatchGateAuthError,
  LatchGateBudgetExhausted,
  LatchGateDenied,
  LatchGateLeaseExpired,
  LatchGateNotConnected,
  LatchGateReplayDetected,
  LatchGateTransportError,
  LatchGateUnavailable,
} from "./errors.js";
import {
  type ActionResult,
  actionResultFromJson,
  type ApprovalStatus,
  approvalStatusFromJson,
  type EgressProfile,
  egressProfileFromJson,
  type ExecutionReceipt,
  executionReceiptFromJson,
} from "./models.js";

const RENEW_THRESHOLD_MS = 60_000;

/**
 * Identifier format: alphanumeric start, then alphanumeric/hyphens/underscores/dots.
 * No path separators, query strings, or URL-special characters.
 */
const IDENTIFIER_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]*$/;

/**
 * Validate that an identifier is safe for URL path interpolation.
 *
 * Rejects empty strings, path separators, URL-special characters, and
 * excessive length. Defense-in-depth: the gate also validates, but
 * rejecting at the SDK boundary prevents path traversal before the
 * request reaches the network.
 *
 * @throws {Error} If the identifier is empty, too long, or malformed.
 */
function validateIdentifier(value: string, label: string): void {
  if (!value) {
    throw new Error(`${label} must not be empty`);
  }
  if (value.length > 256) {
    throw new Error(`${label} exceeds maximum length (256)`);
  }
  if (!IDENTIFIER_RE.test(value)) {
    throw new Error(`${label} contains invalid characters`);
  }
}

/**
 * Resolve the default UDS socket path.
 *
 * Algorithm must match the CLI (`crates/latchgate-cli/src/cmd/util.rs`
 * `default_uds_path`) so that `latchgate up` and `new LatchGateClient()`
 * agree without manual configuration.
 *
 * Resolution order:
 * 1. `$XDG_RUNTIME_DIR/latchgate/gate.sock`
 * 2. `/tmp/latchgate-{uid}/gate.sock`
 */
function defaultSocketPath(): string {
  const xdg = process.env["XDG_RUNTIME_DIR"] ?? "";
  if (xdg) {
    return `${xdg}/latchgate/gate.sock`;
  }
  // Node.js provides uid via process.getuid() on POSIX platforms.
  const uid = process.getuid?.() ?? 0;
  return `/tmp/latchgate-${uid}/gate.sock`;
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface ClientOptions {
  /** Path to the Unix domain socket. Mutually exclusive with `baseUrl`. */
  socket?: string;
  /** HTTP base URL for TCP transport (tests / Docker). Falls back to LATCHGATE_URL env var. */
  baseUrl?: string;
  /**
   * Canonical URL for DPoP `htu` construction.  Must match the
   * `public_base_url` field in `latchgate.toml` exactly.  For TCP
   * transport this defaults to `baseUrl`.  For UDS this **must** be set
   * explicitly (e.g. `"http://localhost:3000"`) — the gate verifies DPoP
   * proofs against its configured public URL.
   */
  publicBaseUrl?: string;
  /** Agent identifier. When set, `execute()` auto-connects on first call. */
  agentId?: string;
  /** Request timeout in milliseconds. Default: 30 000. */
  timeoutMs?: number;
  /**
   * Custom undici Dispatcher — inject a MockAgent in tests.
   * When provided, `socket` is ignored.
   */
  dispatcher?: Dispatcher;
}

export interface ConnectOptions {
  agentId?: string;
  scopes?: string[];
  maxCalls?: number;
  maxCostUsdCents?: number;
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

export class LatchGateClient {
  private readonly baseUrl: string;
  private readonly publicBaseUrl: string;
  private readonly dispatcher: Dispatcher;
  private readonly timeoutMs: number;

  private keypair: DPoPKeyPair | null = null;
  private leaseJwt: string | null = null;
  private leaseExpiresAt: Date | null = null;
  private _sessionId: string | null = null;
  private _leaseJti: string | null = null;
  private agentId: string | null = null;

  // Coalesces concurrent renewal / lazy-connect calls into one Promise.
  private connectPromise: Promise<void> | null = null;

  constructor({
    socket,
    baseUrl,
    publicBaseUrl,
    agentId,
    timeoutMs = 30_000,
    dispatcher,
  }: ClientOptions = {}) {
    this.timeoutMs = timeoutMs;
    this.agentId = agentId ?? null;

    // Resolve URL: explicit arg > env var > UDS fallback.
    const resolvedUrl = baseUrl ?? process.env["LATCHGATE_URL"];

    if (dispatcher) {
      this.dispatcher = dispatcher;
      this.baseUrl = (resolvedUrl ?? "http://localhost").replace(/\/$/, "");
    } else if (resolvedUrl) {
      this.baseUrl = resolvedUrl.replace(/\/$/, "");
      this.dispatcher = new Agent({ connect: { timeout: timeoutMs } });
    } else {
      this.baseUrl = "http://localhost";
      this.dispatcher = new Agent({
        connect: { socketPath: socket ?? defaultSocketPath(), timeout: timeoutMs },
      });
    }

    // Public base URL for DPoP htu construction.  For TCP transport
    // this defaults to the transport base URL.  For UDS the caller
    // must provide it explicitly — the gate verifies htu against its
    // own public_base_url and "http://localhost" will not match.
    this.publicBaseUrl = publicBaseUrl
      ? publicBaseUrl.replace(/\/$/, "")
      : this.baseUrl;
  }

  // -------------------------------------------------------------------------
  // Public accessors (used by framework integrations for UDS discovery)
  // -------------------------------------------------------------------------

  /**
   * Canonical public URL of the LatchGate gate.
   *
   * Returns `publicBaseUrl` when set, otherwise the transport base URL.
   * Framework integrations use this for unauthenticated discovery
   * endpoints and DPoP `htu` construction.
   */
  get gateUrl(): string {
    return this.publicBaseUrl;
  }

  /**
   * The undici Dispatcher powering this client's HTTP transport.
   *
   * Framework integrations (e.g. `@latchgate/ai-sdk`) use this to run
   * action discovery over the same transport as execution — including UDS.
   */
  get httpDispatcher(): Dispatcher {
    return this.dispatcher;
  }

  /**
   * Server-issued session identifier from the current lease.
   *
   * Available after `connect()` completes. Used by the gate for
   * policy decisions and audit attribution.
   */
  get sessionId(): string | null {
    return this._sessionId;
  }

  /**
   * Unique lease JWT identifier from the current lease.
   *
   * Available after `connect()` completes. Useful for forensic
   * correlation with server-side audit events.
   */
  get leaseJti(): string | null {
    return this._leaseJti;
  }

  // -------------------------------------------------------------------------
  // Cleanup
  // -------------------------------------------------------------------------

  async close(): Promise<void> {
    await (this.dispatcher as Agent).close?.();
  }

  /** `await using client = new LatchGateClient(...)` — TypeScript 5.2+ */
  async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  /**
   * Obtain a Lease JWT and prepare the DPoP key pair.
   *
   * Not required when `agentId` is set — `execute()` auto-connects.
   */
  async connect(options: ConnectOptions = {}): Promise<void> {
    if (options.agentId) this.agentId = options.agentId;

    const keypair = await DPoPKeyPair.generate();
    const scopes = options.scopes ?? ["tools:call"];

    const body: Record<string, unknown> = {
      scopes,
      dpop_jwk: keypair.jwk,
    };

    if (options.maxCalls !== undefined || options.maxCostUsdCents !== undefined) {
      const budgets: Record<string, number> = {};
      if (options.maxCalls !== undefined) budgets["max_calls"] = options.maxCalls;
      if (options.maxCostUsdCents !== undefined)
        budgets["max_cost_usd_cents"] = options.maxCostUsdCents;
      body["budgets"] = budgets;
    }

    const url = `${this.baseUrl}/v1/leases`;
    const resp = await this.fetch(url, {
      method: "POST",
      body: JSON.stringify(body),
      headers: { "Content-Type": "application/json" },
    });

    await raiseForStatus(resp, "<connect>");

    const data = await this.jsonBody(resp, "lease");
    this.keypair = keypair;
    this.leaseJwt = data["lease_jwt"] as string;
    this._sessionId = (data["session_id"] as string) ?? null;
    this._leaseJti = (data["lease_jti"] as string) ?? null;
    this.leaseExpiresAt = parseIso(data["expires_at"] as string);
  }

  /**
   * Execute a protected action.
   *
   * If `agentId` was set and no lease exists, auto-connects first.
   * Without `agentId`, throws `LatchGateNotConnected`.
   */
  async execute(
    actionId: string,
    params?: Record<string, unknown>,
  ): Promise<ActionResult> {
    validateIdentifier(actionId, "actionId");
    await this.ensureLease();

    const path = `/v1/actions/${actionId}/execute`;
    const url = `${this.baseUrl}${path}`;
    const headers = await this.dpopHeaders("POST", path);

    const resp = await this.fetch(url, {
      method: "POST",
      body: JSON.stringify(params ?? {}),
      headers: { ...headers, "Content-Type": "application/json" },
    });

    if (resp.status === 202) {
      const data = await this.jsonBody(resp, "execute (approval)");
      throw new LatchGateApprovalRequired(
        actionId,
        data["approval_id"] as string,
      );
    }

    await raiseForStatus(resp, actionId);
    return actionResultFromJson(await this.jsonBody(resp, "execute"));
  }

  /** Retrieve a stored execution receipt by ID. */
  async getReceipt(receiptId: string): Promise<ExecutionReceipt> {
    validateIdentifier(receiptId, "receiptId");
    await this.ensureLease();

    const path = `/v1/receipts/${receiptId}`;
    const url = `${this.baseUrl}${path}`;
    const headers = await this.dpopHeaders("GET", path);

    const resp = await this.fetch(url, { headers });

    if (resp.status === 404) {
      throw new LatchGateDenied("<receipt>", `receipt '${receiptId}' not found`);
    }

    await raiseForStatus(resp, "<receipt>");
    return executionReceiptFromJson(await this.jsonBody(resp, "receipt"));
  }

  /**
   * Retrieve the current status of a pending approval.
   *
   * @example
   * ```ts
   * try {
   *   const result = await client.execute("http_post", params);
   * } catch (err) {
   *   if (err instanceof LatchGateApprovalRequired) {
   *     while (true) {
   *       const status = await client.getApprovalStatus(err.approvalId);
   *       if (status.status !== "pending") break;
   *       await sleep(5_000);
   *     }
   *   }
   * }
   * ```
   */
  async getApprovalStatus(approvalId: string): Promise<ApprovalStatus> {
    validateIdentifier(approvalId, "approvalId");
    await this.ensureLease();

    const path = `/v1/approvals/${approvalId}/poll`;
    const url = `${this.baseUrl}${path}`;
    const headers = await this.dpopHeaders("GET", path);

    const resp = await this.fetch(url, { headers });

    if (resp.status === 404) {
      throw new LatchGateDenied(
        "<approval>",
        `approval '${approvalId}' not found`,
      );
    }

    await raiseForStatus(resp, "<approval>");
    const data = await this.jsonBody(resp, "approval poll");
    // The poll endpoint returns {status, receipt_id?, reason?,
    // retry_after_seconds?} — approval_id is not in the response.
    data["approval_id"] ??= approvalId;
    return approvalStatusFromJson(data);
  }

  /**
   * Fetch the egress profile for an action.
   *
   * Returns the declared egress domains and profile kind, useful for
   * orchestrator UIs showing which external services an action may contact.
   */
  async getActionEgress(actionId: string): Promise<EgressProfile> {
    validateIdentifier(actionId, "actionId");
    await this.ensureLease();

    const path = `/v1/actions/${actionId}`;
    const url = `${this.baseUrl}${path}`;
    const headers = await this.dpopHeaders("GET", path);

    const resp = await this.fetch(url, { headers });

    if (resp.status === 404) {
      throw new LatchGateDenied(
        actionId,
        `action '${actionId}' not found`,
      );
    }

    await raiseForStatus(resp, actionId);
    const data = await this.jsonBody(resp, "action egress");
    return egressProfileFromJson(data["egress"]);
  }

  // -------------------------------------------------------------------------
  // Internal helpers
  // -------------------------------------------------------------------------

  private async ensureLease(): Promise<void> {
    if (!this.keypair || !this.leaseJwt) {
      // Lazy-connect: if agentId is set, connect automatically.
      if (this.agentId !== null) {
        // Coalesce concurrent lazy-connect calls into one Promise.
        if (!this.connectPromise) {
          this.connectPromise = this.connect({}).finally(() => {
            this.connectPromise = null;
          });
        }
        await this.connectPromise;
        return;
      }
      throw new LatchGateNotConnected();
    }

    if (
      this.leaseExpiresAt &&
      Date.now() + RENEW_THRESHOLD_MS > this.leaseExpiresAt.getTime()
    ) {
      if (!this.connectPromise) {
        this.connectPromise = this.connect({}).finally(() => {
          this.connectPromise = null;
        });
      }
      await this.connectPromise;
    }
  }

  /**
   * Build `Authorization` and `DPoP` headers for a request.
   *
   * @param method - HTTP method in uppercase.
   * @param path - Request path (e.g. `/v1/actions/http_fetch/execute`).
   *   The DPoP `htu` is constructed as `publicBaseUrl + path`.
   */
  private async dpopHeaders(
    method: string,
    path: string,
  ): Promise<Record<string, string>> {
    if (!this.keypair || !this.leaseJwt) throw new LatchGateNotConnected();
    const htu = `${this.publicBaseUrl}${path}`;
    const ath = await computeAth(this.leaseJwt);
    const proof = await this.keypair.signProof(method, htu, ath);
    return {
      Authorization: `DPoP ${this.leaseJwt}`,
      DPoP: proof,
    };
  }

  private async fetch(
    url: string,
    init: RequestInit & { headers?: Record<string, string> } = {},
  ): Promise<Response> {
    try {
      return await (undiciFetch as unknown as (
        url: string,
        init: Record<string, unknown>,
      ) => Promise<Response>)(url, {
        ...init,
        signal: AbortSignal.timeout(this.timeoutMs),
        dispatcher: this.dispatcher,
      });
    } catch (err) {
      if (err instanceof Error && err.name !== "AbortError") {
        throw new LatchGateTransportError(err.message);
      }
      throw new LatchGateTransportError(String(err));
    }
  }

  /**
   * Parse a JSON object from a successful response.
   *
   * Raises `LatchGateTransportError` if the body is not valid JSON or not
   * a JSON object — catches proxy/CDN HTML pages on 200 responses.
   */
  private async jsonBody(
    resp: Response,
    context: string,
  ): Promise<Record<string, unknown>> {
    let data: unknown;
    try {
      data = await resp.json();
    } catch {
      throw new LatchGateTransportError(
        `invalid JSON in ${context} response`,
      );
    }
    if (typeof data !== "object" || data === null || Array.isArray(data)) {
      throw new LatchGateTransportError(
        `expected JSON object in ${context} response`,
      );
    }
    return data as Record<string, unknown>;
  }
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

async function raiseForStatus(
  resp: Response,
  actionId: string,
): Promise<void> {
  if (resp.ok) return;

  let body: Record<string, unknown> = {};
  try {
    body = (await resp.json()) as Record<string, unknown>;
  } catch {
    // Empty or non-JSON body — fall through with defaults.
  }

  const error = (body["error"] as string) ?? "unknown";
  const denyReason = body["deny_reason"] as string | undefined;

  switch (resp.status) {
    case 400:
      throw new LatchGateDenied(actionId, error);

    case 401:
      if (error === "lease_expired") {
        throw new LatchGateLeaseExpired(error);
      }
      if (error === "replay_detected") {
        throw new LatchGateReplayDetected(error);
      }
      throw new LatchGateAuthError(error);

    case 403:
      if (error === "budget_exhausted") {
        throw new LatchGateBudgetExhausted(actionId);
      }
      throw new LatchGateDenied(
        actionId,
        denyReason ? `${error}: ${denyReason}` : error,
      );

    case 422: {
      // Append reason only when present and distinct from error to avoid
      // the doubled "schema_violation: schema_violation" bug.
      const reason = body["reason"] as string | undefined;
      const detail =
        reason && reason !== error ? `${error}: ${reason}` : error;
      throw new LatchGateDenied(actionId, detail);
    }

    case 502:
    case 503:
      throw new LatchGateUnavailable(error);

    default:
      throw new LatchGateUnavailable(
        `unexpected_status_${resp.status}: ${error}`,
      );
  }
}

function parseIso(value: string): Date {
  return new Date(value);
}
