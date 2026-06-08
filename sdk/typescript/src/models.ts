/**
 * Result types returned by LatchGateClient methods.
 * All fields mirror the JSON responses from the LatchGate API.
 */

export interface ActionResult {
  /** Raw JSON output from the provider. */
  readonly output: unknown;
  /** Durable receipt identifier. Pass to `getReceipt()` for the full record. */
  readonly receiptId: string;
  /** Correlation ID for this pipeline invocation. */
  readonly traceId: string;
  /** The ExecutionGrant that authorised this execution. */
  readonly grantId: string;
  /** Contains `outcome` (string) and `isFullySuccessful` (boolean). */
  readonly verification: Record<string, unknown>;
  /** Contains `durationMs`, `exitCode`, `fuelConsumed`. */
  readonly runtime: Record<string, unknown>;
}

export function actionResultFromJson(data: Record<string, unknown>): ActionResult {
  return {
    output: data["output"],
    receiptId: data["receipt_id"] as string,
    traceId: data["trace_id"] as string,
    grantId: data["grant_id"] as string,
    verification: (data["verification"] as Record<string, unknown>) ?? {},
    runtime: (data["runtime"] as Record<string, unknown>) ?? {},
  };
}

export interface ExecutionReceipt {
  readonly receiptId: string;
  readonly grantId: string;
  /** SHA-256 digest of the .wasm module that executed. */
  readonly providerModule: string;
  readonly providerReceipt: unknown;
  /** Contains `kind` and optional `summary` or `reason`. */
  readonly normalizedResult: Record<string, unknown>;
  /** Contains `status` and optional `evidence`. */
  readonly verificationOutcome: Record<string, unknown>;
  /** SHA-256 of the canonical result envelope for tamper detection. */
  readonly resultHash: string;
  readonly startedAt: string;
  readonly finishedAt: string;
  readonly failureClass: string | null;
}

export function isFullySuccessful(receipt: ExecutionReceipt): boolean {
  const resultOk = receipt.normalizedResult["kind"] === "success";
  const vStatus = receipt.verificationOutcome["status"] as string | undefined;
  const verified = vStatus === "verified" || vStatus === "unverifiable_declared";
  return resultOk && verified;
}

export function executionReceiptFromJson(
  data: Record<string, unknown>,
): ExecutionReceipt {
  return {
    receiptId: data["receipt_id"] as string,
    grantId: data["grant_id"] as string,
    providerModule: (data["provider_module_digest"] ??
      data["provider_module"]) as string,
    providerReceipt: data["provider_receipt"],
    normalizedResult:
      (data["normalized_result"] as Record<string, unknown>) ?? {},
    verificationOutcome:
      (data["verification_outcome"] as Record<string, unknown>) ?? {},
    resultHash: data["result_hash"] as string,
    startedAt: data["started_at"] as string,
    finishedAt: data["finished_at"] as string,
    failureClass: (data["failure_class"] as string | null) ?? null,
  };
}

export interface ApprovalStatus {
  readonly approvalId: string;
  // eslint-disable-next-line @typescript-eslint/no-redundant-type-constituents
  readonly status: "pending" | "approved" | "denied" | "failed" | string;
  readonly actionId: string;
  /** Present on `"approved"` — receipt from the operator's execution. */
  readonly receiptId: string | null;
  /** Present on `"denied"` or `"failed"` — reason or error description. */
  readonly reason: string | null;
  /** Hint for polling interval when `"pending"`. */
  readonly retryAfterSeconds: number | null;
  readonly raw: Record<string, unknown>;
}

export function approvalStatusFromJson(
  data: Record<string, unknown>,
): ApprovalStatus {
  return {
    approvalId: (data["approval_id"] as string) ?? "",
    status: (data["status"] as string) ?? "pending",
    actionId: (data["action_id"] as string) ?? "",
    receiptId: (data["receipt_id"] as string | null) ?? null,
    reason: (data["reason"] as string | null) ?? null,
    retryAfterSeconds: (data["retry_after_seconds"] as number | null) ?? null,
    raw: data,
  };
}

export interface EgressProfile {
  /** Either `"none"` (no network) or `"proxy_allowlist"` (restricted). */
  readonly profile: string;
  /** Domains the action may contact. Empty for `"none"` profile. */
  readonly allowedDomains: readonly string[];
}

export function egressProfileFromJson(data: unknown): EgressProfile {
  if (data == null || data === "none") {
    return { profile: "none", allowedDomains: [] };
  }
  if (typeof data === "object" && "proxy_allowlist" in data) {
    const inner = (data as Record<string, Record<string, unknown>>)[
      "proxy_allowlist"
    ];
    if (inner != null) {
      return {
        profile: "proxy_allowlist",
        allowedDomains:
          (inner["allowed_domains"] as readonly string[] | undefined) ?? [],
      };
    }
  }
  return { profile: "none", allowedDomains: [] };
}
