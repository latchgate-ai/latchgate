/**
 * LatchGate error hierarchy.
 *
 * All errors thrown by the SDK extend {@link LatchGateError}.
 * Callers that only care about failures can catch the base class;
 * callers that need to react to specific outcomes can catch the
 * more specific subclasses.
 */

export class LatchGateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = this.constructor.name;
    // Maintain proper prototype chain in transpiled ES5.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// ---------------------------------------------------------------------------
// Authorization / policy errors (client must not retry as-is)
// ---------------------------------------------------------------------------

/** The action was denied by policy. */
export class LatchGateDenied extends LatchGateError {
  readonly actionId: string;
  readonly reason: string | undefined;

  constructor(actionId: string, reason?: string) {
    const msg = reason
      ? `action '${actionId}' denied by policy: ${reason}`
      : `action '${actionId}' denied by policy`;
    super(msg);
    this.actionId = actionId;
    this.reason = reason;
  }
}

/**
 * The action requires human approval before it can be executed.
 *
 * Poll `client.getApprovalStatus(approvalId)` until the status
 * transitions out of `"pending"`.
 */
export class LatchGateApprovalRequired extends LatchGateError {
  readonly actionId: string;
  readonly approvalId: string;

  constructor(actionId: string, approvalId: string) {
    super(
      `action '${actionId}' requires approval: poll approvalId='${approvalId}'`,
    );
    this.actionId = actionId;
    this.approvalId = approvalId;
  }
}

/**
 * The caller's budget for this lease has been exhausted.
 *
 * Call `connect()` again to obtain a new lease with a fresh budget.
 */
export class LatchGateBudgetExhausted extends LatchGateError {
  readonly actionId: string;

  constructor(actionId: string) {
    super(`budget exhausted for action '${actionId}'`);
    this.actionId = actionId;
  }
}

/**
 * Authentication failed (expired lease, bad DPoP proof, replay, etc.).
 *
 * Call `connect()` to obtain a fresh lease before retrying.
 */
export class LatchGateAuthError extends LatchGateError {
  readonly detail: string;
  /** Raw error code from the gate (e.g. `"lease_expired"`, `"invalid_dpop"`). */
  readonly code: string;

  constructor(detail: string) {
    super(`authentication failed: ${detail}`);
    this.detail = detail;
    this.code = detail;
  }
}

/** Lease has expired — call `connect()` to obtain a new one. */
export class LatchGateLeaseExpired extends LatchGateAuthError {}

/**
 * A DPoP proof jti was reused — possible replay attack.
 *
 * Alert security; do NOT retry with the same proof.
 */
export class LatchGateReplayDetected extends LatchGateAuthError {}

// ---------------------------------------------------------------------------
// Transient / infrastructure errors (client may retry with backoff)
// ---------------------------------------------------------------------------

/**
 * The gateway or a dependency (OPA, Redis) is temporarily unavailable.
 *
 * Retry with exponential backoff. The action was *not* executed.
 */
export class LatchGateUnavailable extends LatchGateError {
  readonly detail: string;

  constructor(detail: string) {
    super(`gateway unavailable: ${detail}`);
    this.detail = detail;
  }
}

/** Low-level transport failure (socket error, timeout, DNS, etc.). */
export class LatchGateTransportError extends LatchGateError {
  readonly detail: string;

  constructor(detail: string) {
    super(`transport error: ${detail}`);
    this.detail = detail;
  }
}

// ---------------------------------------------------------------------------
// SDK usage errors
// ---------------------------------------------------------------------------

/** `execute()` was called before `connect()`. */
export class LatchGateNotConnected extends LatchGateError {
  constructor() {
    super("call connect() before execute()");
  }
}
