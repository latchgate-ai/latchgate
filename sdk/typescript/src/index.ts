export { LatchGateClient } from "./client.js";
export type { ClientOptions, ConnectOptions } from "./client.js";

export type {
  ActionResult,
  ApprovalStatus,
  EgressProfile,
  ExecutionReceipt,
} from "./models.js";
export { isFullySuccessful, egressProfileFromJson } from "./models.js";

export {
  LatchGateError,
  LatchGateDenied,
  LatchGateApprovalRequired,
  LatchGateBudgetExhausted,
  LatchGateAuthError,
  LatchGateLeaseExpired,
  LatchGateReplayDetected,
  LatchGateUnavailable,
  LatchGateTransportError,
  LatchGateNotConnected,
} from "./errors.js";
