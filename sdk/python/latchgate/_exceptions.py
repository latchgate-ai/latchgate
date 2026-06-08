"""LatchGate exception hierarchy."""

from __future__ import annotations


class LatchGateError(Exception):
    """Base class for all LatchGate SDK errors."""


# ---------------------------------------------------------------------------
# Authorization / policy errors (client must not retry as-is)
# ---------------------------------------------------------------------------


class LatchGateDenied(LatchGateError):
    """The action was denied by policy.

    Retrying the same request without changing the caller context or policy
    will produce the same result.
    """

    def __init__(self, action_id: str, reason: str | None = None) -> None:
        self.action_id = action_id
        self.reason = reason
        msg = f"action '{action_id}' denied by policy"
        if reason:
            msg += f": {reason}"
        super().__init__(msg)


class LatchGateApprovalRequired(LatchGateError):
    """The action requires human approval before it can be executed.

    Poll ``client.get_approval_status(approval_id)`` until the status
    transitions out of ``"pending"``.
    """

    def __init__(self, action_id: str, approval_id: str) -> None:
        self.action_id = action_id
        self.approval_id = approval_id
        super().__init__(
            f"action '{action_id}' requires approval: poll approval_id='{approval_id}'"
        )


class LatchGateBudgetExhausted(LatchGateError):
    """The caller's budget for this lease has been exhausted.

    Obtain a new lease (with a fresh budget allocation) before retrying.
    """

    def __init__(self, action_id: str) -> None:
        self.action_id = action_id
        super().__init__(f"budget exhausted for action '{action_id}'")


class LatchGateAuthError(LatchGateError):
    """Authentication failed (expired lease, bad DPoP proof, replay, etc.).

    Call ``client.connect()`` to obtain a fresh lease before retrying.

    The :attr:`code` attribute carries the gate's raw error code
    (``"lease_expired"``, ``"invalid_dpop"``, ``"replay_detected"``, etc.)
    so callers can ``switch`` on it without catching subclasses.
    """

    def __init__(self, detail: str) -> None:
        self.detail = detail
        self.code = detail
        super().__init__(f"authentication failed: {detail}")


class LatchGateLeaseExpired(LatchGateAuthError):
    """The lease has expired — call ``connect()`` to obtain a new one."""


class LatchGateReplayDetected(LatchGateAuthError):
    """A DPoP proof jti was reused — possible replay attack.

    Alert security; do NOT retry with the same proof.
    """


# ---------------------------------------------------------------------------
# Transient / infrastructure errors (client may retry with backoff)
# ---------------------------------------------------------------------------


class LatchGateUnavailable(LatchGateError):
    """The gateway or a dependency (OPA, Redis) is temporarily unavailable.

    Retry with exponential backoff.  The action was *not* executed.
    """

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(f"gateway unavailable: {detail}")


class LatchGateTransportError(LatchGateError):
    """Low-level transport failure (socket error, timeout, DNS, etc.)."""

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(f"transport error: {detail}")


# ---------------------------------------------------------------------------
# SDK usage errors
# ---------------------------------------------------------------------------


class LatchGateNotConnected(LatchGateError):
    """``execute()`` was called before ``connect()``."""

    def __init__(self) -> None:
        super().__init__("call connect() before execute()")
