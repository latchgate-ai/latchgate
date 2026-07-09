"""LatchGate Python SDK.

Minimal async client for the LatchGate action authorization gateway.

Quick start::

    from latchgate import LatchGateClient

    # Production (UDS — auto-discovers socket via $XDG_RUNTIME_DIR):
    async with LatchGateClient(agent_id="my-agent") as client:
        result = await client.execute("http_fetch", {"url": "https://api.example.com"})

    # Dev mode (TCP):
    async with LatchGateClient(base_url="http://localhost:3000", agent_id="my-agent") as client:
        result = await client.execute("http_fetch", {"url": "https://api.example.com"})

See the README for full documentation.
"""

from latchgate._client import LatchGateClient
from latchgate._exceptions import (
    LatchGateApprovalRequired,
    LatchGateAuthError,
    LatchGateBudgetExhausted,
    LatchGateDenied,
    LatchGateError,
    LatchGateLeaseExpired,
    LatchGateNotConnected,
    LatchGateReplayDetected,
    LatchGateTransportError,
    LatchGateUnavailable,
)
from latchgate._models import (
    ActionResult,
    ApprovalStatus,
    EgressProfile,
    ExecutionReceipt,
)

__all__ = [
    # Client
    "LatchGateClient",
    # Models
    "ActionResult",
    "ApprovalStatus",
    "EgressProfile",
    "ExecutionReceipt",
    # Exceptions
    "LatchGateError",
    "LatchGateDenied",
    "LatchGateApprovalRequired",
    "LatchGateBudgetExhausted",
    "LatchGateAuthError",
    "LatchGateLeaseExpired",
    "LatchGateReplayDetected",
    "LatchGateUnavailable",
    "LatchGateTransportError",
    "LatchGateNotConnected",
]

__version__ = "0.2.0"
