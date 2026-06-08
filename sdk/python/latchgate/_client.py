"""LatchGate async client.

Typical usage::

    from latchgate import LatchGateClient

    # Minimal - reads LATCHGATE_URL from environment:
    async with LatchGateClient(agent_id="my-agent") as client:
        result = await client.execute("http_fetch", {"url": "https://api.example.com/data"})

    # Explicit:
    async with LatchGateClient(base_url="http://localhost:3000", agent_id="my-agent") as client:
        result = await client.execute("http_fetch", {"url": "https://api.example.com/data"})

Connection model
----------------
``connect()`` generates a fresh P-256 DPoP key pair and exchanges it for a
Lease JWT via ``POST /v1/leases``.  The lease is automatically refreshed
when fewer than ``_RENEW_THRESHOLD_SECONDS`` seconds remain before expiry.

If ``agent_id`` is set (constructor or ``connect()``), the first call to
``execute()`` will auto-connect.  If ``agent_id`` is not set, ``execute()``
raises ``LatchGateNotConnected``.

Transport
---------
The client resolves the gate URL in this order:

1. ``base_url`` constructor argument (TCP)
2. ``LATCHGATE_URL`` environment variable (TCP)
3. ``socket`` constructor argument (UDS, default: ``$XDG_RUNTIME_DIR/latchgate/gate.sock``)
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from datetime import datetime, timezone
from typing import Any

import httpx

from latchgate._crypto import DPoPKeyPair, compute_ath
from latchgate._exceptions import (
    LatchGateApprovalRequired,
    LatchGateAuthError,
    LatchGateBudgetExhausted,
    LatchGateDenied,
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

# Renew the lease when fewer than this many seconds remain before expiry.
_RENEW_THRESHOLD_SECONDS = 60

# Environment variable for the gate URL - checked when no base_url is passed.
_ENV_LATCHGATE_URL = "LATCHGATE_URL"

# Identifier format: alphanumeric, hyphens, underscores, dots. No path separators.
_IDENTIFIER_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")


def _validate_identifier(value: str, label: str) -> None:
    """Validate that an identifier is safe for URL path interpolation.

    Rejects empty strings, path separators, URL-special characters, and
    excessive length.  Defense-in-depth: the gate also validates, but
    rejecting at the SDK boundary prevents path traversal before the
    request reaches the network.

    Raises
    ------
    ValueError
        If the identifier is empty, too long, or contains invalid characters.
    """
    if not value:
        raise ValueError(f"{label} must not be empty")
    if len(value) > 256:
        raise ValueError(f"{label} exceeds maximum length (256)")
    if not _IDENTIFIER_PATTERN.match(value):
        raise ValueError(f"{label} contains invalid characters")


def _default_socket_path() -> str:
    """Resolve the default UDS socket path.

    Algorithm must match the CLI (``crates/latchgate-cli/src/cmd/util.rs``
    ``default_uds_path``) so that ``latchgate up`` and
    ``LatchGateClient()`` agree without manual configuration.

    Resolution order:
    1. ``$XDG_RUNTIME_DIR/latchgate/gate.sock``
    2. ``/tmp/latchgate-{uid}/gate.sock``
    """
    xdg = os.environ.get("XDG_RUNTIME_DIR", "")
    if xdg:
        return os.path.join(xdg, "latchgate", "gate.sock")
    return f"/tmp/latchgate-{os.getuid()}/gate.sock"


class LatchGateClient:
    """Async client for the LatchGate action authorization gateway.

    Parameters
    ----------
    socket:
        Path to the Unix domain socket. Mutually exclusive with ``base_url``.
        Defaults to ``$XDG_RUNTIME_DIR/latchgate/gate.sock`` (or
        ``/tmp/latchgate-{uid}/gate.sock`` when ``XDG_RUNTIME_DIR`` is unset).
    base_url:
        HTTP base URL (e.g. ``"http://localhost:8080"``).  Used when the
        server is bound to TCP rather than a UDS socket.  If not provided,
        falls back to the ``LATCHGATE_URL`` environment variable.
    public_base_url:
        Canonical URL used for DPoP ``htu`` construction.  Must match the
        ``public_base_url`` field in ``latchgate.toml`` exactly.  For TCP
        transport this defaults to ``base_url``.  For UDS this **must** be
        set explicitly (e.g. ``"http://localhost:3000"``) — the gate
        verifies DPoP proofs against its configured public URL.
    timeout:
        Default request timeout in seconds.  Applies to all API calls.
    agent_id:
        Agent identifier.  When set, ``execute()`` will auto-connect on the
        first call (lazy-connect).  Without ``agent_id``, ``execute()`` raises
        ``LatchGateNotConnected`` unless ``connect()`` was called explicitly.

    Notes
    -----
    Use as an async context manager to ensure the underlying HTTP transport
    is cleanly closed::

        async with LatchGateClient(agent_id="my-agent") as client:
            result = await client.execute("http_fetch", {"url": "https://example.com"})
    """

    def __init__(
        self,
        *,
        socket: str | None = None,
        base_url: str | None = None,
        public_base_url: str | None = None,
        timeout: float = 30.0,
        agent_id: str | None = None,
    ) -> None:
        # Resolve base_url: explicit arg > env var > UDS fallback.
        resolved_url = base_url or os.environ.get(_ENV_LATCHGATE_URL)

        if resolved_url is None:
            transport = httpx.AsyncHTTPTransport(uds=socket or _default_socket_path())
            self._base_url = "http://localhost"
            self._http = httpx.AsyncClient(transport=transport, timeout=timeout)
        else:
            self._base_url = resolved_url.rstrip("/")
            self._http = httpx.AsyncClient(base_url=self._base_url, timeout=timeout)

        # Public base URL for DPoP htu construction.  For TCP transport
        # this defaults to the transport base URL.  For UDS the caller
        # must provide it explicitly — the gate verifies htu against its
        # own public_base_url and "http://localhost" will not match.
        if public_base_url is not None:
            self._public_base_url = public_base_url.rstrip("/")
        else:
            self._public_base_url = self._base_url

        self._timeout = timeout
        self._agent_id: str | None = agent_id

        # State populated by connect()
        self._keypair: DPoPKeyPair | None = None
        self._lease_jwt: str | None = None
        self._lease_expires_at: datetime | None = None
        self._session_id: str | None = None
        self._lease_jti: str | None = None

        # Coalescing task for connect(). Multiple concurrent callers of
        # _ensure_lease() await the same in-flight task instead of blocking
        # behind a lock held across network I/O.
        self._connect_task: asyncio.Task[None] | None = None

    # -------------------------------------------------------------------------
    # Transport accessors (used by framework integrations for discovery)
    # -------------------------------------------------------------------------

    @property
    def gate_url(self) -> str:
        """Canonical public URL of the LatchGate gate.

        Returns the ``public_base_url`` when set, otherwise the transport
        base URL.  Framework integrations use this for unauthenticated
        discovery endpoints and DPoP ``htu`` construction.
        """
        return self._public_base_url

    @property
    def http_transport(self) -> httpx.AsyncClient:
        """Underlying HTTP transport.

        Exposed for framework integrations that need to reuse the transport
        (e.g. UDS-configured ``httpx.AsyncClient``) for action discovery.
        The caller must not close this client - ownership remains with
        :class:`LatchGateClient`.
        """
        return self._http

    @property
    def session_id(self) -> str | None:
        """Server-issued session identifier from the current lease.

        Available after ``connect()`` completes.  Used by the gate for
        policy decisions and audit attribution.
        """
        return self._session_id

    @property
    def lease_jti(self) -> str | None:
        """Unique lease JWT identifier from the current lease.

        Available after ``connect()`` completes.  Useful for forensic
        correlation with server-side audit events.
        """
        return self._lease_jti

    # -------------------------------------------------------------------------
    # Context manager
    # -------------------------------------------------------------------------

    async def __aenter__(self) -> LatchGateClient:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    async def close(self) -> None:
        """Close the underlying HTTP transport."""
        await self._http.aclose()

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    async def connect(
        self,
        *,
        agent_id: str | None = None,
        scopes: list[str] | None = None,
        max_calls: int | None = None,
        max_cost_usd_cents: int | None = None,
    ) -> None:
        """Obtain a Lease JWT and prepare the DPoP key pair.

        Parameters
        ----------
        agent_id:
            Principal identifier for this agent (e.g. ``"agent:my-bot"``).
            Overrides the value set at construction time.
        scopes:
            JWT scopes to request.  Defaults to ``["tools:call"]``.
        max_calls:
            Optional budget: maximum number of action calls under this lease.
        max_cost_usd_cents:
            Optional budget: maximum cost in USD cents under this lease.
        """
        if agent_id:
            self._agent_id = agent_id

        keypair = DPoPKeyPair.generate()
        requested_scopes = scopes or ["tools:call"]

        body: dict[str, Any] = {
            "scopes": requested_scopes,
            "dpop_jwk": keypair.jwk,
        }
        if max_calls is not None or max_cost_usd_cents is not None:
            body["budgets"] = {
                k: v
                for k, v in [
                    ("max_calls", max_calls),
                    ("max_cost_usd_cents", max_cost_usd_cents),
                ]
                if v is not None
            }

        url = f"{self._base_url}/v1/leases"
        try:
            resp = await self._http.post(url, json=body)
        except httpx.TransportError as exc:
            raise LatchGateTransportError(str(exc)) from exc

        _raise_for_status(resp, action_id="<connect>")

        data = _json_body(resp, context="lease")
        self._keypair = keypair
        self._lease_jwt = data["lease_jwt"]
        self._session_id = data.get("session_id")
        self._lease_jti = data.get("lease_jti")
        self._lease_expires_at = _parse_iso(data["expires_at"])

    async def execute(
        self,
        action_id: str,
        params: dict[str, Any] | None = None,
    ) -> ActionResult:
        """Execute a protected action.

        If ``agent_id`` was set at construction time and no lease exists,
        automatically calls ``connect()`` first (lazy-connect).

        Parameters
        ----------
        action_id:
            Registered action identifier (e.g. ``"http_fetch"``).
        params:
            Action input parameters that match the action's JSON Schema.

        Returns
        -------
        ActionResult

        Raises
        ------
        LatchGateApprovalRequired
            The action requires human approval.
        LatchGateDenied
            The action was denied by policy.
        LatchGateBudgetExhausted
            The caller's budget is exhausted.
        LatchGateAuthError
            Authentication failed.
        LatchGateUnavailable
            The gateway or a dependency is temporarily unavailable.
        LatchGateTransportError
            Low-level transport failure.
        LatchGateNotConnected
            No ``agent_id`` set and ``connect()`` was not called.
        """
        _validate_identifier(action_id, "action_id")
        await self._ensure_lease()

        path = f"/v1/actions/{action_id}/execute"
        url = f"{self._base_url}{path}"
        body = json.dumps(params or {}).encode()
        headers = self._dpop_headers("POST", path)

        try:
            resp = await self._http.post(
                url,
                content=body,
                headers={**headers, "Content-Type": "application/json"},
            )
        except httpx.TransportError as exc:
            raise LatchGateTransportError(str(exc)) from exc

        # 202 = pending approval (not an error from transport perspective)
        if resp.status_code == 202:
            data = _json_body(resp, context="execute (approval)")
            raise LatchGateApprovalRequired(
                action_id=action_id,
                approval_id=data["approval_id"],
            )

        _raise_for_status(resp, action_id=action_id)
        return ActionResult._from_json(_json_body(resp, context="execute"))

    async def get_receipt(self, receipt_id: str) -> ExecutionReceipt:
        """Retrieve a stored execution receipt by ID.

        Parameters
        ----------
        receipt_id:
            The ``receipt_id`` from a previous :class:`ActionResult`.

        Returns
        -------
        ExecutionReceipt

        Raises
        ------
        LatchGateDenied
            No receipt with the given ID exists (404 mapped to denied).
        LatchGateTransportError
            Low-level transport failure.
        """
        _validate_identifier(receipt_id, "receipt_id")
        await self._ensure_lease()

        path = f"/v1/receipts/{receipt_id}"
        url = f"{self._base_url}{path}"
        headers = self._dpop_headers("GET", path)

        try:
            resp = await self._http.get(url, headers=headers)
        except httpx.TransportError as exc:
            raise LatchGateTransportError(str(exc)) from exc

        if resp.status_code == 404:
            raise LatchGateDenied(
                action_id="<receipt>",
                reason=f"receipt '{receipt_id}' not found",
            )

        _raise_for_status(resp, action_id="<receipt>")
        return ExecutionReceipt._from_json(_json_body(resp, context="receipt"))

    async def get_approval_status(self, approval_id: str) -> ApprovalStatus:
        """Retrieve the current status of a pending approval.

        Intended for polling after receiving :class:`LatchGateApprovalRequired`::

            try:
                result = await client.execute("http_post", params)
            except LatchGateApprovalRequired as exc:
                while True:
                    status = await client.get_approval_status(exc.approval_id)
                    if not status.is_pending:
                        break
                    await asyncio.sleep(5)

        Parameters
        ----------
        approval_id:
            The ``approval_id`` from :class:`LatchGateApprovalRequired`.
        """
        _validate_identifier(approval_id, "approval_id")
        await self._ensure_lease()

        path = f"/v1/approvals/{approval_id}/poll"
        url = f"{self._base_url}{path}"
        headers = self._dpop_headers("GET", path)

        try:
            resp = await self._http.get(url, headers=headers)
        except httpx.TransportError as exc:
            raise LatchGateTransportError(str(exc)) from exc

        if resp.status_code == 404:
            raise LatchGateDenied(
                action_id="<approval>",
                reason=f"approval '{approval_id}' not found",
            )

        _raise_for_status(resp, action_id="<approval>")
        data = _json_body(resp, context="approval poll")
        # The poll endpoint returns {status, receipt_id?, reason?,
        # retry_after_seconds?} — approval_id is not in the response
        # since the agent already knows it from the request path.
        data.setdefault("approval_id", approval_id)
        return ApprovalStatus._from_json(data)

    async def get_action_egress(self, action_id: str) -> EgressProfile:
        """Fetch the egress profile for an action.

        Returns the declared egress domains and profile kind, useful for
        orchestrator UIs showing which external services an action may contact.

        Parameters
        ----------
        action_id:
            The action to inspect.

        Returns
        -------
        EgressProfile

        Raises
        ------
        LatchGateDenied
            Action not found (404).
        """
        _validate_identifier(action_id, "action_id")
        await self._ensure_lease()

        path = f"/v1/actions/{action_id}"
        url = f"{self._base_url}{path}"
        headers = self._dpop_headers("GET", path)

        try:
            resp = await self._http.get(url, headers=headers)
        except httpx.TransportError as exc:
            raise LatchGateTransportError(str(exc)) from exc

        if resp.status_code == 404:
            raise LatchGateDenied(
                action_id=action_id,
                reason=f"action '{action_id}' not found",
            )

        _raise_for_status(resp, action_id=action_id)
        data = _json_body(resp, context="action egress")
        return EgressProfile._from_json(data.get("egress"))

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    async def _ensure_lease(self) -> None:
        """Ensure a valid lease exists. Auto-connect if agent_id is set.

        Uses task coalescing: if a ``connect()`` call is already in flight,
        concurrent callers await the same task rather than queuing behind a
        lock held across network I/O. This mirrors the TypeScript SDK's
        ``connectPromise`` pattern.
        """
        needs_connect = False

        if self._keypair is None or self._lease_jwt is None:
            if self._agent_id is None:
                raise LatchGateNotConnected()
            needs_connect = True
        elif self._lease_expires_at is not None:
            remaining = (
                self._lease_expires_at - datetime.now(tz=timezone.utc)
            ).total_seconds()
            if remaining < _RENEW_THRESHOLD_SECONDS:
                needs_connect = True

        if not needs_connect:
            return

        await self._coalesced_connect()

    async def _coalesced_connect(self) -> None:
        """Run or join an in-flight connect() call.

        If no connect task is running (or the previous one completed),
        spawn a new one. Otherwise, await the existing task. All concurrent
        callers coalesce onto the same network round-trip — no lock is held
        across I/O.

        If the shared task raises, the exception propagates to every waiter.
        The failed task is cleared so the next caller retries with a fresh
        attempt.
        """
        task = self._connect_task
        if task is None or task.done():
            task = asyncio.create_task(self.connect())
            self._connect_task = task

        try:
            await asyncio.shield(task)
        except BaseException:
            # Clear the failed task so the next call retries fresh rather
            # than re-awaiting a task whose exception was already consumed.
            if self._connect_task is task:
                self._connect_task = None
            raise

    def _dpop_headers(self, method: str, path: str) -> dict[str, str]:
        """Build ``Authorization`` and ``DPoP`` headers for a request.

        Parameters
        ----------
        method:
            HTTP method in uppercase (e.g. ``"POST"``).
        path:
            Request path (e.g. ``"/v1/actions/http_fetch/execute"``).
            The DPoP ``htu`` is constructed as ``public_base_url + path``.
        """
        if self._keypair is None or self._lease_jwt is None:
            raise LatchGateNotConnected()
        htu = f"{self._public_base_url}{path}"
        ath = compute_ath(self._lease_jwt)
        proof = self._keypair.sign_proof(htm=method, htu=htu, ath=ath)
        return {
            "Authorization": f"DPoP {self._lease_jwt}",
            "DPoP": proof,
        }


# ---------------------------------------------------------------------------
# Response parsing helpers
# ---------------------------------------------------------------------------


def _json_body(resp: httpx.Response, *, context: str) -> dict[str, Any]:
    """Parse a JSON object from a successful response.

    Raises :class:`LatchGateTransportError` if the body is not valid JSON
    or is not a JSON object.  This catches proxy/CDN HTML error pages that
    arrive with a 200 status code.
    """
    try:
        data = resp.json()
    except Exception as exc:
        raise LatchGateTransportError(f"invalid JSON in {context} response") from exc
    if not isinstance(data, dict):
        raise LatchGateTransportError(
            f"expected JSON object in {context} response, " f"got {type(data).__name__}"
        )
    return data


# ---------------------------------------------------------------------------
# Error mapping helpers
# ---------------------------------------------------------------------------


def _raise_for_status(resp: httpx.Response, *, action_id: str) -> None:
    """Map HTTP error responses to LatchGate exceptions.

    This is intentionally explicit rather than using ``resp.raise_for_status()``
    so that each status code maps to the correct typed exception.
    """
    if resp.is_success:
        return

    try:
        body = resp.json()
    except Exception:
        body = {}

    error_code: str = body.get("error", "unknown")

    match resp.status_code:
        case 400:
            raise LatchGateDenied(action_id, reason=error_code)
        case 401:
            if error_code == "lease_expired":
                raise LatchGateLeaseExpired(error_code)
            if error_code == "replay_detected":
                raise LatchGateReplayDetected(error_code)
            raise LatchGateAuthError(error_code)
        case 403:
            if error_code == "budget_exhausted":
                raise LatchGateBudgetExhausted(action_id)
            # The gate surfaces a sanitized deny_reason on policy_denied
            # (see crates/latchgate-kernel/src/pipeline.rs). Include it so
            # callers see the specific cause - missing secret, disallowed
            # domain, ACL gap - not just the generic class.
            deny_reason = body.get("deny_reason")
            if deny_reason:
                raise LatchGateDenied(action_id, reason=f"{error_code}: {deny_reason}")
            raise LatchGateDenied(action_id, reason=error_code)
        case 422:
            # 422 bodies carry only {"error": "schema_violation"} (no reason
            # field). Earlier code did body.get("reason", error_code), which
            # produced the doubled "schema_violation: schema_violation".
            # Append reason only when actually present and distinct.
            reason = body.get("reason")
            if reason and reason != error_code:
                raise LatchGateDenied(action_id, reason=f"{error_code}: {reason}")
            raise LatchGateDenied(action_id, reason=error_code)
        case 503 | 502:
            raise LatchGateUnavailable(error_code)
        case _:
            raise LatchGateUnavailable(
                f"unexpected status {resp.status_code}: {error_code}"
            )


def _parse_iso(value: str) -> datetime:
    """Parse an ISO 8601 timestamp with timezone info."""
    # Python 3.11+ handles Z suffix; for 3.10 compatibility replace it.
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
