"""Unit tests for LatchGateClient (HTTP layer, error mapping, DPoP headers).

Uses ``respx`` to mock httpx at the transport level — no real gate needed.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from latchgate import (
    ActionResult,
    ApprovalStatus,
    ExecutionReceipt,
    LatchGateApprovalRequired,
    LatchGateAuthError,
    LatchGateBudgetExhausted,
    LatchGateClient,
    LatchGateDenied,
    LatchGateNotConnected,
    LatchGateUnavailable,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

BASE_URL = "http://localhost:3000"
LEASE_JWT = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhZ2VudDp0ZXN0In0.sig"
EXPIRES_AT = "2099-01-01T00:00:00Z"

LEASE_RESPONSE = {
    "lease_jwt": LEASE_JWT,
    "session_id": "sess-001",
    "lease_jti": "jti-001",
    "expires_at": EXPIRES_AT,
}

EXECUTE_OK = {
    "trace_id": "trace-001",
    "action_id": "http_fetch",
    "grant_id": "grant-001",
    "receipt_id": "rcpt-001",
    "output": {"status_code": 200, "body": "hello"},
    "verification": {"outcome": "verified", "is_fully_successful": True},
    "runtime": {"duration_ms": 150, "exit_code": 0, "fuel_consumed": 100_000},
}

RECEIPT_OK = {
    "receipt_id": "rcpt-001",
    "grant_id": "grant-001",
    "provider_module_digest": "sha256:abc",
    "provider_receipt": {"status": 200},
    "normalized_result": {"kind": "success", "summary": "HTTP 200 OK"},
    "verification_outcome": {"status": "verified", "evidence": {"status_code": 200}},
    "result_hash": "deadbeef" * 8,
    "started_at": "2026-03-01T12:00:00Z",
    "finished_at": "2026-03-01T12:00:00.150Z",
    "failure_class": None,
}

APPROVAL_PENDING = {
    "decision": "pending_approval",
    "approval_id": "appr-001",
    "request_hash": "sha256:abc",
    "trace_id": "trace-002",
}

APPROVAL_STATUS_PENDING = {
    "status": "pending",
    "retry_after_seconds": 2,
}


async def _connected_client(mock: respx.MockRouter) -> LatchGateClient:
    mock.post(f"{BASE_URL}/v1/leases").respond(200, json=LEASE_RESPONSE)
    client = LatchGateClient(base_url=BASE_URL)
    await client.connect(agent_id="test-agent")
    return client


# ---------------------------------------------------------------------------
# connect()
# ---------------------------------------------------------------------------


class TestConnect:
    @respx.mock
    async def test_connect_posts_to_leases(self) -> None:
        route = respx.post(f"{BASE_URL}/v1/leases").respond(200, json=LEASE_RESPONSE)
        async with LatchGateClient(base_url=BASE_URL) as client:
            await client.connect(agent_id="test-agent")
        assert route.called

    @respx.mock
    async def test_connect_sends_dpop_jwk_and_scopes(self) -> None:
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            captured.update(json.loads(request.content))
            return httpx.Response(200, json=LEASE_RESPONSE)

        respx.post(f"{BASE_URL}/v1/leases").mock(side_effect=capture)

        async with LatchGateClient(base_url=BASE_URL) as client:
            await client.connect(agent_id="test-agent")

        assert captured["dpop_jwk"]["kty"] == "EC"
        assert captured["dpop_jwk"]["crv"] == "P-256"
        assert "tools:call" in captured["scopes"]
        # session_id must NOT be in the request body (server-issued).
        assert "session_id" not in captured

    @respx.mock
    async def test_connect_sends_budgets_when_specified(self) -> None:
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            captured.update(json.loads(request.content))
            return httpx.Response(200, json=LEASE_RESPONSE)

        respx.post(f"{BASE_URL}/v1/leases").mock(side_effect=capture)

        async with LatchGateClient(base_url=BASE_URL) as client:
            await client.connect(max_calls=50, max_cost_usd_cents=1000)

        assert captured["budgets"]["max_calls"] == 50
        assert captured["budgets"]["max_cost_usd_cents"] == 1000

    @respx.mock
    async def test_connect_400_raises_denied(self) -> None:
        respx.post(f"{BASE_URL}/v1/leases").respond(400, json={"error": "bad_request"})
        async with LatchGateClient(base_url=BASE_URL) as client:
            with pytest.raises(LatchGateDenied):
                await client.connect()

    @respx.mock
    async def test_connect_401_raises_auth_error(self) -> None:
        respx.post(f"{BASE_URL}/v1/leases").respond(
            401, json={"error": "identity_forbidden"}
        )
        async with LatchGateClient(base_url=BASE_URL) as client:
            with pytest.raises(LatchGateAuthError):
                await client.connect()


# ---------------------------------------------------------------------------
# execute() — happy path
# ---------------------------------------------------------------------------


class TestExecute:
    @respx.mock
    async def test_execute_returns_action_result(self) -> None:
        client = await _connected_client(respx.mock)
        respx.post(f"{BASE_URL}/v1/actions/http_fetch/execute").respond(
            200, json=EXECUTE_OK
        )
        result = await client.execute("http_fetch", {"url": "https://example.com"})
        assert isinstance(result, ActionResult)
        assert result.receipt_id == "rcpt-001"
        assert result.trace_id == "trace-001"
        assert result.grant_id == "grant-001"
        assert result.output == {"status_code": 200, "body": "hello"}
        await client.close()

    @respx.mock
    async def test_execute_sends_dpop_authorization(self) -> None:
        captured_headers: dict = {}

        client = await _connected_client(respx.mock)

        def capture(request: httpx.Request) -> httpx.Response:
            captured_headers.update(dict(request.headers))
            return httpx.Response(200, json=EXECUTE_OK)

        respx.post(f"{BASE_URL}/v1/actions/http_fetch/execute").mock(
            side_effect=capture
        )
        await client.execute("http_fetch", {})

        auth = captured_headers.get("authorization", "")
        assert auth.startswith("DPoP ")
        assert LEASE_JWT in auth
        assert "dpop" in captured_headers
        assert len(captured_headers["dpop"].split(".")) == 3
        await client.close()


# ---------------------------------------------------------------------------
# execute() — error mapping
# ---------------------------------------------------------------------------


class TestExecuteErrors:
    @respx.mock
    async def test_execute_before_connect_raises_not_connected(self) -> None:
        client = LatchGateClient(base_url=BASE_URL)
        with pytest.raises(LatchGateNotConnected):
            await client.execute("http_fetch", {})
        await client.close()

    @respx.mock
    async def test_execute_202_raises_approval_required(self) -> None:
        client = await _connected_client(respx.mock)
        respx.post(f"{BASE_URL}/v1/actions/http_post/execute").respond(
            202, json=APPROVAL_PENDING
        )
        with pytest.raises(LatchGateApprovalRequired) as exc_info:
            await client.execute("http_post", {"url": "https://httpbin.org/post"})
        assert exc_info.value.approval_id == "appr-001"
        assert exc_info.value.action_id == "http_post"
        await client.close()

    @respx.mock
    async def test_execute_401_raises_auth_error(self) -> None:
        client = await _connected_client(respx.mock)
        respx.post(f"{BASE_URL}/v1/actions/http_fetch/execute").respond(
            401, json={"error": "lease_expired"}
        )
        with pytest.raises(LatchGateAuthError) as exc_info:
            await client.execute("http_fetch", {})
        assert "lease_expired" in exc_info.value.detail
        await client.close()

    @respx.mock
    async def test_execute_403_raises_denied(self) -> None:
        client = await _connected_client(respx.mock)
        respx.post(f"{BASE_URL}/v1/actions/http_fetch/execute").respond(
            403, json={"error": "policy_denied", "deny_reason": "not in ACL"}
        )
        with pytest.raises(LatchGateDenied) as exc_info:
            await client.execute("http_fetch", {})
        assert "not in ACL" in (exc_info.value.reason or "")
        await client.close()

    @respx.mock
    async def test_execute_403_budget_exhausted(self) -> None:
        client = await _connected_client(respx.mock)
        respx.post(f"{BASE_URL}/v1/actions/http_fetch/execute").respond(
            403, json={"error": "budget_exhausted"}
        )
        with pytest.raises(LatchGateBudgetExhausted):
            await client.execute("http_fetch", {})
        await client.close()

    @respx.mock
    async def test_execute_422_raises_denied_with_schema_reason(self) -> None:
        client = await _connected_client(respx.mock)
        respx.post(f"{BASE_URL}/v1/actions/http_fetch/execute").respond(
            422, json={"error": "schema_violation", "reason": "missing field 'url'"}
        )
        with pytest.raises(LatchGateDenied) as exc_info:
            await client.execute("http_fetch", {})
        assert "missing field 'url'" in (exc_info.value.reason or "")
        await client.close()

    @respx.mock
    async def test_execute_422_does_not_double_schema_violation(self) -> None:
        client = await _connected_client(respx.mock)
        respx.post(f"{BASE_URL}/v1/actions/http_fetch/execute").respond(
            422, json={"error": "schema_violation"}
        )
        with pytest.raises(LatchGateDenied) as exc_info:
            await client.execute("http_fetch", {})
        assert exc_info.value.reason == "schema_violation"
        await client.close()

    @respx.mock
    async def test_execute_503_raises_unavailable(self) -> None:
        client = await _connected_client(respx.mock)
        respx.post(f"{BASE_URL}/v1/actions/http_fetch/execute").respond(
            503, json={"error": "policy_engine_unavailable"}
        )
        with pytest.raises(LatchGateUnavailable):
            await client.execute("http_fetch", {})
        await client.close()

    @respx.mock
    async def test_execute_502_raises_unavailable(self) -> None:
        client = await _connected_client(respx.mock)
        respx.post(f"{BASE_URL}/v1/actions/http_fetch/execute").respond(
            502, json={"error": "action_execution_failed"}
        )
        with pytest.raises(LatchGateUnavailable):
            await client.execute("http_fetch", {})
        await client.close()


# ---------------------------------------------------------------------------
# get_receipt()
# ---------------------------------------------------------------------------


class TestGetReceipt:
    @respx.mock
    async def test_get_receipt_returns_receipt(self) -> None:
        client = await _connected_client(respx.mock)
        respx.get(f"{BASE_URL}/v1/receipts/rcpt-001").respond(200, json=RECEIPT_OK)
        receipt = await client.get_receipt("rcpt-001")
        assert isinstance(receipt, ExecutionReceipt)
        assert receipt.receipt_id == "rcpt-001"
        assert receipt.is_fully_successful
        await client.close()

    @respx.mock
    async def test_get_receipt_404_raises_denied(self) -> None:
        client = await _connected_client(respx.mock)
        respx.get(f"{BASE_URL}/v1/receipts/missing").respond(
            404, json={"error": "not_found"}
        )
        with pytest.raises(LatchGateDenied, match="not found"):
            await client.get_receipt("missing")
        await client.close()


# ---------------------------------------------------------------------------
# get_approval_status()
# ---------------------------------------------------------------------------


class TestGetApprovalStatus:
    @respx.mock
    async def test_get_approval_status_returns_pending(self) -> None:
        client = await _connected_client(respx.mock)
        respx.get(f"{BASE_URL}/v1/approvals/appr-001/poll").respond(
            200, json=APPROVAL_STATUS_PENDING
        )
        status = await client.get_approval_status("appr-001")
        assert isinstance(status, ApprovalStatus)
        assert status.approval_id == "appr-001"
        assert status.is_pending
        assert not status.is_approved
        assert status.retry_after_seconds == 2
        await client.close()

    @respx.mock
    async def test_get_approval_status_approved_has_receipt(self) -> None:
        client = await _connected_client(respx.mock)
        respx.get(f"{BASE_URL}/v1/approvals/appr-002/poll").respond(
            200, json={"status": "approved", "receipt_id": "rcpt-099"}
        )
        status = await client.get_approval_status("appr-002")
        assert status.is_approved
        assert status.receipt_id == "rcpt-099"
        assert status.approval_id == "appr-002"
        await client.close()

    @respx.mock
    async def test_get_approval_status_denied_has_reason(self) -> None:
        client = await _connected_client(respx.mock)
        respx.get(f"{BASE_URL}/v1/approvals/appr-003/poll").respond(
            200, json={"status": "denied", "reason": "risk too high"}
        )
        status = await client.get_approval_status("appr-003")
        assert status.is_denied
        assert status.reason == "risk too high"
        await client.close()

    @respx.mock
    async def test_get_approval_status_404_raises_denied(self) -> None:
        client = await _connected_client(respx.mock)
        respx.get(f"{BASE_URL}/v1/approvals/missing/poll").respond(
            404, json={"error": "not_found"}
        )
        with pytest.raises(LatchGateDenied, match="not found"):
            await client.get_approval_status("missing")
        await client.close()


# ---------------------------------------------------------------------------
# Lazy-connect
# ---------------------------------------------------------------------------


class TestLazyConnect:
    @respx.mock
    async def test_execute_auto_connects_when_agent_id_set(self) -> None:
        """If agent_id is set at construction, execute() auto-connects."""
        lease_route = respx.post(f"{BASE_URL}/v1/leases").respond(
            200, json=LEASE_RESPONSE
        )
        respx.post(f"{BASE_URL}/v1/actions/http_fetch/execute").respond(
            200, json=EXECUTE_OK
        )

        async with LatchGateClient(base_url=BASE_URL, agent_id="lazy-agent") as client:
            # No explicit connect() call.
            result = await client.execute("http_fetch", {"url": "https://example.com"})

        assert lease_route.called
        assert result.receipt_id == "rcpt-001"

    @respx.mock
    async def test_execute_without_agent_id_raises_not_connected(self) -> None:
        """Without agent_id, execute() raises — fail-closed."""
        client = LatchGateClient(base_url=BASE_URL)
        with pytest.raises(LatchGateNotConnected):
            await client.execute("http_fetch", {})
        await client.close()

    @respx.mock
    async def test_lazy_connect_only_connects_once(self) -> None:
        """Multiple execute() calls should reuse the lease, not re-connect."""
        lease_route = respx.post(f"{BASE_URL}/v1/leases").respond(
            200, json=LEASE_RESPONSE
        )
        respx.post(f"{BASE_URL}/v1/actions/http_fetch/execute").respond(
            200, json=EXECUTE_OK
        )

        async with LatchGateClient(base_url=BASE_URL, agent_id="lazy-agent") as client:
            await client.execute("http_fetch", {})
            await client.execute("http_fetch", {})

        assert lease_route.call_count == 1

    @respx.mock
    async def test_lazy_connect_propagates_connect_errors(self) -> None:
        """If the gate rejects the lease, the error propagates to execute()."""
        respx.post(f"{BASE_URL}/v1/leases").respond(
            401, json={"error": "identity_forbidden"}
        )

        async with LatchGateClient(base_url=BASE_URL, agent_id="lazy-agent") as client:
            with pytest.raises(LatchGateAuthError):
                await client.execute("http_fetch", {})

    @respx.mock
    async def test_agent_id_from_connect_enables_lazy_reconnect(self) -> None:
        """agent_id set via connect() should enable lazy re-connect on renewal."""
        # This tests that connect(agent_id=...) stores agent_id for later.
        respx.post(f"{BASE_URL}/v1/leases").respond(200, json=LEASE_RESPONSE)
        respx.post(f"{BASE_URL}/v1/actions/http_fetch/execute").respond(
            200, json=EXECUTE_OK
        )

        async with LatchGateClient(base_url=BASE_URL) as client:
            await client.connect(agent_id="explicit-agent")
            result = await client.execute("http_fetch", {})
            assert result.receipt_id == "rcpt-001"


# ---------------------------------------------------------------------------
# LATCHGATE_URL env var
# ---------------------------------------------------------------------------


class TestLatchgateUrlEnv:
    @respx.mock
    async def test_reads_base_url_from_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Client picks up LATCHGATE_URL when no base_url is passed."""
        monkeypatch.setenv("LATCHGATE_URL", BASE_URL)

        lease_route = respx.post(f"{BASE_URL}/v1/leases").respond(
            200, json=LEASE_RESPONSE
        )

        async with LatchGateClient(agent_id="env-agent") as client:
            await client.connect()

        assert lease_route.called

    @respx.mock
    async def test_explicit_base_url_overrides_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Explicit base_url takes priority over LATCHGATE_URL."""
        monkeypatch.setenv("LATCHGATE_URL", "http://wrong:9999")

        lease_route = respx.post(f"{BASE_URL}/v1/leases").respond(
            200, json=LEASE_RESPONSE
        )

        async with LatchGateClient(base_url=BASE_URL, agent_id="env-agent") as client:
            await client.connect()

        assert lease_route.called


# ---------------------------------------------------------------------------
# Session properties
# ---------------------------------------------------------------------------


class TestSessionProperties:
    @respx.mock
    async def test_session_id_available_after_connect(self) -> None:
        respx.post(f"{BASE_URL}/v1/leases").respond(200, json=LEASE_RESPONSE)
        async with LatchGateClient(base_url=BASE_URL) as client:
            assert client.session_id is None
            await client.connect(agent_id="test")
            assert client.session_id == "sess-001"

    @respx.mock
    async def test_lease_jti_available_after_connect(self) -> None:
        respx.post(f"{BASE_URL}/v1/leases").respond(200, json=LEASE_RESPONSE)
        async with LatchGateClient(base_url=BASE_URL) as client:
            assert client.lease_jti is None
            await client.connect(agent_id="test")
            assert client.lease_jti == "jti-001"

    @respx.mock
    async def test_properties_survive_reconnect(self) -> None:
        """Properties update on each connect() call."""
        respx.post(f"{BASE_URL}/v1/leases").respond(
            200,
            json={
                **LEASE_RESPONSE,
                "session_id": "sess-new",
                "lease_jti": "jti-new",
            },
        )
        async with LatchGateClient(base_url=BASE_URL) as client:
            await client.connect(agent_id="test")
            assert client.session_id == "sess-new"
            assert client.lease_jti == "jti-new"


# ---------------------------------------------------------------------------
# Defensive JSON parsing
# ---------------------------------------------------------------------------


class TestJsonParsing:
    @respx.mock
    async def test_connect_non_json_response_raises_transport_error(self) -> None:
        from latchgate import LatchGateTransportError

        respx.post(f"{BASE_URL}/v1/leases").respond(
            200, text="<html>proxy error</html>"
        )
        async with LatchGateClient(base_url=BASE_URL) as client:
            with pytest.raises(LatchGateTransportError, match="invalid JSON"):
                await client.connect(agent_id="test")

    @respx.mock
    async def test_execute_non_json_response_raises_transport_error(self) -> None:
        from latchgate import LatchGateTransportError

        client = await _connected_client(respx.mock)
        respx.post(f"{BASE_URL}/v1/actions/http_fetch/execute").respond(
            200, text="not json"
        )
        with pytest.raises(LatchGateTransportError, match="invalid JSON"):
            await client.execute("http_fetch", {})
        await client.close()
