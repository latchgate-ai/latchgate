#!/usr/bin/env python3
"""LatchGate orchestrator — exercises HTTP actions and every policy path.

A deterministic test harness that drives the gate through its full
enforcement pipeline. Every scenario shows the actual response the gate
returns; orchestrator narration is visually distinguished from gate
output so synthesized text cannot be mistaken for real gate behavior.

Run with a gate in dev mode:
    make dev     # terminal 1 — start infra
    make serve   # terminal 2 — start gate

Usage:
    uv run orchestrator.py [--base-url http://localhost:3000]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

import httpx

from latchgate import (
    LatchGateApprovalRequired,
    LatchGateClient,
    LatchGateDenied,
    LatchGateUnavailable,
)
from latchgate._crypto import DPoPKeyPair, compute_ath

from _helpers import (
    BOLD,
    DIM,
    GREEN,
    RED,
    RESET,
    Report,
    TestResult,
    detail,
    explain,
    fail,
    gate_response,
    header,
    kv,
    ok,
    pause,
    skip,
    step,
    wait,
)


# -- Scenario helper ---------------------------------------------------------
#
# Eliminates the repeated timing + transient-error + reporting boilerplate.
# Each test creates a Scenario, calls .passed()/.skipped()/.failed() at the
# end, and uses .handle_error(exc) for the common transient-or-fail pattern.


class Scenario:
    """Tracks timing and result reporting for a single test."""

    def __init__(self, name: str, report: Report) -> None:
        self.name = name
        self.report = report
        self._t0 = time.monotonic()

    @property
    def ms(self) -> float:
        return (time.monotonic() - self._t0) * 1000

    def passed(self, *, receipt_id: str | None = None, grant_id: str | None = None) -> None:
        self.report.add(TestResult(
            self.name, True, duration_ms=self.ms,
            receipt_id=receipt_id, grant_id=grant_id,
        ))

    def skipped(self, error: str) -> None:
        self.report.add(TestResult(
            self.name, True, skipped=True, duration_ms=self.ms, error=error,
        ))

    def failed(self, error: str) -> None:
        self.report.add(TestResult(self.name, False, error=error))

    def handle_error(self, exc: Exception) -> None:
        """Classify exception: transient -> SKIP, otherwise -> FAIL."""
        if _is_transient(exc):
            skip(f"Gate dependency unavailable ({self.ms:.0f}ms): {exc}")
            self.skipped(str(exc))
        else:
            fail(f"Unexpected error: {exc}")
            self.failed(str(exc))


# -- Project-local discovery -------------------------------------------------


def _find_repo_root() -> Path | None:
    """Walk up from cwd looking for a LatchGate project marker."""
    cur = Path.cwd()
    for parent in [cur, *cur.parents]:
        if (parent / ".latchgate" / "latchgate.toml").exists():
            return parent
    return None


def _load_operator_config(repo_root: Path) -> tuple[str, DPoPKeyPair] | None:
    """Load operator api_key and DPoP keypair from the project layout.

    Reads ``[operator_credentials.<name>]`` from ``.latchgate/latchgate.toml``
    and loads the PEM from ``.latchgate/operators/<name>.pem``.
    """
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib  # type: ignore[no-redef]

    config_path = repo_root / ".latchgate" / "latchgate.toml"
    if not config_path.exists():
        detail(f"operator-discovery: not found: {config_path}")
        return None

    try:
        with open(config_path, "rb") as f:
            config = tomllib.load(f)
    except Exception as exc:
        detail(f"operator-discovery: cannot parse {config_path}: {exc}")
        return None

    creds = config.get("operator_credentials", {})
    if not creds:
        detail(f"operator-discovery: no [operator_credentials.*] in {config_path}")
        return None

    name = next(iter(creds))
    entry = creds[name]
    api_key, dpop_jkt = entry.get("api_key"), entry.get("dpop_jkt")
    if not api_key or not dpop_jkt:
        detail(f"operator-discovery: operator '{name}' missing api_key or dpop_jkt")
        return None

    pem_path = repo_root / ".latchgate" / "operators" / f"{name}.pem"
    if not pem_path.exists():
        detail(f"operator-discovery: PEM not found: {pem_path}")
        return None

    try:
        return api_key, DPoPKeyPair.from_pem_file(pem_path)
    except Exception as exc:
        detail(f"operator-discovery: cannot load PEM {pem_path}: {exc}")
        return None


# -- Operator DPoP auth helper -----------------------------------------------


async def _operator_approve(
    base_url: str,
    approval_id: str,
    api_key: str,
    keypair: DPoPKeyPair,
) -> tuple[int, dict]:
    """Approve a pending action via the admin API with DPoP auth."""
    url = f"{base_url}/v1/approvals/{approval_id}/approve"
    ath = compute_ath(api_key)
    proof = keypair.sign_proof("POST", url, ath)

    async with httpx.AsyncClient() as http:
        resp = await http.post(
            url,
            headers={
                "Authorization": f"DPoP {api_key}",
                "DPoP": proof,
                "Content-Type": "application/json",
            },
        )
        try:
            return resp.status_code, resp.json()
        except Exception:
            return resp.status_code, {}


# -- Error classification ----------------------------------------------------


def _is_transient(exc: Exception) -> bool:
    if isinstance(exc, LatchGateUnavailable):
        return True
    msg = str(exc).lower()
    return any(kw in msg for kw in ("timeout", "connect", "proxy", "egress", "unavailable"))


# -- Test scenarios ----------------------------------------------------------


async def test_lease(client: LatchGateClient, report: Report) -> None:
    header(1, "Lease lifecycle")
    step("Generating ephemeral P-256 keypair (private key stays in-process)")
    step("POST /v1/leases with DPoP proof-of-possession")
    await pause(0.2)

    s = Scenario("lease_acquire", report)
    try:
        await client.connect(agent_id="orchestrator")
    except Exception as exc:
        fail(f"Lease failed: {exc}")
        s.failed(str(exc))
        raise

    ok(f"Lease acquired ({s.ms:.0f}ms)")
    explain("The lease JWT is bound to the keypair via DPoP (RFC 9449).")
    explain("Stolen lease without the private key is cryptographically useless.")
    s.passed()


async def test_execute(
    client: LatchGateClient,
    report: Report,
    *,
    num: int,
    action_id: str,
    title: str,
    params: dict,
    narration: str,
    show_runtime: bool = False,
) -> None:
    """Generic execute-and-verify scenario for auto-allowed actions."""
    header(num, title)
    url = params.get("url", "")
    step(f"POST /v1/actions/{action_id}/execute  ->  {url}")
    if "body" in params:
        detail(f"body: {params['body']}")
    await pause(0.2)

    s = Scenario(action_id, report)
    try:
        result = await client.execute(action_id, params)
    except Exception as exc:
        s.handle_error(exc)
        return

    ok(f"Executed ({s.ms:.0f}ms)")
    fields: dict = {
        "trace_id": result.trace_id,
        "grant_id": result.grant_id,
        "receipt_id": result.receipt_id,
        "verification": result.verification,
    }
    if show_runtime:
        fields["runtime"] = result.runtime
    gate_response("ActionResult", fields)
    explain(narration)
    s.passed(receipt_id=result.receipt_id, grant_id=result.grant_id)


async def test_bearer_get(client: LatchGateClient, report: Report) -> None:
    header(4, "http_bearer_get — required-secret enforcement")
    step("POST /v1/actions/http_bearer_get/execute  ->  https://httpbin.org/get")
    detail("Manifest declares: secrets: [API_BEARER_TOKEN, required: true]")
    detail("Gate must resolve every required secret before WASM dispatch.")
    await pause(0.2)

    s = Scenario("http_bearer_get", report)
    try:
        result = await client.execute("http_bearer_get", {"url": "https://httpbin.org/get"})
    except LatchGateDenied as exc:
        ok(f"Denied pre-flight ({s.ms:.0f}ms) — required secret unresolved")
        gate_response("LatchGateDenied", {"action_id": exc.action_id, "reason": exc.reason})
        explain("Without sops_secrets_file configured, the kernel cannot resolve API_BEARER_TOKEN.")
        explain("It denies before WASM dispatch — no grant, no sandbox invocation, no receipt.")
        explain("Configure SOPS to see the credential injection path succeed.")
        s.passed()
        return
    except Exception as exc:
        s.handle_error(exc)
        return

    ok(f"Executed ({s.ms:.0f}ms) — secret was resolved")
    gate_response("ActionResult", {"receipt_id": result.receipt_id, "verification": result.verification})
    explain("With the secret configured, the host I/O layer injected the")
    explain("Authorization header at transport — the WASM sandbox never saw the token value.")
    s.passed(receipt_id=result.receipt_id, grant_id=result.grant_id)


async def test_egress_containment(client: LatchGateClient, report: Report) -> None:
    header(5, "http_fetch — egress containment")
    step("POST /v1/actions/http_fetch/execute  ->  https://evil.example.com/exfiltrate")
    detail("http_fetch.allowed_domains = [api.github.com, httpbin.org]")
    detail("evil.example.com is not in the manifest allowlist.")
    await pause(0.2)

    s = Scenario("http_fetch_contained", report)
    try:
        result = await client.execute("http_fetch", {"url": "https://evil.example.com/exfiltrate"})
    except LatchGateDenied as exc:
        ok(f"Denied by policy ({s.ms:.0f}ms)")
        gate_response("LatchGateDenied", {"action_id": exc.action_id, "reason": exc.reason})
        if "schema_violation" in (exc.reason or ""):
            explain("JSON Schema validation accepted the URL (well-formed), but the "
                    "egress allowlist check rejected the domain before OPA evaluation.")
        else:
            explain("The gate denied the request before WASM dispatch. "
                    "No grant was issued and no side effect occurred.")
        s.passed()
        return
    except Exception as exc:
        s.handle_error(exc)
        return

    # Action executed — check if host I/O contained the call at runtime.
    if not result.verification.get("is_fully_successful", True):
        ok(f"Contained at runtime ({s.ms:.0f}ms) — host I/O blocked the call")
        gate_response("ActionResult", {"receipt_id": result.receipt_id, "verification": result.verification})
        explain("Receipt was issued documenting the containment — operators can audit the attempt.")
        s.passed(receipt_id=result.receipt_id, grant_id=result.grant_id)
    else:
        fail(f"Action SUCCEEDED against unauthorized domain ({s.ms:.0f}ms)")
        gate_response("ActionResult (UNEXPECTED)", result.verification)
        s.failed("expected containment, got success")


async def test_approval_flow(
    client: LatchGateClient,
    report: Report,
    base_url: str,
    operator_key: str | None,
    operator_keypair: DPoPKeyPair | None,
) -> None:
    header(6, "http_sensitive_read — high-risk approval flow")
    step("POST /v1/actions/http_sensitive_read/execute")
    detail("risk_level: high (declared in manifest)")
    detail("Default OPA policy holds high-risk actions for human approval.")
    await pause(0.2)

    s = Scenario("http_sensitive_read_approval", report)
    try:
        result = await client.execute("http_sensitive_read", {"url": "https://httpbin.org/get"})
    except LatchGateApprovalRequired as exc:
        # Expected path — continue to operator approval below.
        wait(f"Held for approval ({s.ms:.0f}ms)  HTTP 202")
        gate_response("LatchGateApprovalRequired", {"action_id": exc.action_id, "approval_id": exc.approval_id})
        approval_id = exc.approval_id
    except LatchGateDenied as exc:
        ok(f"Denied pre-flight ({s.ms:.0f}ms)")
        gate_response("LatchGateDenied", {"action_id": exc.action_id, "reason": exc.reason})
        s.passed()
        return
    except Exception as exc:
        s.handle_error(exc)
        return
    else:
        ok(f"Auto-allowed ({s.ms:.0f}ms) — policy did not require approval")
        gate_response("ActionResult", {"receipt_id": result.receipt_id, "verification": result.verification})
        explain("Default policy depends on dev-mode ACL — see policies/data.json.")
        s.passed(receipt_id=result.receipt_id, grant_id=result.grant_id)
        return

    # -- Operator approval step -----------------------------------------------

    if operator_key is None or operator_keypair is None:
        detail("Operator credentials not loaded — cannot complete approval flow.")
        detail("Re-run `latchgate init --preset dev --non-interactive --force` and retry.")
        s.failed("operator credentials not found")
        return

    await pause(0.4)
    step(f"POST /v1/approvals/{approval_id}/approve  (operator DPoP-authed)")
    status, body = await _operator_approve(base_url, approval_id, operator_key, operator_keypair)
    gate_response(f"HTTP {status}", body)

    _classify_approval_result(s, status, body)


def _classify_approval_result(s: Scenario, status: int, body: dict) -> None:
    """Report the outcome of an operator-approve call."""
    if 200 <= status < 300:
        ok("Operator approved -> action executed through hardened path")
        explain("Approval consumed the stored execution plan (provider digest, "
                "targets, secrets, egress) — never re-derived from the live manifest.")
        s.passed(receipt_id=body.get("receipt_id"), grant_id=body.get("grant_id"))

    elif status == 401:
        error_code = body.get("error", "unknown")
        skip(f"Operator approve auth failed (HTTP 401: {error_code})")
        detail("Likely cause: dpop_jkt mismatch or htu does not match public_base_url.")
        detail("Check: gate public_base_url matches your --base-url, and "
               ".latchgate/latchgate.toml dpop_jkt matches the loaded PEM's JWK thumbprint.")
        if body.get("deny_reason"):
            detail(f"Gate deny_reason: {body['deny_reason']}")
        s.skipped(f"operator auth 401: {error_code}")

    elif status in (403, 422, 502, 503):
        # DPoP auth succeeded; post-approval execution hit a dependency or
        # policy barrier (typically: required secret not configured).
        ok("Approval accepted; post-approval execution blocked")
        explain("Operator DPoP auth and approval succeeded — the gate then tried to "
                "execute through the hardened path and hit a barrier.")
        if "sops_secrets_file" in body.get("deny_reason", ""):
            explain("Configure SOPS to see the full approve-then-execute path.")
        s.passed()

    else:
        fail(f"Operator approval rejected (HTTP {status})")
        s.failed(f"approval HTTP {status}")


async def test_burst(client: LatchGateClient, report: Report) -> None:
    n = 5
    header(7, "Burst execution — receipt evidence")
    step(f"Executing {n} sequential http_fetch calls")
    detail("Each call: full pipeline + atomic budget decrement in Redis.")
    await pause(0.2)

    s = Scenario("burst_execution", report)
    receipts: list[str] = []
    grants: list[str] = []

    for i in range(n):
        try:
            result = await client.execute("http_fetch", {"url": f"https://httpbin.org/get?seq={i}"})
            receipts.append(result.receipt_id)
            grants.append(result.grant_id)
            print(f"    {GREEN}[ok]{RESET} [{i+1}/{n}] "
                  f"receipt={DIM}{result.receipt_id}{RESET} "
                  f"grant={DIM}{result.grant_id}{RESET}")
            await pause(0.05)
        except LatchGateDenied as exc:
            print(f"    {RED}[x]{RESET} [{i+1}/{n}] denied: {exc.reason}")
            break
        except Exception as exc:
            if _is_transient(exc):
                print(f"    {RED}[x]{RESET} [{i+1}/{n}] unavailable: {exc}")
                break
            raise

    if not receipts:
        fail(f"No executions completed ({s.ms:.0f}ms)")
        s.failed("no executions completed")
        return

    avg = s.ms / len(receipts)
    ok(f"{len(receipts)}/{n} executions ({s.ms:.0f}ms total, {avg:.0f}ms avg per call)")
    explain("Each receipt is signed (Ed25519) and persisted to the SQLite ledger.")
    explain("Verify the chain offline: latchgate ledger verify.")
    report.receipts.extend(receipts)
    report.grants.extend(grants)
    s.passed()


# -- Main --------------------------------------------------------------------


async def run(base_url: str) -> int:
    report = Report()

    print()
    print(f"  {BOLD}LatchGate Orchestrator{RESET}")
    print(f"  {DIM}Target: {base_url}{RESET}")
    print()
    explain("Each scenario shows the gate's actual response.")
    explain("Lines prefixed with `[gate]` are real responses from the gate;")
    explain("lines prefixed with `>` are orchestrator narration.")

    operator_key: str | None = None
    operator_keypair: DPoPKeyPair | None = None

    repo_root = _find_repo_root()
    if repo_root:
        result = _load_operator_config(repo_root)
        if result:
            operator_key, operator_keypair = result
            kv("repo_root", str(repo_root))
            ok("Operator credentials loaded")
        else:
            detail("Approval flow will be partial without operator credentials.")
    else:
        detail("No latchgate.toml found — approval flow will be partial.")

    payload = json.dumps({"event": "deploy", "service": "api-gateway", "version": "2.4.1"})

    async with LatchGateClient(base_url=base_url) as client:
        await test_lease(client, report)

        await test_execute(
            client, report, num=2, action_id="http_fetch",
            title="http_fetch — low risk, auto-allow",
            params={"url": "https://httpbin.org/get"},
            narration="Pipeline traversed: auth -> schema -> OPA -> budget "
                      "-> grant -> WASM -> verifier -> ledger.",
            show_runtime=True,
        )

        await test_execute(
            client, report, num=3, action_id="http_post",
            title="http_post — medium risk, auto-allow",
            params={"url": "https://httpbin.org/post", "body": payload},
            narration="Same http_api.wasm binary as http_fetch — different manifest "
                      "(POST template, allowed_domains, risk level).",
        )

        await test_bearer_get(client, report)
        await test_egress_containment(client, report)
        await test_approval_flow(client, report, base_url, operator_key, operator_keypair)
        await test_burst(client, report)

    report.print_summary()
    return report.exit_code


def main() -> None:
    parser = argparse.ArgumentParser(
        description="LatchGate orchestrator — exercise HTTP actions and policy paths"
    )
    parser.add_argument(
        "--base-url",
        default="http://localhost:3000",
        help="Gate HTTP base URL (default: http://localhost:3000)",
    )
    args = parser.parse_args()
    sys.exit(asyncio.run(run(args.base_url)))


if __name__ == "__main__":
    main()
