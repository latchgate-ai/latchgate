#!/usr/bin/env python3
"""LatchGate approval flow — agent submits, operator approves, gate executes.

Demonstrates the full approval lifecycle:
  1. Agent submits a high-risk action => gate holds it (HTTP 202)
  2. Operator loads credentials and approves via DPoP-authenticated admin API
  3. Gate executes the stored plan and returns a signed receipt

The agent and operator are separate roles with separate authentication.
In production the operator is a human or automated review system on a
different machine. This example plays both roles from a single script.

Requires a running gate:
    latchgate up
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import NoReturn

import httpx

from latchgate import (
    LatchGateApprovalRequired,
    LatchGateClient,
    LatchGateDenied,
)

# Operator DPoP auth uses internal crypto primitives. These are not part of
# the agent SDK's public surface — operator auth is a separate concern that
# runs on the admin socket in production.
from latchgate._crypto import DPoPKeyPair, compute_ath

# Server's default public_base_url — used for DPoP htu construction.
_PUBLIC_BASE_URL = "http://localhost:3000"

# -- Helpers -----------------------------------------------------------------


def _abort(msg: str) -> NoReturn:
    print(f"  error: {msg}", file=sys.stderr)
    sys.exit(1)


# -- Socket paths ------------------------------------------------------------


def _default_admin_socket_path() -> str:
    """Resolve the admin UDS socket path.

    Mirrors the server's default_admin_uds_path so that latchgate up
    and this example agree without manual configuration.
    """
    xdg = os.environ.get("XDG_RUNTIME_DIR", "")
    if xdg:
        return os.path.join(xdg, "latchgate", "gate-admin.sock")
    return f"/tmp/latchgate-{os.getuid()}/gate-admin.sock"


# -- Operator credential discovery ------------------------------------------


def _find_repo_root() -> Path:
    """Walk up from cwd to find the .latchgate project directory."""
    cur = Path.cwd()
    for parent in [cur, *cur.parents]:
        if (parent / ".latchgate" / "latchgate.toml").exists():
            return parent
    _abort(
        "cannot find .latchgate/latchgate.toml — "
        "run 'latchgate up' from the repo root first"
    )


def _load_operator_credentials(repo_root: Path) -> tuple[str, DPoPKeyPair]:
    """Load the first operator's api_key and DPoP keypair.

    Reads ``[operator_credentials.<name>]`` from ``.latchgate/latchgate.toml``
    and loads the PEM from ``.latchgate/operators/<name>.pem``.
    """
    try:
        import tomllib
    except ModuleNotFoundError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ModuleNotFoundError:
            _abort("Python 3.11+ or 'pip install tomli' required for TOML parsing")

    config_path = repo_root / ".latchgate" / "latchgate.toml"
    with open(config_path, "rb") as f:
        config = tomllib.load(f)

    creds = config.get("operator_credentials", {})
    if not creds:
        _abort(f"no [operator_credentials.*] in {config_path}")

    name = next(iter(creds))
    entry = creds[name]
    api_key = entry.get("api_key")
    if not api_key:
        _abort(f"operator '{name}' missing api_key in {config_path}")

    pem_path = repo_root / ".latchgate" / "operators" / f"{name}.pem"
    if not pem_path.exists():
        _abort(f"operator PEM not found: {pem_path}")

    keypair = DPoPKeyPair.from_pem_file(pem_path)
    return api_key, keypair


# -- Operator approval via admin API ----------------------------------------


async def _approve(
    approval_id: str,
    api_key: str,
    keypair: DPoPKeyPair,
) -> dict:
    """Approve a pending action via the admin API with DPoP auth.

    The operator authenticates with their api_key (as a DPoP-bound token)
    and signs each request with their P-256 keypair. This is the same auth
    scheme the gate enforces on all admin endpoints.

    Connects via the admin UDS socket — the admin API is not exposed on the
    client socket.
    """
    path = f"/v1/approvals/{approval_id}/approve"
    htu = f"{_PUBLIC_BASE_URL}{path}"
    ath = compute_ath(api_key)
    proof = keypair.sign_proof("POST", htu, ath)

    transport = httpx.AsyncHTTPTransport(uds=_default_admin_socket_path())
    async with httpx.AsyncClient(transport=transport) as http:
        resp = await http.post(
            f"http://localhost{path}",
            headers={
                "Authorization": f"DPoP {api_key}",
                "DPoP": proof,
                "Content-Type": "application/json",
            },
        )

    if resp.status_code >= 400:
        content_type = resp.headers.get("content-type", "")
        if content_type.startswith("application/json"):
            body = resp.json()
            return {"_error": True, "status": resp.status_code, **body}
        return {"_error": True, "status": resp.status_code, "detail": resp.text[:200]}

    return resp.json()


# -- Agent submission --------------------------------------------------------


async def _submit_as_agent() -> str:
    """Submit http_sensitive_read as an agent. Returns the approval_id.

    Exits early (via return from main) if the policy auto-allows or denies
    outright, since those paths don't involve the approval lifecycle.
    """
    async with LatchGateClient(public_base_url=_PUBLIC_BASE_URL) as client:
        await client.connect(agent_id="approval-flow-example")
        print("  lease acquired")

        try:
            result = await client.execute(
                "http_sensitive_read",
                {"url": "https://httpbin.org/get"},
            )
        except LatchGateApprovalRequired as exc:
            print(f"  held for approval — approval_id: {exc.approval_id}")
            return exc.approval_id

        except LatchGateDenied as exc:
            print(f"  denied: {exc.reason}")
            print("  the action was denied outright — no approval path available.")
            sys.exit(0)

        # If we reach here, the policy auto-allowed.
        print(f"  auto-allowed — receipt: {result.receipt_id}")
        print()
        print("  policy did not require approval for this action.")
        print("  check policies/data.json to enable approval holds.")
        sys.exit(0)


# -- Main --------------------------------------------------------------------


async def main() -> None:
    # -- Discover operator credentials before we start -----------------------
    repo_root = _find_repo_root()
    api_key, keypair = _load_operator_credentials(repo_root)
    print("  operator credentials loaded")

    # -- Step 1: Agent submits a high-risk action ----------------------------
    print()
    print("  step 1: agent submits http_sensitive_read (risk: high)")

    approval_id = await _submit_as_agent()

    # -- Step 2: Operator approves -------------------------------------------
    print()
    print(f"  step 2: operator approves {approval_id}")

    body = await _approve(approval_id, api_key, keypair)

    if body.get("_error"):
        deny_reason = body.get("deny_reason", body.get("error", "unknown"))
        is_secrets_issue = "secrets" in str(deny_reason).lower()

        if is_secrets_issue:
            print("  approved — but execution requires secrets (SOPS not configured)")
            print()
            print("  ✓ The approval lifecycle completed successfully:")
            print("    agent submitted → gate held → operator approved")
            print()
            print("  The action declares required secrets that need SOPS setup.")
            print("  See: https://latchgate-docs.pages.dev/secrets/")
        else:
            print(f"  approval failed (HTTP {body['status']}): {deny_reason}")
        return

    receipt_id = body.get("receipt_id")
    grant_id = body.get("grant_id")

    print("  approved and executed")
    if receipt_id:
        print(f"  receipt:  {receipt_id}")
    if grant_id:
        print(f"  grant:    {grant_id}")

    # -- Done ----------------------------------------------------------------
    print()
    print("  the agent submitted a high-risk action.")
    print("  the gate held it until an operator approved.")
    print("  the gate then executed the stored plan — not a re-derived one.")
    print("  the signed receipt proves what happened and when.")


if __name__ == "__main__":
    asyncio.run(main())
