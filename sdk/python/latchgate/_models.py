"""Result types returned by LatchGateClient methods."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ActionResult:
    """Successful result from ``client.execute()``.

    Attributes
    ----------
    output:
        The raw JSON output from the provider as a Python dict or scalar.
    receipt_id:
        Durable receipt identifier.  Pass to ``client.get_receipt()`` to
        retrieve the full :class:`ExecutionReceipt`.
    trace_id:
        Correlation ID for this pipeline invocation.  Include in bug reports.
    grant_id:
        The ``ExecutionGrant`` that authorised this execution.
    verification:
        Dict containing ``outcome`` (str) and ``is_fully_successful`` (bool).
    runtime:
        Dict containing ``duration_ms``, ``exit_code``, ``fuel_consumed``.
    """

    output: Any
    receipt_id: str
    trace_id: str
    grant_id: str
    verification: dict[str, Any] = field(default_factory=dict)
    runtime: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def _from_json(cls, data: dict[str, Any]) -> ActionResult:
        return cls(
            output=data.get("output"),
            receipt_id=data["receipt_id"],
            trace_id=data["trace_id"],
            grant_id=data["grant_id"],
            verification=data.get("verification", {}),
            runtime=data.get("runtime", {}),
        )


@dataclass(frozen=True)
class ExecutionReceipt:
    """Full durable receipt from ``client.get_receipt(receipt_id)``.

    Attributes
    ----------
    receipt_id:
        Unique receipt identifier.
    grant_id:
        The grant that authorised the execution.
    provider_module_digest:
        SHA-256 digest of the ``.wasm`` module that executed.
    provider_receipt:
        Raw output from the provider.
    normalized_result:
        Structured result with ``kind`` (``"success"`` | ``"provider_failure"``
        | ``"timeout"`` | ...) and optional ``summary`` or ``reason``.
    verification_outcome:
        Structured outcome with ``status`` (``"verified"`` | ``"verification_failed"``
        | ``"unverifiable_declared"`` | ...) and optional ``evidence``.
    result_hash:
        SHA-256 of the canonical result envelope.  Can be used for
        independent tamper detection.
    started_at:
        ISO 8601 timestamp of execution start.
    finished_at:
        ISO 8601 timestamp of execution end.
    failure_class:
        Optional failure classification when execution did not succeed.
    """

    receipt_id: str
    grant_id: str
    provider_module_digest: str
    provider_receipt: Any
    normalized_result: dict[str, Any]
    verification_outcome: dict[str, Any]
    result_hash: str
    started_at: str
    finished_at: str
    failure_class: str | None = None

    @property
    def provider_module(self) -> str:
        """Deprecated alias for :attr:`provider_module_digest`."""
        return self.provider_module_digest

    @property
    def is_fully_successful(self) -> bool:
        """True when the normalized result is a success and verification passed."""
        result_ok = self.normalized_result.get("kind") == "success"
        v_status = self.verification_outcome.get("status", "")
        verified = v_status in ("verified", "unverifiable_declared")
        return result_ok and verified

    @classmethod
    def _from_json(cls, data: dict[str, Any]) -> ExecutionReceipt:
        # Wire format uses "provider_module_digest"; older test fixtures or
        # legacy gate versions may still send "provider_module".
        module_digest = data.get(
            "provider_module_digest", data.get("provider_module", "")
        )
        return cls(
            receipt_id=data["receipt_id"],
            grant_id=data["grant_id"],
            provider_module_digest=module_digest,
            provider_receipt=data.get("provider_receipt"),
            normalized_result=data.get("normalized_result", {}),
            verification_outcome=data.get("verification_outcome", {}),
            result_hash=data["result_hash"],
            started_at=data["started_at"],
            finished_at=data["finished_at"],
            failure_class=data.get("failure_class"),
        )


@dataclass(frozen=True)
class ApprovalStatus:
    """Current status of a pending approval.

    Attributes
    ----------
    approval_id:
        The approval identifier returned by ``execute()`` when the action
        requires human approval.
    status:
        One of ``"pending"``, ``"approved"``, ``"denied"``, ``"failed"``.
    action_id:
        The action that requires approval.
    receipt_id:
        Present on ``"approved"`` status — the receipt from the operator's
        execution.
    reason:
        Present on ``"denied"`` or ``"failed"`` status — why it was denied
        or the failure description.
    retry_after_seconds:
        Hint for polling interval when ``"pending"``.
    """

    approval_id: str
    status: str
    action_id: str = ""
    receipt_id: str | None = None
    reason: str | None = None
    retry_after_seconds: int | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_pending(self) -> bool:
        return self.status == "pending"

    @property
    def is_approved(self) -> bool:
        return self.status == "approved"

    @property
    def is_denied(self) -> bool:
        return self.status == "denied"

    @classmethod
    def _from_json(cls, data: dict[str, Any]) -> ApprovalStatus:
        return cls(
            approval_id=data.get("approval_id", ""),
            status=data.get("status", "pending"),
            action_id=data.get("action_id", ""),
            receipt_id=data.get("receipt_id"),
            reason=data.get("reason"),
            retry_after_seconds=data.get("retry_after_seconds"),
            raw=data,
        )


@dataclass(frozen=True)
class EgressProfile:
    """Egress profile for an action, describing allowed outbound domains.

    Attributes
    ----------
    profile:
        Either ``"none"`` (no network) or ``"proxy_allowlist"`` (restricted).
    allowed_domains:
        Domains the action may contact. Empty for ``"none"`` profile.
    """

    profile: str
    allowed_domains: list[str] = field(default_factory=list)

    @property
    def has_egress(self) -> bool:
        """True when the action has any outbound network access."""
        return self.profile != "none"

    @classmethod
    def _from_json(cls, data: Any) -> EgressProfile:
        if data is None or data == "none":
            return cls(profile="none")
        if isinstance(data, dict) and "proxy_allowlist" in data:
            inner = data["proxy_allowlist"]
            return cls(
                profile="proxy_allowlist",
                allowed_domains=inner.get("allowed_domains", []),
            )
        return cls(profile="none")
