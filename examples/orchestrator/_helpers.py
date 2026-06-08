"""Terminal styling, output helpers, and result tracking for the orchestrator."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any

# ANSI codes ----------------------------------------------------------------

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"
WHITE = "\033[97m"

PASS = f"{GREEN}PASS{RESET}"
FAIL_TAG = f"{RED}FAIL{RESET}"
SKIP_TAG = f"{YELLOW}SKIP{RESET}"
INFO = f"{CYAN}*{RESET}"
WAIT = f"{YELLOW}HOLD{RESET}"


# Output helpers ------------------------------------------------------------


def header(num: int, title: str) -> None:
    print()
    print(f"{BOLD}{GREEN}{'-' * 64}{RESET}")
    print(f"{BOLD}{GREEN}  {num}. {title}{RESET}")
    print(f"{BOLD}{GREEN}{'-' * 64}{RESET}")
    print()


def step(msg: str) -> None:
    print(f"  {INFO} {msg}")


def ok(msg: str) -> None:
    print(f"  [{PASS}] {msg}")


def fail(msg: str) -> None:
    print(f"  [{FAIL_TAG}] {msg}")


def skip(msg: str) -> None:
    print(f"  [{SKIP_TAG}] {msg}")


def wait(msg: str) -> None:
    print(f"  [{WAIT}] {msg}")


def detail(msg: str) -> None:
    print(f"    {DIM}{msg}{RESET}")


def kv(key: str, val: str) -> None:
    print(f"    {DIM}{key}:{RESET} {val}")


def explain(msg: str) -> None:
    """Orchestrator narration."""
    print(f"    {CYAN}> {msg}{RESET}")


def gate_response(label: str, body: Any) -> None:
    """Show a real response from the gate, clearly labeled as gate output.

    Use this whenever the orchestrator wants to display data the gate
    actually produced (response bodies, exception fields, receipt
    contents). Do NOT use detail() or explain() for these -- those
    are for orchestrator narration. Keeping them visually distinct
    prevents synthesized text from being mistaken for real gate output.
    """
    pretty = body if isinstance(body, str) else json.dumps(body, indent=2)
    indent = "      "
    lines = pretty.split("\n")
    print(f"    {MAGENTA}[gate]{RESET} {DIM}{label}{RESET}")
    for line in lines:
        print(f"{indent}{MAGENTA}|{RESET} {line}")


async def pause(seconds: float = 0.6) -> None:
    await asyncio.sleep(seconds)


# Result tracking -----------------------------------------------------------


@dataclass
class TestResult:
    name: str
    passed: bool
    skipped: bool = False
    error: str | None = None
    duration_ms: float = 0.0
    receipt_id: str | None = None
    grant_id: str | None = None


@dataclass
class Report:
    results: list[TestResult] = field(default_factory=list)
    receipts: list[str] = field(default_factory=list)
    grants: list[str] = field(default_factory=list)

    def add(self, result: TestResult) -> None:
        self.results.append(result)
        if result.receipt_id:
            self.receipts.append(result.receipt_id)
        if result.grant_id:
            self.grants.append(result.grant_id)

    def print_summary(self) -> None:
        print()
        print(f"{BOLD}{WHITE}{'=' * 64}{RESET}")
        print(f"{BOLD}{WHITE}  Results{RESET}")
        print(f"{BOLD}{WHITE}{'=' * 64}{RESET}")
        print()

        passed = sum(1 for r in self.results if r.passed)
        failed = sum(1 for r in self.results if not r.passed and not r.skipped)
        skipped = sum(1 for r in self.results if r.skipped)
        total = len(self.results)

        for r in self.results:
            tag = PASS if r.passed else (SKIP_TAG if r.skipped else FAIL_TAG)
            ms = f" ({r.duration_ms:.0f}ms)" if r.duration_ms else ""
            err = f" - {r.error}" if r.error else ""
            print(f"  [{tag}] {r.name}{DIM}{ms}{err}{RESET}")

        print()
        line = f"  {BOLD}{passed}/{total} passed{RESET}"
        if failed:
            line += f"  {RED}{failed} failed{RESET}"
        if skipped:
            line += f"  {YELLOW}{skipped} skipped{RESET}"
        print(line)

        if self.receipts:
            print()
            print(f"{BOLD}{WHITE}{'-' * 64}{RESET}")
            print(f"{BOLD}  Evidence trail{RESET} - {len(self.receipts)} receipts")
            print()
            explain("Every successful execution produced an Ed25519-signed receipt.")
            explain("Receipts persist in the gate's SQLite ledger; fetch any of these")
            explain("with `latchgate audit` or `client.get_receipt(rid)` to verify.")
            print()

            for i, rid in enumerate(self.receipts):
                marker = f"{GREEN}head{RESET}" if i == 0 else f"{DIM}#{i}{RESET}"
                print(f"    {DIM}{rid}{RESET}  {marker}")

        if self.grants:
            print()
            print(f"{BOLD}{WHITE}{'-' * 64}{RESET}")
            print(f"{BOLD}  Execution grants{RESET} - {len(self.grants)} issued")
            print()
            explain("Each grant authorised exactly one execution, binding the")
            explain("provider digest, targets, secrets, and egress rules.")
            print()

            for gid in self.grants:
                print(f"    {DIM}{gid}{RESET}")

        print()
        print(f"{BOLD}{WHITE}{'=' * 64}{RESET}")
        print()

    @property
    def exit_code(self) -> int:
        return 0 if all(r.passed or r.skipped for r in self.results) else 1
