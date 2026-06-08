#!/usr/bin/env python3
"""Run a JSON-RPC session against latchgate-mcp over stdio.

Starts the adapter as a subprocess, sends messages, reads responses.
Used by test_mcp.sh - not meant to be run directly.
"""

import json
import subprocess
import sys
import threading
import time


def main():
    binary = sys.argv[1]
    gate_url = sys.argv[2]

    proc = subprocess.Popen(
        [binary, "serve", "--gate-url", gate_url],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
    )

    responses: list[str] = []
    lock = threading.Lock()

    def reader():
        for line in proc.stdout:
            line = line.strip()
            if line:
                with lock:
                    responses.append(line)

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    def send(msg: dict) -> dict | None:
        proc.stdin.write(json.dumps(msg) + "\n")
        proc.stdin.flush()

        if "id" not in msg:
            # Notification - no response expected
            time.sleep(0.3)
            return None

        # Wait for response with matching id
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            with lock:
                for i, r in enumerate(responses):
                    try:
                        parsed = json.loads(r)
                        if parsed.get("id") == msg["id"]:
                            responses.pop(i)
                            return parsed
                    except json.JSONDecodeError:
                        pass
            time.sleep(0.1)

        return {"error": "timeout"}

    # ── 1. Initialize ────────────────────────────────────────────────────
    resp = send(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "latchgate-test", "version": "0.1"},
            },
        }
    )
    print(json.dumps({"step": "initialize", "response": resp}))

    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    time.sleep(0.5)

    # ── 2. List tools ────────────────────────────────────────────────────
    resp = send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    print(json.dumps({"step": "tools_list", "response": resp}))

    # ── 3. http_fetch allowed ────────────────────────────────────────────
    resp = send(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "http_fetch",
                "arguments": {"url": "https://httpbin.org/get"},
            },
        }
    )
    print(json.dumps({"step": "fetch_allowed", "response": resp}))
    sys.stderr.write(f"DEBUG fetch_allowed: {json.dumps(resp)[:300]}\n")

    # ── 4. http_fetch denied ─────────────────────────────────────────────
    resp = send(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "http_fetch",
                "arguments": {"url": "https://evil.example.com/exfil"},
            },
        }
    )
    print(json.dumps({"step": "fetch_denied", "response": resp}))
    sys.stderr.write(f"DEBUG fetch_denied: {json.dumps(resp)[:300]}\n")

    # ── 5. http_sensitive_read (approval) ───────────────────────────────
    resp = send(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "http_sensitive_read",
                "arguments": {
                    "url": "https://httpbin.org/get",
                },
            },
        }
    )
    print(json.dumps({"step": "http_sensitive_read", "response": resp}))
    sys.stderr.write(f"DEBUG http_sensitive_read: {json.dumps(resp)[:300]}\n")

    proc.stdin.close()
    proc.wait(timeout=5)


if __name__ == "__main__":
    main()
