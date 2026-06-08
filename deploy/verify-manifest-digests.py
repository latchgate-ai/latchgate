#!/usr/bin/env python3
"""
Verify that compiled WASM provider modules match the digests committed in
definitions/manifests/*.yaml. Lightweight CI replacement for
`cargo run -p latchgate-api -- providers verify`.

Exit codes:
    0 — all digests match (or only builtin: entries)
    1 — one or more mismatches / missing files

Usage:
    deploy/verify-manifest-digests.py \\
        --manifests-dir definitions/manifests \\
        --providers-dir target/providers
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

import yaml


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--manifests-dir", type=Path, required=True)
    ap.add_argument("--providers-dir", type=Path, required=True)
    args = ap.parse_args()

    if not args.manifests_dir.is_dir():
        print(f"error: manifests dir not found: {args.manifests_dir}", file=sys.stderr)
        return 1

    manifests = sorted(args.manifests_dir.glob("*.yaml")) + sorted(
        args.manifests_dir.glob("*.yml")
    )
    if not manifests:
        print(f"error: no manifests found in {args.manifests_dir}", file=sys.stderr)
        return 1

    checked = 0
    builtins = 0
    failures: list[str] = []

    for manifest_path in manifests:
        try:
            spec = yaml.safe_load(manifest_path.read_text())
        except yaml.YAMLError as e:
            failures.append(f"{manifest_path.name}: invalid YAML: {e}")
            continue

        if not isinstance(spec, dict):
            continue

        action_id = spec.get("action_id", manifest_path.stem)
        expected = spec.get("provider_module_digest", "")

        # Built-in providers (e.g. `builtin:http_api`) have no WASM digest to
        # verify — trust is implicit from the server binary.
        if expected.startswith("builtin:"):
            builtins += 1
            continue

        source = spec.get("provider_source")
        if not source:
            # Manifest declares no provider source and is not a builtin.
            # Not a hard error here — latchgate-api will catch it at load.
            continue

        wasm_path = args.providers_dir / source
        if not wasm_path.is_file():
            failures.append(f"{action_id}: {source} not found in {args.providers_dir}")
            continue

        actual = sha256_of(wasm_path)
        if actual != expected:
            failures.append(
                f"{action_id}: digest mismatch\n"
                f"       manifest: {expected}\n"
                f"       actual:   {actual}"
            )
            continue

        checked += 1

    print(f"verified {checked} WASM module(s), {builtins} builtin(s)")

    if failures:
        print()
        for f in failures:
            print(f"✗ {f}")
        print()
        print("Digest mismatch. To update, run:")
        print("  make providers-rehash")
        print("and commit the changes in definitions/manifests/.")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
