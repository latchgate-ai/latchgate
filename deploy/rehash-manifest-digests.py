#!/usr/bin/env python3
"""
Update provider_module_digest in definitions/manifests/*.yaml to match the
SHA-256 of freshly compiled WASM modules. Lightweight counterpart to
`cargo run -p latchgate-api -- providers rehash` — no Rust compilation
required, runs in milliseconds.

Usage:
    deploy/rehash-manifest-digests.py \
        --manifests-dir definitions/manifests \
        --providers-dir target/providers
"""

from __future__ import annotations

import argparse
import hashlib
import re
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

    updated = 0
    unchanged = 0
    builtins = 0

    for manifest_path in manifests:
        raw = manifest_path.read_text()
        try:
            spec = yaml.safe_load(raw)
        except yaml.YAMLError as e:
            print(f"  skip  {manifest_path.name}: invalid YAML: {e}")
            continue

        if not isinstance(spec, dict):
            continue

        action_id = spec.get("action_id", manifest_path.stem)
        old_digest = spec.get("provider_module_digest", "")

        if old_digest.startswith("builtin:"):
            builtins += 1
            continue

        source = spec.get("provider_source")
        if not source:
            continue

        wasm_path = args.providers_dir / source
        if not wasm_path.is_file():
            print(f"  skip  {action_id}: {source} not found in {args.providers_dir}")
            continue

        new_digest = sha256_of(wasm_path)
        if new_digest == old_digest:
            unchanged += 1
            continue

        # Replace the digest line in-place, preserving YAML formatting.
        new_raw = re.sub(
            r'(?m)^(provider_module_digest:\s*)"[^"]*"',
            rf'\1"{new_digest}"',
            raw,
        )
        if new_raw == raw:
            # Try without quotes (bare value).
            new_raw = re.sub(
                r"(?m)^(provider_module_digest:\s*)(\S+)",
                rf"\1{new_digest}",
                raw,
            )

        if new_raw != raw:
            manifest_path.write_text(new_raw)
            short = new_digest[:20] + ".."
            print(f"  ✓  {action_id}  {short}")
            updated += 1
        else:
            print(f"  ✗  {action_id}: could not locate digest line in YAML")

    print(f"\n  {updated} updated, {unchanged} unchanged, {builtins} builtin")
    return 0


if __name__ == "__main__":
    sys.exit(main())
