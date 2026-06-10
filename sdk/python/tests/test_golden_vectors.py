"""Cross-language golden vector tests for JCS (RFC 8785) canonical hashing."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest


def _canonicalize(value: object) -> str:
    """Minimal JCS canonicalization for golden vector testing."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


# Resolve path:
# tests/ -> python/ -> sdk/ -> repo root
ROOT = Path(__file__).resolve().parents[3]

GOLDEN_PATH = (
    ROOT
    / "definitions"
    / "test_vectors"
    / "jcs"
    / "golden.json"
)

VECTORS = json.loads(
    GOLDEN_PATH.read_text(encoding="utf-8")
)

def test_vector_count() -> None:
    assert VECTORS
    assert len(VECTORS) >= 8


@pytest.mark.parametrize(
    "vector",
    VECTORS,
    ids=[v["description"] for v in VECTORS],
)
def test_golden_vector(vector: dict) -> None:
    canonical = _canonicalize(vector["input"])
    canonical_bytes = canonical.encode("utf-8")

    if "canonical" in vector:
        assert canonical == vector["canonical"]

    if "canonical_hex" in vector:
        assert (
            canonical_bytes.hex()
            == vector["canonical_hex"]
        )

    digest = hashlib.sha256(
        canonical_bytes
    ).hexdigest()

    assert (
        f"sha256:{digest}"
        == vector["sha256"]
    )
