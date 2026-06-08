"""Unit tests for _crypto.py."""

from __future__ import annotations

import base64
import hashlib
import json

from latchgate._crypto import DPoPKeyPair, _normalize_htu, compute_ath

# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------


def test_generate_returns_ec_p256_jwk() -> None:
    kp = DPoPKeyPair.generate()
    assert kp.jwk["kty"] == "EC"
    assert kp.jwk["crv"] == "P-256"
    assert "x" in kp.jwk
    assert "y" in kp.jwk


def test_jwk_x_y_are_base64url_no_padding() -> None:
    kp = DPoPKeyPair.generate()
    for coord in (kp.jwk["x"], kp.jwk["y"]):
        assert "=" not in coord, "JWK coordinates must not have padding"
        assert "+" not in coord, "JWK coordinates must use base64url alphabet"
        assert "/" not in coord, "JWK coordinates must use base64url alphabet"


def test_jwk_x_y_are_32_bytes() -> None:
    kp = DPoPKeyPair.generate()
    for coord in (kp.jwk["x"], kp.jwk["y"]):
        raw = base64.urlsafe_b64decode(coord + "==")
        assert len(raw) == 32, f"P-256 coordinate must be 32 bytes, got {len(raw)}"


def test_two_keypairs_are_distinct() -> None:
    kp1 = DPoPKeyPair.generate()
    kp2 = DPoPKeyPair.generate()
    assert kp1.jwk != kp2.jwk


# ---------------------------------------------------------------------------
# DPoP proof structure
# ---------------------------------------------------------------------------


def _decode_jwt_part(b64: str) -> dict:  # type: ignore[type-arg]
    padded = b64 + "=" * (-len(b64) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def test_proof_is_three_part_jwt() -> None:
    kp = DPoPKeyPair.generate()
    proof = kp.sign_proof(
        "POST", "http://localhost/v1/actions/http_fetch/execute", "ath-value"
    )
    parts = proof.split(".")
    assert len(parts) == 3, "DPoP proof must be a 3-part JWT"


def test_proof_header_typ_is_dpop_jwt() -> None:
    kp = DPoPKeyPair.generate()
    proof = kp.sign_proof("POST", "http://localhost/v1/leases", "ath-value")
    header = _decode_jwt_part(proof.split(".")[0])
    assert header["typ"] == "dpop+jwt"
    assert header["alg"] == "ES256"


def test_proof_header_jwk_matches_keypair() -> None:
    kp = DPoPKeyPair.generate()
    proof = kp.sign_proof("POST", "http://localhost/v1/leases", "ath-value")
    header = _decode_jwt_part(proof.split(".")[0])
    assert header["jwk"]["kty"] == "EC"
    assert header["jwk"]["crv"] == "P-256"
    assert header["jwk"]["x"] == kp.jwk["x"]
    assert header["jwk"]["y"] == kp.jwk["y"]


def test_proof_payload_htm_is_uppercased() -> None:
    kp = DPoPKeyPair.generate()
    proof = kp.sign_proof("post", "http://localhost/v1/leases", "ath-value")
    payload = _decode_jwt_part(proof.split(".")[1])
    assert payload["htm"] == "POST"


def test_proof_payload_contains_required_claims() -> None:
    kp = DPoPKeyPair.generate()
    proof = kp.sign_proof("POST", "http://localhost/v1/leases", "my-ath")
    payload = _decode_jwt_part(proof.split(".")[1])
    assert "jti" in payload
    assert "htm" in payload
    assert "htu" in payload
    assert "iat" in payload
    assert "ath" in payload
    assert payload["ath"] == "my-ath"


def test_proof_jti_is_unique_per_call() -> None:
    kp = DPoPKeyPair.generate()
    p1 = kp.sign_proof("POST", "http://localhost/v1/leases", "ath")
    p2 = kp.sign_proof("POST", "http://localhost/v1/leases", "ath")
    jti1 = _decode_jwt_part(p1.split(".")[1])["jti"]
    jti2 = _decode_jwt_part(p2.split(".")[1])["jti"]
    assert jti1 != jti2, "Each proof must have a unique jti"


def test_proof_signature_is_64_bytes() -> None:
    kp = DPoPKeyPair.generate()
    proof = kp.sign_proof("POST", "http://localhost/v1/leases", "ath")
    sig_b64 = proof.split(".")[2]
    raw = base64.urlsafe_b64decode(sig_b64 + "==")
    assert len(raw) == 64, "ES256 raw signature must be 64 bytes (r || s)"


def test_proof_signature_is_verifiable() -> None:
    """Verify the signature using the public key from the JWK in the header."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    kp = DPoPKeyPair.generate()
    proof = kp.sign_proof("POST", "http://localhost/v1/actions/test/execute", "ath-val")

    header_b64, payload_b64, sig_b64 = proof.split(".")
    signing_input = f"{header_b64}.{payload_b64}".encode()

    raw_sig = base64.urlsafe_b64decode(sig_b64 + "==")
    r = int.from_bytes(raw_sig[:32], "big")
    s = int.from_bytes(raw_sig[32:], "big")
    der_sig = encode_dss_signature(r, s)

    x_bytes = base64.urlsafe_b64decode(kp.jwk["x"] + "==")
    y_bytes = base64.urlsafe_b64decode(kp.jwk["y"] + "==")
    x = int.from_bytes(x_bytes, "big")
    y = int.from_bytes(y_bytes, "big")
    pub_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
    pub_key = pub_numbers.public_key()

    # Should not raise
    pub_key.verify(der_sig, signing_input, ec.ECDSA(hashes.SHA256()))


# ---------------------------------------------------------------------------
# compute_ath
# ---------------------------------------------------------------------------


def test_ath_is_sha256_base64url_of_token() -> None:
    token = "eyJhbGciOiJFUzI1NiJ9.test.sig"
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(token.encode("ascii")).digest())
        .rstrip(b"=")
        .decode()
    )
    assert compute_ath(token) == expected


def test_ath_has_no_padding() -> None:
    ath = compute_ath("some.lease.jwt")
    assert "=" not in ath


def test_ath_differs_for_different_tokens() -> None:
    assert compute_ath("token-a") != compute_ath("token-b")


def test_ath_is_deterministic() -> None:
    token = "lease.jwt.value"
    assert compute_ath(token) == compute_ath(token)


# ---------------------------------------------------------------------------
# htu normalisation — mirrors server vectors from
# crates/latchgate-auth/src/dpop/mod.rs
# ---------------------------------------------------------------------------


def test_htu_strips_query_string() -> None:
    assert (
        _normalize_htu("https://host.example/path?q=1&r=2")
        == "https://host.example/path"
    )


def test_htu_strips_fragment() -> None:
    assert (
        _normalize_htu("https://host.example/path#section")
        == "https://host.example/path"
    )


def test_htu_strips_query_and_fragment() -> None:
    assert (
        _normalize_htu("https://host.example/path?q=1#frag")
        == "https://host.example/path"
    )


def test_htu_lowercases_scheme_and_host() -> None:
    assert _normalize_htu("HTTPS://HOST.EXAMPLE/Path") == "https://host.example/Path"


def test_htu_removes_default_https_port() -> None:
    assert _normalize_htu("https://host.example:443/api") == _normalize_htu(
        "https://host.example/api"
    )


def test_htu_removes_default_http_port() -> None:
    assert _normalize_htu("http://host.example:80/api") == _normalize_htu(
        "http://host.example/api"
    )


def test_htu_keeps_non_default_port() -> None:
    assert (
        _normalize_htu("https://host.example:8443/api")
        == "https://host.example:8443/api"
    )


def test_htu_without_path_defaults_to_slash() -> None:
    assert _normalize_htu("https://host.example") == "https://host.example/"


def test_htu_no_scheme_returns_as_is() -> None:
    assert _normalize_htu("host.example/path") == "host.example/path"


def test_htu_preserves_percent_encoding_in_path() -> None:
    assert (
        _normalize_htu("https://host.example/path%2Fsegment")
        == "https://host.example/path%2Fsegment"
    )


def test_htu_preserves_path_case() -> None:
    """Scheme and host are lowercased, but path segments are case-sensitive."""
    assert (
        _normalize_htu("http://localhost:3000/v1/actions/Http_Fetch/execute")
        == "http://localhost:3000/v1/actions/Http_Fetch/execute"
    )


def test_htu_typical_gate_url() -> None:
    """End-to-end: the exact URL shape the SDK sends to the gate."""
    assert (
        _normalize_htu("http://localhost:3000/v1/actions/http_fetch/execute")
        == "http://localhost:3000/v1/actions/http_fetch/execute"
    )
