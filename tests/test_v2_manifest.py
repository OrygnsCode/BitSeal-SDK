# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Orygn LLC

"""Tests the v2 manifest verify path against the published BitSeal spec
test vectors. The vectors are signed with the RFC 8032 §7.1 Test 1 keypair
(public, in print since 2017) so any third party can reproduce the same
results without access to the production Authority key.

The vectors file is copied verbatim from spec/v2-test-vectors.json in the
BitSeal web monorepo. CI should re-copy on every commit; drift would mean
the SDK is verifying against a stale spec.
"""

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from bitseal.core import (
    SDK_VERSION,
    SEAL_MODE_V1,
    SEAL_MODE_V2,
    _build_v2_signed_message,
    _canonicalize_v2_manifest,
    verify_manifest_signature,
)

VECTORS_PATH = Path(__file__).parent / "vectors" / "v2-test-vectors.json"


@pytest.fixture(scope="module")
def vectors():
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def test_public_key_pem(vectors):
    """Derive the PEM-format public key from the RFC 8032 raw-hex public bytes
    so we can hand it to verify_manifest_signature without a network round-trip
    to the real Authority key endpoint.
    """
    raw_pub_hex = vectors["ed25519_test_keypair"]["public_key_raw_hex"]
    raw = bytes.fromhex(raw_pub_hex)
    pub = ed25519.Ed25519PublicKey.from_public_bytes(raw)
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# --- Canonicalization byte equivalence ---

def test_canonical_bytes_match_spec_vector_a(vectors):
    """Vector A's canonical_bytes_hex in the spec MUST equal what our
    canonicalizer produces from the same input manifest."""
    a = vectors["positive_vectors"][0]
    assert a["name"] == "A"
    produced = _canonicalize_v2_manifest(a["input_manifest_pretty"])
    assert produced.hex() == a["canonical_bytes_hex"]
    assert len(produced) == a["canonical_bytes_length"]


def test_canonical_bytes_match_spec_vector_b(vectors):
    """Vector B exercises the 3-leaf Merkle tree with odd-layer-duplicate
    rule. Canonical bytes still have to match the spec byte-for-byte."""
    b = vectors["positive_vectors"][1]
    assert b["name"] == "B"
    produced = _canonicalize_v2_manifest(b["input_manifest_pretty"])
    assert produced.hex() == b["canonical_bytes_hex"]


def test_canonical_bytes_match_spec_vector_c(vectors):
    """Vector C has a nested `ots` sub-object. Our canonicalizer must sort
    the nested keys too, not just the top-level ones."""
    c = vectors["positive_vectors"][2]
    assert c["name"] == "C"
    produced = _canonicalize_v2_manifest(c["input_manifest_pretty"])
    assert produced.hex() == c["canonical_bytes_hex"]


def test_sha3_512_digest_matches_spec(vectors):
    """The digest the spec lists must equal what our message-builder produces."""
    for vec in vectors["positive_vectors"]:
        digest = _build_v2_signed_message(vec["input_manifest_pretty"])
        assert digest.hex() == vec["sha3_512_digest_hex"], (
            f"Vector {vec['name']} digest mismatch"
        )
        assert len(digest) == 64


# --- End-to-end verification ---

def test_positive_vector_a_verifies(vectors, test_public_key_pem):
    """Full round-trip: hand the signed Vector A manifest to
    verify_manifest_signature with the test public key. Result must be ok."""
    a = vectors["positive_vectors"][0]
    result = verify_manifest_signature(
        a["signed_manifest"],
        public_key_pem=test_public_key_pem,
    )
    assert result["ok"] is True
    assert result["format"] == "web"
    assert result["seal_mode"] == SEAL_MODE_V2


def test_positive_vector_b_verifies(vectors, test_public_key_pem):
    b = vectors["positive_vectors"][1]
    result = verify_manifest_signature(
        b["signed_manifest"],
        public_key_pem=test_public_key_pem,
    )
    assert result["ok"] is True
    assert result["format"] == "web"
    assert result["seal_mode"] == SEAL_MODE_V2


def test_positive_vector_c_verifies(vectors, test_public_key_pem):
    c = vectors["positive_vectors"][2]
    result = verify_manifest_signature(
        c["signed_manifest"],
        public_key_pem=test_public_key_pem,
    )
    assert result["ok"] is True


# --- Negative vectors — each MUST fail ---

def test_negative_vector_n1_wrong_seal_mode_rejected(vectors, test_public_key_pem):
    """N1: signature was produced over v2 canonical bytes, but seal_mode
    says v1. v2 verifier dispatches on seal_mode → v1 path → signed message
    is different → verify fails. v1 verifier dispatches on seal_mode == v1
    → tries 40-byte v1 message → also fails."""
    n1 = vectors["negative_vectors"][0]
    assert n1["name"] == "N1_seal_mode_mismatch"
    result = verify_manifest_signature(
        n1["manifest"],
        public_key_pem=test_public_key_pem,
    )
    assert result["ok"] is False


def test_negative_vector_n2_unknown_field_rejected(vectors, test_public_key_pem):
    """N2: extra `injected` field added after signing. Canonical bytes now
    differ → SHA3-512 differs → Ed25519 verify fails. This is the headline
    audit-H2 attack class: signed seal must reject post-signing mutations."""
    n2 = vectors["negative_vectors"][1]
    assert n2["name"] == "N2_unknown_field"
    result = verify_manifest_signature(
        n2["manifest"],
        public_key_pem=test_public_key_pem,
    )
    assert result["ok"] is False
    assert result["seal_mode"] == SEAL_MODE_V2


def test_negative_vector_n3_numeric_timestamp_rejected(vectors, test_public_key_pem):
    """N3: timestamp_utc serialized as a JSON number rather than string.
    Spec §4 rule 3 forbids JSON floats in v2 canonical form. The
    canonicalizer dumps the float (no explicit reject because Python doesn't
    know floats are forbidden), but the byte sequence differs from what was
    signed, so verify fails."""
    n3 = vectors["negative_vectors"][2]
    assert n3["name"] == "N3_timestamp_as_number"
    result = verify_manifest_signature(
        n3["manifest"],
        public_key_pem=test_public_key_pem,
    )
    assert result["ok"] is False


def test_negative_vector_n5_tampered_signature_rejected(vectors, test_public_key_pem):
    """N5: last signature byte flipped. Ed25519 verify must catch this."""
    n5 = vectors["negative_vectors"][4]
    assert n5["name"] == "N5_tampered_signature"
    result = verify_manifest_signature(
        n5["manifest"],
        public_key_pem=test_public_key_pem,
    )
    assert result["ok"] is False


# --- Dispatch behavior ---

def test_unknown_seal_mode_rejected(test_public_key_pem):
    """A manifest with a future-dated seal_mode the SDK does not know about
    must be rejected, not silently fall through to v1."""
    m = {
        "root_hash": "ab" * 32,
        "timestamp_utc": "1714378247.123456",
        "signature": "00" * 64,
        "seal_mode": "merkle-blake3-64k-v99",
        "signer": "Orygn Authority",
    }
    result = verify_manifest_signature(m, public_key_pem=test_public_key_pem)
    assert result["ok"] is False
    assert "unknown seal_mode" in result["reason"]


def test_missing_seal_mode_falls_back_to_v1(vectors, test_public_key_pem):
    """Legacy manifests have no seal_mode field. Dispatch must fall back to
    the v1 web path (signer-based) so historical seals keep verifying."""
    a = vectors["positive_vectors"][0]
    # Build a v1-shaped manifest with the same root_hash but signed properly
    # for v1 — we can't reuse the v2 signature because the message is different.
    # So we use a synthetic v1 manifest signed in this test with the v1 layout
    # and confirm it dispatches correctly.
    from bitseal.core import _build_web_signed_message
    raw_priv_hex = vectors["ed25519_test_keypair"]["private_key_raw_hex"]
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(raw_priv_hex))
    root = "ab" * 32
    ts = 1714378247.123456
    sig = priv.sign(_build_web_signed_message(root, ts))
    m = {
        "root_hash": root,
        "timestamp_utc": ts,
        "signature": sig.hex(),
        "signer": "Orygn Authority",
        # no seal_mode — legacy
    }
    result = verify_manifest_signature(m, public_key_pem=test_public_key_pem)
    assert result["ok"] is True
    assert result["seal_mode"] is None
    assert result["format"] == "web"


def test_v1_seal_mode_explicit_uses_v1_path(test_public_key_pem, vectors):
    """A manifest that explicitly declares seal_mode=v1 should use the v1
    web path, not v2. Confirms dispatch is strictly seal_mode-driven."""
    from bitseal.core import _build_web_signed_message
    raw_priv_hex = vectors["ed25519_test_keypair"]["private_key_raw_hex"]
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(raw_priv_hex))
    root = "cd" * 32
    ts = 1714378247.123456
    sig = priv.sign(_build_web_signed_message(root, ts))
    m = {
        "root_hash": root,
        "timestamp_utc": ts,
        "signature": sig.hex(),
        "signer": "Orygn Authority",
        "seal_mode": SEAL_MODE_V1,
    }
    result = verify_manifest_signature(m, public_key_pem=test_public_key_pem)
    assert result["ok"] is True
    assert result["seal_mode"] == SEAL_MODE_V1


# --- Spec constants pinned ---

def test_seal_mode_constants_match_spec():
    """The string values are part of the on-disk wire format. Changing them
    is a spec-breaking change. This test exists so any rename trips CI."""
    assert SEAL_MODE_V1 == "merkle-blake3-64k-v1"
    assert SEAL_MODE_V2 == "merkle-blake3-64k-v2"


def test_sdk_version_bumped():
    """0.3.4 ships the G-6 Merkle log surface (canonical leaf bytes, STH
    canonical bytes + signing, inclusion-proof verifier, STH signature
    verifier, end-to-end verify_seal_in_log orchestrator). Layered on top
    of the 0.3.3 historical-key-fallback fix that unblocks pre-rotation
    seal verification after the Phase 5.1 KMS migration."""
    assert SDK_VERSION == "0.3.5"


# --- 0.3.3 historical-key fallback (Phase 5.1 KMS rotation regression) ---

def test_historical_key_fallback_via_well_known(monkeypatch, vectors):
    """A seal signed by a now-retired key MUST still verify after the well-
    known doc has rotated to a new current_key, provided the retired key is
    listed under historical_keys. Pre-0.3.3 SDKs would reject because they
    only tried current_key.public_key_pem.

    Regression for the Phase 5.1 KMS rotation: pre-KMS seals were signed
    with the env-var key; post-rotation, the well-known doc serves the KMS
    public key as current and the env-var key as historical. Without this
    fix every legacy seal would suddenly report signature_verified=False.
    """
    # Vector A is signed with the RFC 8032 Test 1 keypair. Pretend that
    # keypair is now retired (historical) and a *different* keypair is the
    # current Authority key.
    a = vectors["positive_vectors"][0]
    retired_pub_hex = vectors["ed25519_test_keypair"]["public_key_raw_hex"]
    retired_pub_pem = (
        ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(retired_pub_hex))
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    # Mint a brand-new keypair to play "current".
    new_current_priv = ed25519.Ed25519PrivateKey.generate()
    new_current_pem = (
        new_current_priv.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )

    fake_well_known = {
        "current_key": {
            "key_id": "current",
            "public_key_pem": new_current_pem,
        },
        "historical_keys": [
            {
                "key_id": "pre-kms-2026-04-19",
                "public_key_pem": retired_pub_pem,
                "effective_until": "2026-05-29",
            }
        ],
    }
    import bitseal.core as core
    monkeypatch.setattr(core, "fetch_web_authority_public_key", lambda: fake_well_known)

    result = verify_manifest_signature(a["signed_manifest"])
    assert result["ok"] is True, (
        f"historical-key fallback failed: {result.get('reason')}"
    )
    assert result["key_id"] == "pre-kms-2026-04-19", result
    assert result["seal_mode"] == SEAL_MODE_V2


def test_no_candidate_keys_returns_clear_reason(monkeypatch, vectors):
    """If well-known has neither current nor historical PEM, the verifier
    should not crash — it should return a clear failure reason."""
    fake_well_known = {"current_key": {}, "historical_keys": []}
    import bitseal.core as core
    monkeypatch.setattr(core, "fetch_web_authority_public_key", lambda: fake_well_known)

    a = vectors["positive_vectors"][0]
    result = verify_manifest_signature(a["signed_manifest"])
    assert result["ok"] is False
    assert "0 candidate" in result["reason"], result
