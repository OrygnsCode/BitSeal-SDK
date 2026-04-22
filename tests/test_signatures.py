"""Offline signature verification round-trip using a deterministic Ed25519
keypair. Covers both signer formats the SDK understands: the web-signer
format (32-byte root || 8-byte little-endian double timestamp) and the
legacy CLI-signer format (root|fingerprint|timestamp as UTF-8 bytes).
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from BitSealCore import (
    _build_cli_signed_message,
    _build_web_signed_message,
    verify_manifest_signature,
)

# 32-byte deterministic seed so the test key is stable across runs and CI.
TEST_SEED = b"bitseal-sdk-test-seed-32-bytes!!"
assert len(TEST_SEED) == 32


def _keypair():
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(TEST_SEED)
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub_pem


def test_web_signed_manifest_verifies():
    priv, pub_pem = _keypair()
    root = "ab" * 32
    ts = 1_720_000_000.5
    sig = priv.sign(_build_web_signed_message(root, ts))

    manifest = {
        "root_hash": root,
        "timestamp_utc": ts,
        "signature": sig.hex(),
        "signer": "Orygn Authority (test fixture)",
    }
    result = verify_manifest_signature(manifest, public_key_pem=pub_pem)
    assert result["ok"] is True
    assert result["format"] == "web"


def test_web_signed_rejects_tampered_root():
    priv, pub_pem = _keypair()
    root = "ab" * 32
    ts = 1_720_000_000.5
    sig = priv.sign(_build_web_signed_message(root, ts))

    manifest = {
        "root_hash": "cd" * 32,  # mutated after signing
        "timestamp_utc": ts,
        "signature": sig.hex(),
        "signer": "Orygn Authority",
    }
    result = verify_manifest_signature(manifest, public_key_pem=pub_pem)
    assert result["ok"] is False
    assert result["format"] == "web"


def test_web_signed_rejects_tampered_timestamp():
    priv, pub_pem = _keypair()
    root = "ab" * 32
    ts = 1_720_000_000.5
    sig = priv.sign(_build_web_signed_message(root, ts))

    manifest = {
        "root_hash": root,
        "timestamp_utc": ts + 1.0,  # mutated after signing
        "signature": sig.hex(),
        "signer": "Orygn Authority",
    }
    result = verify_manifest_signature(manifest, public_key_pem=pub_pem)
    assert result["ok"] is False


def test_cli_signed_manifest_verifies():
    priv, pub_pem = _keypair()
    root = "de" * 32
    fingerprint = "test-machine-fp-v1"
    ts = 1_720_000_000.5
    sig = priv.sign(_build_cli_signed_message(root, fingerprint, ts))

    manifest = {
        "root_hash": root,
        "timestamp_utc": ts,
        "signature": sig.hex(),
        "signer": "BitSeal Local CLI",
        "machine_fingerprint": fingerprint,
    }
    result = verify_manifest_signature(manifest, public_key_pem=pub_pem)
    assert result["ok"] is True
    assert result["format"] == "cli"


def test_cli_signed_requires_public_key_pem():
    manifest = {
        "root_hash": "de" * 32,
        "timestamp_utc": 1.0,
        "signature": "ab" * 64,
        "signer": "BitSeal Local CLI",
        "machine_fingerprint": "x",
    }
    result = verify_manifest_signature(manifest, public_key_pem=None)
    assert result["ok"] is False
    assert "public key" in result["reason"].lower()


def test_missing_signature_field_rejected():
    manifest = {"root_hash": "a" * 64, "timestamp_utc": 1.0, "signer": "Orygn Authority"}
    result = verify_manifest_signature(manifest, public_key_pem=b"ignored")
    assert result["ok"] is False
    assert "missing" in result["reason"].lower()


def test_wrong_signature_length_rejected():
    manifest = {
        "root_hash": "a" * 64,
        "timestamp_utc": 1.0,
        "signature": "ab" * 10,  # 10 bytes, Ed25519 wants 64
        "signer": "Orygn Authority",
    }
    result = verify_manifest_signature(manifest, public_key_pem=b"ignored")
    assert result["ok"] is False
    assert "64 bytes" in result["reason"]


def test_non_hex_signature_rejected():
    manifest = {
        "root_hash": "a" * 64,
        "timestamp_utc": 1.0,
        "signature": "NOT-HEX-CHARS-IN-SIGNATURE",
        "signer": "Orygn Authority",
    }
    result = verify_manifest_signature(manifest, public_key_pem=b"ignored")
    assert result["ok"] is False
    assert "hex" in result["reason"].lower()
