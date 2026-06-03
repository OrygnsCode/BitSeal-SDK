# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Orygn LLC

"""Tests for bitseal.log_sth byte-stable against the published vectors.

The published vectors live at spec/log-sth-test-vectors.json in the main
BitSeal repo and are vendored here as tests/log_sth_vectors.json. The
spec doc is at spec/log-sth.md. If those files drift, re-vendor and
re-run.

Vector A: single seal, single leaf (root == leaf).
Vector B: three seals, exercises odd-layer-duplicate.
Vector C: 5-seal inclusion proof for seal_index=2.
Vector D: full STH signing round-trip with RFC 8032 §7.1 Test 1 keypair.
"""

import hashlib
import json
import pathlib

import pytest

from bitseal.log_sth import (
    GENESIS_PREV_MERKLE_ROOT,
    canonical_leaf_bytes,
    leaf_hash_hex,
    compute_merkle_root_from_leaves,
    canonical_sth_bytes,
    build_signed_sth_message,
    verify_inclusion,
    verify_sth_signature,
    verify_seal_in_log,
)


VECTORS_PATH = pathlib.Path(__file__).parent / "log_sth_vectors.json"


@pytest.fixture(scope="module")
def vectors():
    with VECTORS_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Vector A: single seal, single leaf, root == leaf.
# ---------------------------------------------------------------------------

def test_vector_a_canonical_leaf_bytes(vectors):
    v = vectors["vectors"]["A"]
    seal = v["input_seal"]
    actual = canonical_leaf_bytes(seal["seal_id"], seal["seal_index"], seal["signature"])
    assert actual == v["canonical_leaf_bytes_utf8"].encode("utf-8")
    assert actual.hex() == v["canonical_leaf_bytes_hex"]
    assert len(actual) == v["canonical_leaf_bytes_length"]


def test_vector_a_leaf_hash(vectors):
    v = vectors["vectors"]["A"]
    seal = v["input_seal"]
    assert leaf_hash_hex(seal["seal_id"], seal["seal_index"], seal["signature"]) == v["leaf_hash_hex"]


def test_vector_a_merkle_root_equals_leaf(vectors):
    v = vectors["vectors"]["A"]
    root = compute_merkle_root_from_leaves([v["leaf_hash_hex"]])
    assert root == v["merkle_root_hex"]
    # For a single leaf, the root equals the leaf hash.
    assert root == v["leaf_hash_hex"]


# ---------------------------------------------------------------------------
# Vector B: three seals, odd-layer-duplicate exercise.
# ---------------------------------------------------------------------------

def test_vector_b_leaf_hashes(vectors):
    v = vectors["vectors"]["B"]
    seals = v["input_seals"]
    leaves = [leaf_hash_hex(s["seal_id"], s["seal_index"], s["signature"]) for s in seals]
    assert leaves == v["leaf_hashes_hex"]


def test_vector_b_merkle_root(vectors):
    v = vectors["vectors"]["B"]
    root = compute_merkle_root_from_leaves(v["leaf_hashes_hex"])
    assert root == v["merkle_root_hex"]


# ---------------------------------------------------------------------------
# Vector C: 5-seal inclusion proof for seal_index=2.
# ---------------------------------------------------------------------------

def test_vector_c_leaf_hashes(vectors):
    v = vectors["vectors"]["C"]
    seals = v["input_seals"]
    leaves = [leaf_hash_hex(s["seal_id"], s["seal_index"], s["signature"]) for s in seals]
    assert leaves == v["leaf_hashes_hex"]


def test_vector_c_merkle_root(vectors):
    v = vectors["vectors"]["C"]
    root = compute_merkle_root_from_leaves(v["leaf_hashes_hex"])
    assert root == v["merkle_root_hex"]


def test_vector_c_inclusion_proof_verifies(vectors):
    v = vectors["vectors"]["C"]
    proof_data = v["inclusion_proof_for_seal_index_2"]
    ok = verify_inclusion(
        leaf_hash=proof_data["leaf_hash"],
        proof=proof_data["proof"],
        merkle_root=proof_data["merkle_root"],
    )
    assert ok is True


def test_vector_c_inclusion_proof_rejects_wrong_leaf(vectors):
    v = vectors["vectors"]["C"]
    proof_data = v["inclusion_proof_for_seal_index_2"]
    # Use a different leaf (seal_index 3 instead of 2). Proof should not fold.
    wrong_leaf = v["leaf_hashes_hex"][3]
    assert verify_inclusion(
        leaf_hash=wrong_leaf,
        proof=proof_data["proof"],
        merkle_root=proof_data["merkle_root"],
    ) is False


def test_vector_c_inclusion_proof_rejects_wrong_root(vectors):
    v = vectors["vectors"]["C"]
    proof_data = v["inclusion_proof_for_seal_index_2"]
    assert verify_inclusion(
        leaf_hash=proof_data["leaf_hash"],
        proof=proof_data["proof"],
        merkle_root="0" * 64,
    ) is False


# ---------------------------------------------------------------------------
# Vector D: full STH signing round-trip with RFC 8032 §7.1 Test 1 keypair.
# ---------------------------------------------------------------------------

def test_vector_d_canonical_sth_bytes(vectors):
    v = vectors["vectors"]["D"]
    sth = v["input_sth"]
    actual = canonical_sth_bytes(
        sth_index=sth["sth_index"],
        anchor_at_utc=sth["anchor_at_utc"],
        seal_count=sth["seal_count"],
        merkle_root=sth["merkle_root"],
        prev_sth_merkle_root=sth["prev_sth_merkle_root"],
    )
    assert actual == v["canonical_sth_bytes_utf8"].encode("utf-8")
    assert actual.hex() == v["canonical_sth_bytes_hex"]
    assert len(actual) == v["canonical_sth_bytes_length"]


def test_vector_d_sha3_512_digest(vectors):
    v = vectors["vectors"]["D"]
    sth = v["input_sth"]
    digest = build_signed_sth_message(
        sth_index=sth["sth_index"],
        anchor_at_utc=sth["anchor_at_utc"],
        seal_count=sth["seal_count"],
        merkle_root=sth["merkle_root"],
        prev_sth_merkle_root=sth["prev_sth_merkle_root"],
    )
    assert digest.hex() == v["sha3_512_digest_hex"]
    assert len(digest) == 64  # SHA3-512 output


def test_vector_d_ed25519_signature_verifies(vectors):
    """The Ed25519 signature in Vector D was produced by the RFC 8032 §7.1
    Test 1 PRIVATE key. Here we verify it against the corresponding PUBLIC
    key using bitseal.verify_sth_signature."""
    v = vectors["vectors"]["D"]
    sth_input = v["input_sth"]
    pub_hex = vectors["ed25519_test_keypair"]["public_key_raw_hex"]

    # Construct the PEM for the test public key.
    der_prefix = bytes.fromhex("302a300506032b6570032100")
    der = der_prefix + bytes.fromhex(pub_hex)
    import base64
    b64 = base64.b64encode(der).decode("ascii")
    wrapped = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    pem = f"-----BEGIN PUBLIC KEY-----\n{wrapped}\n-----END PUBLIC KEY-----\n"

    sth_with_sig = dict(sth_input)
    sth_with_sig["signature"] = v["ed25519_signature_hex"]

    assert verify_sth_signature(sth=sth_with_sig, public_key_pem=pem) is True


# ---------------------------------------------------------------------------
# verify_seal_in_log orchestrator: builds a synthetic 3-seal STH, signs
# with the RFC 8032 test key, runs the full path through the public API.
# Uses Vector B's leaves to reuse those computed roots.
# ---------------------------------------------------------------------------

def test_verify_seal_in_log_orchestrator_happy_path(vectors):
    v_b = vectors["vectors"]["B"]
    v_d = vectors["vectors"]["D"]
    seals = v_b["input_seals"]

    # Build an inclusion proof for seal_index=0 of the 3-seal tree by
    # iterating: leaves = [L0, L1, L2]. Layer 0 pair (L0, L1) and self-pair
    # (L2, L2). Layer 1 pair the two parents. So inclusion for L0 is:
    #   step 0: sibling = L1, position = "right"
    #   step 1: sibling = parent(L2, L2), position = "right"
    leaves = v_b["leaf_hashes_hex"]
    # Compute parent(L2, L2)
    l2 = bytes.fromhex(leaves[2])
    from blake3 import blake3
    p22 = blake3(l2 + l2).hexdigest()

    proof_for_l0 = [
        {"sibling_hash": leaves[1], "position": "right"},
        {"sibling_hash": p22, "position": "right"},
    ]

    # Compose a synthetic STH (use Vector D's STH inputs verbatim since
    # they correspond to Vector B's 3-seal root).
    sth_input = v_d["input_sth"]
    sth = dict(sth_input)
    sth["signature"] = v_d["ed25519_signature_hex"]

    # Build the same PEM as test_vector_d_ed25519_signature_verifies.
    pub_hex = vectors["ed25519_test_keypair"]["public_key_raw_hex"]
    der_prefix = bytes.fromhex("302a300506032b6570032100")
    import base64
    b64 = base64.b64encode(der_prefix + bytes.fromhex(pub_hex)).decode("ascii")
    wrapped = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    pem = f"-----BEGIN PUBLIC KEY-----\n{wrapped}\n-----END PUBLIC KEY-----\n"

    ok, detail = verify_seal_in_log(
        seal_id=seals[0]["seal_id"],
        seal_index=seals[0]["seal_index"],
        signature=seals[0]["signature"],
        sth=sth,
        inclusion_proof=proof_for_l0,
        authority_public_key_pem=pem,
    )
    assert ok is True, detail
    assert "verified" in detail


def test_verify_seal_in_log_rejects_tampered_signature(vectors):
    v_b = vectors["vectors"]["B"]
    seals = v_b["input_seals"]
    sth = {
        "sth_index": 0,
        "anchor_at_utc": "2026-06-03T11:23:36.542Z",
        "seal_count": 3,
        "merkle_root": v_b["merkle_root_hex"],
        "prev_sth_merkle_root": GENESIS_PREV_MERKLE_ROOT,
        "signature": "00" * 64,  # tampered signature
    }
    # Doesn't matter what the proof looks like; signature check should fail.
    pem = (
        "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPa\n"
        "piMlrwIaaPcHUR=\n-----END PUBLIC KEY-----\n"
    )  # invalid PEM, but failure should happen before parse
    # Use Vector D's pubkey instead so PEM is parseable.
    pub_hex = vectors["ed25519_test_keypair"]["public_key_raw_hex"]
    der_prefix = bytes.fromhex("302a300506032b6570032100")
    import base64
    b64 = base64.b64encode(der_prefix + bytes.fromhex(pub_hex)).decode("ascii")
    wrapped = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    pem = f"-----BEGIN PUBLIC KEY-----\n{wrapped}\n-----END PUBLIC KEY-----\n"

    leaves = v_b["leaf_hashes_hex"]
    from blake3 import blake3
    p22 = blake3(bytes.fromhex(leaves[2]) + bytes.fromhex(leaves[2])).hexdigest()
    proof = [
        {"sibling_hash": leaves[1], "position": "right"},
        {"sibling_hash": p22, "position": "right"},
    ]
    ok, detail = verify_seal_in_log(
        seal_id=seals[0]["seal_id"],
        seal_index=seals[0]["seal_index"],
        signature=seals[0]["signature"],
        sth=sth,
        inclusion_proof=proof,
        authority_public_key_pem=pem,
    )
    assert ok is False
    assert "STH signature" in detail


# ---------------------------------------------------------------------------
# Input validation.
# ---------------------------------------------------------------------------

def test_leaf_hash_rejects_negative_index():
    with pytest.raises(ValueError):
        leaf_hash_hex("x", -1, "a" * 128)


def test_leaf_hash_rejects_short_signature():
    with pytest.raises(ValueError):
        leaf_hash_hex("x", 0, "a" * 64)


def test_canonical_sth_rejects_non_z_anchor():
    with pytest.raises(ValueError):
        canonical_sth_bytes(
            sth_index=0,
            anchor_at_utc="2026-06-03T11:23:36.542",  # missing Z
            seal_count=1,
            merkle_root="a" * 64,
            prev_sth_merkle_root=GENESIS_PREV_MERKLE_ROOT,
        )


def test_canonical_sth_rejects_short_merkle_root():
    with pytest.raises(ValueError):
        canonical_sth_bytes(
            sth_index=0,
            anchor_at_utc="2026-06-03T11:23:36.542Z",
            seal_count=1,
            merkle_root="abc",
            prev_sth_merkle_root=GENESIS_PREV_MERKLE_ROOT,
        )
