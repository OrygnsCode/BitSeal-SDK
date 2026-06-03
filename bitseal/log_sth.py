# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Orygn LLC

"""BitSeal Merkle log (Signed Tree Head) client-side verifier.

Reference implementation matching ``spec/log-sth.md`` byte-for-byte. The
public surface is small on purpose:

- ``canonical_leaf_bytes`` / ``leaf_hash_hex``
  Compute the canonical UTF-8 bytes and the BLAKE3 leaf hash for a seal,
  using exactly three fields (seal_id, seal_index, signature) per spec
  section 3.

- ``canonical_sth_bytes`` / ``build_signed_sth_message``
  Reproduce the byte-stable STH form that the Authority Ed25519
  signature is taken over (after SHA3-512), per spec section 5.

- ``verify_inclusion``
  Fold a Merkle inclusion proof and assert it ends at the STH
  merkle_root, per spec section 7.

- ``verify_consistency``
  Verify an RFC 6962-adapted consistency proof between two STHs, per
  spec section 8.

- ``verify_sth_signature``
  Ed25519-verify the STH against an Authority public key (current or
  historical) from /.well-known/bitseal-authority-key.json.

- ``verify_seal_in_log``
  High-level orchestrator: takes a seal's (seal_id, seal_index,
  signature), an STH, an inclusion proof, and an Authority public key
  PEM, and returns (ok, detail).

The math is pinned against ``spec/log-sth-test-vectors.json`` (vendored
into ``tests/log_sth_vectors.json``); see ``tests/test_log_sth.py``.
"""

from __future__ import annotations

import hashlib
import json
from typing import Iterable, Sequence

try:
    from blake3 import blake3
except ImportError as e:  # pragma: no cover - import-time guard
    raise ImportError(
        "BitSeal SDK requires the `blake3` package for log-sth verification. "
        "Install with: pip install blake3"
    ) from e


__all__ = [
    "GENESIS_PREV_MERKLE_ROOT",
    "STH_CANONICAL_HEADER_V1",
    "STH_MODE_V1",
    "canonical_leaf_bytes",
    "leaf_hash_hex",
    "compute_merkle_root_from_leaves",
    "canonical_sth_bytes",
    "build_signed_sth_message",
    "verify_inclusion",
    "verify_consistency",
    "verify_sth_signature",
    "verify_seal_in_log",
]


GENESIS_PREV_MERKLE_ROOT = "0" * 64
STH_CANONICAL_HEADER_V1 = "BITSEAL_STH_V1"
STH_MODE_V1 = "sth-v1"


# ---------------------------------------------------------------------------
# Leaf hashing
# ---------------------------------------------------------------------------

def canonical_leaf_bytes(seal_id: str, seal_index: int, signature: str) -> bytes:
    """Canonical UTF-8 bytes for a seal's Merkle leaf (spec section 3).

    The bytes are JSON with sorted keys and no whitespace::

        {"seal_id":"<id>","seal_index":<N>,"signature":"<128-hex>"}

    Raises ``ValueError`` on malformed inputs so a caller cannot silently
    publish a leaf hash over a different shape than they intended.
    """
    if not isinstance(seal_id, str) or not seal_id:
        raise ValueError("seal_id must be a non-empty string")
    try:
        si = int(seal_index)
    except (TypeError, ValueError) as exc:
        raise ValueError("seal_index must be an integer") from exc
    if si < 0:
        raise ValueError("seal_index must be non-negative")
    if not isinstance(signature, str) or len(signature) != 128:
        raise ValueError("signature must be a 128-char hex string")
    try:
        int(signature, 16)
    except ValueError as exc:
        raise ValueError("signature must be hex") from exc

    obj = {"seal_id": seal_id, "seal_index": si, "signature": signature}
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def leaf_hash_hex(seal_id: str, seal_index: int, signature: str) -> str:
    """Returns the 32-byte BLAKE3 leaf hash as lowercase hex (64 chars)."""
    return blake3(canonical_leaf_bytes(seal_id, seal_index, signature)).hexdigest()


# ---------------------------------------------------------------------------
# Merkle tree (BLAKE3-64k, odd-layer-duplicate). Identical to spec/v2-manifest.md.
# ---------------------------------------------------------------------------

def _hash_pair(left: bytes, right: bytes) -> bytes:
    if len(left) != 32 or len(right) != 32:
        raise ValueError("pair inputs must be 32 bytes each")
    return blake3(left + right).digest()


def compute_merkle_root_from_leaves(leaf_hashes_hex: Sequence[str]) -> str:
    """BLAKE3-64k Merkle root over an ordered list of 64-hex leaf hashes.

    Mirrors ``web/lib/merkle.js``'s ``computeRootFromLeaves`` byte-for-byte.
    """
    if not leaf_hashes_hex:
        raise ValueError("Merkle tree requires at least one leaf")
    layer = []
    for idx, h in enumerate(leaf_hashes_hex):
        if not isinstance(h, str) or len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
            raise ValueError(f"Leaf #{idx} is not 64-char lowercase hex")
        layer.append(bytes.fromhex(h))
    while len(layer) > 1:
        nxt = []
        for i in range(0, len(layer), 2):
            left = layer[i]
            right = layer[i + 1] if (i + 1) < len(layer) else left
            nxt.append(_hash_pair(left, right))
        layer = nxt
    return layer[0].hex()


# ---------------------------------------------------------------------------
# STH canonical bytes + signed message (SHA3-512 over canonical bytes).
# ---------------------------------------------------------------------------

def _validate_hex64(value: str, name: str) -> None:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(f"{name} must be 64-char hex")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(f"{name} must be hex") from exc
    if value != value.lower():
        raise ValueError(f"{name} must be lowercase hex")


def canonical_sth_bytes(
    *,
    sth_index: int,
    anchor_at_utc: str,
    seal_count: int,
    merkle_root: str,
    prev_sth_merkle_root: str,
) -> bytes:
    """Byte-stable canonical UTF-8 form for an STH (spec section 5).

    The five inputs after the header line are alphabetized; the trailing
    line feed is included. Any deviation breaks Ed25519 verification.
    """
    if not isinstance(sth_index, int) or sth_index < 0:
        raise ValueError("sth_index must be a non-negative integer")
    if not isinstance(seal_count, int) or seal_count < 0:
        raise ValueError("seal_count must be a non-negative integer")
    if not isinstance(anchor_at_utc, str) or not anchor_at_utc.endswith("Z"):
        raise ValueError("anchor_at_utc must be an ISO8601 string ending with Z")
    _validate_hex64(merkle_root, "merkle_root")
    _validate_hex64(prev_sth_merkle_root, "prev_sth_merkle_root")

    lines = [
        STH_CANONICAL_HEADER_V1,
        f"anchor_at_utc: {anchor_at_utc}",
        f"merkle_root: {merkle_root}",
        f"prev_sth_merkle_root: {prev_sth_merkle_root}",
        f"seal_count: {seal_count}",
        f"sth_index: {sth_index}",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def build_signed_sth_message(
    *,
    sth_index: int,
    anchor_at_utc: str,
    seal_count: int,
    merkle_root: str,
    prev_sth_merkle_root: str,
) -> bytes:
    """64-byte SHA3-512 digest of canonical_sth_bytes; the message Ed25519 signs."""
    canonical = canonical_sth_bytes(
        sth_index=sth_index,
        anchor_at_utc=anchor_at_utc,
        seal_count=seal_count,
        merkle_root=merkle_root,
        prev_sth_merkle_root=prev_sth_merkle_root,
    )
    return hashlib.sha3_512(canonical).digest()


# ---------------------------------------------------------------------------
# Inclusion proof verification (spec section 7).
# ---------------------------------------------------------------------------

def verify_inclusion(
    *,
    leaf_hash: str,
    proof: Iterable[dict],
    merkle_root: str,
) -> bool:
    """Returns True iff folding ``leaf_hash`` along ``proof`` produces ``merkle_root``.

    Each proof step is a dict with keys ``sibling_hash`` (64-hex) and
    ``position`` (``"left"`` or ``"right"``). Position indicates which
    side of the pair the sibling occupies when the running node is
    combined with it.
    """
    _validate_hex64(leaf_hash, "leaf_hash")
    _validate_hex64(merkle_root, "merkle_root")
    node = bytes.fromhex(leaf_hash)
    for i, step in enumerate(proof):
        if not isinstance(step, dict) or "sibling_hash" not in step or "position" not in step:
            raise ValueError(f"proof step #{i} missing sibling_hash or position")
        sib_hex = step["sibling_hash"]
        _validate_hex64(sib_hex, f"proof[{i}].sibling_hash")
        sibling = bytes.fromhex(sib_hex)
        pos = step["position"]
        if pos == "left":
            node = _hash_pair(sibling, node)
        elif pos == "right":
            node = _hash_pair(node, sibling)
        else:
            raise ValueError(f"proof step #{i}: position must be 'left' or 'right', got {pos!r}")
    return node.hex() == merkle_root


# ---------------------------------------------------------------------------
# Consistency proof verification (spec section 8, RFC 6962-adapted).
# ---------------------------------------------------------------------------

def _largest_power_of_two_lt(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    if n < 2:
        raise ValueError("n must be >= 2 for _largest_power_of_two_lt")
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def verify_consistency(
    *,
    first_size: int,
    first_root: str,
    second_size: int,
    second_root: str,
    proof: Sequence[str],
) -> bool:
    """Verify an RFC 6962-style consistency proof.

    Returns True iff the proof shows the size-``first_size`` tree is a
    prefix of the size-``second_size`` tree, AND both reconstructed
    roots match ``first_root`` / ``second_root``.

    ``proof`` is the ordered list of 64-hex subtree hashes as produced
    by the BitSeal log's ``/api/log/consistency`` endpoint.
    """
    _validate_hex64(first_root, "first_root")
    _validate_hex64(second_root, "second_root")
    if not isinstance(first_size, int) or first_size <= 0:
        raise ValueError("first_size must be a positive integer")
    if not isinstance(second_size, int) or second_size < first_size:
        raise ValueError("second_size must be >= first_size")
    for i, h in enumerate(proof):
        _validate_hex64(h, f"proof[{i}]")

    if first_size == second_size:
        return first_root == second_root and len(proof) == 0

    proof_bytes = [bytes.fromhex(h) for h in proof]
    # RFC 6962 §2.1.4 verification algorithm, adapted to BLAKE3 + odd-layer-dup.
    fn = first_size
    sn = second_size
    while (fn & 1) == 0:
        fn >>= 1
        sn >>= 1
    if not proof_bytes:
        return False
    fr = proof_bytes[0] if fn == first_size else proof_bytes[0]
    sr = proof_bytes[0]
    idx = 1 if fn == first_size else 1
    # When fn != first_size after the right-shift loop, the first proof
    # element is consumed by both fr and sr; otherwise we still consume
    # one proof element to seed. Implementation below uses the standard
    # CT recursion translated to an iterative loop.
    fn0, sn0 = fn, sn
    if first_size == fn0:
        # first_size is itself the seed; we did not consume a proof entry
        # for fr/sr from the operator side, only the next loop steps do.
        fr_buf = bytes.fromhex(first_root)
        sr_buf = bytes.fromhex(first_root)
        proof_iter = iter(proof_bytes)
    else:
        proof_iter = iter(proof_bytes)
        seed = next(proof_iter)
        fr_buf = seed
        sr_buf = seed
    while fn0 > 0:
        if (fn0 & 1) or fn0 == sn0:
            try:
                p = next(proof_iter)
            except StopIteration:
                return False
            fr_buf = _hash_pair(p, fr_buf)
            sr_buf = _hash_pair(p, sr_buf)
            while (fn0 & 1) == 0 and fn0 != 0:
                fn0 >>= 1
                sn0 >>= 1
        else:
            try:
                p = next(proof_iter)
            except StopIteration:
                return False
            sr_buf = _hash_pair(sr_buf, p)
        fn0 >>= 1
        sn0 >>= 1
    # Drain any remaining proof entries into sr_buf.
    while True:
        try:
            p = next(proof_iter)
        except StopIteration:
            break
        sr_buf = _hash_pair(sr_buf, p)
        while (sn0 & 1) == 0 and sn0 > 0:
            sn0 >>= 1

    return fr_buf == bytes.fromhex(first_root) and sr_buf == bytes.fromhex(second_root)


# ---------------------------------------------------------------------------
# STH signature verification.
# ---------------------------------------------------------------------------

def verify_sth_signature(*, sth: dict, public_key_pem: str) -> bool:
    """Ed25519-verify the STH's signature against a PEM-encoded Authority
    public key. Returns True iff the signature is valid.

    The STH dict must carry the five canonical-form fields (sth_index,
    anchor_at_utc, seal_count, merkle_root, prev_sth_merkle_root) plus
    the ``signature`` field (128-hex).
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
    except ImportError as e:  # pragma: no cover - import guard
        raise ImportError(
            "verify_sth_signature requires `cryptography`. "
            "Install with: pip install cryptography"
        ) from e

    sig_hex = sth.get("signature")
    if not isinstance(sig_hex, str) or len(sig_hex) != 128:
        raise ValueError("sth.signature must be a 128-char hex string")
    sig = bytes.fromhex(sig_hex)

    digest = build_signed_sth_message(
        sth_index=int(sth["sth_index"]),
        anchor_at_utc=sth["anchor_at_utc"],
        seal_count=int(sth["seal_count"]),
        merkle_root=sth["merkle_root"],
        prev_sth_merkle_root=sth["prev_sth_merkle_root"],
    )

    pub = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    if not isinstance(pub, Ed25519PublicKey):
        raise ValueError("public_key_pem is not an Ed25519 public key")
    try:
        pub.verify(sig, digest)
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# High-level orchestrator.
# ---------------------------------------------------------------------------

def verify_seal_in_log(
    *,
    seal_id: str,
    seal_index: int,
    signature: str,
    sth: dict,
    inclusion_proof: Sequence[dict],
    authority_public_key_pem: str,
) -> tuple[bool, str]:
    """End-to-end: confirm a seal is in the log AND the STH is Authority-signed.

    Returns ``(ok, detail)``. On failure ``detail`` describes which step
    failed so callers can surface a useful message.
    """
    # 1. Recompute leaf hash.
    try:
        local_leaf = leaf_hash_hex(seal_id, seal_index, signature)
    except ValueError as e:
        return False, f"leaf hash recompute failed: {e}"

    # 2. Verify inclusion against the STH's merkle_root.
    merkle_root = sth.get("merkle_root")
    if not isinstance(merkle_root, str):
        return False, "sth.merkle_root missing or not a string"
    try:
        ok = verify_inclusion(
            leaf_hash=local_leaf,
            proof=inclusion_proof,
            merkle_root=merkle_root,
        )
    except ValueError as e:
        return False, f"inclusion proof verify failed: {e}"
    if not ok:
        return False, "inclusion proof does not fold to STH merkle_root"

    # 3. Verify STH signature.
    try:
        sig_ok = verify_sth_signature(sth=sth, public_key_pem=authority_public_key_pem)
    except (ValueError, ImportError) as e:
        return False, f"STH signature verify failed: {e}"
    if not sig_ok:
        return False, "STH signature does not verify against the provided Authority public key"

    return True, (
        f"seal_index={seal_index} verified at sth_index={sth.get('sth_index')}; "
        f"STH is Authority-signed; merkle_root={merkle_root[:16]}..."
    )
