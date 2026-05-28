# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Orygn LLC

"""MerkleTree math: verify the `merkle-blake3-64k-v1` layer construction
against hand-computed expected roots.

The construction rule: each non-leaf node is blake3(left_hex || right_hex)
where the concatenation happens on the hex strings then decoded once for
hashing (matches BitSealCore.MerkleTree._build_tree). Odd layers duplicate
the last element before pairing.
"""

import blake3
import pytest

from BitSealCore import MerkleTree


def _hash_pair(left_hex, right_hex):
    return blake3.blake3(bytes.fromhex(left_hex + right_hex)).hexdigest()


def test_single_leaf_is_root():
    leaf = "a" * 64
    tree = MerkleTree([leaf])
    assert tree.root == leaf


def test_two_leaves():
    h1 = "11" * 32
    h2 = "22" * 32
    tree = MerkleTree([h1, h2])
    assert tree.root == _hash_pair(h1, h2)


def test_three_leaves_duplicates_last():
    h1 = "11" * 32
    h2 = "22" * 32
    h3 = "33" * 32
    tree = MerkleTree([h1, h2, h3])
    left = _hash_pair(h1, h2)
    right = _hash_pair(h3, h3)
    assert tree.root == _hash_pair(left, right)


def test_four_leaves_balanced():
    h1 = "11" * 32
    h2 = "22" * 32
    h3 = "33" * 32
    h4 = "44" * 32
    tree = MerkleTree([h1, h2, h3, h4])
    left = _hash_pair(h1, h2)
    right = _hash_pair(h3, h4)
    assert tree.root == _hash_pair(left, right)


def test_five_leaves_mixed_odd_layers():
    leaves = [f"{i:02x}" * 32 for i in range(1, 6)]
    tree = MerkleTree(leaves)

    a = _hash_pair(leaves[0], leaves[1])
    b = _hash_pair(leaves[2], leaves[3])
    c = _hash_pair(leaves[4], leaves[4])
    left = _hash_pair(a, b)
    right = _hash_pair(c, c)
    assert tree.root == _hash_pair(left, right)


def test_root_deterministic_across_invocations():
    leaves = [f"{i:02x}" * 32 for i in range(1, 17)]
    r1 = MerkleTree(leaves).root
    r2 = MerkleTree(leaves).root
    assert r1 == r2


def test_different_leaves_different_roots():
    a = MerkleTree(["11" * 32, "22" * 32]).root
    b = MerkleTree(["22" * 32, "11" * 32]).root
    assert a != b


def test_merkle_tree_raises_when_blake3_missing(monkeypatch):
    """Audit finding M2 regression guard.

    If blake3 failed to import (its module-level binding in
    bitseal.core is None), MerkleTree must hard-raise RuntimeError.
    The pre-M2 code silently fell back to SHA-256, which produced a
    tree that did NOT match the merkle-blake3-64k-v1 spec and would
    misverify against real seals without surfacing any error to the
    caller.

    We simulate the missing-blake3 state by monkeypatching the module
    attribute rather than uninstalling the package. The fail-fast
    must happen at MerkleTree construction time (no partial state),
    and the error message must name blake3 so users know what to
    install."""
    import bitseal.core

    monkeypatch.setattr(bitseal.core, "blake3", None)

    with pytest.raises(RuntimeError, match=r"blake3 is required"):
        bitseal.core.MerkleTree(["11" * 32, "22" * 32])


def test_merkle_tree_never_uses_sha256_fallback(monkeypatch):
    """Belt-and-braces for M2: even with a single-leaf input (which
    doesn't enter the hashing loop), and even if SHA-256 happens to
    be available, the absence of blake3 must still raise."""
    import bitseal.core

    monkeypatch.setattr(bitseal.core, "blake3", None)

    # Two-leaf input exercises the loop path.
    with pytest.raises(RuntimeError):
        bitseal.core.MerkleTree(["aa" * 32, "bb" * 32])

    # Single-leaf input does NOT enter the loop (root == leaf), but
    # the check happens regardless of leaf count. Pre-M2 behavior
    # would have silently constructed a single-leaf tree without
    # touching the broken fallback.
    with pytest.raises(RuntimeError):
        bitseal.core.MerkleTree(["aa" * 32])
