"""MerkleTree math: verify the `merkle-blake3-64k-v1` layer construction
against hand-computed expected roots.

The construction rule: each non-leaf node is blake3(left_hex || right_hex)
where the concatenation happens on the hex strings then decoded once for
hashing (matches BitSealCore.MerkleTree._build_tree). Odd layers duplicate
the last element before pairing.
"""

import blake3

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
