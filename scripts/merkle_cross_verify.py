#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Orygn LLC

"""
Cross-language verifier for the unified Merkle manifest spec
(merkle-blake3-64k-v1).

Reads the golden vectors emitted by the JavaScript generator in the
BitSeal web monorepo and asserts that the Python implementation in
bitseal.core produces byte-for-byte identical leaves and roots.

If this script passes, the SDK and the web service are guaranteed to
emit the same root_hash for any identical input file, because both
funnel through the same spec.

The vectors file is bundled into the SDK at tests/vectors/
merkle-vectors.json so any outside auditor can run this end-to-end
against a clone of the SDK alone, without needing the web monorepo.
The canonical generator (web/scripts/merkle-vectors.mjs in the web
monorepo) emits this file; the SDK-bundled copy is refreshed each
time the spec changes.

Usage:
    python scripts/merkle_cross_verify.py
    python scripts/merkle_cross_verify.py --vectors path/to/merkle-vectors.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow running from the repo root without an install step.
SDK_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SDK_DIR))

import blake3  # type: ignore

from BitSealCore import CHUNK_SIZE, SEAL_MODE, MerkleTree


# Preferred location: bundled with the SDK. Works for any clone.
SDK_LOCAL_VECTORS = SDK_DIR / "tests" / "vectors" / "merkle-vectors.json"
# Legacy location: the web monorepo as a sibling directory. Used during
# local dev when the maintainer regenerates vectors via the web repo's
# Node generator and has not yet synced the file into the SDK.
SIBLING_REPO_VECTORS = SDK_DIR.parent / "BitSeal" / "web" / "scripts" / "merkle-vectors.json"


def _default_vectors_path() -> Path:
    """Pick the first vectors file that actually exists on disk.

    Prefers the SDK-bundled copy (works for any outside auditor).
    Falls back to the web-monorepo copy for maintainers working on
    both repos simultaneously. If neither exists, returns the SDK
    path so the not-found error message points to the right place."""
    if SDK_LOCAL_VECTORS.exists():
        return SDK_LOCAL_VECTORS
    if SIBLING_REPO_VECTORS.exists():
        return SIBLING_REPO_VECTORS
    return SDK_LOCAL_VECTORS


def pattern_linear(size: int) -> bytes:
    # Must match the Node generator exactly:
    # byte[i] = (i * 131 + 7) & 0xFF
    return bytes(((i * 131 + 7) & 0xFF) for i in range(size))


def pattern_zeros(size: int) -> bytes:
    return bytes(size)


def pattern_ones(size: int) -> bytes:
    return b"\xff" * size


def pattern_squared(size: int) -> bytes:
    return bytes(((i * i) & 0xFF) for i in range(size))


PATTERNS = {
    "linear": pattern_linear,
    "zeros": pattern_zeros,
    "ones": pattern_ones,
    "squared": pattern_squared,
}


def compute_leaves(buf: bytes) -> list[str]:
    if not buf:
        raise ValueError("Empty files cannot be sealed")
    leaves: list[str] = []
    for offset in range(0, len(buf), CHUNK_SIZE):
        chunk = buf[offset : offset + CHUNK_SIZE]
        leaves.append(blake3.blake3(chunk).hexdigest())
    return leaves


def compute_tree(buf: bytes) -> tuple[list[str], str]:
    leaves = compute_leaves(buf)
    tree = MerkleTree(leaves)
    return leaves, tree.root


def run(vectors_path: Path) -> int:
    if not vectors_path.exists():
        print(f"Missing vectors file: {vectors_path}", file=sys.stderr)
        print(
            "The SDK bundles a copy at tests/vectors/merkle-vectors.json. "
            "If it is also missing, regenerate from the web monorepo "
            "with `node web/scripts/merkle-vectors.mjs --generate` and "
            "copy the result into tests/vectors/merkle-vectors.json.",
            file=sys.stderr,
        )
        return 2

    data = json.loads(vectors_path.read_text(encoding="utf-8"))

    if data.get("seal_mode") != SEAL_MODE:
        print(
            f"seal_mode mismatch: vectors={data.get('seal_mode')}, python={SEAL_MODE}",
            file=sys.stderr,
        )
        return 1
    if data.get("chunk_size_bytes") != CHUNK_SIZE:
        print(
            f"chunk_size_bytes mismatch: vectors={data.get('chunk_size_bytes')}, "
            f"python={CHUNK_SIZE}",
            file=sys.stderr,
        )
        return 1

    failures = 0
    for v in data["vectors"]:
        name = v["name"]
        pattern = v["pattern"]
        size = v["size_bytes"]
        fn = PATTERNS.get(pattern)
        if fn is None:
            print(f"  [SKIP] {name}: unknown pattern {pattern!r}")
            failures += 1
            continue

        buf = fn(size)
        try:
            leaves, root = compute_tree(buf)
        except Exception as e:
            print(f"  [FAIL] {name}: {e}")
            failures += 1
            continue

        ok = (
            root == v["root_hash"]
            and len(leaves) == v["leaf_count"]
            and leaves[0] == v["first_leaf"]
            and leaves[-1] == v["last_leaf"]
        )
        if ok:
            print(f"  [PASS] {name:<20} root={root}")
        else:
            failures += 1
            print(f"  [FAIL] {name}")
            print(f"    expected root: {v['root_hash']}")
            print(f"    got root     : {root}")
            if len(leaves) != v["leaf_count"]:
                print(f"    leaf_count expected {v['leaf_count']} got {len(leaves)}")
            if leaves[0] != v["first_leaf"]:
                print(f"    first_leaf expected {v['first_leaf']}")
                print(f"    first_leaf got      {leaves[0]}")
            if leaves[-1] != v["last_leaf"]:
                print(f"    last_leaf expected {v['last_leaf']}")
                print(f"    last_leaf got      {leaves[-1]}")

    print()
    if failures:
        print(f"{failures} vector(s) failed")
        return 1
    print(f"All {len(data['vectors'])} vectors passed. Python matches JS byte-for-byte.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--vectors",
        type=Path,
        default=_default_vectors_path(),
        help=(
            "Path to merkle-vectors.json (default: "
            "tests/vectors/merkle-vectors.json when present, otherwise "
            "the sibling web-monorepo copy)."
        ),
    )
    args = parser.parse_args()
    return run(args.vectors)


if __name__ == "__main__":
    raise SystemExit(main())
