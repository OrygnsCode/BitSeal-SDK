"""HashManager.compute_forensics: verify per-chunk blake3 leaves, global
blake3, global sha3-512, entropy, and leaf count against known inputs.
"""

import asyncio
import hashlib
import os
import tempfile

import blake3
import pytest

from BitSealCore import CHUNK_SIZE, HashManager


def _write_temp(data: bytes) -> str:
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        return f.name


def _run(path):
    return asyncio.run(HashManager(path).compute_forensics())


def test_single_chunk_file():
    data = b"\x42" * CHUNK_SIZE
    path = _write_temp(data)
    try:
        b3, s3, leaves, entropy, hotspots = _run(path)
        assert b3 == blake3.blake3(data).hexdigest()
        assert s3 == hashlib.sha3_512(data).hexdigest()
        assert leaves == [blake3.blake3(data).hexdigest()]
        assert entropy == 0.0  # single-value data has zero entropy
        assert hotspots == []
    finally:
        os.unlink(path)


def test_two_chunk_file():
    left = b"A" * CHUNK_SIZE
    right = b"B" * CHUNK_SIZE
    data = left + right
    path = _write_temp(data)
    try:
        b3, s3, leaves, entropy, hotspots = _run(path)
        assert b3 == blake3.blake3(data).hexdigest()
        assert s3 == hashlib.sha3_512(data).hexdigest()
        assert leaves == [
            blake3.blake3(left).hexdigest(),
            blake3.blake3(right).hexdigest(),
        ]
        assert len(leaves) == 2
    finally:
        os.unlink(path)


def test_partial_final_chunk():
    full = b"X" * CHUNK_SIZE
    partial = b"Y" * (CHUNK_SIZE // 3)
    data = full + partial
    path = _write_temp(data)
    try:
        b3, s3, leaves, _, _ = _run(path)
        assert b3 == blake3.blake3(data).hexdigest()
        assert len(leaves) == 2
        assert leaves[0] == blake3.blake3(full).hexdigest()
        assert leaves[1] == blake3.blake3(partial).hexdigest()
    finally:
        os.unlink(path)


def test_high_entropy_chunk_is_flagged():
    # Cryptographically-random bytes should exceed the 7.6 bits/byte hotspot
    # threshold the SDK uses. Use os.urandom so the chunk is near-maximum entropy.
    data = os.urandom(CHUNK_SIZE)
    path = _write_temp(data)
    try:
        _, _, _, entropy, hotspots = _run(path)
        assert entropy > 7.5
        assert hotspots == [0]  # chunk index 0 is flagged
    finally:
        os.unlink(path)


def test_low_entropy_chunk_not_flagged():
    # Pure zeros => entropy 0, no hotspot
    data = b"\x00" * CHUNK_SIZE
    path = _write_temp(data)
    try:
        _, _, _, entropy, hotspots = _run(path)
        assert entropy == 0.0
        assert hotspots == []
    finally:
        os.unlink(path)


def test_empty_file_edge_case():
    # 0-byte file => no leaves, no chunks. process_seal would reject this
    # upstream, but HashManager itself should still run cleanly.
    path = _write_temp(b"")
    try:
        b3, s3, leaves, entropy, hotspots = _run(path)
        assert b3 == blake3.blake3(b"").hexdigest()
        assert s3 == hashlib.sha3_512(b"").hexdigest()
        assert leaves == []
        assert entropy == 0.0
        assert hotspots == []
    finally:
        os.unlink(path)
