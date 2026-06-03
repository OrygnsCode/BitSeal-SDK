# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Orygn LLC

"""BitSeal: Python SDK and offline verifier for the BitSeal cryptographic
proof-of-existence service.

Programmatic entry points::

    from bitseal import BitSealLedger, verify_manifest_signature
    from bitseal import verify_bitcoin_anchor, MerkleTree, HashManager

CLI entry points::

    python -m bitseal.verify --root <hex>
    python -m bitseal.verify --manifest <path>
    python -m bitseal.verify --fingerprint

The web service this SDK talks to lives at https://bitseal.orygn.tech.
The Authority public key is at /.well-known/bitseal-authority-key.json.
Full documentation: https://bitseal.orygn.tech/docs.
"""

from bitseal.core import (
    API_BASE,
    BitSealLedger,
    CHUNK_SIZE,
    DEFAULT_API_BASE,
    HashManager,
    MAX_FILE_SIZE,
    MerkleTree,
    SDK_VERSION,
    SEAL_MODE,
    SEAL_MODE_V1,
    SEAL_MODE_V2,
    SealManifest,
    WEB_AUTHORITY_KEY_URL,
    fetch_web_authority_public_key,
    verify_bitcoin_anchor,
    verify_manifest_signature,
)
from bitseal.log_sth import (
    GENESIS_PREV_MERKLE_ROOT,
    STH_MODE_V1,
    canonical_leaf_bytes,
    leaf_hash_hex,
    compute_merkle_root_from_leaves,
    canonical_sth_bytes,
    build_signed_sth_message,
    verify_inclusion,
    verify_sth_signature,
    verify_seal_in_log,
)

__version__ = SDK_VERSION

__all__ = [
    "API_BASE",
    "BitSealLedger",
    "CHUNK_SIZE",
    "DEFAULT_API_BASE",
    "HashManager",
    "MAX_FILE_SIZE",
    "MerkleTree",
    "SDK_VERSION",
    "SEAL_MODE",
    "SEAL_MODE_V1",
    "SEAL_MODE_V2",
    "SealManifest",
    "WEB_AUTHORITY_KEY_URL",
    "fetch_web_authority_public_key",
    "verify_bitcoin_anchor",
    "verify_manifest_signature",
    # G-6 Merkle log surface (v0.3.4)
    "GENESIS_PREV_MERKLE_ROOT",
    "STH_MODE_V1",
    "canonical_leaf_bytes",
    "leaf_hash_hex",
    "compute_merkle_root_from_leaves",
    "canonical_sth_bytes",
    "build_signed_sth_message",
    "verify_inclusion",
    "verify_sth_signature",
    "verify_seal_in_log",
]
