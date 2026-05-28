# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Orygn LLC

"""Back-compat shim. The real implementation lives in ``bitseal.core``
as of v0.3.0. Importing ``BitSealCore`` directly continues to work for
code written before the package refactor, and for users who clone the
repo and run scripts from the repo root without installing the package.

New code should prefer::

    from bitseal import BitSealLedger, verify_manifest_signature

This shim re-exports every public name from ``bitseal.core``. The names
listed in the explicit imports below are the ones the SDK's tests,
scripts, and external documented API surface depend on; the
``from bitseal.core import *`` line also picks up anything else that
``bitseal.core`` declares non-private.
"""

from bitseal.core import *  # noqa: F401, F403
from bitseal.core import (  # noqa: F401
    API_BASE,
    BitSealLedger,
    CHUNK_SIZE,
    DEFAULT_API_BASE,
    HashManager,
    MAX_FILE_SIZE,
    MerkleTree,
    SDK_VERSION,
    SEAL_MODE,
    SealManifest,
    WEB_AUTHORITY_KEY_URL,
    _build_cli_signed_message,
    _build_web_signed_message,
    _is_web_signed_manifest,
    fetch_web_authority_public_key,
    main,
    verify_bitcoin_anchor,
    verify_manifest_signature,
)

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
    "SealManifest",
    "WEB_AUTHORITY_KEY_URL",
    "_build_cli_signed_message",
    "_build_web_signed_message",
    "_is_web_signed_manifest",
    "fetch_web_authority_public_key",
    "main",
    "verify_bitcoin_anchor",
    "verify_manifest_signature",
]


if __name__ == "__main__":
    main()
