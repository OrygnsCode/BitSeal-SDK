# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Orygn LLC

"""Regression tests for the v0.3.0 package refactor. These tests do
NOT exercise BitSeal's cryptographic surface (other test files do that).
They guard the invariants of the package layout: that the back-compat
shims at the repo root re-export the SAME objects as the new
``bitseal/`` package, that the public API surface is complete and
self-consistent, and that the two CLI invocation paths
(``python verify.py`` and ``python -m bitseal.verify``) stay in sync.

If a future refactor accidentally duplicates symbols (e.g. defining
``BitSealLedger`` twice instead of re-exporting), these tests will
catch it.
"""

import re
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Identity invariants: shim objects must BE the package objects.
# ---------------------------------------------------------------------------

# Public names defined in bitseal/__init__.py. If __init__.py drops one
# of these we want to know.
_BITSEAL_PUBLIC_NAMES = [
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
]


def test_bitseal_init_exports_every_documented_name():
    """Every name in the documented public list must be importable from
    ``bitseal`` as a top-level attribute."""
    import bitseal

    for name in _BITSEAL_PUBLIC_NAMES:
        assert hasattr(bitseal, name), (
            f"bitseal.{name} is missing. If this is intentional, update "
            f"the _BITSEAL_PUBLIC_NAMES list in this test and the "
            f"__all__ list in bitseal/__init__.py."
        )


def test_bitseal_all_matches_documented_names():
    """``bitseal.__all__`` and the documented public name list must
    agree, in either direction. Catches drift in either spot."""
    import bitseal

    declared = set(bitseal.__all__)
    expected = set(_BITSEAL_PUBLIC_NAMES)

    missing_from_all = expected - declared
    extra_in_all = declared - expected
    assert not missing_from_all, (
        f"Names in test list but NOT in bitseal.__all__: {missing_from_all}"
    )
    assert not extra_in_all, (
        f"Names in bitseal.__all__ but NOT in test list: {extra_in_all}. "
        "Add them to _BITSEAL_PUBLIC_NAMES if they are part of the "
        "documented public API."
    )


@pytest.mark.parametrize("name", _BITSEAL_PUBLIC_NAMES)
def test_BitSealCore_shim_reexports_identity(name):
    """``BitSealCore.X is bitseal.core.X`` for every public name.

    Identity (``is``), not equality. If the shim accidentally rebinds
    ``X = SomethingElse`` instead of re-importing, this test fails."""
    import BitSealCore
    import bitseal.core as pkg_core

    shim_obj = getattr(BitSealCore, name)
    pkg_obj = getattr(pkg_core, name)
    assert shim_obj is pkg_obj, (
        f"BitSealCore.{name} is not the same object as bitseal.core.{name}. "
        "The back-compat shim must re-export, not redefine."
    )


@pytest.mark.parametrize("name", _BITSEAL_PUBLIC_NAMES)
def test_bitseal_top_level_reexports_identity(name):
    """``bitseal.X is bitseal.core.X``: the package root re-exports
    from the implementation module without rebinding."""
    import bitseal
    import bitseal.core as pkg_core

    top = getattr(bitseal, name)
    inner = getattr(pkg_core, name)
    assert top is inner, (
        f"bitseal.{name} is not the same object as bitseal.core.{name}."
    )


def test_BitSealCore_shim_exposes_private_test_helpers():
    """The signature tests reach into private helpers
    ``_build_cli_signed_message`` and ``_build_web_signed_message``.
    The shim must surface them or those tests break."""
    import BitSealCore
    import bitseal.core as pkg_core

    for private_name in (
        "_build_cli_signed_message",
        "_build_web_signed_message",
        "_is_web_signed_manifest",
    ):
        assert hasattr(BitSealCore, private_name), (
            f"BitSealCore.{private_name} missing from shim. test_signatures.py "
            "depends on it."
        )
        assert getattr(BitSealCore, private_name) is getattr(pkg_core, private_name)


def test_cli_ui_shim_exposes_documented_helpers():
    """The four ``_cli_ui`` helpers used by tests and by verify.py must
    be reachable through the root shim."""
    import _cli_ui as root_shim
    import bitseal._cli_ui as pkg_cli

    for helper in ("header_panel", "kv_table", "render_panel", "short_hex"):
        assert hasattr(root_shim, helper)
        assert getattr(root_shim, helper) is getattr(pkg_cli, helper)


def test_version_string_is_consistent():
    """``bitseal.__version__``, ``bitseal.SDK_VERSION``, and
    ``BitSealCore.SDK_VERSION`` must all agree. A mismatched version
    string is a packaging bug that breaks ``pip install bitseal==X``."""
    import bitseal
    import BitSealCore

    assert bitseal.__version__ == bitseal.SDK_VERSION
    assert bitseal.SDK_VERSION == BitSealCore.SDK_VERSION
    # Pin format: semver-ish, three numeric components (allow optional
    # suffix like "0.3.0rc1" or "0.3.0+local" if we ever ship one).
    assert re.match(r"^\d+\.\d+\.\d+", bitseal.__version__), (
        f"SDK_VERSION must start with N.N.N, got {bitseal.__version__!r}"
    )


# ---------------------------------------------------------------------------
# CLI invocation parity: the two documented ways to invoke the verifier
# must produce identical output for the same logical operation. The
# happy-path fingerprint computation against a local PEM is the test
# vector we use.
# ---------------------------------------------------------------------------

# A fixed Ed25519 keypair (NOT the production Authority key). Public
# key in PEM form. Computing SHA-256 over its DER SubjectPublicKeyInfo
# must produce the same digest from both invocation paths.
_TEST_PUBKEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAfBlz+wbz7C8tQ2WuoxgrIO3hSqdsApb2eGS+2RpJBXM=
-----END PUBLIC KEY-----
"""


def _run_fingerprint(invocation, tmp_path):
    """Run one of the verify entry points with --fingerprint pointed at
    a local PEM file, return the 64-char SHA-256 hex digest extracted
    from stdout.

    The output is a Rich-rendered panel that may wrap a 64-character
    hex string across two visual lines (the panel column is narrower
    than 64 chars). We walk character-by-character after the
    ``SHA-256 (hex)`` label and accumulate the first 64 hex chars
    we see, which reassembles the digest regardless of panel wrap."""
    pem_path = tmp_path / "authority.pem"
    pem_path.write_bytes(_TEST_PUBKEY_PEM)

    result = subprocess.run(
        invocation + ["--fingerprint", "--public-key", str(pem_path)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=30,
    )
    assert result.returncode == 0, (
        f"{invocation} exited {result.returncode}. stderr:\n{result.stderr}"
    )

    label_idx = result.stdout.find("SHA-256 (hex)")
    assert label_idx >= 0, (
        f"Could not find 'SHA-256 (hex)' label in output:\n{result.stdout}"
    )
    # Stop scanning once we hit a different label so we never bleed
    # into SHA-256 (base64) or SHA-256 (colon).
    after_label = result.stdout[label_idx + len("SHA-256 (hex)"):]
    next_label_idx = after_label.find("SHA-256 (")
    if next_label_idx >= 0:
        after_label = after_label[:next_label_idx]

    hex_chars = []
    for ch in after_label:
        if ch in "0123456789abcdef":
            hex_chars.append(ch)
            if len(hex_chars) == 64:
                break
    assert len(hex_chars) == 64, (
        f"Only found {len(hex_chars)} hex chars after the SHA-256 (hex) "
        f"label. Full output:\n{result.stdout}"
    )
    return "".join(hex_chars)


def test_dual_invocation_fingerprint_matches(tmp_path):
    """``python verify.py --fingerprint --public-key X`` and
    ``python -m bitseal.verify --fingerprint --public-key X`` must
    produce the same 64-character SHA-256 hex digest. If the root shim
    and the package path diverge, this catches it.

    Also doubles as a regression test for the --fingerprint flag itself
    (added in Phase 1.4) since this is the only test that exercises
    the CLI end-to-end on a known input."""
    hex_via_shim = _run_fingerprint(
        [sys.executable, "verify.py"], tmp_path
    )
    hex_via_module = _run_fingerprint(
        [sys.executable, "-m", "bitseal.verify"], tmp_path
    )

    assert hex_via_shim == hex_via_module, (
        f"Dual-invocation divergence:\n"
        f"  python verify.py            -> {hex_via_shim}\n"
        f"  python -m bitseal.verify    -> {hex_via_module}"
    )
    # Sanity check that the hex looks like a real SHA-256 digest, not
    # an empty string or default.
    assert len(hex_via_shim) == 64
    assert all(c in "0123456789abcdef" for c in hex_via_shim)
