# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Orygn LLC

"""Run the cross-language Merkle verifier (scripts/merkle_cross_verify.py)
under pytest so the SDK's claim that 'a web seal and a CLI seal of
identical bytes yield the same root_hash' is automatically tested on
every CI run, not merely asserted in documentation.

Audit findings M1 (cross-implementation test cannot be run by an
outside auditor) and M5 (server-side refold has no published test
vectors) are addressed together by this test plus the bundled
tests/vectors/merkle-vectors.json file. With the vectors bundled and
this test in the suite, any clone of the SDK has a reproducible
end-to-end check of the merkle-blake3-64k-v1 spec.
"""

import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "merkle_cross_verify.py"
VECTORS = REPO_ROOT / "tests" / "vectors" / "merkle-vectors.json"


def test_vectors_file_is_present_and_well_formed():
    """The bundled golden vectors must exist and parse as JSON with
    the expected top-level keys. A missing or malformed file means
    the SDK's cross-implementation claim is unverifiable."""
    assert VECTORS.exists(), (
        f"Bundled merkle vectors missing at {VECTORS}. This file is "
        "required for the SDK to claim byte-for-byte parity with the "
        "web service's Merkle root computation."
    )
    data = json.loads(VECTORS.read_text(encoding="utf-8"))

    # The four fields the cross-verifier script reads.
    assert data["seal_mode"] == "merkle-blake3-64k-v1", (
        f"seal_mode mismatch in bundled vectors: {data.get('seal_mode')!r}"
    )
    assert data["chunk_size_bytes"] == 65536
    assert isinstance(data["vectors"], list)
    assert len(data["vectors"]) >= 1, (
        "Vectors array is empty. At least one vector must be present "
        "for the cross-verify run to be meaningful."
    )

    # Each vector must carry the fields the verifier inspects.
    for v in data["vectors"]:
        for field in ("name", "pattern", "size_bytes", "leaf_count",
                      "first_leaf", "last_leaf", "root_hash"):
            assert field in v, (
                f"Vector {v.get('name')!r} is missing required field "
                f"{field!r}. Regenerate from web/scripts/merkle-vectors.mjs."
            )


def test_cross_verify_script_runs_clean():
    """End-to-end: run the cross-verifier script as a subprocess
    against the bundled vectors and assert exit code 0 plus the
    expected success message in stdout.

    This is the M5 regression guard. If a future refactor changes the
    SDK's MerkleTree construction in any way that diverges from the
    web service's published spec, the vectors will fail and this test
    will catch it before a release."""
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=60,
    )
    assert result.returncode == 0, (
        f"Cross-verify script exited {result.returncode}.\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )

    # The success line includes the vector count and a fixed phrase.
    # Assert both to catch a regression where the script silently
    # exits 0 without actually checking anything.
    assert "Python matches JS byte-for-byte" in result.stdout, (
        f"Expected success phrase not in stdout:\n{result.stdout}"
    )

    # Pull the vector count from the bundled file and assert each one
    # produced a [PASS] line. Catches the case where the script
    # returns 0 because the vectors array was empty.
    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    expected_count = len(data["vectors"])
    pass_count = result.stdout.count("[PASS]")
    assert pass_count == expected_count, (
        f"Expected {expected_count} PASS lines, got {pass_count}. "
        f"stdout:\n{result.stdout}"
    )
