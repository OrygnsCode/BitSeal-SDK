# BitSeal SDK

<div align="center">

<img src="logo.svg" width="120" alt="BitSeal Logo" />

### The Digital Integrity Standard

**Service:** [https://bitseal.orygn.tech/](https://bitseal.orygn.tech/) · **PyPI:** [bitseal](https://pypi.org/project/bitseal/) · **Spec:** [manifest v2](https://github.com/OrygnsCode/BitSeal/blob/main/spec/v2-manifest.md)

[![PyPI](https://img.shields.io/pypi/v/bitseal?style=for-the-badge)](https://pypi.org/project/bitseal/)
[![Website](https://img.shields.io/badge/Website-bitseal.orygn.tech-22d3ee?style=for-the-badge)](https://bitseal.orygn.tech/)
[![License](https://img.shields.io/badge/License-MIT-white?style=for-the-badge)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge)](https://www.python.org/)

</div>

---

## Overview

**BitSeal** is a cryptographic proof-of-existence service. It creates tamper-evident, timestamped proofs for files using BLAKE3 Merkle trees and Ed25519 digital signatures, optionally anchored to Bitcoin via OpenTimestamps.

This repository (**BitSeal-SDK**) is the reference implementation of the protocol and the official Python package on PyPI. It contains the full cryptographic pipeline: chunking, BLAKE3 Merkle tree construction, server-issued Ed25519 signature dispatch, and both online and fully-offline verification. Every seal produced by the web service at [bitseal.orygn.tech](https://bitseal.orygn.tech/) can be verified end-to-end against the code in this repository without trusting the web service itself.

The SDK currently handles two manifest formats — `merkle-blake3-64k-v1` (legacy, signature over `root_hash || timestamp`) and `merkle-blake3-64k-v2` (current default, signature over SHA3-512 of the canonical manifest). A seal's `seal_mode` field tells the verifier which path to use. Cross-language byte vectors for both layouts are published at [spec/v2-test-vectors.json](https://github.com/OrygnsCode/BitSeal/blob/main/spec/v2-test-vectors.json) so third-party implementations can validate themselves against the reference bytes.

**Trust Code, Not Corporations.**
*Developed by [Orygn LLC](https://orygn.tech).*

---

## Features

* **Ed25519 signatures.** Edwards-curve Digital Signature Algorithm, since 2026-05-29 backed by AWS KMS on the production service. The private key never exists as plaintext bytes outside an HSM-backed boundary; verification uses the public key only and works fully offline.
* **Triple-hashing.** BLAKE3 Merkle tree (fast, primary), whole-file BLAKE3 (cross-check), SHA3-512 / FIPS 202 (independent algorithm family for cryptographic redundancy).
* **Bitcoin anchor.** OpenTimestamps integration (`--ots` flag below) lets you independently re-verify that a seal's commitment was present in a specific Bitcoin block, with no trust in the BitSeal service. Block headers come from `mempool.space` with `blockstream.info` as the fallback.
* **Key rotation tolerated.** The verifier iterates `historical_keys` from the well-known endpoint so seals signed by a now-retired Authority key still verify after a rotation.
* **Client-side hashing.** Files never leave the device during the sealing process. Only the manifest is transmitted.

---

## Installation

```bash
pip install bitseal
```

That installs the latest release from PyPI. The package exposes a `bitseal` Python module and the `bitseal-verify` console script.

---

## Quick start

### Verify a seal by root hash

```bash
# Online: look up the seal on the public ledger and verify its signature
python -m bitseal.verify --root <ROOT_HASH>

# Same thing, plus independently re-walk the OpenTimestamps proof and
# check the Bitcoin block header (requires `pip install opentimestamps`)
python -m bitseal.verify --root <ROOT_HASH> --ots

# Offline: verify a downloaded manifest.json with no network access
python -m bitseal.verify --manifest path/to/manifest.json
```

`python verify.py --root ...` (the pre-package syntax from earlier docs) still works against a checked-out copy of this repo because the root-level shims re-export the package symbols, but `python -m bitseal.verify` is the form that always works once the package is installed.

### Reproduce the Authority public-key fingerprint

```bash
python -m bitseal.verify --fingerprint
```

Fetches the current Authority public key from `/.well-known/bitseal-authority-key.json` and prints its SHA-256 fingerprint over the DER-encoded SubjectPublicKeyInfo, formatted as hex, base64, and colon-hex. Compare the colon-hex against the value published in Section 2 of the [Key Ceremony page](https://bitseal.orygn.tech/legal/key-ceremony). A mismatch is the single strongest signal that the well-known endpoint or CDN has been tampered with.

### Python integration

```python
from bitseal import BitSealLedger

ledger = BitSealLedger()
result = ledger.verify_seal("c868c3e09...")

if result["signature_verified"]:
    print("Authenticated:", result["timestamp_utc"])
    print("Signed by:", result["signer"], "(key_id =", result.get("key_id", "current") + ")")
else:
    print("Invalid:", result.get("signature_note"))
```

For full programmatic access to the seal-side pipeline (hashing, manifest construction, POSTing to the web sealer), import `bitseal.SealManifest`, `bitseal.HashManager`, and `bitseal.MerkleTree`. Direct PEM verification of any manifest is available via `bitseal.verify_manifest_signature(manifest, public_key_pem=None)`, which falls back to fetching the well-known doc when no PEM is supplied.

---

## Verification Logic

The `bitseal.verify` module performs four independent checks:

1. **Format validation.** The hash is a 64-char lowercase hex string; the manifest declares a known `seal_mode` (`merkle-blake3-64k-v1` or `merkle-blake3-64k-v2`).
2. **Ledger lookup.** Query the public BitSeal ledger to confirm the seal exists and retrieve its manifest.
3. **Signature verification.** Cryptographically verify that the manifest was signed by the Authority key. For v1 the signed message is the 40-byte concatenation `root_hash || little-endian f64 timestamp_utc`. For v2 the signed message is SHA3-512 of the canonical UTF-8 bytes of the manifest with the `signature` field removed (full canonicalization rules at [spec/v2-manifest.md](https://github.com/OrygnsCode/BitSeal/blob/main/spec/v2-manifest.md) §4). On failure the verifier iterates `historical_keys` from the well-known endpoint so post-rotation lookups of pre-rotation seals still pass.
4. **Merkle tree consistency.** Re-fold the manifest's `merkle_tree` leaves with the BLAKE3 odd-layer-duplicate rule and confirm the recomputed root equals `root_hash`. Separate from the signature check: the signature protects the root, the tree check protects the leaves against the root.

When `--ots` is passed, a fifth, fully-independent check runs: parse the OpenTimestamps proof, walk it to a `BitcoinBlockHeaderAttestation`, fetch the named Bitcoin block header from a public explorer, and confirm the merkle root the attestation commits to matches the real block's merkle root. This check does not require trusting the BitSeal service in any way.

---

## Legal & Compliance

BitSeal is designed to support digital chain-of-custody arguments under US ESIGN / UETA. It is not eIDAS-qualified and does not claim FIPS 140-3 status. For the full positioning, the Authority key ceremony, the rotation policy, and the OpenTimestamps integration details, see the [Documentation Portal](https://bitseal.orygn.tech/docs) and the [Legal section](https://bitseal.orygn.tech/legal/key-ceremony).

---

## License

MIT License. © 2026 [Orygn LLC](https://orygn.tech). All Rights Reserved.
