# BitSeal Core SDK

The open-source verification core for the [BitSeal Digital Integrity Protocol](https://bit-seal.vercel.app).

This repository contains the cryptographic primitives and verification logic used to seal and audit digital evidence.

## Installation

```bash
pip install -r requirements.txt
```

## Usage (CLI)

### Verify a Seal
To check if a hash exists in the public immutable ledger:

```bash
python verify.py --root <ROOT_HASH>
```

### Library Usage

```python
from BitSealCore import BitSealLedger

ledger = BitSealLedger()
result = ledger.verify_seal("c868c3e09...")

if result['valid']:
    print("Valid Seal!")
```

## Security

*   **Ed25519**: Digital Signatures.
*   **BLAKE3**: Fast file hashing.
*   **SHA3-512**: Deep scan hashing.
*   **Merkle Tree**: Data structure for seal manifests.

## License

MIT License.
