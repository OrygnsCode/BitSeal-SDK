
import asyncio
import base64
import hashlib
import os
import struct
import sys
import site
import platform

# Force add user site-packages
try:
    user_site = site.getusersitepackages()
    if user_site not in sys.path:
        sys.path.append(user_site)
except:
    pass

from typing import List, Dict, Any, Optional, Tuple, Union
from dataclasses import dataclass, asdict, field

# 1. Critical UI/Core
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    import numpy as np
except ImportError as e:
    print(f"CRITICAL: UI/Math libraries missing ({e}). Run pip install rich numpy")
    sys.exit(1)

# 2. Crypto (offline verification only — all signing happens server-side).
try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
except ImportError as e:
    print(f"System Libraries missing: {e}. Run pip install cryptography")
    sys.exit(1)

# 3. HTTP client for the BitSeal web API.
try:
    import requests
except ImportError as e:
    print(f"Network library missing: {e}. Run pip install requests")
    sys.exit(1)

console = Console()

# 4. Forensic Libs (individually guarded).
try:
    import blake3
except ImportError:
    blake3 = None

try:
    import filetype
except ImportError:
    filetype = None

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
except ImportError:
    Image = None

# OpenTimestamps (Part 7c) is optional — only required when the user passes
# --ots to verify.py. Keeping it optional lets existing verify flows keep
# working on systems that never installed it.
try:
    from opentimestamps.core.timestamp import Timestamp
    from opentimestamps.core.serialize import BytesDeserializationContext
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
    _HAS_OPENTIMESTAMPS = True
except ImportError:
    _HAS_OPENTIMESTAMPS = False

# --- Configuration Constants ---
SDK_VERSION = "0.3.0"
CHUNK_SIZE = 64 * 1024        # 64KB Merkle leaves (unified spec v1)
BUFFER_SIZE = 2 * 1024 * 1024 # 2MB I/O Buffer (multiple of CHUNK_SIZE)

# Canonical name of the manifest format shared with the web sealer.
# See https://bitseal.orygn.tech/.well-known/bitseal-authority-key.json
# for the full spec published under the "manifest_spec" field.
SEAL_MODE = "merkle-blake3-64k-v1"

# Web API base URL. Override with BITSEAL_API_URL for staging or local dev.
DEFAULT_API_BASE = "https://bitseal.orygn.tech"
API_BASE = (os.environ.get("BITSEAL_API_URL") or DEFAULT_API_BASE).rstrip("/")

# Value sent in X-API-Client. The server uses presence-of-header to bypass the
# Turnstile widget check; rate limits apply identically to web and SDK traffic.
API_CLIENT_TAG = f"BitSeal-SDK/{SDK_VERSION} python/{platform.python_version()}"

HTTP_TIMEOUT = 60  # seconds; 50MB payloads are well under this on typical links

# 50MB upload cap must match the server-side guard in web/app/api/seal/route.js.
MAX_FILE_SIZE = 50 * 1024 * 1024

# Authority key document (for offline manifest verification).
WEB_AUTHORITY_KEY_URL = f"{DEFAULT_API_BASE}/.well-known/bitseal-authority-key.json"


@dataclass
class SealManifest:
    """The subset of fields the web sealer accepts as a request body. The server
    attaches timestamp, signature, and signer itself."""
    filename: str
    size_bytes: int
    root_hash: str
    blake3_hash: str
    sha3_512_hash: str
    entropy: float
    mime_type: str
    merkle_tree: List[str]
    chunk_size_bytes: int = CHUNK_SIZE
    seal_mode: str = SEAL_MODE


# --- Offline Signature Verification ---

def _build_web_signed_message(root_hash_hex: str, timestamp: float) -> bytes:
    """Reconstructs the 40-byte message the web Authority signs: 32-byte root hash
    plus 8-byte little-endian double timestamp. Must match web/lib/signing.js."""
    root_bytes = bytes.fromhex(root_hash_hex)
    if len(root_bytes) != 32:
        raise ValueError("root_hash must decode to 32 bytes")
    return root_bytes + struct.pack("<d", float(timestamp))


def _build_cli_signed_message(root_hash_hex: str, fingerprint: str, timestamp: float) -> bytes:
    """Reconstructs what legacy (pre-0.2) CLI seals signed locally. Kept for
    offline verification of historical manifests produced before the HTTP cutover."""
    return f"{root_hash_hex}|{fingerprint}|{timestamp}".encode()


def _is_web_signed_manifest(manifest: Dict[str, Any]) -> bool:
    signer = manifest.get("signer", "") or ""
    return (
        "Orygn Authority" in signer
        or "Cloud Authority" in signer
        or "Vercel" in signer
    )


def fetch_web_authority_public_key(url: str = WEB_AUTHORITY_KEY_URL, timeout: float = 10.0) -> Dict[str, Any]:
    """Fetches the published Authority public key document over HTTPS.

    Uses `requests` with the SDK's X-API-Client header so Cloudflare's
    edge rules don't 403 us like they would a bare urllib.request call
    (default Python User-Agent is on Cloudflare's managed challenge list).
    """
    resp = requests.get(
        url,
        headers={
            "User-Agent": API_CLIENT_TAG,
            "X-API-Client": API_CLIENT_TAG,
            "Accept": "application/json",
        },
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()


def verify_manifest_signature(manifest: Dict[str, Any], public_key_pem: Optional[Union[str, bytes]] = None) -> Dict[str, Any]:
    """Verifies a seal manifest's Ed25519 signature fully offline.

    For web-signed manifests (signer contains "Orygn Authority" or any of the
    legacy "Cloud Authority" / "Vercel" strings), supply the Authority public
    key PEM or let this function fetch the published key if omitted.

    For CLI-signed manifests (legacy pre-0.2 SDK), supply the signer's public
    key PEM. Those keys were per-machine and never published centrally.

    Returns {"ok": bool, "reason": str, "format": "web"|"cli"}.
    """
    root_hash = manifest.get("root_hash")
    timestamp = manifest.get("timestamp_utc")
    signature_hex = manifest.get("signature")

    if not root_hash or timestamp is None or not signature_hex:
        return {"ok": False, "reason": "manifest is missing required fields", "format": None}

    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError:
        return {"ok": False, "reason": "signature is not hex", "format": None}
    if len(signature) != 64:
        return {"ok": False, "reason": "Ed25519 signatures must be 64 bytes", "format": None}

    is_web = _is_web_signed_manifest(manifest)
    fmt = "web" if is_web else "cli"

    if is_web:
        try:
            message = _build_web_signed_message(root_hash, timestamp)
        except ValueError as e:
            return {"ok": False, "reason": str(e), "format": fmt}
        if public_key_pem is None:
            try:
                doc = fetch_web_authority_public_key()
                public_key_pem = doc.get("current_key", {}).get("public_key_pem")
            except Exception as e:
                return {"ok": False, "reason": f"could not fetch Authority public key: {e}", "format": fmt}
    else:
        fingerprint = manifest.get("machine_fingerprint", "")
        message = _build_cli_signed_message(root_hash, fingerprint, timestamp)
        if public_key_pem is None:
            return {
                "ok": False,
                "reason": "CLI-signed manifest requires the signer's published public key PEM; no default is fetched.",
                "format": fmt,
            }

    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode("utf-8")

    try:
        pub_key = serialization.load_pem_public_key(public_key_pem)
    except Exception as e:
        return {"ok": False, "reason": f"invalid public key PEM: {e}", "format": fmt}

    if not isinstance(pub_key, ed25519.Ed25519PublicKey):
        return {"ok": False, "reason": "public key is not Ed25519", "format": fmt}

    try:
        pub_key.verify(signature, message)
        return {"ok": True, "reason": "signature verified", "format": fmt}
    except Exception:
        return {"ok": False, "reason": "signature did not verify", "format": fmt}


# --- OpenTimestamps / Bitcoin Anchor Verification (Part 7c) ---

# mempool.space is the primary block explorer, blockstream.info is the
# fallback (matches the web server's 7b block-time lookup strategy).
MEMPOOL_SPACE_API = "https://mempool.space/api"
BLOCKSTREAM_API = "https://blockstream.info/api"


def _fetch_bitcoin_block_header(height: int, timeout: float = 10.0) -> Dict[str, Any]:
    """Fetch a block's hash + merkle root + timestamp, tries mempool.space
    first and falls back to blockstream.info. Returns
    {"ok": bool, "reason": str, "block_hash": str, "merkle_root": str, "block_time": int}.

    Both providers return the merkle root as big-endian display hex. Both
    return `timestamp` as Unix seconds. `block_hash` is the standard
    big-endian hash used in explorer URLs.
    """
    for base in (MEMPOOL_SPACE_API, BLOCKSTREAM_API):
        try:
            r1 = requests.get(f"{base}/block-height/{height}", timeout=timeout)
            if r1.status_code != 200:
                continue
            block_hash = r1.text.strip()
            if not block_hash or len(block_hash) != 64:
                continue
            r2 = requests.get(f"{base}/block/{block_hash}", timeout=timeout)
            if r2.status_code != 200:
                continue
            data = r2.json()
            merkle_root = data.get("merkle_root")
            block_time = data.get("timestamp")
            if merkle_root and block_time:
                return {
                    "ok": True,
                    "block_hash": block_hash,
                    "merkle_root": merkle_root,
                    "block_time": int(block_time),
                    "source": base,
                }
        except Exception:
            continue
    return {"ok": False, "reason": f"could not fetch block #{height} from mempool.space or blockstream.info"}


def verify_bitcoin_anchor(ots_payload: Dict[str, Any], timeout: float = 10.0) -> Dict[str, Any]:
    """Independently verify a BitSeal OTS proof against the Bitcoin blockchain.

    Parses the `upgraded_proof_base64` bytes with the `opentimestamps`
    library, walks to the BitcoinBlockHeaderAttestation, fetches the
    corresponding block header from mempool.space (blockstream.info
    fallback), and confirms that the merkle root the attestation commits
    to matches the one in the real block header.

    The server-side cron already stored a block height after finding the
    attestation, but we deliberately do NOT trust that height here: we
    re-walk the proof ourselves and re-query Bitcoin, so the answer is a
    genuine independent attestation that the seal's digest existed by the
    time of the named Bitcoin block.

    Returns:
        {"ok": bool, "reason": str, "block_height": int|None,
         "block_time": str|None, "block_hash": str|None,
         "mempool_url": str|None, "digest": str|None}
    """
    if not _HAS_OPENTIMESTAMPS:
        return {
            "ok": False,
            "reason": "opentimestamps library not installed. Run: pip install opentimestamps",
        }

    if not ots_payload:
        return {"ok": False, "reason": "verify response did not include an ots block"}

    status = ots_payload.get("status")
    if status != "upgraded":
        return {
            "ok": False,
            "reason": f"OTS status is '{status}'; no Bitcoin anchor to verify yet",
            "status": status,
        }

    proof_b64 = ots_payload.get("upgraded_proof_base64")
    digest_hex = ots_payload.get("digest")
    if not proof_b64 or not digest_hex:
        return {
            "ok": False,
            "reason": "server reported status=upgraded but the response is missing upgraded_proof_base64 or digest",
        }

    try:
        proof_bytes = base64.b64decode(proof_b64)
    except Exception as e:
        return {"ok": False, "reason": f"upgraded_proof_base64 is not valid base64: {e}"}
    try:
        digest = bytes.fromhex(digest_hex)
    except Exception as e:
        return {"ok": False, "reason": f"digest is not valid hex: {e}"}
    if len(digest) != 32:
        return {"ok": False, "reason": f"digest must be 32 bytes (sha256); got {len(digest)}"}

    try:
        ctx = BytesDeserializationContext(proof_bytes)
        timestamp = Timestamp.deserialize(ctx, digest)
    except Exception as e:
        return {"ok": False, "reason": f"opentimestamps could not parse proof bytes: {e}"}

    btc_msg = None
    btc_height = None
    for msg, attestation in timestamp.all_attestations():
        if isinstance(attestation, BitcoinBlockHeaderAttestation):
            btc_msg = msg
            btc_height = int(attestation.height)
            break

    if btc_msg is None or btc_height is None:
        return {
            "ok": False,
            "reason": "proof parsed but contains no BitcoinBlockHeaderAttestation (calendar has not yet been Bitcoin-anchored)",
        }

    header = _fetch_bitcoin_block_header(btc_height, timeout=timeout)
    if not header.get("ok"):
        return {
            "ok": False,
            "reason": header.get("reason", "block header fetch failed"),
            "block_height": btc_height,
        }

    # Attestations commit to the merkle root in internal byte order (LE).
    # Explorers return the display hex (BE), so we reverse before comparing.
    claimed_root_display_hex = btc_msg[::-1].hex()
    real_root_display_hex = header["merkle_root"]

    if claimed_root_display_hex != real_root_display_hex:
        return {
            "ok": False,
            "reason": (
                f"merkle root mismatch at block #{btc_height}: "
                f"proof commits to {claimed_root_display_hex}, "
                f"block header has {real_root_display_hex}"
            ),
            "block_height": btc_height,
            "block_hash": header["block_hash"],
        }

    from datetime import datetime, timezone
    block_time_iso = datetime.fromtimestamp(header["block_time"], tz=timezone.utc).isoformat()

    return {
        "ok": True,
        "reason": "Bitcoin anchor independently verified",
        "block_height": btc_height,
        "block_time": block_time_iso,
        "block_hash": header["block_hash"],
        "mempool_url": f"https://mempool.space/block/{header['block_hash']}",
        "digest": digest_hex,
        "source": header.get("source"),
    }


# --- Forensic Engine ---
class MerkleTree:
    def __init__(self, leaf_hashes: List[str]):
        self.leaves = leaf_hashes
        self.tree_layers = [self.leaves]
        self._build_tree()

    def _build_tree(self):
        current_layer = self.leaves
        while len(current_layer) > 1:
            next_layer = []
            for i in range(0, len(current_layer), 2):
                left = current_layer[i]
                right = current_layer[i+1] if i + 1 < len(current_layer) else left
                combined = left + right
                if blake3:
                    node_hash = blake3.blake3(bytes.fromhex(combined)).hexdigest()
                else:
                    node_hash = hashlib.sha256(bytes.fromhex(combined)).hexdigest()
                next_layer.append(node_hash)
            self.tree_layers.append(next_layer)
            current_layer = next_layer

    @property
    def root(self) -> str:
        return self.tree_layers[-1][0] if self.tree_layers else ""


class HashManager:
    """V1 High-Throughput Hash Manager 2MB Buffer"""
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.file_size = os.path.getsize(filepath)

    async def compute_forensics(self) -> Tuple[str, str, List[str], float, List[int]]:
        if not blake3:
            raise RuntimeError(
                "blake3 is required for the unified Merkle format. "
                "Install it with: pip install blake3"
            )
        b3 = blake3.blake3()
        s3 = hashlib.sha3_512()

        merkle_leaves = []
        high_entropy_zones = []
        byte_counts = np.zeros(256, dtype=np.int64)
        total_bytes = 0
        chunk_idx = 0

        with open(self.filepath, "rb") as f:
            while True:
                buffer = f.read(BUFFER_SIZE)
                if not buffer:
                    break

                b3.update(buffer)
                s3.update(buffer)

                for i in range(0, len(buffer), CHUNK_SIZE):
                    sub_chunk = buffer[i:i + CHUNK_SIZE]

                    leaf = blake3.blake3(sub_chunk).hexdigest()
                    merkle_leaves.append(leaf)

                    counts = np.bincount(np.frombuffer(sub_chunk, dtype=np.uint8), minlength=256)
                    byte_counts += counts
                    total_bytes += len(sub_chunk)

                    local_probs = counts[counts > 0] / len(sub_chunk)
                    local_ent = -np.sum(local_probs * np.log2(local_probs))
                    if local_ent > 7.6:
                        high_entropy_zones.append(chunk_idx)

                    chunk_idx += 1

        if total_bytes > 0:
            probs = byte_counts[byte_counts > 0] / total_bytes
            global_entropy = -np.sum(probs * np.log2(probs))
        else:
            global_entropy = 0.0

        return b3.hexdigest(), s3.hexdigest(), merkle_leaves, float(global_entropy), high_entropy_zones


# --- HTTP Ledger Client ---
class BitSealLedger:
    """Thin HTTP client for the BitSeal web ledger. Holds no credentials; all
    state lives on the server. The SDK sends X-API-Client so the server skips
    the Turnstile human-check requirement; per-IP rate limits apply equally to
    browser and SDK traffic."""

    def __init__(self, api_base: str = API_BASE, timeout: int = HTTP_TIMEOUT):
        self.api_base = api_base.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": API_CLIENT_TAG,
            "X-API-Client": API_CLIENT_TAG,
            "Accept": "application/json",
        })

    def _format_http_error(self, resp: "requests.Response") -> str:
        try:
            payload = resp.json()
            msg = payload.get("error") or payload.get("message") or str(payload)
        except Exception:
            msg = (resp.text or "").strip()[:500] or f"HTTP {resp.status_code}"
        if resp.status_code == 429:
            retry = payload.get("retry_after_seconds") if isinstance(payload, dict) else None
            if retry:
                return f"{msg} (retry after ~{retry}s)"
        return f"HTTP {resp.status_code}: {msg}"

    def verify_seal(self, root_hash: str, public_key_pem: Optional[Union[str, bytes]] = None) -> Dict[str, Any]:
        """Look up a root_hash on the ledger and re-verify its signature.

        Return shape is preserved from pre-0.2 for verify.py compatibility:
        { valid, ledger_present, signature_verified, signature_format,
          signature_note, timestamp_utc, signature, filename, signer }
        """
        if not root_hash or len(root_hash) != 64 or not all(c in "0123456789abcdefABCDEF" for c in root_hash):
            return {"valid": False, "error": "Invalid root hash format (expected 64-char hex)."}

        try:
            resp = self.session.get(
                f"{self.api_base}/api/verify",
                params={"root": root_hash.lower()},
                timeout=self.timeout,
            )
        except requests.RequestException as e:
            return {"valid": False, "error": f"Network error contacting {self.api_base}: {e}"}

        if resp.status_code == 404:
            return {"valid": False, "error": "Seal not found in registry."}
        if resp.status_code != 200:
            return {"valid": False, "error": self._format_http_error(resp)}

        try:
            payload = resp.json()
        except Exception as e:
            return {"valid": False, "error": f"Could not parse verify response: {e}"}

        manifest = payload.get("data") or {}

        # The server already re-verifies the Ed25519 signature, but we also
        # re-verify locally so callers with --public-key can pin a specific key
        # and so the SDK's answer does not depend solely on server-side logic.
        local_sig = verify_manifest_signature(manifest, public_key_pem=public_key_pem)

        return {
            "valid": True,
            "ledger_present": True,
            "signature_verified": bool(payload.get("signature_verified")) and local_sig["ok"],
            "signature_format": local_sig.get("format"),
            "signature_note": None if local_sig["ok"] else local_sig["reason"],
            "timestamp_utc": manifest.get("timestamp_utc"),
            "signature": manifest.get("signature"),
            "filename": manifest.get("filename"),
            "signer": manifest.get("signer"),
            "tree_consistent": payload.get("tree_consistent"),
            "tree_note": payload.get("tree_note"),
            # Part 7c: pass the server's OTS block through unchanged so
            # callers (verify.py --ots) can independently re-verify the
            # Bitcoin anchor. None when the seal predates 7a.
            "ots": payload.get("ots"),
        }

    def submit_seal(self, manifest: SealManifest) -> Dict[str, Any]:
        """POST a manifest to /api/seal. The server signs, persists, and returns
        a base64-encoded PDF. Raises RuntimeError on any non-2xx response."""
        body = asdict(manifest)
        try:
            resp = self.session.post(
                f"{self.api_base}/api/seal",
                json=body,
                timeout=self.timeout,
            )
        except requests.RequestException as e:
            raise RuntimeError(f"Network error contacting {self.api_base}: {e}") from e

        if resp.status_code != 200:
            raise RuntimeError(self._format_http_error(resp))

        try:
            data = resp.json()
        except Exception as e:
            raise RuntimeError(f"Could not parse seal response: {e}") from e

        if not data.get("success"):
            raise RuntimeError(f"Seal rejected: {data.get('error') or 'unknown error'}")

        return data


# --- CORE API ---

async def process_seal(filepath: str, output_dir: Optional[str] = None, progress_callback=None) -> Dict[str, Any]:
    """Seal a file end-to-end. Hashes locally, POSTs the manifest to the web
    sealer, writes the returned PDF to disk, and returns a summary dict.

    Return shape (pre-0.2 compatibility plus a couple of new fields):
        { root_hash, seal_id, pdf_path, signature, timestamp, entropy, hotspots,
          signer, seal_mode, leaf_count }
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    size_bytes = os.path.getsize(filepath)
    if size_bytes <= 0:
        raise ValueError("File is empty.")
    if size_bytes > MAX_FILE_SIZE:
        raise ValueError(f"File too large ({size_bytes} bytes). Max is {MAX_FILE_SIZE} bytes (50MB).")

    # 1. Forensics (local)
    hasher = HashManager(filepath)
    b3_hex, s3_hex, leaves, entropy, hotspots = await hasher.compute_forensics()

    merkle = MerkleTree(leaves)
    root = merkle.root

    # 2. MIME detection
    if filetype:
        kind = filetype.guess(filepath)
        mime = kind.mime if kind else "application/octet-stream"
    else:
        mime = "application/octet-stream"

    if progress_callback:
        progress_callback(100)

    # 3. Build request manifest (server fills in timestamp + signature)
    manifest = SealManifest(
        filename=os.path.basename(filepath),
        size_bytes=size_bytes,
        root_hash=root,
        blake3_hash=b3_hex,
        sha3_512_hash=s3_hex,
        entropy=entropy,
        mime_type=mime,
        merkle_tree=leaves,
    )

    # 4. POST to web sealer
    ledger = BitSealLedger()
    result = ledger.submit_seal(manifest)

    # 5. Decode PDF to disk
    if output_dir:
        pdf_name = f"{os.path.basename(filepath)}.seal.pdf"
        pdf_path = os.path.join(output_dir, pdf_name)
    else:
        pdf_path = f"{filepath}.seal.pdf"

    pdf_b64 = result.get("pdf_base64")
    if not pdf_b64:
        raise RuntimeError("Server response missing pdf_base64")
    try:
        pdf_bytes = base64.b64decode(pdf_b64)
    except Exception as e:
        raise RuntimeError(f"Invalid pdf_base64 in response: {e}") from e

    os.makedirs(os.path.dirname(os.path.abspath(pdf_path)) or ".", exist_ok=True)
    with open(pdf_path, "wb") as f:
        f.write(pdf_bytes)

    return {
        "root_hash": result.get("root_hash") or root,
        "seal_id": result.get("seal_id"),
        "pdf_path": pdf_path,
        "signature": result.get("signature"),
        "timestamp": result.get("timestamp"),
        "entropy": entropy,
        "hotspots": hotspots,
        "signer": "Orygn Authority",
        "seal_mode": result.get("seal_mode") or SEAL_MODE,
        "leaf_count": result.get("leaf_count") or len(leaves),
    }


# --- COMMANDS ---

async def cmd_seal(filepath: str):
    from _cli_ui import header_panel, kv_table, render_panel, short_hex

    console.print(header_panel(SDK_VERSION, API_BASE))

    if not os.path.exists(filepath):
        render_panel(console, "File not found", f"Path: {filepath}", kind="error")
        return

    console.rule(f"[bold]Sealing[/bold]  [dim]{os.path.basename(filepath)}[/dim]")

    size_bytes = os.path.getsize(filepath)
    size_mb = size_bytes / (1024 * 1024)
    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        progress.add_task(
            f"Streaming forensics - {size_mb:.2f} MB - submitting to Authority",
            total=None,
        )
        try:
            result = await process_seal(filepath)
        except Exception as e:
            render_panel(console, "SEAL FAILED", str(e), kind="error")
            return

    rows = [
        ("Seal ID", result["seal_id"]),
        ("Root hash", short_hex(result["root_hash"], 32, 8)),
        ("Signer", result["signer"]),
        ("Signature", short_hex(result.get("signature") or "", 20, 10)),
        ("Seal mode", result.get("seal_mode")),
        ("Leaves", f"{result['leaf_count']} chunks of {CHUNK_SIZE // 1024} KB"),
        ("Entropy", f"{result['entropy']:.4f} bits/byte"),
    ]
    hotspots = result.get("hotspots") or []
    if hotspots:
        rows.append(("Anomalies", f"[yellow]{len(hotspots)} high-entropy zones[/yellow]"))
    rows.append(("PDF report", result["pdf_path"]))

    render_panel(console, "SEAL CREATED", kv_table(rows), kind="success")

    root = result.get("root_hash")
    if root:
        hint = Table.grid(padding=(0, 2))
        hint.add_column(style="dim")
        hint.add_row("Verify later with:")
        hint.add_row(f"[cyan]python verify.py --root {root}[/cyan]")
        console.print()
        console.print(hint)


def main():
    from _cli_ui import header_panel, kv_table, render_panel

    if len(sys.argv) < 2:
        console.print(header_panel(SDK_VERSION, API_BASE))
        usage = kv_table(
            [
                ("seal <file>", "Hash, sign, and register a file on the BitSeal ledger."),
                ("verify <root>", "Look up a root hash on the ledger (alias: run verify.py)."),
                ("status", "Show SDK build + endpoint + client tag."),
            ]
        )
        render_panel(console, "USAGE", usage, kind="info")
        console.print(f"\n[dim]Override the API endpoint with the BITSEAL_API_URL env var. Current: {API_BASE}[/dim]")
        return

    cmd = sys.argv[1]
    if cmd == "seal":
        if len(sys.argv) < 3:
            render_panel(console, "Missing argument", "Usage: python BitSealCore.py seal <file>", kind="error")
            return
        asyncio.run(cmd_seal(sys.argv[2]))
    elif cmd == "verify":
        if len(sys.argv) < 3:
            render_panel(console, "Missing argument", "Usage: python BitSealCore.py verify <root-hash>", kind="error")
            return
        import subprocess
        subprocess.call([sys.executable, os.path.join(os.path.dirname(__file__), "verify.py"), "--root", sys.argv[2]])
    elif cmd == "status":
        console.print(header_panel(SDK_VERSION, API_BASE))
        body = kv_table(
            [
                ("SDK version", SDK_VERSION),
                ("API endpoint", API_BASE),
                ("Client tag", API_CLIENT_TAG),
                ("Seal mode", SEAL_MODE),
                ("Max file size", f"{MAX_FILE_SIZE // (1024 * 1024)} MB"),
            ]
        )
        render_panel(console, "STATUS", body, kind="info")
    else:
        render_panel(
            console,
            "Unknown command",
            f"Got: {cmd!r}\nExpected one of: seal, verify, status.",
            kind="error",
        )


if __name__ == "__main__":
    main()
