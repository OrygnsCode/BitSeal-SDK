
import asyncio
import hashlib
import json
import mmap
import os
import struct
import sys
import time
import site
import traceback
import platform
import urllib.request
import uuid

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

# 2. Crypto & Reporting
try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    import ReportGenerator
except ImportError as e:
    print(f"System Libraries missing: {e}. Run pip install cryptography reportlab")

console = Console()

# 3. Forensic Libs (Individually guarded)
try:
    import blake3
except ImportError:
    blake3 = None

try:
    import filetype
except ImportError:
    filetype = None

try:
    import firebase_admin
    from firebase_admin import credentials, firestore
except ImportError:
    firebase_admin = None

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
except ImportError:
    Image = None

# --- Configuration Constants ---
CHUNK_SIZE = 64 * 1024       # 64KB Merkle leaves (unified spec v1)
BUFFER_SIZE = 2 * 1024 * 1024 # 2MB I/O Buffer (multiple of CHUNK_SIZE)
KEYS_DIR = "bitseal_keys"
KEY_NAME = "bitseal"

# Canonical name of the manifest format shared with the web sealer.
# See https://bitseal.orygn.tech/.well-known/bitseal-authority-key.json
# for the full spec published under the "manifest_spec" field.
SEAL_MODE = "merkle-blake3-64k-v1"

@dataclass
class SealManifest:
    """JSON-LD Compliant Seal Manifest."""
    filename: str
    size_bytes: int
    timestamp_utc: float
    root_hash: str
    blake3_hash: str
    sha3_512_hash: str
    fuzzy_hash: str
    entropy: float
    mime_type: str
    metadata: Dict[str, Any]
    merkle_tree: List[str]
    machine_fingerprint: str
    high_entropy_zones: List[int]
    seal_mode: str = SEAL_MODE
    chunk_size_bytes: int = CHUNK_SIZE
    context: str = "https://w3id.org/security/v1"
    type: str = "BitSealManifest"
    signer: str = "Orygn LLC"
    signature: str = ""

    def to_json_ld(self) -> Dict[str, Any]:
        data = asdict(self)
        data['@context'] = data.pop('context')
        return data

# --- Pure Python MinHash (Similarity Fallback) ---
class PyMinHash:
    """
    A simple MinHash implementation for similarity detection.
    Hashes n-grams and keeps the minimum hash values (Sketch).
    """
    def __init__(self, num_perm=128, seed=1):
        self.num_perm = num_perm
        self.seed = seed
        self.minhash = np.full(num_perm, np.inf)

    def update(self, data: bytes):
        # Extremely simple k-gram hashing for demo. 
        # In prod, use rolling hash (Rabin-Karp) for speed.
        # This is strictly a fallback standard.
        if not data: return
        
        # Sample chunks to be fast? Or just hash 128 chunks?
        # Strategy: Hash the 64KB chunk itself.
        h = int(hashlib.md5(data).hexdigest(), 16)
        
        # Permute
        for i in range(self.num_perm):
            # A simple linear permutation
            ph = (h ^ (i * 0x5bd1e995)) & 0xFFFFFFFF
            if ph < self.minhash[i]:
                self.minhash[i] = ph

    def signature(self) -> str:
        return ",".join(map(str, self.minhash[:10])) + "..." # Truncated for display

# --- Authority Manager (Ed25519) ---
class AuthorityManager:
    def __init__(self):
        self.keys_dir = KEYS_DIR
        self.private_key_path = os.path.join(KEYS_DIR, f"{KEY_NAME}_private.pem")
        self.public_key_path = os.path.join(KEYS_DIR, f"{KEY_NAME}_public.pem")
        self._ensure_keys()
        
    def _ensure_keys(self):
        if not os.path.exists(self.keys_dir):
            os.makedirs(self.keys_dir)
            
        if not os.path.exists(self.private_key_path):
            console.print("[yellow]Generating new Ed25519 Identity Keys...[/yellow]")
            priv_key = ed25519.Ed25519PrivateKey.generate()
            
            # Save Private
            with open(self.private_key_path, "wb") as f:
                f.write(priv_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Save Public
            pub_key = priv_key.public_key()
            with open(self.public_key_path, "wb") as f:
                f.write(pub_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
    
    def get_machine_fingerprint(self) -> str:
        # Node + System + Release + Machine
        raw = f"{platform.node()}-{platform.system()}-{platform.release()}-{platform.machine()}"
        # Add MAC
        raw += f"-{uuid.getnode()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def sign_seal(self, root_hash: str, timestamp: float) -> str:
        fingerprint = self.get_machine_fingerprint()
        payload = f"{root_hash}|{fingerprint}|{timestamp}".encode()

        with open(self.private_key_path, "rb") as f:
            priv_key = serialization.load_pem_private_key(f.read(), password=None)

        signature = priv_key.sign(payload)
        return signature.hex()


# --- Offline Signature Verification ---

WEB_AUTHORITY_KEY_URL = "https://bitseal.orygn.tech/.well-known/bitseal-authority-key.json"


def _build_web_signed_message(root_hash_hex: str, timestamp: float) -> bytes:
    """Reconstructs the 40-byte message the web Authority signs: 32-byte root hash
    plus 8-byte little-endian double timestamp. Must match web/lib/signing.js."""
    root_bytes = bytes.fromhex(root_hash_hex)
    if len(root_bytes) != 32:
        raise ValueError("root_hash must decode to 32 bytes")
    return root_bytes + struct.pack("<d", float(timestamp))


def _build_cli_signed_message(root_hash_hex: str, fingerprint: str, timestamp: float) -> bytes:
    """Reconstructs what AuthorityManager.sign_seal signs for local CLI seals."""
    return f"{root_hash_hex}|{fingerprint}|{timestamp}".encode()


def _is_web_signed_manifest(manifest: Dict[str, Any]) -> bool:
    signer = manifest.get("signer", "") or ""
    return "Cloud Authority" in signer or "Vercel" in signer


def fetch_web_authority_public_key(url: str = WEB_AUTHORITY_KEY_URL, timeout: float = 10.0) -> Dict[str, Any]:
    """Fetches the published Authority public key document over HTTPS."""
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def verify_manifest_signature(manifest: Dict[str, Any], public_key_pem: Optional[Union[str, bytes]] = None) -> Dict[str, Any]:
    """Verifies a seal manifest's Ed25519 signature fully offline.

    For web-signed manifests (signer contains "Cloud Authority" or "Vercel"),
    supply the web Authority public key PEM (or let this function fetch the
    published key if omitted).

    For CLI-signed manifests, supply the signer's published public key PEM.
    The CLI's per-machine key is not published by BitSeal, so the caller must
    obtain it out-of-band.

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

    async def compute_forensics(self) -> Tuple[str, str, str, List[str], float, List[int]]:
        b3 = blake3.blake3() if blake3 else hashlib.sha256()
        s3 = hashlib.sha3_512()
        min_hasher = PyMinHash()
        
        merkle_leaves = []
        high_entropy_zones = []
        byte_counts = np.zeros(256, dtype=np.int64)
        total_bytes = 0
        chunk_idx = 0

        with open(self.filepath, "rb") as f:
            while True:
                # 2MB Buffer Read
                buffer = f.read(BUFFER_SIZE)
                if not buffer: break
                
                # Update global stream hashes
                b3.update(buffer)
                s3.update(buffer)
                
                # Process 64KB sub-chunks
                for i in range(0, len(buffer), CHUNK_SIZE):
                    sub_chunk = buffer[i : i + CHUNK_SIZE]
                    
                    # Merkle Leaf
                    if blake3:
                        leaf = blake3.blake3(sub_chunk).hexdigest()
                    else:
                        leaf = hashlib.sha256(sub_chunk).hexdigest()
                    merkle_leaves.append(leaf)
                    
                    # MinHash
                    min_hasher.update(sub_chunk)
                    
                    # Entropy
                    counts = np.bincount(np.frombuffer(sub_chunk, dtype=np.uint8), minlength=256)
                    byte_counts += counts
                    total_bytes += len(sub_chunk)
                    
                    # Local Entropy Heatmap
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

        return b3.hexdigest(), s3.hexdigest(), min_hasher.signature(), merkle_leaves, float(global_entropy), high_entropy_zones

class BitSealLedger:
    def __init__(self):
        self.offline_mode = False
        self.db = None
        
        try:
            # 1. Try existing app
            try:
                firebase_admin.get_app()
            except ValueError:
                # 2. Try Service Account
                if os.path.exists("serviceAccountKey.json"):
                    cred = credentials.Certificate("serviceAccountKey.json")
                    firebase_admin.initialize_app(cred)
                else:
                    # 3. Try ADC (This throws if not set up)
                    try:
                        cred = credentials.ApplicationDefault()
                        firebase_admin.initialize_app(cred)
                    except Exception:
                        self.offline_mode = True
                        print("[yellow]>> No Cloud Credentials found. Running in OFFLINE QUEUE MODE.[/yellow]")

            if not self.offline_mode:
                self.db = firestore.client()
        except Exception as e:
            # Catch-all for any other initialization errors
            self.offline_mode = True
            print(f"[yellow]>> Ledger Init Failed ({e}). Running in OFFLINE QUEUE MODE.[/yellow]")

    def verify_seal(self, root_hash: str, public_key_pem: Optional[Union[str, bytes]] = None) -> Dict[str, Any]:
        if not root_hash or len(root_hash) != 64 or not all(c in "0123456789abcdefABCDEF" for c in root_hash):
            return {"valid": False, "error": "Invalid root hash format (expected 64-char hex)."}

        if self.offline_mode or self.db is None:
            return {"valid": False, "error": "Ledger unreachable (offline mode). Cannot query registry."}

        try:
            docs = list(self.db.collection("seals").where("root_hash", "==", root_hash).limit(1).stream())
            if not docs:
                return {"valid": False, "error": "Seal not found in registry."}

            data = docs[0].to_dict()

            # Ledger presence alone is not proof. Re-verify the Ed25519 signature
            # against the published Authority key (web seals) or caller-supplied
            # key (CLI seals).
            sig_result = verify_manifest_signature(data, public_key_pem=public_key_pem)

            return {
                "valid": True,
                "ledger_present": True,
                "signature_verified": sig_result["ok"],
                "signature_format": sig_result.get("format"),
                "signature_note": None if sig_result["ok"] else sig_result["reason"],
                "timestamp_utc": data.get("timestamp_utc"),
                "signature": data.get("signature"),
                "filename": data.get("filename"),
                "signer": data.get("signer"),
            }
        except Exception as e:
            return {"valid": False, "error": f"Ledger query failed: {e}"}

    def register_seal(self, seal: SealManifest) -> str:
        if self.offline_mode:
            # Delayed Sync Logic
            pending_file = "pending_sync.json"
            queue = []
            if os.path.exists(pending_file):
                with open(pending_file, "r") as f:
                    queue = json.load(f)
            
            queue.append(seal.to_json_ld())
            with open(pending_file, "w") as f:
                json.dump(queue, f, indent=2)
            return "OFFLINE_QUEUED"
        else:
            doc_ref = self.db.collection("seals").add(seal.to_json_ld())
            return doc_ref[1].id

    def sync_pending_seals(self) -> int:
        if self.offline_mode:
            print("[red]Cannot sync: Still in offline mode (Check keys/internet).[/red]")
            return 0
            
        pending_file = "pending_sync.json"
        if not os.path.exists(pending_file):
            return 0
            
        with open(pending_file, "r") as f:
            queue = json.load(f)
            
        if not queue:
            return 0
            
        synced_count = 0
        console.print(f"[cyan]Syncing {len(queue)} offline seals...[/cyan]")
        
        failed = []
        for item in queue:
            try:
                self.db.collection("seals").add(item)
                synced_count += 1
                console.print(f"  [green]Uploaded:[/green] {item['root_hash'][:16]}...")
            except Exception as e:
                console.print(f"  [red]Failed:[/red] {e}")
                failed.append(item)
        
        # Rewrite queue if failures, else delete
        if failed:
            with open(pending_file, "w") as f:
                json.dump(failed, f, indent=2)
        else:
            os.remove(pending_file)
            
        return synced_count

# --- CORE API ---

async def process_seal(filepath: str, output_dir: str = None, progress_callback=None) -> Dict[str, Any]:
    """
    Programmatic entry point for sealing a file.
    Returns dictionary with: {root_hash, seal_id, pdf_path, signature}
    """
    # 1. Authority
    auth = AuthorityManager()
    fp = auth.get_machine_fingerprint()

    # 2. Forensics
    hasher = HashManager(filepath)
    b3_hex, s3_hex, min_sig, leaves, entropy, hotspots = await hasher.compute_forensics()
    
    merkle = MerkleTree(leaves)
    root = merkle.root
    
    # Deep Scan (Metadata)
    if filetype:
        kind = filetype.guess(filepath)
        mime = kind.mime if kind else "application/octet-stream"
    else:
        mime = "application/octet-stream"
        
    if progress_callback:
        progress_callback(100)

    # 3. Signing
    timestamp = time.time()
    signature = auth.sign_seal(root, timestamp)

    # 4. Manifest
    manifest = SealManifest(
        filename=os.path.basename(filepath),
        size_bytes=os.path.getsize(filepath),
        timestamp_utc=timestamp,
        root_hash=root,
        blake3_hash=b3_hex,
        sha3_512_hash=s3_hex,
        fuzzy_hash=min_sig,
        entropy=entropy,
        mime_type=mime,
        metadata={},
        merkle_tree=leaves,
        machine_fingerprint=fp,
        high_entropy_zones=hotspots,
        signature=signature
    )

    # 5. Output PDF
    # If output_dir is specified, put it there. Otherwise, side-by-side.
    if output_dir:
        pdf_name = f"{os.path.basename(filepath)}.seal.pdf"
        pdf_path = os.path.join(output_dir, pdf_name)
    else:
        pdf_path = f"{filepath}.seal.pdf"
        
    gen = ReportGenerator.ReportGenerator(pdf_path)
    gen.build_report(manifest.to_json_ld())
    
    # 6. Ledger
    ledger = BitSealLedger()
    seal_id = ledger.register_seal(manifest)
    
    return {
        "root_hash": root,
        "seal_id": seal_id,
        "pdf_path": pdf_path,
        "signature": signature,
        "entropy": entropy,
        "hotspots": hotspots,
        "machine_id": fp
    }

# --- COMMANDS ---

async def cmd_seal(filepath: str):
    if not os.path.exists(filepath):
        console.print(f"[red]File not found: {filepath}[/red]")
        return
        
    console.print(f"[bold cyan]>> BITSEAL V1 // PROTOCOL INITIATED[/bold cyan]")
    
    # Hook into UI
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        task = progress.add_task("Streaming Forensics (2MB Buffer)...", total=None)
        
        # Call the Core API
        result = await process_seal(filepath)
        
        progress.update(task, completed=100)

    console.print(f"   Authority Identity: [green]{result['machine_id']}[/green]")

    # 7. Display
    table = Table(title="BitSeal Certificate", style="green")
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="magenta")
    table.add_row("Root Hash", result['root_hash'][:32]+"...")
    table.add_row("Ed25519 Sig", result['signature'][:32]+"...")
    table.add_row("Entropy", f"{result['entropy']:.4f}")
    if result['hotspots']:
        table.add_row("Anomalies", f"[red]{len(result['hotspots'])} high-entropy zones detected[/red]")
    table.add_row("Status", f"[bold]{result['seal_id']}[/bold]")
    table.add_row("PDF Report", result['pdf_path'])
    console.print(table)

async def cmd_sync():
    ledger = BitSealLedger()
    count = ledger.sync_pending_seals()
    if count > 0:
        console.print(f"[bold green]Sync Complete: {count} seals pushed to blockchain.[/bold green]")
    else:
        console.print("No pending seals to sync.")

def main():
    if len(sys.argv) < 2:
        console.print("Usage: bitseal <seal|status|sync> <args>")
        return
        
    cmd = sys.argv[1]
    if cmd == "seal":
        asyncio.run(cmd_seal(sys.argv[2]))
    elif cmd == "sync":
        asyncio.run(cmd_sync())
    elif cmd == "status":
        auth = AuthorityManager()
        console.print(f"Machine FP: {auth.get_machine_fingerprint()}")
        console.print(f"Keys stored in: {auth.keys_dir}")
    else:
        console.print("Unknown command")

if __name__ == "__main__":
    main()
