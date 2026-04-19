"""Cross-verify a web-signed manifest using the Python SDK's offline verifier.

Reads a hex signature from argv[1], hex root from argv[2], timestamp from argv[3],
and the Authority public key URL from argv[4] (defaults to localhost dev server).
"""
import sys
import os
import json
import urllib.request

# Ensure parent dir import works when run from scripts/
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from BitSealCore import verify_manifest_signature

if len(sys.argv) < 4:
    print("usage: python e2e_cross_verify.py <sig_hex> <root_hex> <timestamp> [key_url]")
    sys.exit(2)

sig_hex = sys.argv[1]
root_hex = sys.argv[2]
ts = float(sys.argv[3])
key_url = sys.argv[4] if len(sys.argv) > 4 else "http://localhost:3099/.well-known/bitseal-authority-key.json"

with urllib.request.urlopen(key_url) as resp:
    doc = json.loads(resp.read().decode("utf-8"))
pem = doc["current_key"]["public_key_pem"]
print("[*] fetched key from:", key_url)

manifest = {
    "root_hash": root_hex,
    "timestamp_utc": ts,
    "signature": sig_hex,
    "signer": "Orygn Cloud Authority (Vercel)",
}
r = verify_manifest_signature(manifest, public_key_pem=pem)
print("[*] verify result:", r)
assert r["ok"], "signature should verify"

# Tamper test
tampered = dict(manifest)
tampered["timestamp_utc"] = ts + 1.0
r2 = verify_manifest_signature(tampered, public_key_pem=pem)
print("[*] tampered result:", r2)
assert not r2["ok"], "tampered signature must NOT verify"

print("[+] cross-verification PASS")
