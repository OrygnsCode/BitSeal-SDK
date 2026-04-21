import sys
import argparse
import json
from BitSealCore import BitSealLedger, verify_manifest_signature, verify_bitcoin_anchor

def main():
    print("BitSeal Verification Tool - https://bitseal.orygn.tech/")
    parser = argparse.ArgumentParser(description="BitSeal Verification Tool (https://bitseal.orygn.tech/)")
    parser.add_argument("--root", help="Root Hash to verify against the ledger")
    parser.add_argument("--manifest", help="Path to a seal manifest JSON file for fully-offline verification")
    parser.add_argument("--public-key", help="Path to Ed25519 public key PEM (required for --manifest with CLI signer; optional for web signer)")
    parser.add_argument(
        "--ots",
        action="store_true",
        help="Independently verify the OpenTimestamps Bitcoin anchor against mempool.space "
             "(requires --root and `pip install opentimestamps`)",
    )
    args = parser.parse_args()

    if args.manifest:
        try:
            with open(args.manifest, "r", encoding="utf-8") as f:
                manifest = json.load(f)
        except Exception as e:
            print(f"[-] Could not read manifest: {e}")
            sys.exit(1)

        pub_pem = None
        if args.public_key:
            with open(args.public_key, "rb") as f:
                pub_pem = f.read()

        print(f"[*] Verifying manifest: {args.manifest} (offline)")
        result = verify_manifest_signature(manifest, public_key_pem=pub_pem)
        if result["ok"]:
            print(f"\n[+] SIGNATURE VALID ({result['format']} format)")
            print(f"    Signer:    {manifest.get('signer')}")
            print(f"    Root:      {manifest.get('root_hash')}")
            print(f"    Timestamp: {manifest.get('timestamp_utc')}")
            sys.exit(0)
        else:
            print(f"\n[-] SIGNATURE INVALID ({result.get('format')} format)")
            print(f"    Reason: {result['reason']}")
            sys.exit(1)

    if not args.root:
        print("[-] Provide either --root <hash> or --manifest <path>")
        sys.exit(2)

    print(f"[*] Verifying Seal Root: {args.root}...")

    ledger = BitSealLedger()
    result = ledger.verify_seal(args.root)

    if not result.get("valid"):
        print("\n[-] SEAL INVALID or NOT FOUND")
        print(f"    Reason: {result.get('error')}")
        sys.exit(1)

    print("\n[+] LEDGER HIT")
    print(f"    Filename:  {result.get('filename', 'Unknown')}")
    print(f"    Timestamp: {result.get('timestamp_utc')}")
    print(f"    Signer:    {result.get('signer')}")
    print(f"    Signature: {result.get('signature')}")

    if result.get("signature_verified"):
        print(f"\n[+] SIGNATURE VERIFIED ({result.get('signature_format')} format)")
    else:
        print(f"\n[!] SIGNATURE NOT VERIFIED ({result.get('signature_format')} format)")
        note = result.get("signature_note")
        if note:
            print(f"    Note: {note}")
        sys.exit(1)

    # --ots: independent Bitcoin anchor verification.
    # This is additive to the signature check above. A verified signature
    # proves the BitSeal Authority sealed this root hash; a verified
    # Bitcoin anchor proves a sha256 of that signature existed in a
    # specific Bitcoin block, giving a trust-minimized external witness.
    if args.ots:
        ots = result.get("ots") or {}
        status = ots.get("status")

        print("\n[*] Verifying Bitcoin anchor (OpenTimestamps)...")

        if status == "none":
            print("[!] BITCOIN ANCHOR NOT APPLICABLE")
            print("    This seal predates OpenTimestamps support or the public calendars")
            print("    were unreachable at seal time. No independent Bitcoin witness is")
            print("    available for this seal.")
            return

        if status == "pending":
            print("[!] BITCOIN ANCHOR PENDING")
            print("    Public calendars have accepted the commitment but a Bitcoin block")
            print("    has not yet confirmed it. Typical latency is 1-6 hours after sealing.")
            cals = ots.get("calendars") or []
            if cals:
                print(f"    Calendars: {len(cals)} accepted")
                for c in cals:
                    print(f"      - {c}")
            submitted = ots.get("submitted_at")
            if submitted:
                print(f"    Submitted: {submitted}")
            print("    Re-run with --ots later to pick up the anchor.")
            return

        if status != "upgraded":
            print(f"[-] UNEXPECTED OTS STATUS: {status!r}")
            sys.exit(1)

        anchor = verify_bitcoin_anchor(ots)
        if anchor.get("ok"):
            print("[+] BITCOIN ANCHOR VERIFIED")
            print(f"    Block height: #{anchor['block_height']}")
            print(f"    Block time:   {anchor['block_time']}")
            print(f"    Block hash:   {anchor['block_hash']}")
            print(f"    Mempool.space: {anchor['mempool_url']}")
            src = anchor.get("source")
            if src:
                print(f"    Source:       {src}")
        else:
            print("[-] BITCOIN ANCHOR VERIFICATION FAILED")
            print(f"    Reason: {anchor.get('reason')}")
            if anchor.get("block_height"):
                print(f"    Block height claimed: #{anchor['block_height']}")
            if anchor.get("block_hash"):
                print(f"    Block hash:           {anchor['block_hash']}")
            sys.exit(1)

if __name__ == "__main__":
    main()
