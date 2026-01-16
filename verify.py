import sys
import argparse
from BitSealCore import BitSealLedger

def main():
    parser = argparse.ArgumentParser(description="BitSeal Verification Tool")
    parser.add_argument("--root", required=True, help="Root Hash to verify")
    args = parser.parse_args()

    print(f"[*] Verifying Seal Root: {args.root}...")
    
    # Initialize Ledger (Read-Only Mode)
    ledger = BitSealLedger()
    
    # Verify
    result = ledger.verify_seal(args.root)
    
    if result["valid"]:
        print("\n[+] SEAL VERIFIED (VALID)")
        print(f"    Timestamp: {result['timestamp_utc']}")
        print(f"    Signature: {result['signature']}")
        print(f"    Filename:  {result.get('filename', 'Unknown')}")
    else:
        print("\n[-] SEAL INVALID or NOT FOUND")
        print(f"    Reason: {result['error']}")
        sys.exit(1)

if __name__ == "__main__":
    main()
