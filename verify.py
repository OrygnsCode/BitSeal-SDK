import sys
import argparse
import json

from rich.console import Console

from _cli_ui import header_panel, kv_table, render_panel, short_hex
from BitSealCore import (
    API_BASE,
    SDK_VERSION,
    BitSealLedger,
    verify_bitcoin_anchor,
    verify_manifest_signature,
)

console = Console()


def _handle_manifest(path, public_key_path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except FileNotFoundError:
        render_panel(console, "File not found", f"Could not read manifest: {path}", kind="error")
        return 1
    except json.JSONDecodeError as e:
        render_panel(console, "Invalid JSON", f"Could not parse manifest: {e}", kind="error")
        return 1
    except OSError as e:
        render_panel(console, "Read error", f"Could not read manifest: {e}", kind="error")
        return 1

    pub_pem = None
    if public_key_path:
        try:
            with open(public_key_path, "rb") as f:
                pub_pem = f.read()
        except OSError as e:
            render_panel(console, "Public key read failed", str(e), kind="error")
            return 1

    console.rule(f"[bold]Offline manifest verification[/bold]  [dim]{path}[/dim]")
    result = verify_manifest_signature(manifest, public_key_pem=pub_pem)

    if result.get("ok"):
        body = kv_table(
            [
                ("Format", result.get("format", "unknown")),
                ("Signer", manifest.get("signer")),
                ("Root hash", short_hex(manifest.get("root_hash"), 32, 8)),
                ("Timestamp", manifest.get("timestamp_utc")),
            ]
        )
        render_panel(console, "SIGNATURE VALID", body, kind="success")
        return 0

    reason = result.get("reason") or "unknown failure"
    body = kv_table(
        [
            ("Format", result.get("format") or "unknown"),
            ("Reason", reason),
        ]
    )
    render_panel(console, "SIGNATURE INVALID", body, kind="error")
    return 1


def _handle_root(root, want_ots):
    console.rule(f"[bold]Ledger verification[/bold]  [dim]{short_hex(root, 32, 8)}[/dim]")

    ledger = BitSealLedger()
    result = ledger.verify_seal(root)

    if not result.get("valid"):
        render_panel(
            console,
            "SEAL INVALID OR NOT FOUND",
            result.get("error") or "Reason unknown.",
            kind="error",
        )
        return 1

    sig_verified = bool(result.get("signature_verified"))
    sig_format = result.get("signature_format") or "unknown"
    sig_note = result.get("signature_note")

    rows = [
        ("Filename", result.get("filename") or "(no filename)"),
        ("Timestamp", result.get("timestamp_utc")),
        ("Signer", result.get("signer")),
        ("Signature", short_hex(result.get("signature"), 20, 10)),
        ("Signature fmt", sig_format),
    ]
    tree_consistent = result.get("tree_consistent")
    if tree_consistent is not None:
        rows.append(("Merkle tree", "consistent" if tree_consistent else "inconsistent"))

    if sig_verified:
        render_panel(console, "LEDGER HIT  -  SIGNATURE VERIFIED", kv_table(rows), kind="success")
    else:
        if sig_note:
            rows.append(("Note", sig_note))
        render_panel(console, "LEDGER HIT  -  SIGNATURE NOT VERIFIED", kv_table(rows), kind="error")
        return 1

    if want_ots:
        exit_code = _render_ots(result.get("ots") or {})
        if exit_code != 0:
            return exit_code

    return 0


def _render_ots(ots):
    """Independently re-verify the Bitcoin anchor. Returns the exit code
    contribution (0 for success / non-applicable / pending, 1 for hard
    verification failure). Matches the pre-refactor semantics."""
    status = ots.get("status")
    console.rule("[bold]Bitcoin anchor (OpenTimestamps)[/bold]")

    if status == "none":
        render_panel(
            console,
            "BITCOIN ANCHOR NOT APPLICABLE",
            "This seal predates OpenTimestamps support, or the public calendars were unreachable\n"
            "at seal time. No independent Bitcoin witness is available for this seal.",
            kind="warning",
        )
        return 0

    if status == "pending":
        rows = []
        cals = ots.get("calendars") or []
        if cals:
            rows.append(("Calendars", f"{len(cals)} accepted"))
            for i, url in enumerate(cals, start=1):
                rows.append((f"  #{i}", url))
        submitted = ots.get("submitted_at")
        if submitted:
            rows.append(("Submitted", submitted))
        rows.append(("Next step", "Re-run with --ots once Bitcoin confirms (typically 1-6h)."))
        render_panel(console, "BITCOIN ANCHOR PENDING", kv_table(rows), kind="pending")
        return 0

    if status != "upgraded":
        render_panel(
            console,
            "UNEXPECTED OTS STATUS",
            f"Server returned status={status!r}. Expected one of: none, pending, upgraded.",
            kind="error",
        )
        return 1

    anchor = verify_bitcoin_anchor(ots)
    if anchor.get("ok"):
        rows = [
            ("Block height", f"#{anchor.get('block_height')}"),
            ("Block time", anchor.get("block_time")),
            ("Block hash", short_hex(anchor.get("block_hash"), 16, 8)),
            ("Mempool.space", anchor.get("mempool_url")),
        ]
        source = anchor.get("source")
        if source:
            rows.append(("Source", source))
        render_panel(console, "BITCOIN ANCHOR VERIFIED", kv_table(rows), kind="success")
        return 0

    rows = [("Reason", anchor.get("reason") or "unknown")]
    if anchor.get("block_height"):
        rows.append(("Block height claimed", f"#{anchor['block_height']}"))
    if anchor.get("block_hash"):
        rows.append(("Block hash", short_hex(anchor["block_hash"], 16, 8)))
    render_panel(console, "BITCOIN ANCHOR VERIFICATION FAILED", kv_table(rows), kind="error")
    return 1


def main():
    parser = argparse.ArgumentParser(
        prog="verify.py",
        description="BitSeal verification tool. Online (ledger lookup) or fully offline (manifest signature).",
    )
    parser.add_argument("--root", help="Root hash to verify against the public ledger (64-char hex).")
    parser.add_argument("--manifest", help="Path to a seal manifest JSON file for fully-offline verification.")
    parser.add_argument(
        "--public-key",
        help="Path to Ed25519 public key PEM. Required for --manifest with CLI signer; optional for web signer.",
    )
    parser.add_argument(
        "--ots",
        action="store_true",
        help="Independently verify the OpenTimestamps Bitcoin anchor against mempool.space. "
             "Requires --root and `pip install opentimestamps`.",
    )
    args = parser.parse_args()

    console.print(header_panel(SDK_VERSION, API_BASE))

    if args.manifest:
        sys.exit(_handle_manifest(args.manifest, args.public_key))

    if not args.root:
        render_panel(
            console,
            "Missing argument",
            "Provide one of:\n"
            "  --root <64-char hex>        lookup + verify on the public ledger\n"
            "  --manifest <path/to.json>   verify a downloaded manifest fully offline",
            kind="error",
        )
        sys.exit(2)

    sys.exit(_handle_root(args.root, args.ots))


if __name__ == "__main__":
    main()
