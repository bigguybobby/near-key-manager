#!/usr/bin/env python3
"""NEAR access key management skill for OpenClaw."""

import argparse
import json
import sys
import urllib.request
from datetime import datetime
from pathlib import Path

DEFAULT_RPC = "https://rpc.mainnet.near.org"

def rpc_call(rpc_url, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": "1", "method": method, "params": params}).encode()
    req = urllib.request.Request(rpc_url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())

def list_keys(rpc_url, account_id):
    """List all access keys for an account."""
    result = rpc_call(rpc_url, "query", {"request_type": "view_access_key_list", "finality": "final", "account_id": account_id})
    if "result" in result:
        return result["result"].get("keys", [])
    return {"error": result.get("error", "Unknown error")}

def view_key(rpc_url, account_id, public_key):
    """View details of a specific access key."""
    result = rpc_call(rpc_url, "query", {"request_type": "view_access_key", "finality": "final", "account_id": account_id, "public_key": public_key})
    return result.get("result", result.get("error", {}))

def backup_keys(account_id, keys, backup_dir="backups"):
    """Backup key list to JSON file."""
    Path(backup_dir).mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path = Path(backup_dir) / f"{account_id}_keys_{ts}.json"
    data = {"account_id": account_id, "backed_up_at": datetime.utcnow().isoformat() + "Z", "keys": keys}
    path.write_text(json.dumps(data, indent=2))
    return str(path)

def analyze_keys(keys, account_id):
    """Analyze keys for security concerns."""
    alerts = []
    full_access = [k for k in keys if k.get("access_key", {}).get("permission") == "FullAccess"]
    func_keys = [k for k in keys if isinstance(k.get("access_key", {}).get("permission"), dict)]

    if len(full_access) > 2:
        alerts.append(f"⚠️ {len(full_access)} full-access keys found — consider reducing")
    if len(full_access) == 0:
        alerts.append("🔴 No full-access keys! Account may be locked")
    for k in func_keys:
        perm = k["access_key"]["permission"].get("FunctionCall", {})
        allowance = int(perm.get("allowance", "0"))
        if allowance > 10 * 10**24:  # > 10 NEAR
            alerts.append(f"⚠️ High allowance key: {k['public_key'][:20]}... ({allowance/1e24:.1f} NEAR)")

    return {
        "account_id": account_id,
        "total_keys": len(keys),
        "full_access_keys": len(full_access),
        "function_call_keys": len(func_keys),
        "alerts": alerts
    }

def format_display(keys, account_id, analysis=None):
    lines = [f"🔑 *Keys for `{account_id}`*", ""]
    for k in keys:
        perm = k.get("access_key", {}).get("permission", "?")
        ptype = "FullAccess" if perm == "FullAccess" else "FunctionCall"
        pk = k.get("public_key", "?")
        lines.append(f"• `{pk[:30]}...` — {ptype}")
        if isinstance(perm, dict):
            fc = perm.get("FunctionCall", {})
            lines.append(f"  Contract: {fc.get('receiver_id', '?')}, Methods: {fc.get('method_names', ['*'])}")
    if analysis and analysis.get("alerts"):
        lines.append("\n⚠️ *Security Alerts:*")
        for a in analysis["alerts"]:
            lines.append(f"  {a}")
    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(description="NEAR access key manager for OpenClaw")
    sub = parser.add_subparsers(dest="command")

    ls = sub.add_parser("list", help="List access keys for an account")
    ls.add_argument("account_id", help="NEAR account ID")
    ls.add_argument("--rpc", default=DEFAULT_RPC)
    ls.add_argument("--json", action="store_true")

    bk = sub.add_parser("backup", help="Backup keys to file")
    bk.add_argument("account_id")
    bk.add_argument("--rpc", default=DEFAULT_RPC)
    bk.add_argument("--dir", default="backups")

    an = sub.add_parser("analyze", help="Security analysis of keys")
    an.add_argument("account_id")
    an.add_argument("--rpc", default=DEFAULT_RPC)
    an.add_argument("--json", action="store_true")

    vw = sub.add_parser("view", help="View specific key details")
    vw.add_argument("account_id")
    vw.add_argument("public_key")
    vw.add_argument("--rpc", default=DEFAULT_RPC)

    args = parser.parse_args()

    if args.command == "list":
        keys = list_keys(args.rpc, args.account_id)
        if isinstance(keys, dict) and "error" in keys:
            print(f"Error: {keys['error']}", file=sys.stderr); sys.exit(1)
        if args.json:
            print(json.dumps(keys, indent=2))
        else:
            print(format_display(keys, args.account_id))

    elif args.command == "backup":
        keys = list_keys(args.rpc, args.account_id)
        if isinstance(keys, dict) and "error" in keys:
            print(f"Error: {keys['error']}", file=sys.stderr); sys.exit(1)
        path = backup_keys(args.account_id, keys, args.dir)
        print(f"✅ Backed up {len(keys)} keys to {path}")

    elif args.command == "analyze":
        keys = list_keys(args.rpc, args.account_id)
        if isinstance(keys, dict) and "error" in keys:
            print(f"Error: {keys['error']}", file=sys.stderr); sys.exit(1)
        analysis = analyze_keys(keys, args.account_id)
        if args.json:
            print(json.dumps(analysis, indent=2))
        else:
            print(format_display(keys, args.account_id, analysis))

    elif args.command == "view":
        result = view_key(args.rpc, args.account_id, args.public_key)
        print(json.dumps(result, indent=2))

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
