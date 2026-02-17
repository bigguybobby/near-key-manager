#!/usr/bin/env python3
"""
NEAR Key Manager — OpenClaw Skill.

Access key management, security monitoring, backup, and rotation guidance
for NEAR accounts. Detects over-privileged keys, tracks key age, and
recommends rotation schedules based on configurable policies.
"""

import argparse
import hashlib
import json
import logging
import sys
import urllib.request
import urllib.error
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("near-key-manager")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_RPC = "https://rpc.mainnet.near.org"
DEFAULT_BACKUP_DIR = "backups"
DEFAULT_POLICY_FILE = "key-policy.json"

# Default rotation policy (days)
DEFAULT_ROTATION_DAYS = {
    "full_access": 90,
    "function_call": 365,
}

# Allowance thresholds
ALLOWANCE_HIGH_THRESHOLD = 10 * 10 ** 24   # 10 NEAR in yoctoNEAR
ALLOWANCE_MEDIUM_THRESHOLD = 1 * 10 ** 24  # 1 NEAR in yoctoNEAR

SEVERITY_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "ℹ️"}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class KeyDetail:
    """Normalised representation of a NEAR access key."""

    public_key: str
    permission_type: str  # "FullAccess" or "FunctionCall"
    receiver_id: Optional[str] = None
    method_names: list[str] = field(default_factory=list)
    allowance_yocto: Optional[int] = None
    allowance_near: Optional[float] = None
    nonce: int = 0
    # Metadata (not from RPC — inferred from backups or user-provided)
    created_at: Optional[str] = None
    rotation_due: Optional[str] = None
    days_old: Optional[int] = None


@dataclass
class SecurityFinding:
    """A single security finding from key analysis."""

    severity: str  # CRITICAL / HIGH / MEDIUM / LOW / INFO
    code: str
    message: str
    public_key_short: str = ""
    recommendation: str = ""


@dataclass
class KeyAnalysis:
    """Full security analysis result for an account's keys."""

    account_id: str
    total_keys: int
    full_access_keys: int
    function_call_keys: int
    findings: list[SecurityFinding] = field(default_factory=list)
    rotation_due: list[dict[str, Any]] = field(default_factory=list)
    risk_score: int = 0  # 0=low, 100=critical


# ---------------------------------------------------------------------------
# RPC helpers
# ---------------------------------------------------------------------------

def rpc_call(rpc_url: str, method: str, params: dict) -> dict:
    """
    Make a NEAR JSON-RPC call.

    Args:
        rpc_url: NEAR RPC endpoint.
        method:  RPC method.
        params:  Method parameters dict.

    Returns:
        Parsed JSON response dict.

    Raises:
        RuntimeError: On HTTP or network error.
    """
    body = json.dumps({
        "jsonrpc": "2.0", "id": "1",
        "method": method, "params": params,
    }).encode()
    req = urllib.request.Request(
        rpc_url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "OpenClaw-NEAR-KeyManager/2.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"RPC HTTP error {exc.code}: {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"RPC connection error: {exc.reason}") from exc


def list_keys_raw(rpc_url: str, account_id: str) -> list[dict]:
    """
    Fetch raw access key list from NEAR RPC.

    Args:
        rpc_url:    NEAR RPC endpoint.
        account_id: Account to query.

    Returns:
        List of raw key dicts from RPC.

    Raises:
        RuntimeError: If RPC returns an error.
    """
    result = rpc_call(rpc_url, "query", {
        "request_type": "view_access_key_list",
        "finality": "final",
        "account_id": account_id,
    })
    if "result" in result:
        return result["result"].get("keys", [])
    error_name = result.get("error", {}).get("name", "Unknown error")
    raise RuntimeError(f"RPC error for {account_id}: {error_name}")


def view_key_raw(rpc_url: str, account_id: str, public_key: str) -> dict:
    """
    Fetch details for a specific access key.

    Args:
        rpc_url:    NEAR RPC endpoint.
        account_id: Account owning the key.
        public_key: The public key to query.

    Returns:
        Key detail dict from RPC.
    """
    result = rpc_call(rpc_url, "query", {
        "request_type": "view_access_key",
        "finality": "final",
        "account_id": account_id,
        "public_key": public_key,
    })
    return result.get("result", result.get("error", {}))


# ---------------------------------------------------------------------------
# Key normalisation
# ---------------------------------------------------------------------------

def normalise_key(raw_key: dict) -> KeyDetail:
    """
    Convert a raw RPC key dict to a KeyDetail dataclass.

    Args:
        raw_key: Raw key dict from NEAR RPC (has ``public_key`` and ``access_key``).

    Returns:
        Normalised KeyDetail.
    """
    pub = raw_key.get("public_key", "")
    ak = raw_key.get("access_key", {})
    perm = ak.get("permission", "FullAccess")
    nonce = ak.get("nonce", 0)

    if perm == "FullAccess":
        return KeyDetail(
            public_key=pub,
            permission_type="FullAccess",
            nonce=nonce,
        )

    # FunctionCall permission
    fc = perm.get("FunctionCall", {}) if isinstance(perm, dict) else {}
    allowance_str = fc.get("allowance")
    allowance_yocto = int(allowance_str) if allowance_str else None
    allowance_near = allowance_yocto / 10 ** 24 if allowance_yocto else None

    return KeyDetail(
        public_key=pub,
        permission_type="FunctionCall",
        receiver_id=fc.get("receiver_id"),
        method_names=fc.get("method_names", []),
        allowance_yocto=allowance_yocto,
        allowance_near=allowance_near,
        nonce=nonce,
    )


def enrich_with_policy(
    key: KeyDetail,
    policy: dict[str, Any],
    backup_metadata: Optional[dict] = None,
) -> KeyDetail:
    """
    Enrich a KeyDetail with rotation policy and age information.

    Args:
        key:             KeyDetail to enrich.
        policy:          Rotation policy dict (keys: full_access, function_call days).
        backup_metadata: Optional dict mapping public_key → {created_at}.

    Returns:
        Enriched KeyDetail (in-place modification + return).
    """
    rotation_days = (
        policy.get("full_access", DEFAULT_ROTATION_DAYS["full_access"])
        if key.permission_type == "FullAccess"
        else policy.get("function_call", DEFAULT_ROTATION_DAYS["function_call"])
    )

    if backup_metadata and key.public_key in backup_metadata:
        created = backup_metadata[key.public_key].get("created_at")
        if created:
            key.created_at = created
            try:
                created_dt = datetime.fromisoformat(created.rstrip("Z"))
                now = datetime.now(timezone.utc).replace(tzinfo=None)
                key.days_old = (now - created_dt).days
                due_dt = created_dt + timedelta(days=rotation_days)
                key.rotation_due = due_dt.isoformat() + "Z"
            except (ValueError, TypeError):
                pass

    return key


# ---------------------------------------------------------------------------
# Security analysis
# ---------------------------------------------------------------------------

def analyse_keys(
    keys: list[KeyDetail],
    account_id: str,
    policy: Optional[dict] = None,
) -> KeyAnalysis:
    """
    Run security analysis on a list of normalised keys.

    Checks for:
      - No full-access keys (locked account)
      - Too many full-access keys
      - High allowance function-call keys
      - Wildcard method names
      - Missing nonce activity (unused keys)
      - Rotation overdue

    Args:
        keys:       List of KeyDetail objects.
        account_id: Account being analysed.
        policy:     Optional rotation policy dict.

    Returns:
        KeyAnalysis with findings and risk score.
    """
    policy = policy or {}
    full_access = [k for k in keys if k.permission_type == "FullAccess"]
    func_call = [k for k in keys if k.permission_type == "FunctionCall"]
    findings: list[SecurityFinding] = []
    risk_score = 0

    # 1. No full-access keys
    if not full_access and not func_call:
        findings.append(SecurityFinding(
            severity="INFO",
            code="NO_KEYS",
            message="Account has no access keys (contract-only or deleted).",
            recommendation="If this is unexpected, verify the account is not compromised.",
        ))

    elif not full_access:
        findings.append(SecurityFinding(
            severity="CRITICAL",
            code="NO_FULL_ACCESS",
            message="No full-access keys found — account may be unrecoverable if FunctionCall keys expire.",
            recommendation="Add a full-access key via recovery process before all function-call allowances drain.",
        ))
        risk_score += 40

    # 2. Too many full-access keys
    if len(full_access) > 3:
        findings.append(SecurityFinding(
            severity="HIGH",
            code="EXCESS_FULL_ACCESS",
            message=f"{len(full_access)} full-access keys exist. Each is a full compromise risk.",
            recommendation=f"Reduce to 1–2 full-access keys. Delete unused ones.",
        ))
        risk_score += 30

    elif len(full_access) > 2:
        findings.append(SecurityFinding(
            severity="MEDIUM",
            code="MANY_FULL_ACCESS",
            message=f"{len(full_access)} full-access keys — consider reducing.",
            recommendation="Keep only keys in active use.",
        ))
        risk_score += 15

    # 3. High allowance function-call keys
    for k in func_call:
        if k.allowance_yocto and k.allowance_yocto > ALLOWANCE_HIGH_THRESHOLD:
            findings.append(SecurityFinding(
                severity="HIGH",
                code="HIGH_ALLOWANCE",
                message=f"Key {k.public_key[:20]}… has allowance {k.allowance_near:.1f} NEAR (>{ALLOWANCE_HIGH_THRESHOLD / 10**24} NEAR).",
                public_key_short=k.public_key[:20],
                recommendation="Reduce allowance to minimum needed for the DApp.",
            ))
            risk_score += 20

        elif k.allowance_yocto and k.allowance_yocto > ALLOWANCE_MEDIUM_THRESHOLD:
            findings.append(SecurityFinding(
                severity="MEDIUM",
                code="ELEVATED_ALLOWANCE",
                message=f"Key {k.public_key[:20]}… has allowance {k.allowance_near:.2f} NEAR.",
                public_key_short=k.public_key[:20],
                recommendation="Review whether this allowance is necessary.",
            ))
            risk_score += 10

    # 4. Wildcard method names
    for k in func_call:
        if not k.method_names:
            findings.append(SecurityFinding(
                severity="MEDIUM",
                code="WILDCARD_METHODS",
                message=f"Key {k.public_key[:20]}… allows ALL methods on {k.receiver_id}.",
                public_key_short=k.public_key[:20],
                recommendation="Restrict method_names to the minimum required set.",
            ))
            risk_score += 10

    # 5. Stale keys (nonce == 0 → never used)
    stale = [k for k in keys if k.nonce == 0]
    if stale:
        findings.append(SecurityFinding(
            severity="LOW",
            code="UNUSED_KEYS",
            message=f"{len(stale)} key(s) have never been used (nonce = 0).",
            recommendation="Delete unused keys to reduce attack surface.",
        ))
        risk_score += 5 * len(stale)

    # 6. Rotation overdue (requires enrichment)
    rotation_due_items = []
    rotation_days_fa = policy.get("full_access", DEFAULT_ROTATION_DAYS["full_access"])
    rotation_days_fc = policy.get("function_call", DEFAULT_ROTATION_DAYS["function_call"])
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    for k in keys:
        if k.days_old is not None:
            threshold = rotation_days_fa if k.permission_type == "FullAccess" else rotation_days_fc
            if k.days_old > threshold:
                findings.append(SecurityFinding(
                    severity="MEDIUM",
                    code="ROTATION_OVERDUE",
                    message=f"Key {k.public_key[:20]}… is {k.days_old} days old (rotation recommended every {threshold} days).",
                    public_key_short=k.public_key[:20],
                    recommendation=f"Rotate this key. Use: near delete-key {account_id} {k.public_key}",
                ))
                risk_score += 15
                rotation_due_items.append({
                    "public_key": k.public_key,
                    "days_old": k.days_old,
                    "threshold_days": threshold,
                })

    risk_score = min(risk_score, 100)

    return KeyAnalysis(
        account_id=account_id,
        total_keys=len(keys),
        full_access_keys=len(full_access),
        function_call_keys=len(func_call),
        findings=findings,
        rotation_due=rotation_due_items,
        risk_score=risk_score,
    )


# ---------------------------------------------------------------------------
# Backup
# ---------------------------------------------------------------------------

def backup_keys(
    account_id: str,
    keys: list[KeyDetail],
    backup_dir: str = DEFAULT_BACKUP_DIR,
    policy: Optional[dict] = None,
) -> str:
    """
    Backup key list to a dated JSON file.

    The backup includes a checksum for integrity verification.

    Args:
        account_id: NEAR account ID.
        keys:       List of KeyDetail objects.
        backup_dir: Directory to write backup files.
        policy:     Optional rotation policy to include.

    Returns:
        Path to the written backup file.
    """
    Path(backup_dir).mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = Path(backup_dir) / f"{account_id}_keys_{ts}.json"

    data = {
        "account_id": account_id,
        "backed_up_at": datetime.now(timezone.utc).isoformat(),
        "key_count": len(keys),
        "policy": policy or {},
        "keys": [asdict(k) for k in keys],
    }
    content = json.dumps(data, indent=2, ensure_ascii=False)
    checksum = hashlib.sha256(content.encode()).hexdigest()
    data["checksum"] = checksum

    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info("Backup written to %s (sha256: %s)", path, checksum[:16])
    return str(path)


def verify_backup(backup_path: str) -> tuple[bool, str]:
    """
    Verify integrity of a backup file via SHA-256 checksum.

    Args:
        backup_path: Path to the backup JSON file.

    Returns:
        ``(valid: bool, message: str)``
    """
    path = Path(backup_path)
    if not path.exists():
        return False, f"File not found: {backup_path}"

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return False, f"Could not parse backup: {exc}"

    stored_checksum = data.pop("checksum", None)
    if not stored_checksum:
        return False, "No checksum in backup file."

    recomputed = hashlib.sha256(
        json.dumps(data, indent=2, ensure_ascii=False).encode()
    ).hexdigest()

    if recomputed == stored_checksum:
        return True, f"✅ Checksum valid ({stored_checksum[:16]}…)"
    return False, f"❌ Checksum mismatch! Expected {stored_checksum[:16]}…, got {recomputed[:16]}…"


# ---------------------------------------------------------------------------
# Rotation guidance
# ---------------------------------------------------------------------------

def rotation_plan(account_id: str, keys: list[KeyDetail], policy: dict) -> list[dict[str, Any]]:
    """
    Generate a step-by-step key rotation plan.

    Args:
        account_id: NEAR account ID.
        keys:       Current key list.
        policy:     Rotation policy dict.

    Returns:
        Ordered list of rotation step dicts.
    """
    steps = []
    fa_keys = [k for k in keys if k.permission_type == "FullAccess"]
    fc_keys = [k for k in keys if k.permission_type == "FunctionCall"]

    fa_threshold = policy.get("full_access", DEFAULT_ROTATION_DAYS["full_access"])
    fc_threshold = policy.get("function_call", DEFAULT_ROTATION_DAYS["function_call"])

    for k in fa_keys:
        if k.days_old and k.days_old > fa_threshold:
            steps.append({
                "priority": "HIGH",
                "key": k.public_key,
                "type": "FullAccess",
                "action": "rotate",
                "near_cli": (
                    f"# 1. Generate new key pair\n"
                    f"near generate-key {account_id}\n"
                    f"# 2. Add new full-access key\n"
                    f"near add-key {account_id} <NEW_PUBLIC_KEY>\n"
                    f"# 3. Delete old key\n"
                    f"near delete-key {account_id} {k.public_key}"
                ),
                "reason": f"Key is {k.days_old} days old (threshold: {fa_threshold} days)",
            })

    for k in fc_keys:
        if k.days_old and k.days_old > fc_threshold:
            steps.append({
                "priority": "MEDIUM",
                "key": k.public_key,
                "type": "FunctionCall",
                "action": "rotate",
                "near_cli": (
                    f"near delete-key {account_id} {k.public_key}\n"
                    f"# Re-authorise the DApp to generate a new function-call key"
                ),
                "reason": f"Key is {k.days_old} days old (threshold: {fc_threshold} days)",
            })

    # Flag stale keys for deletion
    for k in keys:
        if k.nonce == 0:
            steps.append({
                "priority": "LOW",
                "key": k.public_key,
                "type": k.permission_type,
                "action": "delete_unused",
                "near_cli": f"near delete-key {account_id} {k.public_key}",
                "reason": "Key has never been used (nonce = 0)",
            })

    return steps


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def format_key_list(keys: list[KeyDetail], account_id: str) -> str:
    """Format key list as Telegram markdown."""
    lines = [f"🔑 *Keys for `{account_id}`* ({len(keys)} total)", ""]
    for k in keys:
        icon = "🔓" if k.permission_type == "FullAccess" else "🔐"
        lines.append(f"{icon} `{k.public_key[:32]}…`")
        lines.append(f"   Type: {k.permission_type}  |  Nonce: {k.nonce}")
        if k.receiver_id:
            methods = ", ".join(k.method_names) if k.method_names else "*all*"
            lines.append(f"   Contract: `{k.receiver_id}`")
            lines.append(f"   Methods: {methods}")
        if k.allowance_near is not None:
            lines.append(f"   Allowance: {k.allowance_near:.4f} NEAR")
        if k.days_old is not None:
            lines.append(f"   Age: {k.days_old} days | Rotation due: {k.rotation_due or '?'}")
        lines.append("")
    return "\n".join(lines)


def format_analysis(analysis: KeyAnalysis) -> str:
    """Format security analysis as Telegram markdown."""
    risk_bar = "🟢" if analysis.risk_score < 25 else "🟡" if analysis.risk_score < 60 else "🔴"
    lines = [
        f"🔍 *Security Analysis: `{analysis.account_id}`*",
        f"Keys: {analysis.total_keys} ({analysis.full_access_keys} full, {analysis.function_call_keys} func-call)",
        f"Risk Score: {risk_bar} {analysis.risk_score}/100",
        "",
    ]
    if not analysis.findings:
        lines.append("✅ No security issues found.")
    else:
        for f in sorted(analysis.findings, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x.severity)):
            icon = SEVERITY_ICON.get(f.severity, "❓")
            lines.append(f"{icon} [{f.severity}] {f.code}")
            lines.append(f"   {f.message}")
            if f.recommendation:
                lines.append(f"   💡 {f.recommendation}")
            lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="NEAR Key Manager — access key analysis, backup, and rotation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List all keys for an account
  python3 key-manager.py list example.near

  # Security analysis
  python3 key-manager.py analyze example.near --json

  # Backup keys
  python3 key-manager.py backup example.near --dir backups/

  # Verify backup integrity
  python3 key-manager.py verify-backup backups/example.near_keys_20250101.json

  # View a specific key
  python3 key-manager.py view example.near ed25519:ABC...

  # Generate rotation plan
  python3 key-manager.py rotation-plan example.near

  # Check access control on a contract
  python3 key-manager.py access-control example.near
""",
    )
    sub = parser.add_subparsers(dest="command")

    # list
    ls = sub.add_parser("list", help="List access keys")
    ls.add_argument("account_id")
    ls.add_argument("--rpc", default=DEFAULT_RPC)
    ls.add_argument("--json", action="store_true")

    # backup
    bk = sub.add_parser("backup", help="Backup keys to dated JSON file")
    bk.add_argument("account_id")
    bk.add_argument("--rpc", default=DEFAULT_RPC)
    bk.add_argument("--dir", default=DEFAULT_BACKUP_DIR)
    bk.add_argument("--policy", default=DEFAULT_POLICY_FILE)

    # verify-backup
    vb = sub.add_parser("verify-backup", help="Verify backup file checksum")
    vb.add_argument("backup_file", help="Path to backup JSON file")

    # analyze
    an = sub.add_parser("analyze", help="Security analysis of keys")
    an.add_argument("account_id")
    an.add_argument("--rpc", default=DEFAULT_RPC)
    an.add_argument("--policy", default=DEFAULT_POLICY_FILE)
    an.add_argument("--json", action="store_true")

    # view
    vw = sub.add_parser("view", help="View a specific access key")
    vw.add_argument("account_id")
    vw.add_argument("public_key")
    vw.add_argument("--rpc", default=DEFAULT_RPC)
    vw.add_argument("--json", action="store_true")

    # rotation-plan
    rp = sub.add_parser("rotation-plan", help="Generate key rotation steps")
    rp.add_argument("account_id")
    rp.add_argument("--rpc", default=DEFAULT_RPC)
    rp.add_argument("--policy", default=DEFAULT_POLICY_FILE)
    rp.add_argument("--json", action="store_true")

    # access-control
    ac = sub.add_parser("access-control", help="Audit access control on an account's contracts")
    ac.add_argument("account_id")
    ac.add_argument("--rpc", default=DEFAULT_RPC)
    ac.add_argument("--json", action="store_true")

    return parser


def _load_policy(policy_file: str) -> dict:
    """Load rotation policy from JSON file, returning defaults if missing."""
    path = Path(policy_file)
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Could not load policy %s: %s", policy_file, exc)
    return DEFAULT_ROTATION_DAYS.copy()


def main() -> None:
    """Entry point for the NEAR key manager skill."""
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "list":
        try:
            raw_keys = list_keys_raw(args.rpc, args.account_id)
        except RuntimeError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
        keys = [normalise_key(k) for k in raw_keys]
        if args.json:
            print(json.dumps([asdict(k) for k in keys], indent=2))
        else:
            print(format_key_list(keys, args.account_id))

    elif args.command == "backup":
        try:
            raw_keys = list_keys_raw(args.rpc, args.account_id)
        except RuntimeError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
        policy = _load_policy(args.policy)
        keys = [normalise_key(k) for k in raw_keys]
        path = backup_keys(args.account_id, keys, args.dir, policy)
        print(f"✅ Backed up {len(keys)} keys to {path}")

    elif args.command == "verify-backup":
        valid, msg = verify_backup(args.backup_file)
        print(msg)
        if not valid:
            sys.exit(1)

    elif args.command == "analyze":
        try:
            raw_keys = list_keys_raw(args.rpc, args.account_id)
        except RuntimeError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
        policy = _load_policy(args.policy)
        keys = [normalise_key(k) for k in raw_keys]
        analysis = analyse_keys(keys, args.account_id, policy)
        if args.json:
            print(json.dumps(asdict(analysis), indent=2))
        else:
            print(format_analysis(analysis))

    elif args.command == "view":
        result = view_key_raw(args.rpc, args.account_id, args.public_key)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            key = normalise_key({"public_key": args.public_key, "access_key": result})
            print(format_key_list([key], args.account_id))

    elif args.command == "rotation-plan":
        try:
            raw_keys = list_keys_raw(args.rpc, args.account_id)
        except RuntimeError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
        policy = _load_policy(args.policy)
        keys = [normalise_key(k) for k in raw_keys]
        plan = rotation_plan(args.account_id, keys, policy)
        if args.json:
            print(json.dumps(plan, indent=2))
        else:
            if not plan:
                print("✅ No rotation actions needed at this time.")
            else:
                for step in plan:
                    icon = "🔴" if step["priority"] == "HIGH" else "🟡" if step["priority"] == "MEDIUM" else "🟢"
                    print(f"{icon} [{step['priority']}] {step['action'].upper()}: {step['key'][:30]}…")
                    print(f"   Reason: {step['reason']}")
                    print(f"   Commands:\n{step['near_cli']}\n")

    elif args.command == "access-control":
        try:
            raw_keys = list_keys_raw(args.rpc, args.account_id)
        except RuntimeError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
        keys = [normalise_key(k) for k in raw_keys]
        fc_keys = [k for k in keys if k.permission_type == "FunctionCall"]
        contracts = {}
        for k in fc_keys:
            r = k.receiver_id or "?"
            contracts.setdefault(r, []).append({
                "key": k.public_key[:30] + "…",
                "methods": k.method_names or ["*all*"],
                "allowance_near": k.allowance_near,
            })
        if args.json:
            print(json.dumps({"account_id": args.account_id, "contracts": contracts}, indent=2))
        else:
            print(f"🔐 *Access Control Summary: `{args.account_id}`*")
            for contract, keys_list in contracts.items():
                print(f"\n  Contract: {contract}")
                for entry in keys_list:
                    methods = ", ".join(entry["methods"])
                    print(f"    Key: {entry['key']}")
                    print(f"    Methods: {methods}")
                    if entry["allowance_near"]:
                        print(f"    Allowance: {entry['allowance_near']:.4f} NEAR")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
