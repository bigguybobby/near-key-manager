# NEAR Key Manager — OpenClaw Skill

Access key management, security analysis, backup with integrity verification, and rotation guidance for NEAR accounts.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)

---

## Features

- 🔑 **Key listing**: all access keys with type, allowance, methods, nonce
- 🔍 **Security analysis**: detect over-privileged keys, wildcards, high allowances, unused keys
- 💾 **Backup with checksums**: SHA-256 integrity verification
- 🔄 **Rotation planning**: age-based rotation schedule with `near-cli` commands
- 🔐 **Access control audit**: per-contract method permission summary
- 📊 **Risk scoring**: 0–100 risk score from weighted findings
- ⚙️ **Policy-driven**: configurable rotation thresholds per key type

---

## Installation

```bash
cd ~/projects/near-market/near-key-manager
python3 --version   # 3.8+ required (stdlib only)
```

---

## Usage

### List all keys

```bash
python3 scripts/key-manager.py list example.near
python3 scripts/key-manager.py list example.near --json
```

### Security analysis

```bash
python3 scripts/key-manager.py analyze example.near
python3 scripts/key-manager.py analyze example.near --json
```

### Backup keys

```bash
python3 scripts/key-manager.py backup example.near --dir backups/
# ✅ Backed up 3 keys to backups/example.near_keys_20250117_090000.json
```

### Verify backup integrity

```bash
python3 scripts/key-manager.py verify-backup backups/example.near_keys_20250117_090000.json
# ✅ Checksum valid (a1b2c3d4…)
```

### View a specific key

```bash
python3 scripts/key-manager.py view example.near ed25519:YOURPUBKEY...
```

### Rotation plan

```bash
python3 scripts/key-manager.py rotation-plan example.near
python3 scripts/key-manager.py rotation-plan example.near --json
```

### Access control audit

```bash
python3 scripts/key-manager.py access-control example.near
```

---

## Configuration

### Rotation policy (`key-policy.json`)

```json
{
  "full_access": 90,
  "function_call": 365
}
```

| Key | Default | Description |
|-----|---------|-------------|
| `full_access` | 90 days | Days before full-access key rotation recommended |
| `function_call` | 365 days | Days before function-call key rotation recommended |

---

## Security Findings Reference

| Code | Severity | Description |
|------|----------|-------------|
| `NO_FULL_ACCESS` | CRITICAL | No full-access keys — account may be locked |
| `EXCESS_FULL_ACCESS` | HIGH | More than 3 full-access keys |
| `MANY_FULL_ACCESS` | MEDIUM | More than 2 full-access keys |
| `HIGH_ALLOWANCE` | HIGH | Function-call key with > 10 NEAR allowance |
| `ELEVATED_ALLOWANCE` | MEDIUM | Function-call key with 1–10 NEAR allowance |
| `WILDCARD_METHODS` | MEDIUM | Function-call key with no method restrictions |
| `UNUSED_KEYS` | LOW | Key(s) with nonce = 0 (never used) |
| `ROTATION_OVERDUE` | MEDIUM | Key exceeds rotation policy age |
| `NO_KEYS` | INFO | Account has no access keys |

---

## API Reference

### `normalise_key(raw_key) → KeyDetail`

Convert raw RPC key dict to `KeyDetail` dataclass.

### `analyse_keys(keys, account_id, policy) → KeyAnalysis`

Run security checks. Returns `KeyAnalysis` with `findings`, `risk_score`, `rotation_due`.

### `backup_keys(account_id, keys, backup_dir, policy) → str`

Write dated backup JSON with SHA-256 checksum. Returns file path.

### `verify_backup(backup_path) → (bool, str)`

Verify backup integrity. Returns `(valid, message)`.

### `rotation_plan(account_id, keys, policy) → list[dict]`

Generate step-by-step rotation actions with `near-cli` commands.

### `enrich_with_policy(key, policy, backup_metadata) → KeyDetail`

Attach age/rotation-due fields to a key using backup metadata.

---

## Testing

```bash
pip install pytest
cd ~/projects/near-market/near-key-manager
pytest tests/ -v
```

---

## License

[MIT](LICENSE) © 2025 bigguybobby
