# near-key-manager

## Description
Manage NEAR access keys — list, analyze, backup, and monitor for security issues.

## Commands
- `key-manager.py list ACCOUNT` — List all access keys
- `key-manager.py analyze ACCOUNT` — Security analysis with alerts
- `key-manager.py backup ACCOUNT` — Backup key list to JSON file
- `key-manager.py view ACCOUNT PUBLIC_KEY` — View specific key details

## Security Alerts
- Too many full-access keys
- Locked accounts (no full-access)
- High-allowance function-call keys
