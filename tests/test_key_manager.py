"""Tests for NEAR key manager skill."""
import json
import sys
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
# key-manager.py → import as key_manager via alias file
import importlib.util
spec = importlib.util.spec_from_file_location(
    "key_manager",
    Path(__file__).parent.parent / "scripts" / "key-manager.py",
)
km = importlib.util.module_from_spec(spec)
spec.loader.exec_module(km)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def full_access_key_raw():
    return {
        "public_key": "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "access_key": {"permission": "FullAccess", "nonce": 10},
    }


@pytest.fixture
def func_call_key_raw():
    return {
        "public_key": "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
        "access_key": {
            "nonce": 5,
            "permission": {
                "FunctionCall": {
                    "receiver_id": "app.near",
                    "method_names": ["stake", "unstake"],
                    "allowance": str(2 * 10**24),  # 2 NEAR
                }
            },
        },
    }


@pytest.fixture
def high_allowance_key_raw():
    return {
        "public_key": "ed25519:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=",
        "access_key": {
            "nonce": 0,
            "permission": {
                "FunctionCall": {
                    "receiver_id": "defi.near",
                    "method_names": [],
                    "allowance": str(50 * 10**24),  # 50 NEAR — HIGH
                }
            },
        },
    }


# ---------------------------------------------------------------------------
# normalise_key
# ---------------------------------------------------------------------------

class TestNormaliseKey:
    def test_full_access(self, full_access_key_raw):
        key = km.normalise_key(full_access_key_raw)
        assert key.permission_type == "FullAccess"
        assert key.nonce == 10
        assert key.receiver_id is None
        assert key.allowance_yocto is None

    def test_function_call(self, func_call_key_raw):
        key = km.normalise_key(func_call_key_raw)
        assert key.permission_type == "FunctionCall"
        assert key.receiver_id == "app.near"
        assert key.method_names == ["stake", "unstake"]
        assert key.allowance_near == pytest.approx(2.0)
        assert key.nonce == 5

    def test_high_allowance_wildcard(self, high_allowance_key_raw):
        key = km.normalise_key(high_allowance_key_raw)
        assert key.allowance_near == pytest.approx(50.0)
        assert key.method_names == []
        assert key.nonce == 0


# ---------------------------------------------------------------------------
# analyse_keys
# ---------------------------------------------------------------------------

class TestAnalyseKeys:
    def test_no_issues_single_full_access(self, full_access_key_raw):
        keys = [km.normalise_key(full_access_key_raw)]
        analysis = km.analyse_keys(keys, "alice.near")
        assert analysis.full_access_keys == 1
        assert analysis.function_call_keys == 0
        # Should have LOW finding for unused key (nonce=10 means used, but depends)
        # nonce=10 means it was used — no unused key finding
        codes = [f.code for f in analysis.findings]
        assert "NO_FULL_ACCESS" not in codes
        assert "EXCESS_FULL_ACCESS" not in codes

    def test_no_full_access_critical(self, func_call_key_raw):
        keys = [km.normalise_key(func_call_key_raw)]
        analysis = km.analyse_keys(keys, "alice.near")
        codes = [f.code for f in analysis.findings]
        assert "NO_FULL_ACCESS" in codes
        assert analysis.risk_score >= 40

    def test_excess_full_access_keys(self, full_access_key_raw):
        keys = []
        for i in range(4):
            raw = dict(full_access_key_raw)
            raw["public_key"] = f"ed25519:KEY{i}{'A'*40}"
            keys.append(km.normalise_key(raw))
        analysis = km.analyse_keys(keys, "alice.near")
        codes = [f.code for f in analysis.findings]
        assert "EXCESS_FULL_ACCESS" in codes

    def test_high_allowance_detected(self, high_allowance_key_raw):
        keys = [km.normalise_key(high_allowance_key_raw)]
        # Also add a full access key so we don't get NO_FULL_ACCESS
        fa_raw = {
            "public_key": "ed25519:FAKEY" + "A" * 40,
            "access_key": {"permission": "FullAccess", "nonce": 1},
        }
        keys.append(km.normalise_key(fa_raw))
        analysis = km.analyse_keys(keys, "alice.near")
        codes = [f.code for f in analysis.findings]
        assert "HIGH_ALLOWANCE" in codes

    def test_wildcard_methods_detected(self, high_allowance_key_raw):
        key = km.normalise_key(high_allowance_key_raw)
        fa_raw = {
            "public_key": "ed25519:FAKEY" + "A" * 40,
            "access_key": {"permission": "FullAccess", "nonce": 1},
        }
        fa_key = km.normalise_key(fa_raw)
        analysis = km.analyse_keys([key, fa_key], "alice.near")
        codes = [f.code for f in analysis.findings]
        assert "WILDCARD_METHODS" in codes

    def test_unused_key_detected(self, full_access_key_raw):
        # nonce=0 means unused
        raw = dict(full_access_key_raw)
        raw["access_key"] = {"permission": "FullAccess", "nonce": 0}
        keys = [km.normalise_key(raw)]
        analysis = km.analyse_keys(keys, "alice.near")
        codes = [f.code for f in analysis.findings]
        assert "UNUSED_KEYS" in codes

    def test_risk_score_capped_at_100(self, high_allowance_key_raw):
        # Create many issues
        keys = []
        for i in range(10):
            raw = dict(high_allowance_key_raw)
            raw["public_key"] = f"ed25519:BAD{i}{'C'*40}"
            keys.append(km.normalise_key(raw))
        analysis = km.analyse_keys(keys, "alice.near")
        assert analysis.risk_score <= 100

    def test_empty_keys(self):
        analysis = km.analyse_keys([], "ghost.near")
        codes = [f.code for f in analysis.findings]
        assert "NO_KEYS" in codes


# ---------------------------------------------------------------------------
# backup_keys & verify_backup
# ---------------------------------------------------------------------------

class TestBackup:
    def test_backup_creates_file(self, full_access_key_raw, tmp_path):
        keys = [km.normalise_key(full_access_key_raw)]
        path = km.backup_keys("alice.near", keys, str(tmp_path))
        assert Path(path).exists()

    def test_backup_json_valid(self, full_access_key_raw, tmp_path):
        keys = [km.normalise_key(full_access_key_raw)]
        path = km.backup_keys("alice.near", keys, str(tmp_path))
        data = json.loads(Path(path).read_text())
        assert data["account_id"] == "alice.near"
        assert data["key_count"] == 1
        assert "checksum" in data

    def test_verify_backup_valid(self, full_access_key_raw, tmp_path):
        keys = [km.normalise_key(full_access_key_raw)]
        path = km.backup_keys("alice.near", keys, str(tmp_path))
        valid, msg = km.verify_backup(path)
        assert valid
        assert "✅" in msg

    def test_verify_backup_tampered(self, full_access_key_raw, tmp_path):
        keys = [km.normalise_key(full_access_key_raw)]
        path = km.backup_keys("alice.near", keys, str(tmp_path))
        # Tamper with the file
        data = json.loads(Path(path).read_text())
        data["key_count"] = 999
        Path(path).write_text(json.dumps(data))
        valid, msg = km.verify_backup(path)
        assert not valid
        assert "mismatch" in msg.lower() or "❌" in msg

    def test_verify_nonexistent_file(self, tmp_path):
        valid, msg = km.verify_backup(str(tmp_path / "ghost.json"))
        assert not valid
        assert "not found" in msg.lower()


# ---------------------------------------------------------------------------
# rotation_plan
# ---------------------------------------------------------------------------

class TestRotationPlan:
    def test_no_age_info_empty_plan(self, full_access_key_raw):
        keys = [km.normalise_key(full_access_key_raw)]
        plan = km.rotation_plan("alice.near", keys, {})
        # No age info → no overdue rotation; but nonce=10 → not unused
        actions = [s["action"] for s in plan]
        assert "rotate" not in actions

    def test_unused_key_in_plan(self):
        raw = {
            "public_key": "ed25519:UNUSED" + "A" * 38,
            "access_key": {"permission": "FullAccess", "nonce": 0},
        }
        keys = [km.normalise_key(raw)]
        plan = km.rotation_plan("alice.near", keys, {})
        assert any(s["action"] == "delete_unused" for s in plan)

    def test_old_key_in_plan(self):
        raw = {
            "public_key": "ed25519:OLD" + "A" * 40,
            "access_key": {"permission": "FullAccess", "nonce": 5},
        }
        key = km.normalise_key(raw)
        key.days_old = 200  # Over 90-day default
        plan = km.rotation_plan("alice.near", [key], {})
        assert any(s["action"] == "rotate" for s in plan)


# ---------------------------------------------------------------------------
# rpc_call (mocked)
# ---------------------------------------------------------------------------

class TestRpcCall:
    @patch("urllib.request.urlopen")
    def test_successful_rpc(self, mock_open):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"result": {"keys": []}}).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_open.return_value = mock_resp
        result = km.rpc_call("https://rpc.test", "query", {})
        assert "result" in result

    @patch("urllib.request.urlopen", side_effect=Exception("network down"))
    def test_network_error_raises(self, mock_open):
        with pytest.raises(Exception):
            km.rpc_call("https://rpc.test", "query", {})
