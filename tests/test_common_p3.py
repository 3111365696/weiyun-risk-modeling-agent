"""P3 测试：脱敏、STRIDE 覆盖度、报告差异、用户与审计、策略钩子。"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "apps"))

from common import generation, scrub, store


@pytest.fixture()
def sandbox(tmp_path, monkeypatch):
    data_dir = tmp_path / ".stride-gpt"
    monkeypatch.setattr(store, "DATA_DIR", data_dir)
    monkeypatch.setattr(store, "CONFIG_FILE", data_dir / "web_config.json")
    monkeypatch.setattr(store, "KEY_FILE", data_dir / "web_key")
    monkeypatch.setattr(store, "DB_FILE", data_dir / "web.db")
    return data_dir


# ---------------------------------------------------------------------------
# 脱敏
# ---------------------------------------------------------------------------


class TestScrub:
    def test_redacts_common_secret_shapes(self):
        text = (
            "openai=sk-abcdefghijklmnopqrstuvwxyz012345 "
            "github=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
            "jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghij "
            "password: hunter2secret"
        )
        cleaned, hits = scrub.scrub_text(text)
        assert "sk-abcdefghijklmnopqrstuvwxyz012345" not in cleaned
        assert "ghp_" not in cleaned
        assert "eyJhbGci" not in cleaned
        assert "hunter2secret" not in cleaned
        assert set(hits) >= {"OpenAI Key", "GitHub Token", "JWT"}

    def test_private_key_block(self):
        block = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----"
        cleaned, hits = scrub.scrub_text(block)
        assert "MIIEow" not in cleaned
        assert "Private Key" in hits

    def test_plain_text_untouched(self):
        text = "这是一个订单系统，使用 React 与 PostgreSQL，通过 OAuth2 登录。"
        cleaned, hits = scrub.scrub_text(text)
        assert cleaned == text
        assert hits == []

    def test_short_values_not_redacted(self):
        cleaned, hits = scrub.scrub_text("token: ab12")
        assert hits == []
        assert cleaned == "token: ab12"


# ---------------------------------------------------------------------------
# 覆盖度 / 差异
# ---------------------------------------------------------------------------


class TestCoverage:
    def test_counts_and_missing(self):
        threats = [
            {"Threat Type": "Spoofing"},
            {"Threat Type": "spoofing"},
            {"Threat Type": "Tampering"},
        ]
        result = generation.stride_coverage(threats)
        assert result["counts"]["Spoofing"] == 2
        assert result["counts"]["Tampering"] == 1
        assert "Repudiation" in result["missing"]
        assert result["total"] == 3

    def test_full_coverage(self):
        threats = [{"Threat Type": t} for t in generation.STRIDE_TYPES]
        assert generation.stride_coverage(threats)["missing"] == []

    def test_empty(self):
        result = generation.stride_coverage([])
        assert result["total"] == 0
        assert len(result["missing"]) == 6


class TestDiff:
    def test_added_removed_unchanged(self):
        old = [
            {"Threat Type": "Spoofing", "Scenario": "A"},
            {"Threat Type": "Tampering", "Scenario": "B"},
        ]
        new = [
            {"Threat Type": "Spoofing", "Scenario": "A"},
            {"Threat Type": "Repudiation", "Scenario": "C"},
        ]
        diff = generation.diff_threats(old, new)
        assert diff["added_count"] == 1
        assert diff["removed_count"] == 1
        assert diff["unchanged_count"] == 1
        assert diff["added"][0]["Scenario"] == "C"
        assert diff["removed"][0]["Scenario"] == "B"

    def test_diff_latest_requires_two_reports(self, sandbox):
        generation.archive_result(
            "threat_model", "# tm", {"threat_model": [{"Threat Type": "Spoofing", "Scenario": "A"}]},
            project="D1",
        )
        assert generation.diff_latest_threat_models("D1") is None
        generation.archive_result(
            "threat_model", "# tm", {"threat_model": [{"Threat Type": "Spoofing", "Scenario": "A"},
                                                       {"Threat Type": "Tampering", "Scenario": "B"}]},
            project="D1",
        )
        diff = generation.diff_latest_threat_models("D1")
        assert diff is not None
        assert diff["added_count"] == 1
        assert diff["removed_count"] == 0
        assert diff["unchanged_count"] == 1


# ---------------------------------------------------------------------------
# 用户与审计
# ---------------------------------------------------------------------------


class TestUsers:
    def test_create_verify(self, sandbox):
        store.create_user("alice", "Str0ng!Pass1", "admin")
        account = store.verify_user("alice", "Str0ng!Pass1")
        assert account == {"username": "alice", "role": "admin"}
        assert store.verify_user("alice", "wrong") is None
        assert store.verify_user("nobody", "Str0ng!Pass1") is None

    def test_duplicate_and_short_password(self, sandbox):
        store.create_user("bob", "Str0ng!Pass1")
        with pytest.raises(ValueError):
            store.create_user("bob", "Str0ng!Pass2")
        with pytest.raises(ValueError):
            store.create_user("carol", "123")

    def test_password_reset_and_delete(self, sandbox):
        store.create_user("dave", "Str0ng!Pass1")
        store.set_user_password("dave", "Another!Pass2")
        assert store.verify_user("dave", "Another!Pass2") is not None
        store.delete_user("dave")
        assert store.get_user("dave") is None
        assert store.verify_user("dave", "Another!Pass2") is None

    def test_password_not_stored_plaintext(self, sandbox):
        store.create_user("erin", "Sup3rSecret!x")
        with store._conn() as conn:
            row = conn.execute("SELECT password_hash, salt FROM users WHERE username='erin'").fetchone()
        assert "Sup3rSecret!x" not in (row["password_hash"] + row["salt"])


class TestAudit:
    def test_log_and_filter(self, sandbox):
        store.log_action("alice", "登录", "密码登录")
        store.log_action("bob", "删除报告", "#3")
        rows = store.list_audit()
        assert [r["action"] for r in rows] == ["删除报告", "登录"]  # 新→旧
        only_alice = store.list_audit(username="alice")
        assert len(only_alice) == 1 and only_alice[0]["action"] == "登录"


# ---------------------------------------------------------------------------
# 策略钩子（企业基线 + 脱敏）
# ---------------------------------------------------------------------------


class TestPolicies:
    def test_apply_sets_core_hooks(self, sandbox):
        from stride_gpt.core import llm

        store.save_config({"security_baseline": "必须符合等保 2.0 三级", "scrub_enabled": True})
        result = generation.apply_policies()
        assert result == {"baseline": True, "scrubbing": True}
        messages = llm._apply_message_policies([{"role": "user", "content": "key=sk-abcdefghijklmnopqrstuvwxyz"}])
        assert messages[0]["role"] == "system"
        assert "等保" in messages[0]["content"]
        assert "sk-abcdefghijklmnopqrstuvwxyz" not in messages[1]["content"]

        # 关闭脱敏后不再替换
        store.save_config({"security_baseline": "", "scrub_enabled": False})
        generation.apply_policies()
        messages = llm._apply_message_policies([{"role": "user", "content": "key=sk-abcdefghijklmnopqrstuvwxyz"}])
        assert messages[0]["content"] == "key=sk-abcdefghijklmnopqrstuvwxyz"
        # 清理全局钩子，避免影响其他测试
        llm.set_extra_system_instruction(None)
        llm.set_prompt_scrubber(None)
