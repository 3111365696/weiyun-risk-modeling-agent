"""P5 测试：用量与成本、API 配额、对抗式验证。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "apps"))

from common import generation, store, usage


@pytest.fixture()
def sandbox(tmp_path, monkeypatch):
    data_dir = tmp_path / ".stride-gpt"
    monkeypatch.setattr(store, "DATA_DIR", data_dir)
    monkeypatch.setattr(store, "CONFIG_FILE", data_dir / "web_config.json")
    monkeypatch.setattr(store, "KEY_FILE", data_dir / "web_key")
    monkeypatch.setattr(store, "DB_FILE", data_dir / "web.db")
    return data_dir


# ---------------------------------------------------------------------------
# 价格与估算
# ---------------------------------------------------------------------------


class TestPricing:
    def test_known_models_have_prices(self):
        assert usage.price_for("claude-sonnet-5") is not None
        assert usage.price_for("gpt-6-astra") is not None
        assert usage.price_for("deepseek-v4-flash") is not None

    def test_unknown_model_returns_none(self):
        assert usage.price_for("homebrew-llm-9000") is None
        assert usage.estimate_cost("homebrew-llm-9000", 1000, 1000) is None

    def test_estimate_cost_math(self):
        # claude-sonnet: 3 / 15 美元每百万 token
        cost = usage.estimate_cost("claude-sonnet-5", 1_000_000, 1_000_000)
        assert cost == pytest.approx(18.0)
        assert usage.estimate_cost("claude-sonnet-5", None, None) == 0.0


# ---------------------------------------------------------------------------
# 用量记录与汇总
# ---------------------------------------------------------------------------


class TestUsageLog:
    def test_record_and_summary_groups(self, sandbox):
        store.log_usage(
            actor="admin", source="web", provider="OpenAI API", model="gpt-6-astra",
            kind="threat_model", project="项目A", prompt_tokens=100, completion_tokens=50, cost=0.5,
        )
        store.log_usage(
            actor="api:CI", source="api", provider="Anthropic API", model="claude-sonnet-5",
            kind="dfd", project="项目B", prompt_tokens=200, completion_tokens=100, cost=1.5,
        )
        summary = store.usage_summary()
        assert summary["totals"]["calls"] == 2
        assert summary["totals"]["total_tokens"] == 450
        assert summary["totals"]["cost"] == pytest.approx(2.0)
        assert summary["groups"]["model"]["gpt-6-astra"]["calls"] == 1
        assert summary["groups"]["project"]["项目B"]["tokens"] == 300
        assert summary["groups"]["source"]["api"]["cost"] == pytest.approx(1.5)

    def test_actor_windows(self, sandbox):
        store.log_usage(actor="api:CI", prompt_tokens=10, completion_tokens=5, cost=0.1)
        today = store.usage_for_actor_today("api:CI")
        assert today["tokens"] == 15
        month = store.usage_for_actor_month("api:CI")
        assert month["cost"] == pytest.approx(0.1)
        assert store.usage_for_actor_today("nobody")["tokens"] == 0

    def test_recorder_skipped_under_pytest(self, sandbox):
        """测试环境下钩子必须跳过，避免 mock 调用污染真实统计。"""

        class _Cfg:
            provider = "Anthropic API"
            model_name = "claude-sonnet-5"

        class _Resp:
            prompt_tokens = 1000
            completion_tokens = 500

        usage.record_from_response(_Cfg(), _Resp())
        assert store.usage_rows() == []


# ---------------------------------------------------------------------------
# API 配额
# ---------------------------------------------------------------------------


class TestQuota:
    def _key(self, sandbox, daily=0, monthly=0.0):
        store.create_api_key("CI")
        row = store.get_api_key_by_name("CI")
        store.set_api_key_quota(row["id"], daily, monthly)
        return store.get_api_key_by_name("CI")

    def test_unlimited_by_default(self, sandbox):
        key = self._key(sandbox)
        allowed, reason = usage.check_api_quota(key)
        assert allowed and reason == ""

    def test_daily_token_limit(self, sandbox):
        key = self._key(sandbox, daily=100)
        store.log_usage(actor="api:CI", prompt_tokens=60, completion_tokens=50)
        allowed, reason = usage.check_api_quota(key)
        assert not allowed and "token" in reason

    def test_monthly_cost_limit(self, sandbox):
        key = self._key(sandbox, monthly=0.5)
        store.log_usage(actor="api:CI", prompt_tokens=1, completion_tokens=1, cost=0.6)
        allowed, reason = usage.check_api_quota(key)
        assert not allowed and "费用" in reason

    def test_budget_status(self, sandbox):
        store.save_config({"monthly_budget": 10})
        store.log_usage(actor="admin", cost=2.5, prompt_tokens=10, completion_tokens=10)
        status = usage.budget_status()
        assert status["budget"] == 10
        assert status["spent"] == pytest.approx(2.5)
        assert status["ratio"] == pytest.approx(0.25)
        assert not status["over"]


# ---------------------------------------------------------------------------
# 对抗式验证
# ---------------------------------------------------------------------------


def _fake_response(content: str):
    from stride_gpt.core.schemas import LLMResponse

    return LLMResponse(content=content, model="mock", prompt_tokens=10, completion_tokens=5)


VERIFY_THREATS = [
    {"Threat Type": "Spoofing", "Scenario": "伪造令牌", "Potential Impact": "接管"},
    {"Threat Type": "Denial of Service", "Scenario": "泛泛而谈的问题", "Potential Impact": "未知"},
]
VERIFY_SETTINGS = {"provider": "OpenAI API", "model": "gpt-6-astra", "api_key": "test-key"}


class TestVerification:

    def test_verify_normalises_verdicts(self, sandbox, monkeypatch):
        payload = {
            "results": [
                {"i": 1, "verdict": "confirmed", "confidence": "high", "reason": "路径清晰"},
                {"i": 2, "verdict": "refuted", "confidence": "low", "reason": "过于笼统"},
            ]
        }
        monkeypatch.setattr(
            "stride_gpt.core.llm.call_llm", lambda config, messages: _fake_response(json.dumps(payload))
        )
        results = generation.verify_threats(VERIFY_THREATS, VERIFY_SETTINGS)
        assert results[0]["verdict"] == "已确认" and results[0]["confidence"] == "高"
        assert results[1]["verdict"] == "已驳回" and results[1]["confidence"] == "低"
        assert results[0]["scenario"] == "伪造令牌"

    def test_verify_handles_bad_output(self, sandbox, monkeypatch):
        monkeypatch.setattr(
            "stride_gpt.core.llm.call_llm",
            lambda config, messages: _fake_response("模型开始胡说八道"),
        )
        assert generation.verify_threats(VERIFY_THREATS, VERIFY_SETTINGS) == []

    def test_verify_and_store_updates_register(self, sandbox, monkeypatch):
        generation.archive_result(
            "threat_model",
            "# tm",
            {"threat_model": VERIFY_THREATS},
            project="项目V",
        )
        assert store.threat_verdict_stats("项目V")["未验证"] == 2
        payload = {
            "results": [
                {"i": 1, "verdict": "已确认", "confidence": "高", "reason": "ok"},
                {"i": 2, "verdict": "已驳回", "confidence": "中", "reason": "太泛"},
            ]
        }
        monkeypatch.setattr(
            "stride_gpt.core.llm.call_llm", lambda config, messages: _fake_response(json.dumps(payload))
        )
        stats = generation.verify_and_store("项目V", VERIFY_THREATS, VERIFY_SETTINGS)
        assert stats == {"已确认": 1, "存疑": 0, "已驳回": 1, "verified": 2}
        rows = {t["scenario"]: t for t in store.list_threats(project="项目V")}
        assert rows["伪造令牌"]["verdict"] == "已确认"
        assert rows["泛泛而谈的问题"]["verification_note"] == "太泛"
        assert store.threat_verdict_stats("项目V") == {
            "已确认": 1,
            "存疑": 0,
            "已驳回": 1,
            "未验证": 0,
            "total": 2,
        }

    def test_verification_toggle(self, sandbox):
        assert generation.verification_enabled() is True  # 默认开启
        store.save_config({"verify_threats": False})
        assert generation.verification_enabled() is False
