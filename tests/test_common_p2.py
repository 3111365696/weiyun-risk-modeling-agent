"""P2 公共层测试：API Key、配置加解密、Webhook、归档/台账、SARIF、提示词构造。

所有存储路径都指向 tmp_path，不会触碰真实的 ~/.stride-gpt。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "apps"))

from common import generation, store


@pytest.fixture()
def sandbox(tmp_path, monkeypatch):
    """把 store 的所有落盘路径重定向到临时目录。"""
    data_dir = tmp_path / ".stride-gpt"
    monkeypatch.setattr(store, "DATA_DIR", data_dir)
    monkeypatch.setattr(store, "CONFIG_FILE", data_dir / "web_config.json")
    monkeypatch.setattr(store, "KEY_FILE", data_dir / "web_key")
    monkeypatch.setattr(store, "DB_FILE", data_dir / "web.db")
    return data_dir


# ---------------------------------------------------------------------------
# API Key
# ---------------------------------------------------------------------------


class TestApiKeys:
    def test_lifecycle(self, sandbox):
        key = store.create_api_key("CI")
        assert key.startswith(store.API_KEY_PREFIX)
        assert store.verify_api_key(key) == "CI"
        assert store.verify_api_key("wy_wrong") is None
        assert store.verify_api_key(None) is None

        rows = store.list_api_keys()
        assert [r["name"] for r in rows] == ["CI"]
        assert rows[0]["last_used_at"]  # 校验过一次会刷新

        store.revoke_api_key(rows[0]["id"])
        assert store.verify_api_key(key) is None
        assert store.list_api_keys() == []

    def test_keys_are_unique(self, sandbox):
        keys = {store.create_api_key(f"k{i}") for i in range(5)}
        assert len(keys) == 5


# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------


class TestConfig:
    def test_roundtrip_is_encrypted(self, sandbox):
        store.save_config({"model_provider": "Anthropic API", "anthropic_api_key": "sk-secret"})
        assert store.load_config() == {
            "model_provider": "Anthropic API",
            "anthropic_api_key": "sk-secret",
        }
        raw = store.CONFIG_FILE.read_bytes()
        assert b"sk-secret" not in raw  # Fernet 加密后不应出现明文

    def test_clear(self, sandbox):
        store.save_config({"model_provider": "OpenAI API"})
        store.clear_config()
        assert store.load_config() == {}
        assert store.config_saved_at() is None


# ---------------------------------------------------------------------------
# 会话令牌
# ---------------------------------------------------------------------------


class TestSessionToken:
    def test_roundtrip_and_tamper(self, sandbox):
        token = store.make_session_token("admin")
        assert store.verify_session_token(token) == "admin"
        # 篡改签名首字符（避免"末位恰好相同"的偶然通过）
        b64, sig = token.split(".", 1)
        tampered = f"{b64}.{'0' if sig[0] != '0' else '1'}{sig[1:]}"
        assert store.verify_session_token(tampered) is None
        assert store.verify_session_token("garbage") is None
        assert store.verify_session_token(None) is None


# ---------------------------------------------------------------------------
# Webhook
# ---------------------------------------------------------------------------


class TestWebhooks:
    def test_crud_and_payload_shapes(self, sandbox):
        wid = store.add_webhook("飞书群", "https://example.com/hook", "feishu")
        rows = store.list_webhooks()
        assert rows and rows[0]["id"] == wid and rows[0]["kind"] == "feishu"

        threats = [
            {
                "threat_type": "Spoofing",
                "scenario": "伪造令牌",
                "risk_score": 7.5,
                "status": "待处理",
                "owner": "张三",
            }
        ]
        feishu = store.threat_webhook_payload("feishu", "演示项目", threats)
        assert "msg_type" in feishu and "伪造令牌" in feishu["content"]["text"]
        wecom = store.threat_webhook_payload("wecom", "演示项目", threats)
        assert wecom["msgtype"] == "text"
        generic = store.threat_webhook_payload("generic", "演示项目", threats)
        assert generic["event"] == "threat_register.push"
        assert generic["threats"][0]["owner"] == "张三"

        store.delete_webhook(wid)
        assert store.list_webhooks() == []


# ---------------------------------------------------------------------------
# 归档 / 台账 / DREAD 回填
# ---------------------------------------------------------------------------


class TestArchive:
    def test_threat_extraction_and_dedup(self, sandbox):
        threats = [
            {"Threat Type": "Spoofing", "Scenario": "伪造令牌", "Potential Impact": "账户接管"},
            {"Threat Type": "Tampering", "Scenario": "篡改金额", "Potential Impact": "资金损失"},
        ]
        rid1 = generation.archive_result(
            "threat_model",
            "# 威胁模型\n",
            {"threat_model": threats},
            project="项目A",
            description="测试系统",
            provider="OpenAI API",
            model="gpt-6-astra",
        )
        assert rid1 > 0
        assert len(store.list_threats(project="项目A")) == 2

        # 再次归档相同内容：指纹去重，不新增
        generation.archive_result(
            "threat_model",
            "# 威胁模型\n",
            {"threat_model": threats},
            project="项目A",
        )
        assert len(store.list_threats(project="项目A")) == 2

    def test_dread_scores_backfilled(self, sandbox):
        generation.archive_result(
            "threat_model",
            "# tm\n",
            {"threat_model": [{"Threat Type": "Spoofing", "Scenario": "伪造令牌"}]},
            project="项目B",
        )
        generation.archive_result(
            "dread",
            "# dread\n",
            {
                "Risk Assessment": [
                    {
                        "Threat Type": "Spoofing",
                        "Scenario": "伪造令牌",
                        "Damage Potential": 10,
                        "Reproducibility": 8,
                        "Exploitability": 6,
                        "Affected Users": 4,
                        "Discoverability": 2,
                    }
                ]
            },
            project="项目B",
        )
        rows = store.list_threats(project="项目B")
        assert rows[0]["risk_score"] == 6.0

    def test_backfill_project_is_idempotent(self, sandbox):
        generation.archive_result(
            "threat_model",
            "# tm\n",
            {"threat_model": [{"Threat Type": "Spoofing", "Scenario": "X"}]},
            project="项目C",
        )
        assert store.backfill_project("项目C") == 0
        assert len(store.list_threats(project="项目C")) == 1

    def test_project_stats(self, sandbox):
        generation.archive_result(
            "threat_model",
            "# tm\n",
            {"threat_model": [{"Threat Type": "Spoofing", "Scenario": "X"}]},
            project="项目D",
        )
        stats = store.threat_stats("项目D")
        assert stats["total"] == 1
        assert stats["by_status"]["待处理"] == 1


# ---------------------------------------------------------------------------
# 草稿
# ---------------------------------------------------------------------------


class TestDrafts:
    def test_save_and_load(self, sandbox):
        store.save_draft("__default__", {"app_input": "描述"})
        assert store.load_draft("__default__") == {"app_input": "描述"}
        assert store.load_draft("missing") is None


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------


class TestSarif:
    def test_structure_and_levels(self):
        sarif = generation.threat_model_to_sarif(
            [
                {
                    "Threat Type": "Elevation of Privilege",
                    "Scenario": "越权",
                    "Potential Impact": "提权",
                    "OWASP_LLM": "LLM01",
                },
                {"Threat Type": "Repudiation", "Scenario": "抵赖"},
            ],
            project="演示",
            tool_version="0.20.0",
        )
        assert sarif["version"] == "2.1.0"
        run = sarif["runs"][0]
        level_by_rule = {r["ruleId"]: r["level"] for r in run["results"]}
        assert set(level_by_rule.values()) == {"error", "note"}
        assert run["results"][0]["properties"]["owasp_llm"] == "LLM01"
        assert run["tool"]["driver"]["version"] == "0.20.0"

    def test_empty_threats(self):
        sarif = generation.threat_model_to_sarif([], project="空")
        assert sarif["runs"][0]["results"] == []


# ---------------------------------------------------------------------------
# 提示词构造 / 设置解析
# ---------------------------------------------------------------------------


PROFILE = {
    "app_type": "Web application",
    "authentication": ["SSO"],
    "internet_facing": "Yes",
    "sensitive_data": "Confidential",
}


class TestPromptBuilding:
    @pytest.mark.parametrize("kind", generation.KINDS)
    def test_every_kind_builds_prompt(self, kind):
        prompt = generation.build_prompt(kind, PROFILE, "一个订单系统", "威胁模型 markdown")
        assert isinstance(prompt, str) and len(prompt) > 50

    def test_unknown_kind_raises(self):
        with pytest.raises(generation.GenerationError):
            generation.build_prompt("nope", PROFILE, "x")

    def test_dependent_kinds_need_threats(self):
        # 缓解措施提示词在缺少威胁内容时依然可构造（由调用方决定是否跳过）
        prompt = generation.build_prompt("mitigations", PROFILE, "x", "")
        assert isinstance(prompt, str)


class TestSettingsResolution:
    def test_saved_config_wins_over_defaults(self, sandbox, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        store.save_config(
            {
                "model_provider": "Anthropic API",
                "selected_model": "claude-sonnet-5",
                "anthropic_api_key": "sk-ant",
            }
        )
        settings = generation.resolve_model_settings()
        assert settings["provider"] == "Anthropic API"
        assert settings["model"] == "claude-sonnet-5"
        assert settings["api_key"] == "sk-ant"

    def test_overrides_take_precedence(self, sandbox):
        store.save_config({"model_provider": "Anthropic API", "selected_model": "claude-sonnet-5"})
        settings = generation.resolve_model_settings({"provider": "OpenAI API"})
        assert settings["provider"] == "OpenAI API"
        # 覆盖提供商后应回退到该提供商的默认模型
        assert settings["model"] in [m.model_id for m in generation.get_models_for_provider("OpenAI API")]

    def test_build_llm_config_requires_key_for_cloud(self, sandbox):
        settings = {"provider": "OpenAI API", "model": "gpt-6-astra", "api_key": ""}
        with pytest.raises(generation.GenerationError):
            generation.build_llm_config(settings)

    def test_build_llm_config_allows_keyless_local(self, sandbox):
        settings = {
            "provider": "LM Studio Server",
            "model": "local-model",
            "api_key": "",
            "api_base": "http://localhost:1234",
        }
        config = generation.build_llm_config(settings)
        assert config.provider == "LM Studio Server"
        assert config.api_base == "http://localhost:1234"


# ---------------------------------------------------------------------------
# 全流程编排（用假生成器替换模型调用）
# ---------------------------------------------------------------------------


class TestPipeline:
    def test_full_pipeline_archives_all_steps(self, sandbox, monkeypatch):
        calls = []

        def fake_generation(kind, prompt, settings):
            calls.append(kind)
            if kind == "threat_model":
                data = {"threat_model": [{"Threat Type": "Spoofing", "Scenario": "S"}]}
                return generation.json_to_markdown(data["threat_model"], []), data
            if kind == "dread":
                return "# dread", {"Risk Assessment": []}
            return f"# {kind}", None

        monkeypatch.setattr(generation, "run_generation", fake_generation)
        results = generation.run_full_pipeline(
            description="测试",
            profile={"app_type": "Web application"},
            project="流水线项目",
            settings={"provider": "OpenAI API", "model": "gpt-6-astra", "api_key": "x"},
        )
        assert calls == generation.KINDS
        assert all(item["ok"] for item in results)
        assert len(store.list_reports(project="流水线项目")) == len(generation.KINDS)
        assert len(store.list_threats(project="流水线项目")) == 1

    def test_dependent_steps_skipped_without_threat_model(self, sandbox, monkeypatch):
        def failing_generation(kind, prompt, settings):
            if kind == "threat_model":
                raise RuntimeError("模型挂了")
            return f"# {kind}", None

        monkeypatch.setattr(generation, "run_generation", failing_generation)
        results = generation.run_full_pipeline(
            description="测试",
            profile={},
            project="失败项目",
            settings={"provider": "OpenAI API", "model": "gpt-6-astra", "api_key": "x"},
        )
        by_kind = {r["kind"]: r for r in results}
        assert by_kind["threat_model"]["ok"] is False
        assert by_kind["mitigations"].get("skipped") is True
        assert by_kind["dfd"]["ok"] is True  # 不依赖威胁模型的步骤继续执行


def test_json_helpers_roundtrip():
    md = generation.json_to_markdown(
        [{"Threat Type": "Spoofing", "Scenario": "S", "Potential Impact": "I"}], ["建议"]
    )
    assert "Spoofing" in md and "建议" in md
    dread = generation.dread_json_to_markdown(
        {"Risk Assessment": [{"Threat Type": "Spoofing", "Scenario": "S"}]}
    )
    assert "风险评分" in dread and "Spoofing" in dread


def test_pipeline_serialises_json_as_text(sandbox):
    generation.archive_result(
        "threat_model",
        "# tm",
        {"threat_model": [{"Threat Type": "Spoofing", "Scenario": "S"}]},
        project="序列化项目",
    )
    row = store.list_reports(project="序列化项目")[0]
    assert json.loads(row["content_json"])["threat_model"][0]["Scenario"] == "S"
