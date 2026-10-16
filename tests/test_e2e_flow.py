"""P9-4 端到端流程测试：模型生成 → 归档入库 → 标准导出 → 备份恢复。

不依赖外部服务：使用进程内 mock LLM（OpenAI 兼容）与临时数据目录。
覆盖「配好 Key 后用户实际会走一遍」的主链路。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "apps"))
sys.path.insert(0, str(ROOT / "tests"))

from common import backup, generation, interop, standards, store, usage  # noqa: E402
from support_mock_llm import MockLLM  # noqa: E402


@pytest.fixture()
def env(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    for name, value in [
        ("DATA_DIR", data_dir),
        ("CONFIG_FILE", data_dir / "web_config.json"),
        ("KEY_FILE", data_dir / "web_key"),
        ("DB_FILE", data_dir / "web.db"),
    ]:
        monkeypatch.setattr(store, name, value)
    store.init_db()
    # 用量记录器在 pytest 环境下默认跳过（避免污染真实库）；这里库是沙箱的，
    # 换成一个不跳过、但只写沙箱库的版本，以验证「模型调用 → 用量归因」整条链路。
    def _record(config, response):
        ctx = usage.current_context()
        prompt = getattr(response, "prompt_tokens", None)
        completion = getattr(response, "completion_tokens", None)
        store.log_usage(
            actor=ctx["actor"],
            source=ctx["source"],
            provider=getattr(config, "provider", "") or "",
            model=getattr(config, "model_name", "") or "",
            kind="",
            project=ctx["project"],
            prompt_tokens=prompt,
            completion_tokens=completion,
            cost=usage.estimate_cost(getattr(config, "model_name", ""), prompt, completion),
        )

    monkeypatch.setattr(usage, "record_from_response", _record)
    usage.set_call_context(actor="admin", source="test", project="订单系统")
    with MockLLM() as mock:
        store.save_config(
            {
                "model_provider": "LM Studio Server",
                "lm_studio_endpoint": mock.base_url,
                "selected_model": "mock-model",
            }
        )
        yield mock, data_dir


DESCRIPTION = "订单系统：客户下单、支付、运营后台审核；互联网可达，存手机号与支付信息。"


def _generate_and_archive(kind: str, **kw) -> tuple[dict | None, int]:
    settings = generation.resolve_model_settings()
    prompt = generation.build_prompt(kind, {"app_type": "Web application"}, DESCRIPTION, kw.pop("threats_md", ""))
    md, payload = generation.run_generation(kind, prompt, settings)
    report_id = generation.archive_result(
        kind,
        md,
        payload,
        project="订单系统",
        description=DESCRIPTION,
        provider=settings.get("provider", ""),
        model=settings.get("model", ""),
    )
    return payload, report_id


class TestThreatModelFlow:
    def test_generate_archive_and_query(self, env):
        payload, report_id = _generate_and_archive("threat_model")
        assert payload and len(payload["threat_model"]) == 4

        threats = store.list_threats(project="订单系统")
        assert len(threats) == 4
        assert {t["threat_type"] for t in threats} >= {"Spoofing", "Tampering"}
        assert all(threat["cwe"] for t in threats for threat in [t]), "应自动关联 CWE"
        assert threats[0]["report_id"] == report_id

        reports = store.list_reports(project="订单系统")
        assert [r["kind"] for r in reports] == ["threat_model"]

        # 用量也被记录（含来源与项目）
        summary = store.usage_summary()
        assert summary["totals"]["calls"] >= 1
        assert "订单系统" in summary["groups"]["project"]

    def test_register_workflow(self, env):
        _generate_and_archive("threat_model")
        threats = store.list_threats(project="订单系统")
        target = threats[0]
        store.update_threats(
            [
                {
                    "id": target["id"],
                    "status": "已确认",
                    "owner": "alice",
                    "note": "已安排修复",
                }
            ]
        )
        updated = next(t for t in store.list_threats(project="订单系统") if t["id"] == target["id"])
        assert updated["status"] == "已确认"
        assert updated["owner"] == "alice"
        stats = store.threat_stats("订单系统")
        assert stats["by_status"]["已确认"] == 1

    def test_dread_scores_written_back(self, env):
        _generate_and_archive("threat_model")
        _generate_and_archive("dread")
        scored = [t for t in store.list_threats(project="订单系统") if t["risk_score"] is not None]
        assert scored, "DREAD 评分应回填到台账"
        assert max(float(t["risk_score"]) for t in scored) > 0


class TestExports:
    def test_sarif_stix_and_threat_dragon(self, env):
        payload, _ = _generate_and_archive("threat_model")
        threats = payload["threat_model"]

        sarif = generation.threat_model_to_sarif(threats, project="订单系统")
        assert sarif["version"] == "2.1.0"
        assert sarif["runs"][0]["results"], "SARIF 应包含结果"
        assert any("cwe" in (r.get("properties") or {}) for r in sarif["runs"][0]["results"])

        stix = standards.threats_to_stix(threats, project="订单系统")
        assert [o["type"] for o in stix["objects"]].count("vulnerability") == 4
        report = next(o for o in stix["objects"] if o["type"] == "report")
        assert len(report["object_refs"]) == 4

        dragon = interop.to_threat_dragon("订单系统", threats)
        assert dragon["version"] == "2.0.0"
        assert len(dragon["threats"]) == 4
        # 往返：导出的模型可再导入为分析输入
        text = interop.from_threat_dragon(dragon)
        assert "订单系统" in text and "会话 Cookie" in text

    def test_report_bundle_export(self, env):
        _generate_and_archive("threat_model")
        report = store.list_reports(project="订单系统")[0]
        bundle = store.export_zip([report])
        assert bundle[:2] == b"PK"
        html = store.report_to_html(report)
        assert "订单系统" in html


class TestBackupRestoreFlow:
    def test_full_cycle(self, env):
        _generate_and_archive("threat_model")
        _, data_dir = env
        snapshot = backup.create_backup(out_dir=data_dir / "backups")
        assert backup.verify_backup(snapshot)["files"]

        before = len(store.list_threats(project="订单系统"))
        with store._conn() as conn:
            conn.execute("DELETE FROM threats")
        assert store.list_threats(project="订单系统") == []

        result = backup.restore_backup(snapshot, keep_pre_restore=False)
        assert result["ok"] and "web.db" in result["restored"]
        assert len(store.list_threats(project="订单系统")) == before
        assert store.load_config().get("sample") is None  # 配置仍在
        assert store.load_config().get("model_provider") == "LM Studio Server"


class TestFullPipeline:
    def test_generates_all_kinds(self, env):
        from common import usage

        settings = generation.resolve_model_settings()
        results = generation.run_full_pipeline(
            description=DESCRIPTION,
            profile={"app_type": "Web application"},
            project="订单系统",
            settings=settings,
        )
        assert all(item["ok"] for item in results), results
        kinds = {r["kind"] for r in results}
        assert kinds == {"threat_model", "dfd", "attack_tree", "mitigations", "dread", "test_cases"}
        assert usage.budget_status()["calls"] >= len(results)
        # 六类产物都归档了
        archived = {r["kind"] for r in store.list_reports(project="订单系统")}
        assert archived == kinds
