"""P6 测试：代码审计（安全解压 / 仓库校验 / 报告归档 / API 任务）。"""

from __future__ import annotations

import io
import json
import sys
import time
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "apps"))

from common import agentic, store


@pytest.fixture()
def sandbox(tmp_path, monkeypatch):
    data_dir = tmp_path / ".stride-gpt"
    monkeypatch.setattr(store, "DATA_DIR", data_dir)
    monkeypatch.setattr(store, "CONFIG_FILE", data_dir / "web_config.json")
    monkeypatch.setattr(store, "KEY_FILE", data_dir / "web_key")
    monkeypatch.setattr(store, "DB_FILE", data_dir / "web.db")
    return data_dir


def _zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# ZIP 解压安全
# ---------------------------------------------------------------------------


class TestExtractZip:
    def test_extracts_and_detects_single_root(self, sandbox):
        dest = agentic.new_workspace("t")
        root = agentic.extract_zip(_zip({"app/main.py": "x=1", "app/auth.py": "y=2"}), dest)
        assert root.name == "app"
        assert sorted(p.name for p in root.glob("*.py")) == ["auth.py", "main.py"]

    def test_keeps_flat_layout(self, sandbox):
        dest = agentic.new_workspace("t")
        root = agentic.extract_zip(_zip({"main.py": "x=1", "readme.txt": "hi"}), dest)
        assert root == dest
        assert (root / "main.py").exists()

    def test_rejects_path_traversal(self, sandbox):
        with pytest.raises(agentic.AgenticError, match="非法路径"):
            agentic.extract_zip(_zip({"../evil.py": "x"}), agentic.new_workspace("t"))

    def test_rejects_absolute_path(self, sandbox):
        with pytest.raises(agentic.AgenticError, match="非法路径"):
            agentic.extract_zip(_zip({"/etc/passwd": "x"}), agentic.new_workspace("t"))

    def test_rejects_empty_zip(self, sandbox):
        with pytest.raises(agentic.AgenticError):
            agentic.extract_zip(_zip({}), agentic.new_workspace("t"))

    def test_rejects_non_zip(self, sandbox):
        with pytest.raises(agentic.AgenticError, match="不是有效的 ZIP"):
            agentic.extract_zip(b"not a zip at all", agentic.new_workspace("t"))


# ---------------------------------------------------------------------------
# Git 地址校验
# ---------------------------------------------------------------------------


class TestRepoUrl:
    def test_accepts_allowlisted_https(self):
        assert agentic.validate_repo_url("https://github.com/a/b") == "github.com"
        assert agentic.validate_repo_url("https://gitlab.com/a/b.git") == "gitlab.com"

    def test_rejects_http_and_other_hosts(self):
        with pytest.raises(agentic.AgenticError, match="https"):
            agentic.validate_repo_url("http://github.com/a/b")
        with pytest.raises(agentic.AgenticError, match="白名单"):
            agentic.validate_repo_url("https://evil.example.com/a/b")
        with pytest.raises(agentic.AgenticError, match="https"):
            agentic.validate_repo_url("git@github.com:a/b.git")

    def test_env_extends_allowlist(self, monkeypatch):
        monkeypatch.setenv("STRIDE_GPT_GIT_HOSTS", "git.internal.example")
        assert agentic.validate_repo_url("https://git.internal.example/team/repo") == (
            "git.internal.example"
        )

    def test_missing_path_rejected(self):
        with pytest.raises(agentic.AgenticError):
            agentic.validate_repo_url("https://github.com")


# ---------------------------------------------------------------------------
# 报告归档
# ---------------------------------------------------------------------------


def _fake_report():
    from stride_gpt.core.schemas import AnalysisPlan, AnalysisReport, Subsystem, SubsystemFinding

    threats = [
        {
            "Threat Type": "Spoofing",
            "Scenario": "JWT 校验被禁用",
            "Potential Impact": "账户接管",
            "evidence": [
                {"path": "app/auth.py", "snippet": "verify_signature=False", "verified": True}
            ],
        },
        {
            "Threat Type": "Elevation of Privilege",
            "Scenario": "管理员接口缺角色校验",
            "Potential Impact": "越权",
        },
    ]
    return AnalysisReport(
        plan=AnalysisPlan(
            target_path="/tmp/repo",
            overall_description="演示服务",
            subsystems=[
                Subsystem(
                    name="认证与授权",
                    description="登录与权限",
                    key_files=["app/auth.py"],
                    focus_areas=["认证绕过"],
                )
            ],
        ),
        findings=[SubsystemFinding(subsystem="认证与授权", threats=threats, files_analyzed=["app/auth.py"])],
        metadata={
            "worker_model": "gpt-6-astra",
            "worker_provider": "OpenAI API",
            "run_summary": {"status": "completed"},
        },
    )


class TestArchiveReport:
    def test_archives_with_evidence_and_sarif(self, sandbox):
        result = agentic.archive_report(_fake_report(), project="代码库A", description="演示服务")
        assert result["report_id"] > 0
        assert result["threats_inserted"] == 2
        assert result["threats_total"] == 2
        assert result["status"] == "completed"

        report = store.get_report(result["report_id"])
        assert report["kind"] == "code_analysis"
        assert store.KIND_LABELS["code_analysis"] in report["title"]

        rows = {t["scenario"]: t for t in store.list_threats(project="代码库A")}
        assert rows["JWT 校验被禁用"]["subsystem"] == "认证与授权"
        assert rows["JWT 校验被禁用"]["source"] == "agentic"
        evidence = json.loads(rows["JWT 校验被禁用"]["evidence"])
        assert evidence[0]["path"] == "app/auth.py"

        assert result["sarif"]["version"] == "2.1.0"
        assert len(result["sarif"]["runs"][0]["results"]) == 2
        assert "认证与授权" in result["markdown"]

    def test_rearchive_dedupes_threats(self, sandbox):
        agentic.archive_report(_fake_report(), project="代码库B")
        agentic.archive_report(_fake_report(), project="代码库B")
        assert len(store.list_threats(project="代码库B")) == 2
        assert len(store.list_reports(project="代码库B")) == 2  # 报告仍保留两份


# ---------------------------------------------------------------------------
# 模型配置
# ---------------------------------------------------------------------------


class TestModelPair:
    def test_uses_saved_config(self, sandbox):
        store.save_config(
            {
                "model_provider": "Anthropic API",
                "selected_model": "claude-sonnet-5",
                "anthropic_api_key": "sk-ant",
            }
        )
        pair = agentic.build_model_pair()
        assert pair.worker.provider == "Anthropic API"
        assert pair.worker.model_name == "claude-sonnet-5"
        assert pair.architect is None

    def test_overrides(self, sandbox):
        store.save_config(
            {
                "model_provider": "Anthropic API",
                "selected_model": "claude-sonnet-5",
                "anthropic_api_key": "sk-ant",
            }
        )
        pair = agentic.build_model_pair(worker_model="claude-haiku-4-5", architect_model="claude-opus-5-5")
        assert pair.worker.model_name == "claude-haiku-4-5"
        assert pair.for_architect().model_name == "claude-opus-5-5"


# ---------------------------------------------------------------------------
# 进度适配器
# ---------------------------------------------------------------------------


class TestProgressAdapter:
    def test_emits_and_cancels(self):
        events = []
        progress = agentic._EventProgress(on_event=lambda k, p: events.append((k, p)))
        progress.phase_start("Phase 1", "Planning")
        progress.subsystem_done("认证", 2, "completed")
        progress.token_budget("m", 1000, "queried")
        progress.synthesis_done(3)
        progress.no_tool_use_warning("认证")
        progress.complete("done")
        assert [k for k, _ in events] == [
            "phase",
            "subsystem_done",
            "token_budget",
            "synthesis_done",
            "no_tool_use",
            "complete",
        ]

        cancel = agentic._EventProgress(cancel_check=lambda: True)
        with pytest.raises(agentic.AgenticCancelledError):
            cancel.status("x")


# ---------------------------------------------------------------------------
# API 任务注册表
# ---------------------------------------------------------------------------


class TestApiJobs:

    def _load_api(self):
        import importlib

        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "apps"))
        return importlib.import_module("api.main")

    def test_start_job_success(self, sandbox, monkeypatch):
        api = self._load_api()
        monkeypatch.setattr(api.agentic, "build_model_pair", lambda **kw: "models")
        monkeypatch.setattr(
            api.agentic,
            "audit_zip",
            lambda data, **kwargs: {
                "report_id": 7,
                "threats_inserted": 3,
                "threats_total": 4,
                "status": "completed",
                "markdown": "# 报告",
            },
        )
        job_id = api._start_job(
            source="zip",
            project="API代码库",
            description="",
            api_key_name="CI",
            worker_model=None,
            architect_model=None,
            max_llm_calls=10,
            max_tool_calls=10,
            zip_bytes=b"zip",
        )
        for _ in range(100):
            if (store.get_job(job_id) or {}).get("status") not in ("queued", "running"):
                break
            time.sleep(0.05)
        job = api._job_public(store.get_job(job_id))
        assert job["status"] == "done"
        assert job["result"]["report_id"] == 7

    def test_start_job_failure(self, sandbox, monkeypatch):
        api = self._load_api()
        monkeypatch.setattr(api.agentic, "build_model_pair", lambda **kw: "models")

        def _boom(data, **kwargs):
            raise RuntimeError("模型挂了")

        monkeypatch.setattr(api.agentic, "audit_zip", _boom)
        job_id = api._start_job(
            source="zip",
            project="API代码库",
            description="",
            api_key_name="CI",
            worker_model=None,
            architect_model=None,
            max_llm_calls=10,
            max_tool_calls=10,
            zip_bytes=b"zip",
        )
        for _ in range(100):
            if (store.get_job(job_id) or {}).get("status") not in ("queued", "running"):
                break
            time.sleep(0.05)
        job = api._job_public(store.get_job(job_id))
        assert job["status"] == "failed"
        assert "模型挂了" in job["error"]
