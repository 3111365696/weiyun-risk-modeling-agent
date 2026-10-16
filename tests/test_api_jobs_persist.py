"""P7 测试：代码审计任务持久化（重启恢复 / 取消 / 重跑 / 令牌不落库）。"""

from __future__ import annotations

import importlib
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "apps"))

from common import agentic, store  # noqa: E402


@pytest.fixture()
def api(tmp_path, monkeypatch):
    data_dir = tmp_path / "api-data"
    data_dir.mkdir()
    for name, value in [
        ("DATA_DIR", data_dir),
        ("CONFIG_FILE", data_dir / "web_config.json"),
        ("KEY_FILE", data_dir / "web_key"),
        ("DB_FILE", data_dir / "web.db"),
    ]:
        monkeypatch.setattr(store, name, value)
    module = importlib.import_module("api.main")
    store.init_db()
    return module


def _wait_done(job_id: str, timeout: float = 8.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = store.get_job(job_id)
        if job and job["status"] not in ("queued", "running"):
            return job
        time.sleep(0.05)
    raise AssertionError(f"任务超时未结束：{store.get_job(job_id)}")


def _job_kwargs(**overrides):
    """_start_job 的关键字参数模板。"""
    base = {
        "source": "zip",
        "project": "API代码库",
        "description": "",
        "api_key_name": "CI",
        "worker_model": None,
        "architect_model": None,
        "max_llm_calls": 10,
        "max_tool_calls": 10,
        "zip_bytes": b"PK zip bytes",
    }
    base.update(overrides)
    return base


def _mock_audit(data, **kwargs):
    """假的审计实现：发一条进度事件后成功返回。"""
    if kwargs.get("on_event"):
        kwargs["on_event"]("phase", {"phase": "分析"})
    return {
        "report_id": 7,
        "threats_inserted": 3,
        "threats_total": 4,
        "status": "completed",
        "markdown": "# 报告",
        "scanner_summary": {"total": 0},
    }


class TestJobPersistence:
    def test_job_written_to_db(self, api, monkeypatch):
        monkeypatch.setattr(api.agentic, "build_model_pair", lambda **kw: "models")
        monkeypatch.setattr(api.agentic, "audit_zip", _mock_audit)

        job_id = api._start_job(**_job_kwargs())
        job = _wait_done(job_id)
        assert job["status"] == "done"
        assert job["result"]["report_id"] == 7
        assert job["params"]["max_llm_calls"] == 10
        assert job["progress"], "进度事件应写库"
        assert store.get_job(job_id)["status"] == "done"

    def test_artifact_saved_for_retry(self, api, monkeypatch):
        monkeypatch.setattr(api.agentic, "build_model_pair", lambda **kw: "models")
        monkeypatch.setattr(api.agentic, "audit_zip", _mock_audit)
        job_id = api._start_job(**_job_kwargs())
        _wait_done(job_id)
        artifact = Path(store.get_job(job_id)["artifact"])
        assert artifact.exists() and artifact.name == f"{job_id}.zip"
        assert artifact.read_bytes() == b"PK zip bytes"

    def test_job_readable_after_process_reload(self, api, monkeypatch):
        monkeypatch.setattr(api.agentic, "build_model_pair", lambda **kw: "models")
        monkeypatch.setattr(api.agentic, "audit_zip", _mock_audit)
        job_id = api._start_job(**_job_kwargs())
        _wait_done(job_id)

        reloaded = importlib.reload(api)  # 模拟服务重启
        monkeypatch.setattr(reloaded.agentic, "build_model_pair", lambda **kw: "models")
        monkeypatch.setattr(reloaded.agentic, "audit_zip", _mock_audit)
        job = reloaded.api_code_audit_job(job_id, api_key_name="CI")
        assert job["job_id"] == job_id
        assert job["status"] == "done"

    def test_token_never_persisted(self, api, monkeypatch):
        seen: dict = {}

        def _capture_repo(repo_url, token=None, **kwargs):
            seen["token"] = token
            return _mock_audit(None, **kwargs)

        monkeypatch.setattr(api.agentic, "build_model_pair", lambda **kw: "models")
        monkeypatch.setattr(api.agentic, "audit_repo", _capture_repo)
        job_id = api._start_job(**_job_kwargs(source="repo", zip_bytes=None, token="ghp_supersecret"))
        _wait_done(job_id)  # 等线程结束，避免用例结束后仍在写库
        assert seen["token"] == "ghp_supersecret", "令牌应经内存传给克隆流程"
        raw = str(store.get_job(job_id))
        assert "ghp_supersecret" not in raw, "令牌绝不能落库"
        assert api._TOKENS.get(job_id) is None, "用后即清"


class TestInterruptedRecovery:
    def test_running_jobs_marked_interrupted(self, api):
        store.create_job("job-running", project="p", source="repo", params={})
        store.job_set_running("job-running")
        store.create_job("job-queued", project="p", source="repo", params={})
        assert store.recover_interrupted_jobs() == 2
        assert store.get_job("job-running")["status"] == "interrupted"
        assert "可重跑" in store.get_job("job-queued")["error"]

    def test_recovery_is_idempotent(self, api):
        store.create_job("job-1", project="p", source="repo", params={})
        store.recover_interrupted_jobs()
        assert store.recover_interrupted_jobs() == 0

    def test_lifespan_runs_recovery(self, api):
        store.create_job("job-lifespan", project="p", source="repo", params={})
        store.job_set_running("job-lifespan")
        api._recover_jobs()
        assert store.get_job("job-lifespan")["status"] == "interrupted"


class TestCancelAndRetry:
    def test_cancel_running_job(self, api, monkeypatch):
        monkeypatch.setattr(api.agentic, "build_model_pair", lambda **kw: "models")

        def _slow(data, **kwargs):
            for _ in range(200):
                if kwargs["cancel_check"]():
                    raise agentic.AgenticCancelledError("任务已取消")
                time.sleep(0.02)
            raise AssertionError("未被取消")

        monkeypatch.setattr(api.agentic, "audit_zip", _slow)
        job_id = api._start_job(**_job_kwargs())
        time.sleep(0.1)
        result = api.api_code_audit_cancel(job_id, api_key_name="CI")
        assert result["status"] == "cancelling"
        job = _wait_done(job_id)
        assert job["status"] == "cancelled"

    def test_retry_failed_job(self, api, monkeypatch):
        monkeypatch.setattr(api.agentic, "build_model_pair", lambda **kw: "models")

        def _boom(data, **kwargs):
            raise RuntimeError("模型挂了")

        monkeypatch.setattr(api.agentic, "audit_zip", _boom)
        job_id = api._start_job(**_job_kwargs())
        failed = _wait_done(job_id)
        assert failed["status"] == "failed"

        monkeypatch.setattr(api.agentic, "audit_zip", _mock_audit)
        response = api.api_code_audit_retry(job_id, api_key_name="CI")
        assert response["retry_of"] == job_id
        retried = _wait_done(response["job_id"])
        assert retried["status"] == "done"
        assert retried["project"] == "API代码库"
        assert Path(retried["artifact"]).exists(), "重跑应复制上传产物"

    def test_retry_rejects_running_job(self, api, monkeypatch):
        from fastapi import HTTPException

        store.create_job("job-live", project="p", source="repo", params={})
        store.job_set_running("job-live")
        with pytest.raises(HTTPException) as excinfo:
            api.api_code_audit_retry("job-live", api_key_name="CI")
        assert excinfo.value.status_code == 409

    def test_retry_missing_artifact_410(self, api, monkeypatch):
        from fastapi import HTTPException

        monkeypatch.setattr(api.agentic, "build_model_pair", lambda **kw: "models")
        monkeypatch.setattr(api.agentic, "audit_zip", _mock_audit)
        job_id = api._start_job(**_job_kwargs())
        _wait_done(job_id)
        Path(store.get_job(job_id)["artifact"]).unlink()
        with pytest.raises(HTTPException) as excinfo:
            api.api_code_audit_retry(job_id, api_key_name="CI")
        assert excinfo.value.status_code == 410

    def test_delete_finished_job(self, api, monkeypatch):
        monkeypatch.setattr(api.agentic, "build_model_pair", lambda **kw: "models")
        monkeypatch.setattr(api.agentic, "audit_zip", _mock_audit)
        job_id = api._start_job(**_job_kwargs())
        _wait_done(job_id)
        artifact = Path(store.get_job(job_id)["artifact"])
        assert api.api_code_audit_cancel(job_id, api_key_name="CI")["status"] == "deleted"
        assert store.get_job(job_id) is None
        assert not artifact.exists(), "删除任务应清理上传产物"

    def test_jobs_list_persisted(self, api, monkeypatch):
        monkeypatch.setattr(api.agentic, "build_model_pair", lambda **kw: "models")
        monkeypatch.setattr(api.agentic, "audit_zip", _mock_audit)
        job_id = api._start_job(**_job_kwargs())
        _wait_done(job_id)
        listing = api.api_code_audit_jobs(api_key_name="CI")
        assert listing["count"] >= 1
        assert any(item["job_id"] == job_id for item in listing["jobs"])
        assert "progress" not in listing["jobs"][0]

    def test_prune_keeps_recent(self, api):
        for index in range(5):
            store.create_job(f"keep-{index}", project="p", source="repo", params={})
            store.job_finish(f"keep-{index}", "done")
        assert store.prune_jobs(keep=3) == 2
        remaining = {job["job_id"] for job in store.list_jobs(limit=10)}
        assert len(remaining) == 3
