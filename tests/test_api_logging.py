"""P7 测试：API 请求追踪、访问日志与未处理异常响应。"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "apps"))

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture()
def api_client(tmp_path, monkeypatch):
    from common import logging_setup
    from common import store as store_module

    data_dir = tmp_path / "api-data"
    data_dir.mkdir()
    for name, value in [
        ("DATA_DIR", data_dir),
        ("CONFIG_FILE", data_dir / "web_config.json"),
        ("KEY_FILE", data_dir / "web_key"),
        ("DB_FILE", data_dir / "web.db"),
    ]:
        monkeypatch.setattr(store_module, name, value)

    log_dir = tmp_path / "logs"
    module = importlib.import_module("api.main")
    logging_setup.setup("api", log_dir_path=log_dir)

    client = TestClient(module.app, raise_server_exceptions=False)
    return client, module, log_dir


def _rows(log_dir: Path) -> list[dict]:
    path = log_dir / "api.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


class TestRequestTracing:
    def test_health_returns_request_id_and_logs(self, api_client):
        client, _, log_dir = api_client
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        trace = response.headers.get("x-request-id")
        assert trace and trace.startswith("api-")
        access = [row for row in _rows(log_dir) if row.get("msg") == "请求完成"]
        assert access, "应有访问日志"
        assert access[-1]["status"] == 200
        assert access[-1]["trace"] == trace
        assert access[-1]["path"] == "/api/v1/health"
        assert "ms" in access[-1]

    def test_incoming_request_id_is_kept(self, api_client):
        client, _, _ = api_client
        response = client.get("/api/v1/health", headers={"X-Request-ID": "caller-trace-42"})
        assert response.headers.get("x-request-id") == "caller-trace-42"

    def test_error_status_is_logged_as_warning(self, api_client):
        client, _, log_dir = api_client
        response = client.get("/api/v1/reports/999999")  # 无 API Key -> 401
        assert response.status_code == 401
        rows = [row for row in _rows(log_dir) if row.get("msg") == "请求完成"]
        hit = [row for row in rows if row["path"] == "/api/v1/reports/999999"]
        assert hit and hit[-1]["status"] == 401
        assert hit[-1]["level"] == "WARNING"


class TestUnhandledException:
    def test_returns_error_id_without_traceback(self, api_client):
        client, module, log_dir = api_client
        if not any(getattr(route, "path", "") == "/api/v1/_boom" for route in module.app.routes):

            @module.app.get("/api/v1/_boom")
            def _boom():
                raise RuntimeError("注入故障")

        response = client.get("/api/v1/_boom")
        assert response.status_code == 500
        body = response.json()
        assert body["error"] == "internal_error"
        assert body["error_id"].startswith("ERR-")
        assert "RuntimeError" not in json.dumps(body)  # 不外泄堆栈

        hits = [row for row in _rows(log_dir) if row.get("error_id") == body["error_id"]]
        assert hits, "异常应带 error_id 写入日志"
        assert "RuntimeError" in hits[0]["exc"]
        assert hits[0]["path"] == "/api/v1/_boom"
