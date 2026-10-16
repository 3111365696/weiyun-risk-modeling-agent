"""P8-2 测试：API Key 作用域 / 有效期 / 轮换 / 接口强制。"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "apps"))

from common import store  # noqa: E402


@pytest.fixture()
def store_sandbox(tmp_path, monkeypatch):
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
    return store


class TestKeyLifecycle:
    def test_scopes_normalized(self, store_sandbox):
        assert store.normalize_scopes(["write"]) == "write"
        assert store.normalize_scopes("read,write") == "read,write"
        assert store.normalize_scopes("write,read,write") == "read,write"
        assert store.normalize_scopes("unknown") == "read,write"  # 非法输入回退为全量

    def test_create_with_metadata(self, store_sandbox):
        plain = store.create_api_key(
            "CI", scopes=["read"], expires_days=30, owner="admin"
        )
        info = store.verify_api_key_full(plain)
        assert info["name"] == "CI"
        assert info["scopes"] == "read"
        assert info["owner"] == "admin"
        assert info["expires_at"]

    def test_verify_unknown_key(self, store_sandbox):
        assert store.verify_api_key_full("wy-nonexistent") is None
        assert store.verify_api_key_full(None) is None

    def test_expired_key_rejected(self, store_sandbox):
        plain = store.create_api_key("old", expires_days=1)
        with store._conn() as conn:
            conn.execute(
                "UPDATE api_keys SET expires_at='2020-01-01 00:00:00' WHERE name='old'"
            )
        assert store.verify_api_key_full(plain) is None
        assert store.verify_api_key(plain) is None
        assert store.list_api_keys()[0]["expired"] is True

    def test_no_expiry_key_lists_as_such(self, store_sandbox):
        store.create_api_key("forever")
        assert store.list_api_keys()[0]["expires_at"] == ""
        assert store.list_api_keys()[0]["expired"] is False

    def test_rotate_replaces_key_and_keeps_metadata(self, store_sandbox):
        plain = store.create_api_key("CI", scopes=["read"], expires_days=30, owner="admin")
        old_info = store.verify_api_key_full(plain)
        store.set_api_key_quota(old_info["id"], 1000, 5.0)

        rotated = store.rotate_api_key(old_info["id"])
        assert rotated and rotated != plain
        assert store.verify_api_key_full(plain) is None, "旧密钥必须立即失效"
        new_info = store.verify_api_key_full(rotated)
        assert new_info["name"] == "CI"
        assert new_info["scopes"] == "read"
        assert new_info["owner"] == "admin"
        assert new_info["expires_at"] == old_info["expires_at"]
        row = store.list_api_keys()[0]
        assert row["daily_token_limit"] == 1000
        assert row["monthly_cost_limit"] == 5.0

    def test_rotate_missing_key(self, store_sandbox):
        assert store.rotate_api_key(9999) is None


@pytest.fixture()
def api_client(tmp_path, monkeypatch, store_sandbox):
    from fastapi.testclient import TestClient

    module = importlib.import_module("api.main")
    client = TestClient(module.app, raise_server_exceptions=False)
    return client, module


class TestApiScopeEnforcement:
    def test_read_only_key_can_get(self, api_client):
        client, _ = api_client
        plain = store.create_api_key("reader", scopes=["read"])
        response = client.get("/api/v1/config", headers={"X-API-Key": plain})
        assert response.status_code == 200, response.text

    def test_read_only_key_cannot_write(self, api_client):
        client, _ = api_client
        plain = store.create_api_key("reader", scopes=["read"])
        response = client.patch(
            "/api/v1/threats/1", json={"status": "已确认"}, headers={"X-API-Key": plain}
        )
        assert response.status_code == 403
        assert "只读" in response.json()["detail"]

    def test_write_key_passes_gate(self, api_client):
        client, _ = api_client
        plain = store.create_api_key("writer", scopes=["read", "write"])
        response = client.patch(
            "/api/v1/threats/1", json={"status": "已确认"}, headers={"X-API-Key": plain}
        )
        assert response.status_code == 404, "写作用域应放行到业务层（此处威胁不存在）"

    def test_expired_key_401(self, api_client):
        client, _ = api_client
        plain = store.create_api_key("expired", expires_days=1)
        with store._conn() as conn:
            conn.execute("UPDATE api_keys SET expires_at='2020-01-01 00:00:00'")
        response = client.get("/api/v1/config", headers={"X-API-Key": plain})
        assert response.status_code == 401

    def test_rotated_key_401_old_works(self, api_client):
        client, _ = api_client
        old = store.create_api_key("rot", scopes=["read", "write"])
        info = store.verify_api_key_full(old)
        new = store.rotate_api_key(info["id"])
        assert client.get("/api/v1/config", headers={"X-API-Key": old}).status_code == 401
        assert client.get("/api/v1/config", headers={"X-API-Key": new}).status_code == 200

    def test_health_needs_no_key(self, api_client):
        client, _ = api_client
        assert client.get("/api/v1/health").status_code == 200
