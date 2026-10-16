"""P7 测试：系统状态页（渲染 / 组件健康 / 备份入口 / 权限）。"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "apps"))
sys.path.insert(0, str(ROOT / "apps" / "web"))

streamlit = pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

MAIN = str(ROOT / "apps" / "web" / "main.py")


@pytest.fixture()
def sandboxed_store(tmp_path, monkeypatch):
    from common import store as store_module

    data_dir = tmp_path / "web-data"
    data_dir.mkdir()
    monkeypatch.setattr(store_module, "DATA_DIR", data_dir)
    monkeypatch.setattr(store_module, "CONFIG_FILE", data_dir / "web_config.json")
    monkeypatch.setattr(store_module, "KEY_FILE", data_dir / "web_key")
    monkeypatch.setattr(store_module, "DB_FILE", data_dir / "web.db")
    store_module.init_db()
    return store_module


def _app(*, role: str = "admin", language: str = "zh") -> AppTest:
    at = AppTest.from_file(MAIN, default_timeout=120)
    at.session_state["authenticated"] = True
    at.session_state["user"] = "admin" if role == "admin" else "someone"
    at.session_state["role"] = role
    at.session_state["ui_language"] = language
    at.session_state["view"] = "status"
    at.run()
    return at


class TestStatusPage:
    def test_renders_all_sections(self, sandboxed_store):
        at = _app()
        assert [e.value for e in at.exception] == []
        titles = [m.value for m in at.markdown if m.value.strip().startswith("####")]
        for expected in (
            "#### 版本与运行环境",
            "#### 数据概况",
            "#### 最近任务",
            "#### 组件健康",
            "#### 最近告警",
            "#### 数据备份",
        ):
            assert expected in titles, f"缺少区块 {expected}（实际：{titles}）"

    def test_renders_in_english(self, sandboxed_store):
        at = _app(language="en")
        assert [e.value for e in at.exception] == []
        titles = [m.value for m in at.markdown if m.value.strip().startswith("####")]
        assert "#### Version & runtime" in titles
        assert "#### Data backup" in titles

    def test_database_health_is_ok(self, sandboxed_store):
        at = _app()
        body = "\n".join(m.value for m in at.markdown)
        assert "🟢 **数据库**" in body
        assert "wal" in body

    def test_status_view_is_admin_only(self, sandboxed_store):
        """非管理员即使会话里塞了 view=status，也看不到任何运维内容。"""
        at = _app(role="user")
        assert [e.value for e in at.exception] == []
        assert not any("#### 数据备份" in m.value for m in at.markdown)
        assert not any("#### 组件健康" in m.value for m in at.markdown)
        assert not any(b.key == "backup_create" for b in at.button)

    def test_topbar_has_status_toggle_for_admin(self, sandboxed_store):
        at = AppTest.from_file(MAIN, default_timeout=120)
        at.session_state["authenticated"] = True
        at.session_state["user"] = "admin"
        at.session_state["role"] = "admin"
        at.run()
        assert any(b.key == "status_toggle" for b in at.button)

    def test_topbar_toggle_absent_for_user(self, sandboxed_store):
        at = AppTest.from_file(MAIN, default_timeout=120)
        at.session_state["authenticated"] = True
        at.session_state["user"] = "someone"
        at.session_state["role"] = "user"
        at.run()
        assert not any(b.key == "status_toggle" for b in at.button)


class TestBackupFromUi:
    def test_create_backup_produces_download(self, sandboxed_store):
        store = sandboxed_store
        store.save_report(kind="threat_model", project="状态页项目", title="t", content_md="# 报告")
        at = _app()
        assert [e.value for e in at.exception] == []

        at.button(key="backup_create").click().run()
        assert [e.value for e in at.exception] == []
        assert any("备份已生成" in s.value for s in at.success)
        assert at.session_state["_backup_bytes"][:2] == b"PK"
        downloads = list(at.get("download_button"))
        assert downloads and downloads[0].label == "下载备份包"

    def test_backup_button_available_with_workspaces_option(self, sandboxed_store):
        at = _app()
        assert any(c.key == "backup_include_ws" for c in at.checkbox)
