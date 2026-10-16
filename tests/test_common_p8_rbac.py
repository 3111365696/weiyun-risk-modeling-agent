"""P8-3 测试：项目级权限（成员/角色/隔离）——store、API 与 Web 三层。"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "apps"))
sys.path.insert(0, str(ROOT / "apps" / "web"))

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


@pytest.fixture()
def project(store_sandbox):
    store.upsert_project("支付系统", "")
    store.create_user("alice", "Str0ng!Pass1", "user")
    store.create_user("bob", "Str0ng!Pass2", "user")
    store.create_user("carol", "Str0ng!Pass3", "user")
    store.create_user("riley", "Str0ng!Pass4", "admin")
    return "支付系统"


class TestProjectRoles:
    def test_open_project_defaults_to_editor(self, store_sandbox, project):
        assert store.project_role(project, "alice") == "editor"
        assert store.can_edit_project(project, "alice") is True

    def test_viewer_cannot_edit(self, store_sandbox, project):
        store.set_project_member(project, "alice", "viewer")
        assert store.project_role(project, "alice") == "viewer"
        assert store.can_edit_project(project, "alice") is False
        assert store.can_manage_project(project, "alice") is False

    def test_editor_can_edit_not_manage(self, store_sandbox, project):
        store.set_project_member(project, "alice", "editor")
        assert store.can_edit_project(project, "alice") is True
        assert store.can_manage_project(project, "alice") is False

    def test_owner_can_manage(self, store_sandbox, project):
        store.set_project_member(project, "bob", "owner")
        assert store.can_manage_project(project, "bob") is True

    def test_members_lock_down_access(self, store_sandbox, project):
        store.set_project_member(project, "alice", "viewer")
        assert store.project_role(project, "bob") is None, "配置成员后，非成员不可访问"
        assert store.can_edit_project(project, "bob") is False

    def test_admin_override(self, store_sandbox, project):
        store.set_project_member(project, "alice", "viewer")
        assert store.project_role(project, "riley") == "owner"  # users.role=admin
        assert store.can_edit_project(project, "riley") is True
        assert store.can_manage_project(project, "riley") is True

    def test_explicit_is_admin_flag(self, store_sandbox, project):
        store.set_project_member(project, "alice", "viewer")
        assert store.can_edit_project(project, "outsider", is_admin=True) is True

    def test_role_upsert_and_remove(self, store_sandbox, project):
        store.set_project_member(project, "alice", "viewer")
        store.set_project_member(project, "alice", "owner")
        assert store.project_role(project, "alice") == "owner"
        assert len(store.list_project_members(project)) == 1
        store.remove_project_member(project, "alice")
        assert store.project_role(project, "alice") == "editor"  # 回到未配置状态

    def test_invalid_inputs(self, store_sandbox, project):
        with pytest.raises(ValueError, match="不存在"):
            store.set_project_member(project, "ghost", "viewer")
        with pytest.raises(ValueError, match="角色"):
            store.set_project_member(project, "alice", "superuser")
        with pytest.raises(ValueError):
            store.set_project_member("", "alice", "viewer")

    def test_accessible_projects_filtered(self, store_sandbox, project):
        store.upsert_project("内部系统", "")
        store.set_project_member(project, "alice", "viewer")
        names = [p["name"] for p in store.list_accessible_projects("alice")]
        assert project in names
        assert "内部系统" in names, "未配置成员的项目对所有人可见"
        bob_rows = store.list_accessible_projects("bob")
        assert project not in [p["name"] for p in bob_rows], "成员化项目对非成员不可见"

    def test_member_columns_persist(self, store_sandbox, project):
        store.set_project_member(project, "alice", "editor")
        row = store.list_project_members(project)[0]
        assert row["project"] == project
        assert row["username"] == "alice"
        assert row["created_at"]


@pytest.fixture()
def api_client(tmp_path, monkeypatch, store_sandbox):
    from fastapi.testclient import TestClient

    module = importlib.import_module("api.main")
    return TestClient(module.app, raise_server_exceptions=False), module


def _key(owner: str, scopes=("read", "write")) -> str:
    return store.create_api_key(f"key-{owner}", scopes=list(scopes), owner=owner)


class TestApiProjectAccess:
    def test_viewer_can_read_but_not_write(self, api_client, project):
        """viewer 是只读角色：可读（业务层 404），但写操作被 403 拦截。"""
        store.set_project_member(project, "alice", "viewer")
        client, _ = api_client
        response = client.get(
            f"/api/v1/projects/{project}/coverage", headers={"X-API-Key": _key("alice")}
        )
        assert response.status_code == 404, "viewer 应可读取"
        write_response = client.post(
            "/api/v1/threat-model",
            json={"description": "x", "project": project, "profile": {}},
            headers={"X-API-Key": _key("alice")},
        )
        assert write_response.status_code == 403
        assert "权限" in write_response.json()["detail"]

    def test_viewer_blocked_from_write(self, api_client, project):
        store.set_project_member(project, "alice", "viewer")
        client, _ = api_client
        response = client.post(
            "/api/v1/threat-model",
            json={"description": "x", "project": project, "profile": {}},
            headers={"X-API-Key": _key("alice")},
        )
        assert response.status_code == 403

    def test_editor_can_reach_business_layer(self, api_client, project):
        store.set_project_member(project, "bob", "editor")
        client, _ = api_client
        response = client.get(
            f"/api/v1/projects/{project}/coverage", headers={"X-API-Key": _key("bob")}
        )
        assert response.status_code == 404, response.text  # 无报告 → 通过权限层

    def test_non_member_blocked(self, api_client, project):
        store.set_project_member(project, "alice", "viewer")
        client, _ = api_client
        response = client.get(
            f"/api/v1/projects/{project}/coverage", headers={"X-API-Key": _key("bob")}
        )
        assert response.status_code == 403

    def test_admin_owner_allowed(self, api_client, project):
        store.set_project_member(project, "alice", "viewer")
        client, _ = api_client
        response = client.get(
            f"/api/v1/projects/{project}/coverage", headers={"X-API-Key": _key("admin")}
        )
        assert response.status_code == 404  # 管理员直通业务层

    def test_open_project_allows_everyone(self, api_client, project):
        client, _ = api_client
        response = client.get(
            f"/api/v1/projects/{project}/coverage", headers={"X-API-Key": _key("alice")}
        )
        assert response.status_code == 404

    def test_threat_patch_checks_project(self, api_client, project):
        report_id = store.save_report(
            kind="threat_model", project=project, title="t", content_md="m"
        )
        store.add_threats(
            project,
            report_id,
            [{"Threat Type": "Spoofing", "Scenario": "伪造令牌"}],
        )
        threat_id = store.list_threats(project=project)[0]["id"]
        store.set_project_member(project, "alice", "viewer")
        client, _ = api_client
        response = client.patch(
            f"/api/v1/threats/{threat_id}",
            json={"status": "已确认"},
            headers={"X-API-Key": _key("alice")},
        )
        assert response.status_code == 403

        store.set_project_member(project, "bob", "editor")
        response = client.patch(
            f"/api/v1/threats/{threat_id}",
            json={"status": "已确认"},
            headers={"X-API-Key": _key("bob")},
        )
        assert response.status_code == 200


class TestWebPermissionHelpers:
    def test_shared_helpers_respect_session(self, project, monkeypatch):
        import streamlit as st
        from shared import can_manage_project, can_write_project

        store.set_project_member(project, "alice", "viewer")
        st.session_state.clear()
        st.session_state["user"] = "alice"
        st.session_state["role"] = "user"
        assert can_write_project(project) is False
        assert can_manage_project(project) is False

        st.session_state["user"] = "riley"
        st.session_state["role"] = "admin"
        assert can_write_project(project) is True
        assert can_manage_project(project) is True
        st.session_state.clear()


# ---------------------------------------------------------------------------
# Web：项目页成员管理与只读态
# ---------------------------------------------------------------------------

PROBE = """\
import sys, importlib.util
sys.path[:0] = [{apps!r}, {web!r}]
import streamlit as st

st.session_state.setdefault("authenticated", True)
st.session_state.setdefault("user", "{user}")
st.session_state.setdefault("role", "{role}")


class _DummyPg:
    title = "probe"

    def run(self):
        return None


_real = st.navigation
st.navigation = lambda *args, **kwargs: _DummyPg()
spec = importlib.util.spec_from_file_location("webmain", {main!r})
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
st.navigation = _real

from pages.projects import _page_projects

_page_projects()
"""


def _projects_page(tmp_path, *, user: str, role: str, project: str) -> object:
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest

    script = tmp_path / f"probe_projects_{user}.py"
    script.write_text(
        PROBE.format(
            apps=str(ROOT / "apps"),
            web=str(ROOT / "apps" / "web"),
            main=str(ROOT / "apps" / "web" / "main.py"),
            user=user,
            role=role,
        ),
        encoding="utf-8",
    )
    at = AppTest.from_file(str(script), default_timeout=120)
    at.run()
    return at


class TestProjectsPagePermissions:
    def test_owner_sees_member_management(self, store_sandbox, project, tmp_path):
        store_sandbox.set_project_member(project, "bob", "owner")
        at = _projects_page(tmp_path, user="bob", role="user", project=project)
        assert [e.value for e in at.exception] == []
        labels = [e.label for e in at.expander]
        assert any("成员与权限" in label for label in labels), labels
        body = "\n".join(m.value for m in at.markdown)
        assert "bob" in body

    def test_viewer_sees_readonly_warning(self, store_sandbox, project, tmp_path):
        store_sandbox.set_project_member(project, "alice", "viewer")
        at = _projects_page(tmp_path, user="alice", role="user", project=project)
        assert [e.value for e in at.exception] == []
        warnings = " ".join(w.value for w in at.warning)
        assert "只读" in warnings or "view-only" in warnings.lower()
        # 生成按钮存在但不可点（disabled 由 Streamlit 在服务端拒绝点击）
        pipeline = [b for b in at.button if b.key == "ws_pipeline"]
        assert pipeline, "生成按钮应仍可见（以便灰显）"

    def test_non_member_cannot_edit(self, store_sandbox, project, tmp_path):
        store_sandbox.set_project_member(project, "bob", "owner")
        at = _projects_page(tmp_path, user="carol", role="user", project=project)
        assert [e.value for e in at.exception] == []
        warnings = " ".join(w.value for w in at.warning)
        assert "只读" in warnings
        labels = [e.label for e in at.expander]
        assert not any("添加成员" in label for label in labels)
