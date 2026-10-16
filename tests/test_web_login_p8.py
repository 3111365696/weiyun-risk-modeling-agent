"""P8 测试：登录失败锁定与账号安全交互（AppTest 走真实登录表单）。"""

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


def _state_of(at: AppTest, key: str, default=None):
    try:
        return at.session_state[key]
    except Exception:
        return default


def _flag(at: AppTest, key: str) -> bool:
    return bool(_state_of(at, key, False))


def _login_page() -> AppTest:
    at = AppTest.from_file(MAIN, default_timeout=120)
    at.run()
    return at


def _attempt(at: AppTest, username: str, password: str) -> AppTest:
    at.text_input(key="login_user").set_value(username)
    at.text_input(key="login_password").set_value(password)
    submit = next(b for b in at.button if str(b.key or "").startswith("FormSubmitter:login_form"))
    submit.click()
    at.run()
    return at


class TestLoginPage:
    def test_renders_login_form(self, sandboxed_store):
        at = _login_page()
        assert [e.value for e in at.exception] == []
        assert not _flag(at, "authenticated")
        assert {t.key for t in at.text_input} >= {"login_user", "login_password"}

    def test_wrong_password_shows_error(self, sandboxed_store):
        at = _attempt(_login_page(), "someone", "bad-password")
        assert [e.value for e in at.exception] == []
        assert any("错误" in e.value or "incorrect" in e.value.lower() for e in at.error)

    def test_lockout_after_five_failures(self, sandboxed_store):
        at = _login_page()
        for _ in range(5):
            at = _attempt(at, "locktest", "bad-password")
        assert [e.value for e in at.exception] == []
        messages = " ".join(e.value for e in at.error)
        assert "锁定" in messages or "locked" in messages, messages
        assert sandboxed_store.login_lock_status("locktest")["locked"] is True

    def test_locked_account_rejected_even_with_correct_password(self, sandboxed_store):
        store = sandboxed_store
        store.create_user("locktest", "Wq!7tR2pLm9", "user")
        for _ in range(5):
            store.record_login_failure("locktest")
        at = _attempt(_login_page(), "locktest", "Wq!7tR2pLm9")
        assert not _flag(at, "authenticated")
        assert store.login_lock_status("locktest")["locked"] is True
        actions = [row["action"] for row in store.list_audit(limit=20)]
        assert "登录被拒" in actions

    def test_successful_login_clears_failures(self, sandboxed_store):
        store = sandboxed_store
        store.create_user("bob", "Wq!7tR2pLm9", "user")
        for _ in range(3):
            store.record_login_failure("bob")
        at = _attempt(_login_page(), "bob", "Wq!7tR2pLm9")
        assert _flag(at, "authenticated") is True
        assert _state_of(at, "user") == "bob"
        assert store.login_lock_status("bob")["fails"] == 0

    def test_failure_is_audited(self, sandboxed_store):
        _attempt(_login_page(), "someone", "bad-password")
        rows = sandboxed_store.list_audit(limit=10)
        assert any(row["action"] == "登录失败" for row in rows)


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

from pages.users import _page_users

_page_users()
"""


def _users_page(tmp_path, *, user: str = "bob", role: str = "user") -> AppTest:
    script = tmp_path / f"probe_users_{user}.py"
    script.write_text(
        PROBE.format(
            apps=str(ROOT / "apps"), web=str(ROOT / "apps" / "web"), main=MAIN, user=user, role=role
        ),
        encoding="utf-8",
    )
    at = AppTest.from_file(str(script), default_timeout=120)
    at.run()
    return at


class TestAccountPage:
    def test_regular_user_sees_account_section(self, sandboxed_store, tmp_path):
        sandboxed_store.create_user("bob", "Wq!7tR2pLm9", "user")
        at = _users_page(tmp_path)
        assert [e.value for e in at.exception] == []
        body = "\n".join(m.value for m in at.markdown)
        assert "我的账号" in body

    def test_change_password_form_present(self, sandboxed_store, tmp_path):
        sandboxed_store.create_user("bob", "Wq!7tR2pLm9", "user")
        at = _users_page(tmp_path)
        keys = [t.key for t in at.text_input if t.key in {"cp_old", "cp_new", "cp_new2"}]
        assert keys == ["cp_old", "cp_new", "cp_new2"], keys

    def test_change_password_flow(self, sandboxed_store, tmp_path):
        store = sandboxed_store
        store.create_user("bob", "Wq!7tR2pLm9", "user")
        at = _users_page(tmp_path)
        at.text_input(key="cp_old").set_value("Wq!7tR2pLm9")
        at.text_input(key="cp_new").set_value("N3wPass!xyz")
        at.text_input(key="cp_new2").set_value("N3wPass!xyz")
        submit = next(b for b in at.button if str(b.key or "").startswith("FormSubmitter:change_pw_form"))
        submit.click()
        at.run()
        assert [e.value for e in at.exception] == []
        assert store.verify_user("bob", "N3wPass!xyz") is not None

    def test_admin_sees_management(self, sandboxed_store, tmp_path):
        sandboxed_store.create_user("carol", "Wq!7tR2pLm9", "user")
        at = _users_page(tmp_path, user="admin", role="admin")
        assert [e.value for e in at.exception] == []
        assert any(b.key == "create_user" for b in at.button)
        assert any(b.key == "kick_user_carol" for b in at.button), "管理员应有强制下线按钮"
        assert any(t.key == "audit_filter" for t in at.text_input), "管理员应看到审计筛选"

