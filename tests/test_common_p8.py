"""P8 测试：密码策略、修改/重置、登录失败锁定、会话参数。"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "apps"))

from common import store


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


class TestPasswordPolicy:
    @pytest.mark.parametrize(
        ("password", "expected"),
        [
            ("short1", "too_short"),
            ("12345678", "need_classes"),
            ("alice1234", "contains_username"),
            ("Password1", "too_common"),
        ],
    )
    def test_policy_codes(self, password, expected):
        issues = store.validate_password("alice", password)
        assert expected in issues, f"{password!r} -> {issues}"

    def test_strong_password_ok(self):
        assert store.validate_password("alice", "Wq!7tR2pLm9") == []

    def test_create_user_rejects_weak_password(self, store_sandbox):
        with pytest.raises(ValueError, match=r"need_classes|too_short"):
            store.create_user("bob", "password", "user")

    def test_create_user_accepts_strong(self, store_sandbox):
        store.create_user("bob", "Wq!7tR2pLm9", "user")
        assert store.get_user("bob")["role"] == "user"


class TestChangePassword:
    def test_old_password_required(self, store_sandbox):
        store.create_user("bob", "Wq!7tR2pLm9", "user")
        with pytest.raises(ValueError, match="old_password_incorrect"):
            store.change_password("bob", "WrongPass1!", "N3wPass!xyz")

    def test_change_success_and_invalidates_sessions(self, store_sandbox):
        store.create_user("bob", "Wq!7tR2pLm9", "user")
        token = store.make_session_token("bob")
        assert store.verify_session_token(token) == "bob"
        store.change_password("bob", "Wq!7tR2pLm9", "N3wPass!xyz")
        assert store.verify_user("bob", "N3wPass!xyz") is not None
        assert store.verify_user("bob", "Wq!7tR2pLm9") is None
        assert store.verify_session_token(token) is None, "改密码后旧会话必须失效"

    def test_admin_reset_requires_existing_user(self, store_sandbox):
        with pytest.raises(ValueError, match="不存在"):
            store.set_user_password("ghost", "Wq!7tR2pLm9")

    def test_admin_reset_bumps_epoch(self, store_sandbox):
        store.create_user("bob", "Wq!7tR2pLm9", "user")
        token = store.make_session_token("bob")
        store.set_user_password("bob", "An0ther!Pass")
        assert store.verify_session_token(token) is None


class TestForceLogout:
    def test_force_logout_invalidates_cookie(self, store_sandbox):
        store.create_user("bob", "Wq!7tR2pLm9", "user")
        token = store.make_session_token("bob")
        assert store.verify_session_token(token) == "bob"
        store.force_logout("bob")
        assert store.verify_session_token(token) is None
        actions = [row["action"] for row in store.list_audit(limit=10)]
        assert "强制下线" in actions


class TestLoginLockout:
    def test_lock_after_five_failures(self, store_sandbox):
        for _ in range(4):
            status = store.record_login_failure("alice")
            assert not status["locked"]
        status = store.record_login_failure("alice")
        assert status["locked"] is True
        assert status["minutes"] >= 4  # 5 分钟锁定（容忍边界）
        assert status["fails_left"] == 0

    def test_long_lock_after_double_threshold(self, store_sandbox):
        for _ in range(10):
            store.record_login_failure("alice")
        status = store.login_lock_status("alice")
        assert status["locked"] and status["minutes"] >= 25

    def test_success_clears_failures(self, store_sandbox):
        for _ in range(3):
            store.record_login_failure("alice")
        assert store.login_lock_status("alice")["fails"] == 3
        store.clear_login_failures("alice")
        assert store.login_lock_status("alice") == {
            "locked": False,
            "minutes": 0,
            "fails": 0,
            "fails_left": 5,
        }

    def test_window_expiry_resets_counter(self, store_sandbox):
        for _ in range(3):
            store.record_login_failure("alice")
        # 伪造首次失败时间为 16 分钟前 → 超出统计窗口，重新计数
        with store._conn() as conn:
            conn.execute(
                "UPDATE login_attempts SET first_fail_at = ? WHERE identifier = 'alice'",
                (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 16 * 60)),),
            )
        status = store.record_login_failure("alice")
        assert status["fails"] == 1 and not status["locked"]

    def test_expired_lock_is_not_locked(self, store_sandbox):
        for _ in range(5):
            store.record_login_failure("alice")
        with store._conn() as conn:
            conn.execute(
                "UPDATE login_attempts SET locked_until = ? WHERE identifier = 'alice'",
                (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 60)),),
            )
        assert store.login_lock_status("alice")["locked"] is False

    def test_identifiers_are_isolated(self, store_sandbox):
        for _ in range(5):
            store.record_login_failure("alice")
        assert store.login_lock_status("alice")["locked"] is True
        assert store.login_lock_status("bob")["locked"] is False


class TestSessionSettings:
    def test_session_days_default_and_clamp(self, store_sandbox):
        assert store.session_days() == 7
        store.set_meta("session_days", "60")
        assert store.session_days() == 30
        store.set_meta("session_days", "0")
        assert store.session_days() == 1
        store.set_meta("session_days", "not-a-number")
        assert store.session_days() == 7

    def test_session_days_env_fallback(self, store_sandbox, monkeypatch):
        monkeypatch.setenv("STRIDE_GPT_SESSION_DAYS", "3")
        assert store.session_days() == 3

    def test_token_respects_days(self, store_sandbox):
        token = store.make_session_token("alice", days=1)
        assert store.verify_session_token(token) == "alice"

    def test_secure_cookie_flag(self, monkeypatch):
        monkeypatch.delenv("STRIDE_GPT_SECURE_COOKIE", raising=False)
        assert store.secure_cookie() is False
        monkeypatch.setenv("STRIDE_GPT_SECURE_COOKIE", "1")
        assert store.secure_cookie() is True
