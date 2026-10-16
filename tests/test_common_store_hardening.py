"""P7 测试：SQLite 硬化（WAL / busy_timeout / 连接关闭 / 索引 / 并发写）。"""

from __future__ import annotations

import sqlite3
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "apps"))

from common import store as store_module


@pytest.fixture()
def store(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    for name, value in [
        ("DATA_DIR", data_dir),
        ("CONFIG_FILE", data_dir / "web_config.json"),
        ("KEY_FILE", data_dir / "web_key"),
        ("DB_FILE", data_dir / "web.db"),
    ]:
        monkeypatch.setattr(store_module, name, value)
    store_module.init_db()
    return store_module


class TestConnectionHardening:
    def test_wal_mode_enabled(self, store):
        with store._conn() as conn:
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            # WAL 文件在连接打开期间存在（最后一根连接关闭时 SQLite 会清理它）
            assert (store.DB_FILE.parent / (store.DB_FILE.name + "-wal")).exists()
        assert str(mode).lower() == "wal"

    def test_busy_timeout_set(self, store):
        with store._conn() as conn:
            assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 30000

    def test_connection_is_closed_after_with(self, store):
        with store._conn() as conn:
            handle = conn
            assert handle.execute("SELECT 1").fetchone()[0] == 1
        with pytest.raises(sqlite3.ProgrammingError):
            handle.execute("SELECT 1")

    def test_rollback_on_exception(self, store):
        with pytest.raises(RuntimeError), store._conn() as conn:
            conn.execute(
                "INSERT INTO audit_log(ts, username, action, detail) VALUES('now','u','t','')"
            )
            raise RuntimeError("boom")
        assert not [r for r in store.list_audit(limit=5) if r["action"] == "t"]

    def test_indexes_created(self, store):
        with store._conn() as conn:
            names = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'"
                )
            }
        for expected in (
            "idx_reports_project",
            "idx_reports_created",
            "idx_threats_project",
            "idx_threats_status",
            "idx_audit_ts",
            "idx_usage_ts",
        ):
            assert expected in names


class TestConcurrentWrites:
    def test_parallel_log_actions_do_not_lock(self, store):
        """Web + API + 调度器同时写审计日志：WAL + busy_timeout 下不应报锁。"""
        errors: list[Exception] = []
        per_thread = 15
        threads = [
            threading.Thread(
                target=lambda worker=index: [
                    store.log_action(f"u{worker}", f"动作{n}", "x" * 40)
                    for n in range(per_thread)
                ]
            )
            for index in range(6)
        ]
        original = store.log_action

        def guarded(*args, **kwargs):
            try:
                return original(*args, **kwargs)
            except Exception as exc:
                errors.append(exc)
                return None

        store.log_action = guarded
        try:
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        finally:
            store.log_action = original

        assert errors == [], f"并发写入报错：{errors[:2]}"
        rows = store.list_audit(limit=1000)
        assert len([r for r in rows if r["detail"] == "x" * 40]) == 6 * per_thread

    def test_parallel_read_and_write(self, store):
        store.log_action("u", "seed")
        stop = threading.Event()
        errors: list[Exception] = []

        def reader():
            while not stop.is_set():
                try:
                    store.list_audit(limit=50)
                    store.list_reports(limit=20)
                except Exception as exc:
                    errors.append(exc)
                    return

        threads = [threading.Thread(target=reader) for _ in range(3)]
        for thread in threads:
            thread.start()
        try:
            for index in range(40):
                store.log_action("writer", f"w{index}")
        finally:
            stop.set()
            for thread in threads:
                thread.join()

        assert errors == []


class TestDbStats:
    def test_stats_shape(self, store):
        store.log_action("u", "a1")
        stats = store.db_stats()
        assert stats["journal_mode"].lower() == "wal"
        assert stats["bytes"] > 0
        assert stats["page_size"] > 0
        assert stats["tables"]["audit_log"] >= 1
        assert stats["tables"]["reports"] >= 0

    def test_stats_survives_missing_db(self, store, tmp_path, monkeypatch):
        monkeypatch.setattr(store, "DB_FILE", tmp_path / "none" / "web.db")
        stats = store.db_stats()
        assert stats["bytes"] == 0
        assert stats["tables"] == {}
