"""P9-1 测试：版本信息与数据库结构迁移版本。"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "apps"))

from common import store, version  # noqa: E402


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
    return store


class TestVersionModule:
    def test_version_matches_pyproject(self):
        assert version.package_version() == "1.0.0"

    def test_build_info_shape(self):
        info = version.build_info()
        assert info["product"] == "威云-风险建模智能体"
        assert info["version"] == "1.0.0"
        assert info["python"]
        assert "commit" in info

    def test_version_line(self):
        line = version.version_line()
        assert line.startswith("v1.0.0")

    def test_backup_uses_same_version(self):
        from common import backup

        assert backup.tool_version() == version.package_version()


class TestSchemaMigrations:
    def test_fresh_db_records_all_migrations(self, store_sandbox):
        store.init_db()
        history = store.migration_history()
        assert [row["version"] for row in history] == [1, 2, 3, 4]
        assert all(row["applied_at"] for row in history)
        assert store.schema_version() == max(v for v, _ in store.MIGRATIONS)

    def test_migrations_are_idempotent(self, store_sandbox):
        store.init_db()
        first = store.migration_history()
        store._initialized.clear()  # 模拟进程重启后再次初始化
        store.init_db()
        second = store.migration_history()
        assert len(first) == len(second)

    def test_upgrade_of_legacy_db(self, store_sandbox):
        """老库（没有 schema_migrations 表）自动补记迁移。"""
        import sqlite3

        store.init_db()
        store._initialized.clear()
        with sqlite3.connect(store.DB_FILE) as conn:
            conn.execute("DROP TABLE schema_migrations")
        store.init_db()  # 重新建表并补记
        assert store.schema_version() == 4

    def test_db_stats_includes_schema_version(self, store_sandbox):
        store.init_db()
        stats = store.db_stats()
        assert stats["schema_version"] == 4

    def test_init_db_cached_per_file(self, store_sandbox):
        store.init_db()
        assert str(store.DB_FILE) in store._initialized
        # 切换数据库文件后应重新初始化
        store.DB_FILE = store.DATA_DIR / "other.db"
        assert str(store.DB_FILE) not in store._initialized
        store.init_db()
        assert str(store.DB_FILE) in store._initialized
        assert store.schema_version() == 4
