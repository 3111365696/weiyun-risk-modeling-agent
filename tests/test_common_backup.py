"""P7 测试：备份 / 校验 / 恢复。"""

from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "apps"))

from common import backup, store


@pytest.fixture()
def sandbox(tmp_path, monkeypatch):
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
    return data_dir


def _seed():
    report_id = store.save_report(
        kind="threat_model", project="备份项目", title="t", content_md="# 报告"
    )
    store.save_config({"model_provider": "OpenAI API", "selected_model": "gpt-4o-mini"})
    store.log_action("admin", "种子")
    return report_id


class TestCreateBackup:
    def test_backup_contains_db_and_config(self, sandbox):
        _seed()
        path = backup.create_backup(out_dir=sandbox / "backups")
        assert path.exists() and path.name.startswith("backup-")
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
            assert {"manifest.json", "web.db", "web_config.json", "web_key"} <= names
            manifest = json.loads(archive.read("manifest.json"))
        assert manifest["format"] == "wy-stride-backup"
        assert manifest["db_tables"]["reports"] >= 1
        assert manifest["files"]["web.db"]["sha256"]

    def test_workspaces_optional(self, sandbox):
        (sandbox / "workspaces" / "zip" / "a").mkdir(parents=True)
        (sandbox / "workspaces" / "zip" / "a" / "code.py").write_text("print(1)")
        plain = backup.create_backup(out_dir=sandbox / "b1")
        full = backup.create_backup(out_dir=sandbox / "b2", include_workspaces=True)
        with zipfile.ZipFile(plain) as archive:
            assert not [n for n in archive.namelist() if n.startswith("workspaces/")]
        with zipfile.ZipFile(full) as archive:
            assert "workspaces/zip/a/code.py" in archive.namelist()

    def test_backup_bytes(self, sandbox):
        _seed()
        data = backup.create_backup_bytes()
        assert data[:2] == b"PK"
        buffer = sandbox / "mem.zip"
        buffer.write_bytes(data)
        assert backup.read_manifest(buffer)["format"] == "wy-stride-backup"

    def test_empty_database_still_backs_up(self, sandbox):
        path = backup.create_backup(out_dir=sandbox / "backups")
        assert backup.verify_backup(path)["files"]


class TestVerify:
    def test_verify_ok(self, sandbox):
        _seed()
        path = backup.create_backup(out_dir=sandbox / "backups")
        manifest = backup.verify_backup(path)
        assert manifest["tool_version"]

    def test_tampered_file_rejected(self, sandbox):
        _seed()
        path = backup.create_backup(out_dir=sandbox / "backups")
        tampered = sandbox / "tampered.zip"
        with zipfile.ZipFile(path) as source, zipfile.ZipFile(tampered, "w") as dest:
            for item in source.infolist():
                data = source.read(item.filename)
                if item.filename == "web.db":
                    data = data[:-1] + bytes([data[-1] ^ 0xFF])  # 改最后一个字节
                dest.writestr(item, data)
        with pytest.raises(backup.BackupError, match="哈希不符"):
            backup.verify_backup(tampered)

    def test_non_backup_zip_rejected(self, sandbox):
        path = sandbox / "random.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("hello.txt", "hi")
        with pytest.raises(backup.BackupError):
            backup.read_manifest(path)

    def test_missing_file_rejected(self, sandbox):
        _seed()
        path = backup.create_backup(out_dir=sandbox / "backups")
        stripped = sandbox / "stripped.zip"
        with zipfile.ZipFile(path) as source, zipfile.ZipFile(stripped, "w") as dest:
            for item in source.infolist():
                if item.filename == "web.db":
                    continue
                dest.writestr(item, source.read(item.filename))
        with pytest.raises(backup.BackupError, match="缺少文件"):
            backup.verify_backup(stripped)


class TestRestore:
    def test_restore_recovers_data(self, sandbox):
        _seed()
        snapshot = backup.create_backup(out_dir=sandbox / "backups")
        # 制造"事故"：删掉报告与配置
        with store._conn() as conn:
            conn.execute("DELETE FROM reports")
            conn.execute("DELETE FROM threats")
        store.clear_config()
        assert store.list_reports(limit=5) == []

        result = backup.restore_backup(snapshot)
        assert result["ok"] and "web.db" in result["restored"]
        assert result["restart_required"] is True
        assert [r["project"] for r in store.list_reports(limit=5)] == ["备份项目"]
        assert store.load_config().get("model_provider") == "OpenAI API"

    def test_restore_creates_pre_restore_backup(self, sandbox):
        _seed()
        snapshot = backup.create_backup(out_dir=sandbox / "backups")
        result = backup.restore_backup(snapshot)
        assert result["pre_restore"]
        assert Path(result["pre_restore"]).exists()
        assert Path(result["pre_restore"]).name.startswith("pre-restore-")

    def test_pre_restore_can_be_disabled(self, sandbox):
        _seed()
        snapshot = backup.create_backup(out_dir=sandbox / "backups")
        result = backup.restore_backup(snapshot, keep_pre_restore=False)
        assert result["pre_restore"] == ""

    def test_pre_restore_pruned(self, sandbox):
        _seed()
        snapshot = backup.create_backup(out_dir=sandbox / "backups")
        for _ in range(7):
            backup.restore_backup(snapshot)
        keep = list((sandbox / "backups").glob("pre-restore-*.zip"))
        assert len(keep) <= backup.KEEP_PRE_RESTORE

    def test_wal_removed_on_restore(self, sandbox):
        _seed()
        snapshot = backup.create_backup(out_dir=sandbox / "backups")
        stale = sandbox / "web.db-wal"
        stale.write_bytes(b"stale wal")
        backup.restore_backup(snapshot)
        assert not stale.exists()

    def test_restore_rejects_corrupt(self, sandbox):
        (sandbox / "bad.zip").write_text("not a zip")
        with pytest.raises(backup.BackupError):
            backup.restore_backup(sandbox / "bad.zip")


class TestListAndCli:
    def test_list_backups(self, sandbox):
        _seed()
        backup.create_backup(out_dir=sandbox / "backups")
        rows = backup.list_backups(directory=sandbox / "backups")
        assert len(rows) == 1
        assert rows[0]["kind"] == "backup"
        assert rows[0]["tool_version"]

    def test_cli_create_list_verify_restore(self, sandbox, capsys, monkeypatch):
        monkeypatch.setenv("STRIDE_GPT_SKIP_UPDATE_CHECK", "1")
        _seed()
        assert backup.cli(["create"]) == 0
        assert "备份完成" in capsys.readouterr().out

        assert backup.cli(["list"]) == 0
        assert "backup-" in capsys.readouterr().out

        created = next((sandbox / "backups").glob("backup-*.zip"))
        assert backup.cli(["verify", str(created)]) == 0
        assert "校验通过" in capsys.readouterr().out

        assert backup.cli(["restore", str(created), "--no-pre-restore"]) == 0
        assert "恢复完成" in capsys.readouterr().out
