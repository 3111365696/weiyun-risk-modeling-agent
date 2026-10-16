"""备份与恢复：数据库 + 加密配置 + 密钥，用于升级前快照与灾难恢复。

备份包（ZIP）内容：
- ``manifest.json``：版本、时间、主机、Python、各文件 SHA-256 与大小、各表行数
- ``web.db``：用 SQLite 在线备份 API 导出（WAL 中的已提交数据也会包含，保证一致性）
- ``web_config.json`` / ``web_key`` / ``web_session_secret``（存在则打包）

恢复流程：
1. 校验 manifest 与全部文件哈希，并做 ``PRAGMA integrity_check``
2. 默认先自动把当前状态备份为 ``pre-restore-*.zip``（可用 keep_pre_restore=False 关闭）
3. 先写临时文件再 ``os.replace`` 原子替换；恢复后需重启服务生效

命令行：
    PYTHONPATH=apps python -m common.backup create [--out DIR] [--with-workspaces]
    PYTHONPATH=apps python -m common.backup list
    PYTHONPATH=apps python -m common.backup verify FILE
    PYTHONPATH=apps python -m common.backup restore FILE
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import platform
import shutil
import sqlite3
import sys
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path

from . import store

MANIFEST_NAME = "manifest.json"
KEEP_PRE_RESTORE = 5


class BackupError(RuntimeError):
    """备份/恢复失败（损坏、哈希不符、格式不对等）。"""


def backup_dir() -> Path:
    target = Path(store.DATA_DIR) / "backups"
    target.mkdir(parents=True, exist_ok=True)
    return target


def tool_version() -> str:
    from . import version

    return version.package_version()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _snapshot_db() -> bytes:
    """用 SQLite 在线备份 API 导出数据库（一致性快照，含 WAL 已提交数据）。"""
    if not Path(store.DB_FILE).exists():
        return b""
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "snapshot.db"
        source = sqlite3.connect(store.DB_FILE)
        try:
            dest = sqlite3.connect(target)
            try:
                source.backup(dest)
            finally:
                dest.close()
        finally:
            source.close()
        return target.read_bytes()


def _config_files() -> list[Path]:
    candidates = [
        Path(store.CONFIG_FILE),
        Path(store.KEY_FILE),
        Path(store.DATA_DIR) / "web_session_secret",
    ]
    return [path for path in candidates if path.exists()]


def _workspace_files() -> list[Path]:
    root = Path(store.DATA_DIR) / "workspaces"
    if not root.is_dir():
        return []
    return [path for path in root.rglob("*") if path.is_file()]


def _build_manifest(entries: dict[str, dict], *, include_workspaces: bool) -> dict:
    stats = {}
    try:
        stats = store.db_stats().get("tables", {})
    except Exception:
        stats = {}
    return {
        "format": "wy-stride-backup",
        "format_version": 1,
        "tool_version": tool_version(),
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "host": platform.node(),
        "python": platform.python_version(),
        "include_workspaces": include_workspaces,
        "files": entries,
        "db_tables": stats,
    }


def _build_zip(*, include_workspaces: bool) -> tuple[io.BytesIO, dict]:
    entries: dict[str, dict] = {}
    payloads: dict[str, bytes] = {}

    db_bytes = _snapshot_db()
    if db_bytes:
        payloads["web.db"] = db_bytes

    for path in _config_files():
        try:
            payloads[path.name] = path.read_bytes()
        except OSError:
            continue

    if include_workspaces:
        for path in _workspace_files():
            rel = path.relative_to(Path(store.DATA_DIR))
            payloads[str(rel)] = path.read_bytes()

    for name, data in payloads.items():
        entries[name] = {"sha256": _sha256_bytes(data), "bytes": len(data)}

    manifest = _build_manifest(entries, include_workspaces=include_workspaces)

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(MANIFEST_NAME, json.dumps(manifest, ensure_ascii=False, indent=2))
        for name, data in payloads.items():
            archive.writestr(name, data)
    buffer.seek(0)
    return buffer, manifest


def create_backup(*, out_dir: Path | None = None, include_workspaces: bool = False) -> Path:
    """创建备份包，返回文件路径。"""
    buffer, _ = _build_zip(include_workspaces=include_workspaces)
    target_dir = Path(out_dir) if out_dir is not None else backup_dir()
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}.zip"
    target.write_bytes(buffer.getvalue())
    with contextlib.suppress(OSError):
        target.chmod(0o600)
    return target


def create_backup_bytes(*, include_workspaces: bool = False) -> bytes:
    """内存备份（Web 下载按钮用）。"""
    buffer, _ = _build_zip(include_workspaces=include_workspaces)
    return buffer.getvalue()


def read_manifest(zip_path: Path) -> dict:
    try:
        with zipfile.ZipFile(zip_path) as archive:
            raw = archive.read(MANIFEST_NAME)
    except (OSError, KeyError, zipfile.BadZipFile) as exc:
        raise BackupError(f"不是有效的备份包：{exc}") from exc
    try:
        manifest = json.loads(raw)
    except ValueError as exc:
        raise BackupError(f"manifest.json 解析失败：{exc}") from exc
    if manifest.get("format") != "wy-stride-backup":
        raise BackupError("备份包格式不匹配（缺少 wy-stride-backup 标识）")
    return manifest


def verify_backup(zip_path: Path, *, check_db: bool = True) -> dict:
    """校验备份包：manifest、文件哈希、（可选）数据库完整性。"""
    manifest = read_manifest(zip_path)
    with zipfile.ZipFile(zip_path) as archive:
        names = set(archive.namelist())
        for name, info in (manifest.get("files") or {}).items():
            if name not in names:
                raise BackupError(f"备份缺少文件：{name}")
            data = archive.read(name)
            if len(data) != info.get("bytes"):
                raise BackupError(f"文件大小不符：{name}")
            if _sha256_bytes(data) != info.get("sha256"):
                raise BackupError(f"文件哈希不符（可能已损坏）：{name}")
        if check_db and "web.db" in names:
            with tempfile.TemporaryDirectory() as tmp:
                target = Path(tmp) / "check.db"
                target.write_bytes(archive.read("web.db"))
                conn = sqlite3.connect(target)
                try:
                    result = conn.execute("PRAGMA integrity_check").fetchone()[0]
                finally:
                    conn.close()
                if str(result).lower() != "ok":
                    raise BackupError(f"数据库完整性校验失败：{result}")
    return manifest


def list_backups(*, directory: Path | None = None) -> list[dict]:
    target = Path(directory) if directory is not None else backup_dir()
    if not target.is_dir():
        return []
    out: list[dict] = []
    for path in sorted(target.glob("*.zip"), reverse=True):
        item = {
            "name": path.name,
            "path": str(path),
            "bytes": path.stat().st_size,
            "modified": datetime.fromtimestamp(path.stat().st_mtime).strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "kind": "pre-restore" if path.name.startswith("pre-restore") else "backup",
        }
        try:
            manifest = read_manifest(path)
            item["tool_version"] = manifest.get("tool_version", "")
            item["created_at"] = manifest.get("created_at", item["modified"])
        except BackupError:
            item["error"] = "无法读取 manifest"
        out.append(item)
    return out


def _prune_pre_restore(directory: Path, keep: int = KEEP_PRE_RESTORE) -> None:
    files = sorted(directory.glob("pre-restore-*.zip"), reverse=True)
    for path in files[keep:]:
        with contextlib.suppress(OSError):
            path.unlink()


def restore_backup(zip_path: Path, *, keep_pre_restore: bool = True) -> dict:
    """从备份包恢复数据；返回恢复详情。调用方应在恢复后重启服务。"""
    zip_path = Path(zip_path)
    manifest = verify_backup(zip_path)
    data_dir = Path(store.DATA_DIR)
    data_dir.mkdir(parents=True, exist_ok=True)

    pre_restore = ""
    if keep_pre_restore and (Path(store.DB_FILE).exists() or _config_files()):
        target_dir = backup_dir()
        buffer, _ = _build_zip(include_workspaces=False)
        path = target_dir / f"pre-restore-{datetime.now().strftime('%Y%m%d-%H%M%S')}.zip"
        path.write_bytes(buffer.getvalue())
        pre_restore = str(path)
        _prune_pre_restore(target_dir)

    restored: list[str] = []
    with tempfile.TemporaryDirectory(dir=str(data_dir)) as tmp:
        staging = Path(tmp)
        with zipfile.ZipFile(zip_path) as archive:
            for name in (manifest.get("files") or {}):
                dest = staging / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(archive.read(name))
        for name in (manifest.get("files") or {}):
            source = staging / name
            target = data_dir / name
            if name == "web.db":
                # SQLite 替换：先清掉 -wal/-shm，避免旧日志覆盖新库
                for suffix in ("-wal", "-shm"):
                    with contextlib.suppress(OSError):
                        (data_dir / (name + suffix)).unlink()
            target.parent.mkdir(parents=True, exist_ok=True)
            tmp_target = target.with_name(target.name + ".restore-tmp")
            shutil.copyfile(source, tmp_target)
            tmp_target.replace(target)
            restored.append(name)

    store.init_db()
    return {
        "ok": True,
        "restored": restored,
        "pre_restore": pre_restore,
        "tool_version": manifest.get("tool_version", ""),
        "backup_created_at": manifest.get("created_at", ""),
        "restart_required": True,
    }


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="backup", description="威云-风险建模智能体 备份/恢复")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create", help="创建备份")
    create.add_argument("--out", type=Path, default=None, help="输出目录（默认数据目录/backups）")
    create.add_argument("--with-workspaces", action="store_true", help="一并打包工作区文件")

    sub.add_parser("list", help="列出备份")

    verify = sub.add_parser("verify", help="校验备份包")
    verify.add_argument("file", type=Path)

    restore = sub.add_parser("restore", help="从备份恢复（恢复后需重启服务）")
    restore.add_argument("file", type=Path)
    restore.add_argument("--no-pre-restore", action="store_true", help="不再自动备份当前状态")

    args = parser.parse_args(argv)
    if args.command == "create":
        path = create_backup(out_dir=args.out, include_workspaces=args.with_workspaces)
        print(f"备份完成：{path}（{path.stat().st_size // 1024} KB）")
        return 0
    if args.command == "list":
        rows = list_backups()
        if not rows:
            print("暂无备份")
            return 0
        for row in rows:
            print(
                f"{row['created_at'] if 'created_at' in row else row['modified']}  "
                f"{row['bytes'] // 1024:>8} KB  {row['name']}"
                + (f"  [{row['error']}]" if row.get("error") else "")
            )
        return 0
    if args.command == "verify":
        manifest = verify_backup(args.file)
        files = manifest.get("files") or {}
        print(
            f"校验通过：{args.file}\n"
            f"  工具版本 {manifest.get('tool_version')} · 创建于 {manifest.get('created_at')}\n"
            f"  包含 {len(files)} 个文件：" + "、".join(files)
        )
        return 0
    if args.command == "restore":
        result = restore_backup(args.file, keep_pre_restore=not args.no_pre_restore)
        print(
            f"恢复完成：{', '.join(result['restored'])}\n"
            f"  恢复前的当前状态备份：{result['pre_restore'] or '（未创建）'}\n"
            "  ⚠️ 请重启 Web / API / 调度器使恢复生效。"
        )
        return 0
    return 1


if __name__ == "__main__":  # pragma: no cover - CLI 入口
    sys.exit(cli())
