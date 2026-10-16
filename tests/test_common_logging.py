"""P7 测试：结构化日志与错误边界。"""

from __future__ import annotations

import json
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "apps"))

from common import logging_setup


@pytest.fixture()
def log_dir(tmp_path):
    target = tmp_path / "logs"
    logging_setup.setup("test", log_dir_path=target, console=False)
    yield target
    logging_setup.clear_context()


def _read(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


class TestJsonLogging:
    def test_line_has_core_fields(self, log_dir):
        logging_setup.set_context(source="test", trace="tr-1", user="admin")
        logging_setup.get_logger("unit").info("生成完成", extra={"project": "演示", "tokens": 128})
        row, = _read(log_dir / "test.jsonl")
        assert row["level"] == "INFO"
        assert row["logger"] == "wy.unit"
        assert row["msg"] == "生成完成"
        assert row["source"] == "test"
        assert row["trace"] == "tr-1"
        assert row["user"] == "admin"
        assert row["project"] == "演示"
        assert row["tokens"] == 128
        assert row["pid"] and row["thread"] and row["ts"]

    def test_exception_included(self, log_dir):
        log = logging_setup.get_logger("unit")
        try:
            raise ValueError("坏掉了")
        except ValueError:
            log.error("操作失败", exc_info=True)
        row, = _read(log_dir / "test.jsonl")
        assert "ValueError: 坏掉了" in row["exc"]
        assert "Traceback" in row["exc"]

    def test_extra_fields_are_flattened(self, log_dir):
        with pytest.raises(KeyError):
            # 标准字段由 logging 自己保护：extra 里同名键会直接报错
            logging_setup.get_logger("unit").info("hi", extra={"pathname": "nope"})
        logging_setup.get_logger("unit").info("hi", extra={"rule": "wy-1", "severity": "high"})
        row, = _read(log_dir / "test.jsonl")
        assert row["rule"] == "wy-1"
        assert row["severity"] == "high"
        assert "pathname" not in row  # 标准字段不进 JSON（payload 保持精简）

    def test_setup_is_idempotent(self, log_dir):
        handler_count = len(logging_setup.get_logger().handlers)
        logging_setup.setup("test", log_dir_path=log_dir)
        assert len(logging_setup.get_logger().handlers) == handler_count

    def test_rotation_settings(self, log_dir):
        logging_setup.setup("rot", log_dir_path=log_dir, max_bytes=1024, backups=2)
        handler = next(
            h for h in logging_setup.get_logger().handlers
            if isinstance(h, logging_setup.logging.handlers.RotatingFileHandler)
        )
        assert handler.maxBytes == 1024
        assert handler.backupCount == 2


class TestContext:
    def test_bind_merges_and_reset_clears(self, log_dir):
        logging_setup.set_context(source="api", trace="t1")
        logging_setup.bind(user="u1")
        logging_setup.get_logger("x").info("m")
        logging_setup.set_context(source="api")
        logging_setup.get_logger("x").info("m2")
        rows = _read(log_dir / "test.jsonl")
        assert rows[0]["user"] == "u1"
        assert "user" not in rows[1]

    def test_bound_is_scoped(self, log_dir):
        logging_setup.set_context(source="web")
        with logging_setup.bound(project="p1"):
            logging_setup.get_logger("x").info("inner")
        logging_setup.get_logger("x").info("outer")
        rows = _read(log_dir / "test.jsonl")
        assert rows[0]["project"] == "p1"
        assert "project" not in rows[1]

    def test_context_is_per_thread(self, log_dir):
        logging_setup.set_context(source="main", trace="main-trace")
        seen: list[str] = []

        def worker():
            seen.append(logging_setup.current_trace() or "无")
            logging_setup.bind(trace="worker-trace")
            seen.append(logging_setup.current_trace())

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join()
        assert seen == ["无", "worker-trace"]  # 线程内初始为空，不串主线程上下文
        assert logging_setup.current_trace() == "main-trace"

    def test_new_trace_unique(self):
        ids = {logging_setup.new_trace("web") for _ in range(200)}
        assert len(ids) == 200
        assert all(item.startswith("web-") for item in ids)


class TestRecentErrors:
    def test_reads_and_sorts_newest_first(self, log_dir):
        log = logging_setup.get_logger("unit")
        log.info("普通信息")
        log.warning("注意", extra={"code": "W1"})
        log.error("失败", extra={"code": "E1"})
        rows = logging_setup.recent_errors(directory=log_dir)
        assert [r["code"] for r in rows[:2]] == ["E1", "W1"]
        assert all(r["level"] in {"WARNING", "ERROR", "CRITICAL"} for r in rows)

    def test_limit_and_empty(self, log_dir):
        for index in range(10):
            logging_setup.get_logger("unit").warning(f"w{index}")
        assert len(logging_setup.recent_errors(limit=3, directory=log_dir)) == 3
        assert logging_setup.recent_errors(directory=log_dir / "none") == []

    def test_ignores_broken_lines(self, log_dir):
        (log_dir / "test.jsonl").write_text("不是 JSON\n" + json.dumps(
            {"ts": "2026-01-01T00:00:00", "level": "ERROR", "msg": "ok"}
        ), encoding="utf-8")
        rows = logging_setup.recent_errors(directory=log_dir)
        assert len(rows) == 1
        assert rows[0]["msg"] == "ok"

    def test_log_files_listing(self, log_dir):
        logging_setup.get_logger("unit").info("x")
        files = logging_setup.log_files()
        assert any(item["name"] == "rot.jsonl" or item["name"] == "test.jsonl" for item in files)
