"""结构化日志：JSON 行、按大小轮转、上下文（追踪编号/用户/来源）。

设计目标（P7 工程化）：

- 每个进程调用一次 ``setup("<组件>")``（web / api / scheduler / cli），
  日志写入 ``<数据目录>/logs/<组件>.jsonl``，单文件 5MB、保留 5 份。
- 机器可读：每行一个 JSON 对象，含 ts/level/logger/msg/pid/thread 以及
  当前上下文（trace/user/source/...）与 ``extra=`` 附加字段；异常带完整堆栈。
- 上下文用 ``contextvars`` 保存：每个请求/页面重跑/任务线程各自独立，
  不会互相串号；``reset_context()`` 在重跑或请求开始时重置。
- ``recent_errors()`` 供「系统状态」页读取最近的告警/错误。
"""

from __future__ import annotations

import contextlib
import contextvars
import json
import logging
import logging.handlers
import os
import socket
import uuid
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT_LOGGER = "wy"
_DEFAULT_MAX_BYTES = 5 * 1024 * 1024
_DEFAULT_BACKUPS = 5

_context: contextvars.ContextVar[dict[str, Any]] = contextvars.ContextVar(
    "wy_log_context", default=None  # type: ignore[arg-type]  # 见下方读取处的空值兜底
)
_configured_components: set[str] = set()
_signatures: dict[str, tuple] = {}
_log_dir: Path | None = None

_STANDARD_ATTRS = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "taskName", "message", "asctime",
}


def default_log_dir() -> Path:
    """日志目录：跟随数据目录（测试里可被 store.DATA_DIR 的重定向自然带走）。"""
    from . import store

    return Path(store.DATA_DIR) / "logs"


def log_dir() -> Path | None:
    return _log_dir


def _resolve_log_dir(explicit: Path | None) -> Path:
    target = Path(explicit) if explicit is not None else default_log_dir()
    target.mkdir(parents=True, exist_ok=True)
    return target


class _JsonFormatter(logging.Formatter):
    """一行一个 JSON 对象；上下文 + extra 字段平铺进去。"""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created).astimezone().isoformat(
                timespec="milliseconds"
            ),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "pid": record.process,
            "thread": record.threadName,
            "host": socket.gethostname(),
        }
        ctx = _context.get() or {}
        payload.update({key: value for key, value in ctx.items() if value not in (None, "")})
        payload.update(
            {
                key: value
                for key, value in record.__dict__.items()
                if key not in _STANDARD_ATTRS and not key.startswith("_")
            }
        )
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


def setup(
    component: str,
    *,
    log_dir_path: Path | None = None,
    level: int | str | None = None,
    console: bool = False,
    max_bytes: int = _DEFAULT_MAX_BYTES,
    backups: int = _DEFAULT_BACKUPS,
) -> Path:
    """初始化组件日志。可重复调用（测试会用不同目录重建）。"""
    global _log_dir
    target = _resolve_log_dir(log_dir_path)
    _log_dir = target

    resolved_level = level or os.environ.get("STRIDE_GPT_LOG_LEVEL") or "INFO"
    if isinstance(resolved_level, str):
        resolved_level = getattr(logging, resolved_level.upper(), logging.INFO)

    signature = (str(target), resolved_level, console, max_bytes, backups)
    if _signatures.get(component) == signature and component in _configured_components:
        return target  # 页面重跑时保持同一套 handler，避免频繁开关文件

    root = logging.getLogger(ROOT_LOGGER)
    root.setLevel(resolved_level)
    for handler in list(root.handlers):  # 重建时清掉旧 handler，避免重复写
        root.removeHandler(handler)
        with contextlib.suppress(Exception):
            handler.close()

    file_handler = logging.handlers.RotatingFileHandler(
        target / f"{component}.jsonl",
        maxBytes=max_bytes,
        backupCount=backups,
        encoding="utf-8",
    )
    file_handler.setFormatter(_JsonFormatter())
    root.addHandler(file_handler)

    if console:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(_JsonFormatter())
        root.addHandler(console_handler)

    _configured_components.add(component)
    _signatures[component] = signature
    set_context(component=component)
    return target


def get_logger(name: str = "") -> logging.Logger:
    return logging.getLogger(f"{ROOT_LOGGER}.{name}" if name else ROOT_LOGGER)


def set_context(**kwargs: Any) -> None:
    """整体替换日志上下文（页面重跑 / 请求开始时应调用）。"""
    _context.set({k: v for k, v in kwargs.items() if v not in (None, "")})


def clear_context() -> None:
    _context.set({})


def bind(**kwargs: Any) -> None:
    """合并式追加上下文（保留已有键）。"""
    merged = dict(_context.get() or {})
    merged.update({k: v for k, v in kwargs.items() if v not in (None, "")})
    _context.set(merged)


@contextlib.contextmanager
def bound(**kwargs: Any) -> Iterator[None]:
    """临时上下文（块结束自动还原），适合任务/工具调用。"""
    token = _context.set(
        {**(_context.get() or {}), **{k: v for k, v in kwargs.items() if v not in (None, "")}}
    )
    try:
        yield
    finally:
        _context.reset(token)


def new_trace(prefix: str = "") -> str:
    """生成短的追踪编号，如 ``web-3f9a1c2b``。"""
    token = uuid.uuid4().hex[:8]
    return f"{prefix}-{token}" if prefix else token


def current_trace() -> str:
    return str((_context.get() or {}).get("trace") or "")


def _tail_lines(path: Path, *, max_bytes: int = 512 * 1024) -> list[str]:
    try:
        size = path.stat().st_size
        with path.open("rb") as fh:
            if size > max_bytes:
                fh.seek(size - max_bytes)
                fh.readline()  # 丢掉可能被截断的首行
            data = fh.read()
    except OSError:
        return []
    return data.decode("utf-8", errors="replace").splitlines()


def recent_errors(limit: int = 20, *, directory: Path | None = None) -> list[dict]:
    """最近的 WARNING 及以上日志（新→旧）。"""
    target = Path(directory) if directory is not None else _log_dir
    if target is None or not Path(target).is_dir():
        return []
    rows: list[tuple[str, int, dict]] = []
    seq = 0
    for path in sorted(Path(target).glob("*.jsonl")):
        for line in _tail_lines(path):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if str(entry.get("level", "")).upper() in {"WARNING", "ERROR", "CRITICAL"}:
                entry.setdefault("component", path.stem)
                rows.append((str(entry.get("ts") or ""), seq, entry))
                seq += 1
    # 时间戳同毫秒时用写入顺序兜底，保证「后写的更新」
    rows.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return [entry for _, _, entry in rows[:limit]]


def log_files() -> list[dict]:
    """日志文件清单（供状态页展示）。"""
    if _log_dir is None or not Path(_log_dir).is_dir():
        return []
    out = []
    for path in sorted(Path(_log_dir).glob("*")):
        if path.is_file():
            stat = path.stat()
            out.append(
                {
                    "name": path.name,
                    "bytes": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                }
            )
    return out


def configured_components() -> list[str]:
    return sorted(_configured_components)
