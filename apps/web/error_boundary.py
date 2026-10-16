"""Web 页面错误边界：把 Python 堆栈换成「友好错误卡片 + 错误编号」。

- 完整堆栈进结构化日志（含 trace/页面/用户）
- 审计日志记一行「页面异常」，便于事后检索
- 管理员（或 STRIDE_GPT_DEBUG=1）可展开技术细节；普通用户只看到错误编号
- 重新抛出 Streamlit 内部控制流异常（RerunException / StopException 等），
  否则会吞掉 st.rerun() / st.stop() 的行为
"""

from __future__ import annotations

import contextlib
import functools
import os
import traceback
import uuid
from collections.abc import Iterator
from typing import Any

import streamlit as st
from common import logging_setup as _logging
from common import store

_log = _logging.get_logger("web.boundary")

# Streamlit 内部控制流异常（不同版本类路径不同，按类名判断最稳）
_CONTROL_FLOW = {"RerunException", "StopException", "SwitchPageException", "RerunData"}


def new_error_id() -> str:
    return "ERR-" + uuid.uuid4().hex[:6].upper()


def _debug_enabled() -> bool:
    return (os.environ.get("STRIDE_GPT_DEBUG") or "").strip().lower() in {"1", "true", "yes", "on"}


def _is_admin() -> bool:
    return st.session_state.get("role") == "admin" or st.session_state.get("user") == "admin"


def _t(zh: str, en: str) -> str:
    return en if st.session_state.get("ui_language") == "en" else zh


def handle_error(exc: BaseException, page: str) -> str:
    """记录并展示一个页面级异常，返回错误编号。"""
    error_id = new_error_id()
    user = st.session_state.get("user", "")
    trace = _logging.current_trace()
    _log.error(
        "页面渲染异常",
        exc_info=exc,
        extra={"page": page, "error_id": error_id, "user": user, "trace": trace},
    )
    with contextlib.suppress(Exception):
        store.log_action(
            user,
            "页面异常",
            f"{page} · {error_id} · {type(exc).__name__}: {str(exc)[:160]}",
        )

    st.error(
        _t(
            f"这个页面暂时无法显示（错误编号 **{error_id}**）。"
            "已记录到服务端日志；请刷新重试，若反复出现请把错误编号发给管理员。",
            f"This page can't be displayed right now (error ID **{error_id}**). "
            "It has been logged on the server; refresh to retry, or give this ID to your administrator.",
        )
    )
    if _is_admin() or _debug_enabled():
        with st.expander(
            _t("技术细节（管理员可见）", "Technical details (admin only)"), expanded=False
        ):
            st.caption(f"page={page} · error_id={error_id} · trace={trace or '—'}")
            st.code("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)), language="text")
    return error_id


def guard(page: str):
    """装饰页面函数：异常不再冒泡成红色堆栈，而是走错误卡片。"""

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any):
            try:
                return func(*args, **kwargs)
            except Exception as exc:
                if type(exc).__name__ in _CONTROL_FLOW:
                    raise
                handle_error(exc, page)
                return None

        return wrapper

    return decorator


@contextlib.contextmanager
def guard_block(page: str) -> Iterator[None]:
    """with 形式（模块级渲染路径用）。"""
    try:
        yield
    except Exception as exc:
        if type(exc).__name__ in _CONTROL_FLOW:
            raise
        handle_error(exc, page)
