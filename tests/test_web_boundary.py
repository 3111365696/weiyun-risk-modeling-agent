"""P7 测试：Web 错误边界（友好错误卡片 + 日志 + 审计）。"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "apps"))
sys.path.insert(0, str(ROOT / "apps" / "web"))

streamlit = pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

PROBE = '''\
import os, sys
sys.path[:0] = [{apps!r}, {web!r}]
import streamlit as st
from common import logging_setup, store

logging_setup.setup("web", log_dir_path=__import__("pathlib").Path(os.environ["PROBE_LOG_DIR"]))
st.session_state.setdefault("user", "admin")
st.session_state.setdefault("role", "admin")
st.session_state.setdefault("ui_language", "zh")

from error_boundary import guard


def boom():
    raise RuntimeError("测试用故障")


guard("unit-page")(boom)()
'''


@pytest.fixture()
def probe(tmp_path, monkeypatch):
    from common import store as store_module

    data_dir = tmp_path / "data"
    data_dir.mkdir()
    monkeypatch.setattr(store_module, "DATA_DIR", data_dir)
    monkeypatch.setattr(store_module, "CONFIG_FILE", data_dir / "web_config.json")
    monkeypatch.setattr(store_module, "KEY_FILE", data_dir / "web_key")
    monkeypatch.setattr(store_module, "DB_FILE", data_dir / "web.db")

    log_dir = tmp_path / "logs"
    script = tmp_path / "probe_boundary.py"
    script.write_text(
        PROBE.format(apps=str(ROOT / "apps"), web=str(ROOT / "apps" / "web")),
        encoding="utf-8",
    )
    monkeypatch.setenv("PROBE_LOG_DIR", str(log_dir))
    return script, log_dir, store_module


class TestBoundaryRendering:
    def test_shows_friendly_error_with_id(self, probe):
        script, log_dir, store_module = probe
        at = AppTest.from_file(str(script), default_timeout=90)
        at.run()
        assert [e.value for e in at.exception] == [], "错误不应冒泡成堆栈"
        errors = [e.value for e in at.error]
        assert errors, "应显示错误卡片"
        match = re.search(r"ERR-[0-9A-F]{6}", errors[0])
        assert match, f"错误卡片应包含错误编号：{errors[0]}"

        # 管理员可见技术细节
        details = "\n".join(code.value for code in at.code)
        assert "RuntimeError" in details and "测试用故障" in details

        # 审计日志
        audit = store_module.list_audit(limit=5)
        assert any(row["action"] == "页面异常" for row in audit)
        assert match.group(0) in audit[0]["detail"]

        # 结构化日志含 page / error_id / 堆栈
        rows = [
            json.loads(line)
            for line in (log_dir / "web.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        hit = [row for row in rows if row.get("error_id") == match.group(0)]
        assert hit, "结构化日志里应能按 error_id 找到"
        assert hit[0]["page"] == "unit-page"
        assert hit[0]["level"] == "ERROR"
        assert "RuntimeError" in hit[0]["exc"]

    def test_non_admin_sees_no_traceback(self, probe):
        script, _, _ = probe
        at = AppTest.from_file(str(script), default_timeout=90)
        at.session_state["role"] = "user"
        at.session_state["user"] = "someone"
        at.run()
        assert [e.value for e in at.exception] == []
        assert at.error, "普通用户也应看到错误卡片"
        assert not at.code, "普通用户不应看到堆栈"


class TestControlFlowPassthrough:
    def test_rerun_exception_propagates(self):
        from error_boundary import guard

        class RerunException(Exception):  # noqa: N818 —— 名字必须与 Streamlit 一致
            pass

        def trigger():
            raise RerunException()

        with pytest.raises(RerunException):
            guard("x")(trigger)()

    def test_stop_exception_propagates(self):
        from error_boundary import guard

        class StopException(Exception):  # noqa: N818 —— 名字必须与 Streamlit 一致
            pass

        def trigger():
            raise StopException()

        with pytest.raises(StopException):
            guard("x")(trigger)()

    def test_error_id_format(self):
        from error_boundary import new_error_id

        ids = {new_error_id() for _ in range(50)}
        assert len(ids) == 50
        assert all(re.fullmatch(r"ERR-[0-9A-F]{6}", item) for item in ids)


class TestMainPageGuard:
    """main.py 的页面注册必须包了错误边界（防止回归去掉 guard）。"""

    def test_pages_are_guarded(self):
        import ast

        source = (ROOT / "apps" / "web" / "main.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        page_calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "Page"
        ]
        assert len(page_calls) >= 11, "页面注册数量异常"
        for call in page_calls:
            first = call.args[0] if call.args else None
            assert first is not None, "st.Page 缺少页面函数"
            # 注册形态是 guard("<slug>")(_page_xxx)
            wrapped = isinstance(first, ast.Call) and isinstance(first.func, ast.Call)
            assert wrapped and getattr(first.func.func, "id", "") == "guard", (
                f"页面 {ast.dump(first)[:80]} 未套错误边界"
            )
        assert 'guard_block("settings")' in source
        assert 'guard_block("system-status")' in source
        assert "from error_boundary import guard, guard_block" in source
