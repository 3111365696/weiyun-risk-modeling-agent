"""Web 回归测试：系统配置页必须在生产执行路径下完整渲染。

背景：main.py 是「模块级执行」脚本，`render_settings()` 在 2163 行就被调用，
而辅助函数若定义在文件更下方（如 `_usage_month_groups` 原先在 4262 行），
渲染时就会 `NameError`，页面前半部分正常、后半部分整块报错。
这里用 Streamlit AppTest 走与浏览器完全相同的路径，防止同类问题再次发生。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

streamlit = pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

sys.path.insert(0, str(ROOT / "apps"))
sys.path.insert(0, str(ROOT / "apps" / "web"))

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
    return store_module


def _app(view: str, language: str = "zh") -> AppTest:
    at = AppTest.from_file(MAIN, default_timeout=120)
    at.session_state["authenticated"] = True
    at.session_state["user"] = "admin"
    at.session_state["role"] = "admin"
    at.session_state["ui_language"] = language
    at.session_state["view"] = view
    at.run()
    return at


class TestSettingsPage:
    def test_renders_all_sections(self, sandboxed_store):
        at = _app("settings")
        assert [e.value for e in at.exception] == []
        titles = [m.value for m in at.markdown if m.value.strip().startswith("####")]
        for expected in (
            "#### 模型服务",
            "#### 当前配置",
            "#### GitHub 集成",
            "#### 分析参数",
            "#### 报告模板",
            "#### 安全策略",
            "#### 用量与成本",
            "#### API 访问",
        ):
            assert expected in titles, f"缺少区块 {expected}（实际：{titles}）"

    def test_renders_in_english(self, sandboxed_store):
        at = _app("settings", language="en")
        assert [e.value for e in at.exception] == []
        titles = [m.value for m in at.markdown if m.value.strip().startswith("####")]
        assert "#### Model service" in titles
        # 曾硬编码中文的几处必须随语言切换
        assert any("- Provider:" in m.value for m in at.markdown), "当前配置摘要未翻译"
        assert any(
            sl.label == "Max token budget for repo analysis" for sl in at.slider
        ), "token 上限滑块未翻译"
        assert any("Changes apply immediately" in c.value for c in at.caption), "保存状态说明未翻译"
        assert not any("#### 模型服务" in m.value for m in at.markdown)

    def test_save_button_works(self, sandboxed_store):
        at = _app("settings")
        assert [e.value for e in at.exception] == []
        at.button(key="save_server_config").click().run()
        assert [e.value for e in at.exception] == []
        assert any("加密保存" in s.value for s in at.success)
        assert sandboxed_store.config_saved_at(), "配置应已持久化"

    def test_usage_section_renders_with_data(self, sandboxed_store):
        """本月有调用记录时，配置页的用量表格也必须正常渲染（原 NameError 触发点）。"""
        from common import usage as usage_module

        usage_module.record_usage(
            actor="admin",
            source="web",
            provider="OpenAI API",
            model="gpt-4o-mini",
            kind="threat_model",
            project="演示",
            prompt_tokens=100,
            completion_tokens=50,
        )
        at = _app("settings")
        assert [e.value for e in at.exception] == []
        tables = [m.value for m in at.markdown if "| 模型 | 调用 | tokens |" in m.value]
        assert tables, "应渲染按模型的用量表格"

    def test_main_page_still_renders(self, sandboxed_store):
        at = _app("main")
        assert [e.value for e in at.exception] == []
