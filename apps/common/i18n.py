"""轻量国际化：UI 文案中英切换。

用法：`t("中文", "English")`。语言由上层应用通过 set_language() 设置（默认 zh）。
"""

from __future__ import annotations

LANGUAGES = {"zh": "简体中文", "en": "English"}
DEFAULT_LANGUAGE = "zh"

_current = DEFAULT_LANGUAGE


def set_language(lang: str | None) -> None:
    global _current
    _current = lang if lang in LANGUAGES else DEFAULT_LANGUAGE


def current_language() -> str:
    return _current


def t(zh: str, en: str) -> str:
    """按当前语言返回文案。"""
    return en if _current == "en" else zh
