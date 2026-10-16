"""i18n 门禁：界面中文字面量必须用 _t(中文, English) 包裹。

允许的中文场景（不算违规）：
- 中英标签字典（*_LABELS / *_FIELDS / *_CSS / *_JS …）；
- 日志与审计（log_action / logging）；
- 提示词构造与诊断函数（generate_/build_/create_/analyze_/summarize_/inject_theme）；
- 数据枚举值（威胁状态、验证结论、置信度等，属数据库取值而非界面文案）。

新增页面/文案若忘记 _t 包裹，本测试会失败并给出文件:行号。
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "apps" / "web"

CJK = re.compile(r"[\u4e00-\u9fff]")

# 数据库枚举取值（界面文案由映射表负责翻译）
DATA_ENUMS = {
    "待处理",
    "已确认",
    "已修复",
    "已接受",
    "已忽略",
    "存疑",
    "已驳回",
    "未验证",
    "高",
    "中",
    "低",
    "admin",
    "user",
}
LABEL_TARGET = re.compile(r"(_LABELS(_EN)?|_FIELDS|_CSS|_JS|_KEY_BY_PROVIDER|_MAP|_HINTS|_TEXTS)$")
PROMPT_FUNC_PREFIX = (
    "generate_",
    "build_",
    "create_",
    "analyze_",
    "summarize_",
    "inject_theme",
)
ALLOWED_CALLS = {"_t", "t", "log_action"}
LOG_CALLS = {"debug", "info", "warning", "warn", "error", "exception", "critical"}


def _call_name(call: ast.Call) -> str:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def collect_violations(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    parents: dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node

    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = getattr(node, "body", [])
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                docstrings.add(id(body[0].value))

    problems: list[str] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            continue
        text = node.value
        if not CJK.search(text) or id(node) in docstrings or text in DATA_ENUMS:
            continue
        allowed = False
        cur: ast.AST = node
        while id(cur) in parents:
            cur = parents[id(cur)]
            if isinstance(cur, ast.Call):
                name = _call_name(cur)
                func = cur.func
                is_logger = (
                    isinstance(func, ast.Attribute)
                    and isinstance(func.value, ast.Name)
                    and func.value.id in {"_log", "log", "logger"}
                )
                if name in ALLOWED_CALLS or (is_logger and name in LOG_CALLS):
                    allowed = True
                    break
            if isinstance(cur, ast.Assign):
                targets = [t.id for t in cur.targets if isinstance(t, ast.Name)] + [
                    t.attr for t in cur.targets if isinstance(t, ast.Attribute)
                ]
                if any(LABEL_TARGET.search(name) for name in targets):
                    allowed = True
                    break
            if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
                allowed = cur.name.startswith(PROMPT_FUNC_PREFIX)
                break
            if isinstance(cur, ast.Module):
                break
        if not allowed:
            problems.append(f"{path.relative_to(ROOT)}:{node.lineno}: {text[:70]!r}")
    return problems


def test_all_ui_chinese_literals_are_wrapped():
    problems: list[str] = []
    for path in sorted(WEB.rglob("*.py")):
        problems.extend(collect_violations(path))
    assert not problems, (
        f"发现 {len(problems)} 处未国际化的界面文案（用 _t(中文, English) 包裹）：\n"
        + "\n".join(problems[:40])
    )
