"""Web 脚本静态检查：防止局部变量遮蔽 i18n/公共层名字（曾导致项目工作区 UnboundLocalError）。"""

from __future__ import annotations

import ast
from pathlib import Path

MAIN = Path(__file__).resolve().parent.parent / "apps" / "web" / "main.py"

WATCHED = {
    "_t",
    "_i18n",
    "_generation",
    "_exporters",
    "_kind_label",
    "_ui_label",
    "_store",
    "_generation_apply_policies",
}


def _module_level_names(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(node.name)
    return names


def test_no_local_shadowing_of_module_helpers():
    tree = ast.parse(MAIN.read_text(encoding="utf-8"))
    module_names = _module_level_names(tree)
    watched = WATCHED & module_names
    issues: list[str] = []
    for func in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        for child in ast.walk(func):
            targets: list[ast.expr] = []
            if isinstance(child, ast.Assign):
                targets = list(child.targets)
            elif isinstance(child, (ast.AnnAssign, ast.AugAssign)) or isinstance(child, (ast.For, ast.AsyncFor)):
                targets = [child.target]
            for target in targets:
                for name_node in ast.walk(target):
                    if isinstance(name_node, ast.Name) and name_node.id in watched:
                        issues.append(f"{func.name}: 局部变量 {name_node.id} 遮蔽了模块级名字")
    assert not issues, "发现名字遮蔽：\n" + "\n".join(issues)


def test_page_functions_exist_and_are_registered():
    src = MAIN.read_text(encoding="utf-8")
    tree = ast.parse(src)
    funcs = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    for page_func in ("_page_threat_model", "_page_projects", "_page_reports", "_page_users"):
        assert page_func in funcs, f"缺少页面函数 {page_func}"
        assert f"{page_func}," in src or f"{page_func})" in src, f"{page_func} 未注册到路由"
