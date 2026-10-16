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


def _shadowing_issues(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    module_names = _module_level_names(tree)
    watched = WATCHED & module_names
    issues: list[str] = []
    for func in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        for child in ast.walk(func):
            targets: list[ast.expr] = []
            if isinstance(child, ast.Assign):
                targets = list(child.targets)
            elif isinstance(child, (ast.AnnAssign, ast.AugAssign, ast.For, ast.AsyncFor)):
                targets = [child.target]
            for target in targets:
                issues.extend(
                    f"{path.name}:{func.name} 局部变量 {node.id} 遮蔽了模块级名字"
                    for node in ast.walk(target)
                    if isinstance(node, ast.Name) and node.id in watched
                )
    return issues


def test_no_local_shadowing_of_module_helpers():
    """P7 拆分后覆盖 apps/web 下所有模块（页面在 pages/ 里）。"""
    web_dir = MAIN.parent
    issues: list[str] = []
    for path in sorted(web_dir.rglob("*.py")):
        issues.extend(_shadowing_issues(path))
    assert not issues, "发现名字遮蔽：\n" + "\n".join(issues)


def test_page_functions_exist_and_are_registered():
    """页面实现分布在 pages/*.py，main.py 负责注册（P7 拆分后按全目录查找）。"""
    web_dir = MAIN.parent
    defined: set[str] = set()
    for path in web_dir.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        defined |= {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}

    main_src = MAIN.read_text(encoding="utf-8")
    for page_func in (
        "_page_threat_model",
        "_page_projects",
        "_page_reports",
        "_page_users",
        "_page_code_audit",
        "_page_overview",
    ):
        assert page_func in defined, f"缺少页面函数 {page_func}"
        assert page_func in main_src, f"{page_func} 未在 main.py 注册/导入"


def test_main_py_is_bootstrap_sized():
    """main.py 只做装配：拆分后不应再膨胀回巨石文件。"""
    lines = MAIN.read_text(encoding="utf-8").splitlines()
    assert len(lines) < 700, f"main.py 已 {len(lines)} 行，页面实现应放进 pages/"


def test_page_modules_import_from_shared_only():
    """页面模块不得反向 import main（会造成循环依赖）。"""
    for path in (MAIN.parent / "pages").glob("*.py"):
        src = path.read_text(encoding="utf-8")
        assert "import main" not in src, f"{path.name} 不应 import main"
