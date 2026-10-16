"""产品版本与构建信息（单一数据源）。

版本号来自 pyproject.toml（打包元数据兜底）；构建信息含 git 提交号、Python 版本，
用于「系统状态」页、登录页角标、`/api/v1/health` 与问题排查。
"""

from __future__ import annotations

import platform
import subprocess
import sys
from functools import lru_cache
from pathlib import Path

PRODUCT_NAME = "威云-风险建模智能体"
PRODUCT_NAME_EN = "Weiyun Risk Modeling Agent"
HOMEPAGE = "https://github.com/…"  # 内部部署无需外链

_REPO_ROOT = Path(__file__).resolve().parents[2]


@lru_cache(maxsize=1)
def package_version() -> str:
    """读取 pyproject.toml 的 project.version；读不到时退回已安装包元数据。"""
    try:
        import tomllib

        with (_REPO_ROOT / "pyproject.toml").open("rb") as fh:
            version = str(tomllib.load(fh).get("project", {}).get("version") or "")
            if version:
                return version
    except Exception:
        pass
    try:
        from importlib.metadata import version as _dist_version

        return _dist_version("stride-gpt")
    except Exception:
        return "0.0.0"


@lru_cache(maxsize=1)
def git_commit() -> str:
    """当前 git 提交短号（未提交时加 `*` 后缀）；非 git 环境返回空串。"""
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        ).stdout.strip()
        if not commit:
            return ""
        dirty = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        ).stdout.strip()
        return f"{commit}*" if dirty else commit
    except Exception:
        return ""


def build_info() -> dict:
    return {
        "product": PRODUCT_NAME,
        "product_en": PRODUCT_NAME_EN,
        "version": package_version(),
        "commit": git_commit(),
        "python": platform.python_version(),
        "platform": f"{platform.system()} {platform.machine()}",
        "executable": sys.executable,
    }


def version_line() -> str:
    """形如 ``v1.0.0 (8db7f2b)``。"""
    commit = git_commit()
    return f"v{package_version()}" + (f" ({commit})" if commit else "")
