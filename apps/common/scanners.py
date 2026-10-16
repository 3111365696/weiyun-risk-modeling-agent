"""静态分析线索（SAST）：探测本机可用工具、运行、归一化为 agent 可读的线索。

设计原则：
- 工具「可用则用，缺失即降级」——本机没装 semgrep/bandit 等不影响主流程
- 统一输出 Lead（工具/规则/严重度/文件/行号/说明），便于注入提示词与入库
- 子进程一律用参数列表（不经过 shell），带超时与输出截断
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

RULES_FILE = Path(__file__).with_name("semgrep-rules.yml")

_SEVERITY_MAP = {
    "error": "high",
    "warning": "medium",
    "info": "low",
    "critical": "high",
    "high": "high",
    "medium": "medium",
    "low": "low",
    # trivy
    "unknown": "low",
}


@dataclass
class Lead:
    tool: str
    rule: str
    severity: str
    path: str
    line: int | None
    message: str

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "rule": self.rule,
            "severity": self.severity,
            "path": self.path,
            "line": self.line,
            "message": self.message,
        }


@dataclass
class ScannerInfo:
    name: str
    kind: str  # "python" | "binary"
    available: bool
    hint: str = ""
    leads: int = 0
    error: str = ""


def _which(name: str) -> str | None:
    return shutil.which(name)


def probe() -> list[dict]:
    """探测各扫描器是否可用（供 UI 展示）。"""
    scanners = [
        ("semgrep", "静态规则扫描（内置规则包）"),
        ("bandit", "Python 安全缺陷"),
        ("detect-secrets", "密钥/凭据泄露"),
        ("gitleaks", "密钥/凭据泄露"),
        ("trivy", "依赖漏洞与配置问题"),
    ]
    out = []
    for name, hint in scanners:
        out.append(
            {
                "name": name,
                "available": bool(_which(name)),
                "hint": hint,
                "install": "" if _which(name) else _install_hint(name),
            }
        )
    return out


def _install_hint(name: str) -> str:
    if name in ("semgrep", "bandit", "detect-secrets"):
        return "uv sync（scanners 依赖组）"
    if name == "gitleaks":
        return "brew install gitleaks / 下载二进制"
    if name == "trivy":
        return "brew install trivy / 下载二进制"
    return ""


def _run(cmd: list[str], *, timeout: int, cwd: Path | None = None) -> tuple[int, str]:
    env = {**os.environ, "SEMGREP_SEND_METRICS": "off", "NO_COLOR": "1"}
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            env=env,
        )
    except FileNotFoundError:
        return 127, ""
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {timeout}s"
    return proc.returncode, proc.stdout or proc.stderr


def _norm_severity(value: str | None) -> str:
    return _SEVERITY_MAP.get((value or "").strip().lower(), "medium")


def _rel(path: str, root: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(root.resolve()))
    except Exception:
        return str(path)


# ---------------------------------------------------------------------------
# 各扫描器
# ---------------------------------------------------------------------------


def run_semgrep(root: Path, timeout: int) -> tuple[list[Lead], str]:
    binary = _which("semgrep")
    if not binary:
        return [], "semgrep 未安装"
    config = os.getenv("STRIDE_GPT_SEMGREP_CONFIG") or str(RULES_FILE)
    code, out = _run(
        [
            binary,
            "--json",
            "--quiet",
            "--metrics",
            "off",
            "--timeout",
            "10",
            "--max-target-bytes",
            "2000000",
            "--config",
            config,
            str(root),
        ],
        timeout=timeout,
    )
    # semgrep: 0=无命中 1=有命中 2=部分文件/规则失败（仍会返回可用结果）
    try:
        data = json.loads(out or "{}")
    except json.JSONDecodeError:
        return [], (out or "semgrep 输出无法解析")[:200]
    if code not in (0, 1, 2):
        return [], f"semgrep 退出码 {code}：" + (out or "")[:160]
    leads = []
    for item in data.get("results") or []:
        extra = item.get("extra") or {}
        leads.append(
            Lead(
                tool="semgrep",
                rule=str(item.get("check_id") or "").split(".")[-1],
                severity=_norm_severity(extra.get("severity")),
                path=_rel(item.get("path") or "", root),
                line=(item.get("start") or {}).get("line"),
                message=str(extra.get("message") or "")[:300],
            )
        )
    return leads, ""


def run_bandit(root: Path, timeout: int) -> tuple[list[Lead], str]:
    binary = _which("bandit")
    if not binary:
        return [], "bandit 未安装"
    code, out = _run([binary, "-r", "-q", "-f", "json", str(root)], timeout=timeout)
    if code not in (0, 1):
        return [], (out or "bandit 执行失败")[:200]
    try:
        data = json.loads(out or "{}")
    except json.JSONDecodeError:
        return [], "bandit 输出无法解析"
    leads = [
        Lead(
            tool="bandit",
            rule=str(item.get("test_id") or ""),
            severity=_norm_severity(item.get("issue_severity")),
            path=_rel(item.get("filename") or "", root),
            line=item.get("line_number"),
            message=str(item.get("issue_text") or "")[:300],
        )
        for item in data.get("results") or []
    ]
    return leads, ""


def run_detect_secrets(root: Path, timeout: int) -> tuple[list[Lead], str]:
    binary = _which("detect-secrets")
    if not binary:
        return [], "detect-secrets 未安装"
    code, out = _run(
        [binary, "scan", "--all-files", "--force-use-all-plugins", str(root)],
        timeout=timeout,
    )
    if code != 0:
        return [], (out or "detect-secrets 执行失败")[:200]
    try:
        data = json.loads(out or "{}")
    except json.JSONDecodeError:
        return [], "detect-secrets 输出无法解析"
    leads = [
        Lead(
            tool="detect-secrets",
            rule=str(item.get("type") or "secret"),
            severity="high",
            path=_rel(path, root),
            line=item.get("line_number"),
            message="疑似密钥/凭据泄露",
        )
        for path, items in (data.get("results") or {}).items()
        for item in items
    ]
    return leads, ""


def run_gitleaks(root: Path, timeout: int) -> tuple[list[Lead], str]:
    binary = _which("gitleaks")
    if not binary:
        return [], "gitleaks 未安装"
    code, out = _run(
        [
            binary,
            "detect",
            "--no-git",
            "--source",
            str(root),
            "--report-format",
            "json",
            "--report-path",
            "/dev/stdout",
            "--exit-code",
            "0",
        ],
        timeout=timeout,
    )
    if code not in (0, 1):
        return [], (out or "gitleaks 执行失败")[:200]
    try:
        data = json.loads(out or "[]")
    except json.JSONDecodeError:
        return [], "gitleaks 输出无法解析"
    leads = [
        Lead(
            tool="gitleaks",
            rule=str(item.get("RuleID") or "secret"),
            severity="high",
            path=_rel(item.get("File") or "", root),
            line=item.get("StartLine"),
            message=str(item.get("Description") or "疑似密钥泄露")[:300],
        )
        for item in (data if isinstance(data, list) else [])
    ]
    return leads, ""


def run_trivy(root: Path, timeout: int) -> tuple[list[Lead], str]:
    binary = _which("trivy")
    if not binary:
        return [], "trivy 未安装"
    code, out = _run(
        [binary, "fs", "--quiet", "--format", "json", "--scanners", "vuln,misconfig", str(root)],
        timeout=timeout,
    )
    if code != 0:
        return [], (out or "trivy 执行失败")[:200]
    try:
        data = json.loads(out or "{}")
    except json.JSONDecodeError:
        return [], "trivy 输出无法解析"
    leads: list[Lead] = []
    for result in data.get("Results") or []:
        target = result.get("Target") or ""
        leads.extend(
            Lead(
                tool="trivy",
                rule=str(item.get("VulnerabilityID") or ""),
                severity=_norm_severity(item.get("Severity")),
                path=_rel(target, root),
                line=None,
                message=f"{item.get('PkgName')} {item.get('InstalledVersion')} -> "
                f"{item.get('FixedVersion') or '无修复版本'}: "
                f"{str(item.get('Title') or '')[:160]}",
            )
            for item in result.get("Vulnerabilities") or []
        )
        leads.extend(
            Lead(
                tool="trivy",
                rule=str(item.get("ID") or ""),
                severity=_norm_severity(item.get("Severity")),
                path=_rel(target, root),
                line=None,
                message=str(item.get("Title") or "")[:200],
            )
            for item in result.get("Misconfigurations") or []
        )
    return leads, ""


_ADAPTERS = [
    ("semgrep", run_semgrep),
    ("bandit", run_bandit),
    ("detect-secrets", run_detect_secrets),
    ("gitleaks", run_gitleaks),
    ("trivy", run_trivy),
]


def run_scanners(
    root: Path,
    *,
    max_leads: int = 80,
    per_tool_timeout: int = 120,
    only: list[str] | None = None,
) -> dict:
    """运行所有可用扫描器，返回 {leads, scanners, skipped}。"""
    leads: list[Lead] = []
    infos: list[ScannerInfo] = []
    for name, adapter in _ADAPTERS:
        if only and name not in only:
            continue
        if not _which(name):
            infos.append(ScannerInfo(name=name, kind="binary", available=False,
                                     hint=_install_hint(name)))
            continue
        tool_leads, error = adapter(root, per_tool_timeout)
        infos.append(
            ScannerInfo(
                name=name,
                kind="binary",
                available=True,
                leads=len(tool_leads),
                error=error,
            )
        )
        leads.extend(tool_leads)

    # 去重（工具+文件+行+规则）并按严重度排序
    seen = set()
    unique: list[Lead] = []
    for lead in leads:
        key = (lead.tool, lead.path, lead.line, lead.rule)
        if key in seen:
            continue
        seen.add(key)
        unique.append(lead)
    order = {"high": 0, "medium": 1, "low": 2}
    unique.sort(key=lambda item: (order.get(item.severity, 3), item.path, item.line or 0))
    truncated = len(unique) > max_leads
    unique = unique[:max_leads]
    return {
        "leads": unique,
        "scanners": infos,
        "truncated": truncated,
        "total_before_cap": len(leads),
    }


def leads_markdown(leads: list[Lead], *, limit: int = 60, max_chars: int = 4000) -> str:
    """把线索整理成紧凑的提示词片段（带工具与行号，便于 agent 核实）。"""
    if not leads:
        return ""
    lines = [
        "## 静态分析线索（来自本机扫描工具，可能包含误报）",
        "请优先核实与当前子系统相关的条目；确认属实的威胁请在证据中引用对应代码。",
        "",
    ]
    used = 0
    for lead in leads[:limit]:
        loc = f"{lead.path}:{lead.line}" if lead.line else lead.path
        line = f"- [{lead.severity}] {loc} · {lead.tool}/{lead.rule}：{lead.message}"
        if used + len(line) > max_chars:
            lines.append("- （更多线索已省略）")
            break
        lines.append(line)
        used += len(line)
    return "\n".join(lines)


def summarize_for_report(leads: list[Lead]) -> dict:
    by_severity: dict[str, int] = {}
    by_tool: dict[str, int] = {}
    for lead in leads:
        by_severity[lead.severity] = by_severity.get(lead.severity, 0) + 1
        by_tool[lead.tool] = by_tool.get(lead.tool, 0) + 1
    return {"total": len(leads), "by_severity": by_severity, "by_tool": by_tool}
