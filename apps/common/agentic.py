"""Agentic 代码库分析（Web / API 共用）：安全解压、克隆、运行 agent 引擎、归档。

安全边界：
- ZIP：拒绝路径穿越/绝对路径/符号链接，限制解压总量与文件数
- Git：仅 https，主机白名单（github.com / gitlab.com / 环境变量追加），深度 1、无子模块、
  禁止交互式认证；令牌只在主机校验通过后通过 http.extraheader 注入，不落入 URL 与日志
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import stat
import subprocess
import uuid
import zipfile
from pathlib import Path

from stride_gpt.agent.loop import run_analysis
from stride_gpt.agent.report import render_json, render_markdown, render_sarif
from stride_gpt.core.schemas import ModelPair

from . import scanners as _scanners
from . import standards as _standards
from . import store
from .generation import build_llm_config, resolve_model_settings

# 解压安全上限
MAX_TOTAL_BYTES = 300 * 1024 * 1024
MAX_FILES = 20_000
# 克隆超时（秒）
CLONE_TIMEOUT = 300


class AgenticError(RuntimeError):
    """代码审计流程中的可预期错误（参数/环境问题）。"""


class AgenticCancelledError(RuntimeError):
    """用户取消。"""


def workspaces_root() -> Path:
    root = store.DATA_DIR / "workspaces"
    root.mkdir(parents=True, exist_ok=True)
    return root


def new_workspace(prefix: str = "job") -> Path:
    path = workspaces_root() / f"{prefix}-{uuid.uuid4().hex[:12]}"
    path.mkdir(parents=True, exist_ok=True)
    return path


# ---------------------------------------------------------------------------
# ZIP 解压
# ---------------------------------------------------------------------------


def extract_zip(zip_bytes: bytes, dest: Path) -> Path:
    """把上传的 ZIP 安全解压到 dest，返回代码根目录。"""
    if not zip_bytes:
        raise AgenticError("压缩包为空")
    import io

    total = 0
    count = 0
    dest = dest.resolve()
    try:
        archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile as exc:
        raise AgenticError("不是有效的 ZIP 文件") from exc

    with archive:
        for info in archive.infolist():
            count += 1
            if count > MAX_FILES:
                raise AgenticError(f"压缩包文件数超过上限（{MAX_FILES}）")
            name = info.filename
            if not name or name.endswith("/"):
                continue
            if name.startswith("/") or ".." in Path(name).parts:
                raise AgenticError(f"压缩包包含非法路径：{name}")
            # 符号链接条目直接拒绝
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise AgenticError(f"压缩包包含符号链接：{name}")
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                raise AgenticError("压缩包解压后体积超过上限")
            target = (dest / name).resolve()
            if not str(target).startswith(str(dest)):
                raise AgenticError(f"压缩包包含越界路径：{name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as src, target.open("wb") as out:
                shutil.copyfileobj(src, out, length=1024 * 1024)

    if total == 0:
        raise AgenticError("压缩包中没有文件")
    return _code_root(dest)


def _code_root(dest: Path) -> Path:
    """若解压结果只有一个顶层目录，则把它当作代码根目录。"""
    entries = [p for p in dest.iterdir() if not p.name.startswith(".")]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return dest


# ---------------------------------------------------------------------------
# Git 克隆
# ---------------------------------------------------------------------------


def allowed_git_hosts() -> set[str]:
    hosts = {"github.com", "gitlab.com"}
    extra = os.getenv("STRIDE_GPT_GIT_HOSTS", "")
    if extra:
        hosts.update(h.strip().lower() for h in extra.split(",") if h.strip())
    ghe = os.getenv("STRIDE_GPT_GHE_HOST", "").strip().lower()
    if ghe:
        hosts.add(ghe)
    return hosts


def validate_repo_url(url: str) -> str:
    """校验仓库地址，返回主机名。"""
    from urllib.parse import urlparse

    parsed = urlparse((url or "").strip())
    if parsed.scheme != "https":
        raise AgenticError("仅支持 https 的 Git 仓库地址")
    host = (parsed.hostname or "").lower()
    if not host:
        raise AgenticError("无法解析仓库地址")
    if host not in allowed_git_hosts():
        raise AgenticError(
            f"仓库主机 {host} 不在白名单内（可通过 STRIDE_GPT_GIT_HOSTS 追加）"
        )
    if not parsed.path or parsed.path.strip("/") == "":
        raise AgenticError("仓库地址缺少路径")
    return host


def clone_repo(url: str, dest: Path, token: str | None = None) -> Path:
    """浅克隆仓库到 dest，返回代码根目录。"""
    validate_repo_url(url)  # 主机白名单校验（含 token 注入前的安全检查）
    cmd = [
        "git",
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--no-tags",
        "-q",
    ]
    if token:
        # 仅在校验过主机后注入；不写进 URL，避免出现在进程列表/日志
        auth = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        cmd += ["-c", f"http.extraheader=Authorization: Basic {auth}"]
    cmd += [url, str(dest)]

    env = {
        **os.environ,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "echo",
        "GCM_INTERACTIVE": "never",
    }
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=CLONE_TIMEOUT, env=env
        )
    except FileNotFoundError as exc:
        raise AgenticError("服务器未安装 git，无法克隆仓库") from exc
    except subprocess.TimeoutExpired as exc:
        raise AgenticError(f"克隆超时（{CLONE_TIMEOUT} 秒）") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip().splitlines()
        raise AgenticError("克隆失败：" + (detail[-1][:200] if detail else "未知错误"))
    if not dest.exists():
        raise AgenticError("克隆完成但未找到代码目录")
    return dest


# ---------------------------------------------------------------------------
# 运行 agent
# ---------------------------------------------------------------------------

class _EventProgress:
    """把 agent 进度事件转成回调（Web / API 各自消费）。"""

    def __init__(self, on_event=None, cancel_check=None):
        self.on_event = on_event
        self.cancel_check = cancel_check

    def _emit(self, kind: str, **payload) -> None:
        if self.cancel_check and self.cancel_check():
            raise AgenticCancelledError("任务已取消")
        if self.on_event:
            self.on_event(kind, payload)

    def phase_start(self, phase: str, description: str) -> None:
        self._emit("phase", phase=phase, description=description)

    def status(self, message: str) -> None:
        self._emit("status", message=message)

    def subsystem_start(self, index: int, total: int, name: str, description: str) -> None:
        self._emit("subsystem_start", index=index, total=total, name=name, description=description)

    def subsystem_done(self, name: str, threat_count: int, outcome: str) -> None:
        self._emit("subsystem_done", name=name, threat_count=threat_count, outcome=outcome)

    def subsystems_skipped(self, names: list[str]) -> None:
        self._emit("subsystems_skipped", names=list(names))

    def tool_call(self, name: str, args_brief: str, cached: bool) -> None:
        self._emit("tool_call", name=name, args=args_brief, cached=cached)

    def error(self, name: str, reason: str) -> None:
        self._emit("error", name=name, reason=reason)

    def limit_reached(self, kind: str, current: int, maximum: int) -> None:
        self._emit("limit", kind=kind, current=current, maximum=maximum)

    def synthesis_done(self, count: int) -> None:
        self._emit("synthesis_done", count=count)

    def token_budget(self, model: str, limit: int, source: str) -> None:
        self._emit("token_budget", model=model, limit=limit, source=source)

    def no_tool_use_warning(self, subsystem: str) -> None:
        self._emit("no_tool_use", subsystem=subsystem)

    def complete(self, summary: str) -> None:
        self._emit("complete", summary=summary)


def build_model_pair(
    *, worker_model: str | None = None, architect_model: str | None = None, provider: str | None = None
) -> ModelPair:
    """从服务端配置（可被请求覆盖）构建 worker/architect 两级模型。"""
    base = resolve_model_settings({"provider": provider} if provider else None)
    worker_settings = {**base, "model": worker_model or base["model"]}
    worker = build_llm_config(worker_settings)
    if architect_model:
        architect = build_llm_config({**base, "model": architect_model})
    elif architect_model is None and worker_model is None:
        architect = None  # 使用保存配置里的单模型
    else:
        architect = build_llm_config(base)
    return ModelPair(worker=worker, architect=architect)


def run_agentic(
    target: Path,
    *,
    models: ModelPair,
    max_llm_calls: int = 0,
    max_tool_calls: int = 0,
    on_event=None,
    cancel_check=None,
    seed_context: str | None = None,
):
    """执行一次 agentic 分析，返回 AnalysisReport。

    ``seed_context`` 会附加到每个子系统的初始提示词（如静态分析线索）。
    """
    progress = _EventProgress(on_event=on_event, cancel_check=cancel_check)
    return run_analysis(
        models,
        target,
        max_llm_calls=max_llm_calls,
        max_tool_calls=max_tool_calls,
        auto_approve=True,
        progress=progress,
        seed_context=seed_context,
    )


def archive_report(
    report, *, project: str, description: str = "", leads: list | None = None
) -> dict:
    """把 agentic 报告归档为代码审计报告，并把带证据的威胁写入台账。

    ``leads`` 为静态分析线索（scanners.Lead），会附在报告末尾并写入元数据。
    """
    markdown = render_markdown(report)
    leads = leads or []
    if leads:
        report.metadata["scanner_leads"] = _scanners.summarize_for_report(leads)
        lines = [
            "",
            "## 附：静态分析线索（工具原始输出）",
            "",
            "> 以下为扫描工具直接给出的候选线索，未经 agent 逐条核实；"
            "已确认的威胁见正文与威胁台账。",
            "",
            "| 严重度 | 位置 | 工具/规则 | 说明 |",
            "|---|---|---|---|",
        ]
        for lead in leads[:60]:
            loc = f"`{lead.path}:{lead.line}`" if lead.line else f"`{lead.path}`"
            message = lead.message.replace("|", "\\|").replace("\n", " ")[:120]
            lines.append(
                f"| {lead.severity} | {loc} | {lead.tool}/{lead.rule} | {message} |"
            )
        markdown = markdown.rstrip() + "\n" + "\n".join(lines) + "\n"
    data = render_json(report)
    sarif = render_sarif(report)
    provider = report.metadata.get("worker_model", "")
    model = report.metadata.get("worker_provider", "")
    report_id = store.save_report(
        kind="code_analysis",
        title=f"{store.KIND_LABELS.get('code_analysis', 'code_analysis')} · {project}",
        project=project,
        content_md=markdown,
        content_json=json.dumps(data, ensure_ascii=False),
        provider=str(provider),
        model=str(model),
    )
    store.upsert_project(project, description)

    threats = [
        {**threat, "subsystem": finding.subsystem}
        for finding in report.findings
        for threat in finding.threats
    ]
    inserted = store.add_threats(
        project, report_id, _standards.annotate_threats(threats), source="agentic"
    )
    return {
        "report_id": report_id,
        "markdown": markdown,
        "json": data,
        "sarif": sarif,
        "threats_inserted": inserted,
        "threats_total": len(threats),
        "status": report.metadata.get("run_summary", {}).get("status", "completed"),
        "scanner_summary": _scanners.summarize_for_report(leads) if leads else {"total": 0},
    }


def cleanup_workspace(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)


def _collect_leads(root: Path, *, enabled: bool, on_event, cancel_check):
    """运行静态分析扫描器（失败/未安装都不影响主流程）。"""
    if not enabled:
        return []
    if cancel_check and cancel_check():
        raise AgenticCancelledError("任务已取消")
    if on_event:
        on_event("scanner_start", {"root": str(root)})
    try:
        result = _scanners.run_scanners(root)
    except Exception as exc:
        if on_event:
            on_event("scanner_error", {"error": f"{type(exc).__name__}: {exc}"})
        return []
    leads = result["leads"]
    if on_event:
        on_event(
            "scanner_done",
            {
                "leads": len(leads),
                "summary": _scanners.summarize_for_report(leads),
                "tools": [
                    {"name": info.name, "available": info.available, "leads": info.leads}
                    for info in result["scanners"]
                ],
            },
        )
    return leads


def audit_zip(
    zip_bytes: bytes,
    *,
    project: str,
    description: str = "",
    models: ModelPair,
    max_llm_calls: int = 0,
    max_tool_calls: int = 0,
    on_event=None,
    cancel_check=None,
    keep_workspace: bool = False,
    enable_scanners: bool = True,
) -> dict:
    """上传 ZIP → 解压 → 分析 → 归档 的完整流程。"""
    workspace = new_workspace("zip")
    try:
        root = extract_zip(zip_bytes, workspace)
        leads = _collect_leads(root, enabled=enable_scanners, on_event=on_event, cancel_check=cancel_check)
        report = run_agentic(
            root,
            models=models,
            max_llm_calls=max_llm_calls,
            max_tool_calls=max_tool_calls,
            on_event=on_event,
            cancel_check=cancel_check,
            seed_context=_scanners.leads_markdown(leads) if leads else None,
        )
        return archive_report(report, project=project, description=description, leads=leads)
    finally:
        if not keep_workspace:
            cleanup_workspace(workspace)


def audit_repo(
    repo_url: str,
    *,
    project: str,
    description: str = "",
    token: str | None = None,
    models: ModelPair,
    max_llm_calls: int = 0,
    max_tool_calls: int = 0,
    on_event=None,
    cancel_check=None,
    keep_workspace: bool = False,
    enable_scanners: bool = True,
) -> dict:
    """克隆仓库 → 分析 → 归档 的完整流程。"""
    workspace = new_workspace("repo")
    try:
        root = clone_repo(repo_url, workspace / "repo", token=token)
        leads = _collect_leads(root, enabled=enable_scanners, on_event=on_event, cancel_check=cancel_check)
        report = run_agentic(
            root,
            models=models,
            max_llm_calls=max_llm_calls,
            max_tool_calls=max_tool_calls,
            on_event=on_event,
            cancel_check=cancel_check,
            seed_context=_scanners.leads_markdown(leads) if leads else None,
        )
        return archive_report(report, project=project, description=description, leads=leads)
    finally:
        if not keep_workspace:
            cleanup_workspace(workspace)


def estimate_context() -> dict:
    """给 UI 的成本提示：当前模型与可选的调用上限。"""
    settings = resolve_model_settings()
    return {"provider": settings.get("provider"), "model": settings.get("model")}


__all__ = [
    "AgenticCancelledError",
    "AgenticError",
    "archive_report",
    "audit_repo",
    "audit_zip",
    "build_model_pair",
    "cleanup_workspace",
    "clone_repo",
    "estimate_context",
    "extract_zip",
    "new_workspace",
    "run_agentic",
    "validate_repo_url",
]
