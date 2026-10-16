"""威云-风险建模智能体 REST API。

启动：
    uv run uvicorn apps.api.main:app --host 0.0.0.0 --port 8000

鉴权：请求头 X-API-Key（在 Web「系统配置 → API 访问」中创建）。
文档：启动后访问 http://localhost:8000/docs
"""

from __future__ import annotations

import json
import sys
import threading
import uuid
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

_APPS_DIR = Path(__file__).resolve().parent.parent
_REPO_ROOT = _APPS_DIR.parent
for _p in (_REPO_ROOT, _APPS_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from common import agentic, generation, store, usage  # noqa: E402
from common import logging_setup as _logging  # noqa: E402
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402

VERSION = "0.20.0"

_logging.setup("api")
_log = _logging.get_logger("api")

app = FastAPI(
    title="威云-风险建模智能体 API",
    version=VERSION,
    description=(
        "STRIDE 威胁建模能力接口：威胁模型、数据流图、攻击树、缓解措施、"
        "DREAD 风险评估与测试用例。请求头需携带 X-API-Key。"
    ),
)
@app.middleware("http")
async def _request_context(request, call_next):
    """每个请求一个追踪编号：响应头 X-Request-ID + 访问日志。"""
    import time

    trace = request.headers.get("X-Request-ID") or _logging.new_trace("api")
    _logging.set_context(source="api", trace=trace, method=request.method, path=request.url.path)
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        _log.exception("请求处理异常", extra={"path": request.url.path})
        raise
    elapsed = (time.perf_counter() - started) * 1000
    level = _log.warning if response.status_code >= 400 else _log.info
    level(
        "请求完成",
        extra={
            "status": response.status_code,
            "ms": round(elapsed, 1),
            "client": request.client.host if request.client else "",
        },
    )
    response.headers["X-Request-ID"] = trace
    return response


@app.exception_handler(Exception)
async def _unhandled_exception(request, exc: Exception):
    """未捕获异常：返回错误编号，堆栈只进日志。"""
    from fastapi.responses import JSONResponse

    error_id = "ERR-" + uuid.uuid4().hex[:6].upper()
    _log.error(
        "未处理异常",
        exc_info=exc,
        extra={"path": request.url.path, "error_id": error_id, "method": request.method},
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_error",
            "error_id": error_id,
            "detail": f"服务器内部错误（错误编号 {error_id}）",
        },
    )


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# 鉴权与模型
# ---------------------------------------------------------------------------


def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> str:
    name = store.verify_api_key(x_api_key)
    if not name:
        raise HTTPException(status_code=401, detail="无效或已吊销的 API Key")
    return name


class Profile(BaseModel):
    """应用画像（与 Web 界面一致）。"""

    app_type: str = "Web application"
    authentication: list[str] = Field(default_factory=list)
    internet_facing: str = ""
    sensitive_data: str = ""
    dfd: str | None = Field(default=None, description="已确认的 Mermaid 数据流图（可选）")


class GenerateRequest(BaseModel):
    description: str = Field(..., description="应用描述")
    project: str = Field(default="", description="项目名（用于归档；留空自动取名）")
    profile: Profile = Field(default_factory=Profile)
    provider: str | None = Field(default=None, description="覆盖默认模型提供商")
    model: str | None = Field(default=None, description="覆盖默认模型")
    save: bool = Field(default=True, description="是否归档到报告库与威胁台账")
    threats_md: str | None = Field(
        default=None, description="缓解措施/DREAD/测试用例可显式传入威胁模型 markdown"
    )


class FullPipelineRequest(BaseModel):
    description: str
    project: str = ""
    profile: Profile = Field(default_factory=Profile)
    provider: str | None = None
    model: str | None = None


class ThreatPatch(BaseModel):
    status: str | None = None
    owner: str | None = None
    note: str | None = None


class CodeAuditRequest(BaseModel):
    repo_url: str = Field(..., description="https 的 Git 仓库地址")
    project: str = Field(default="", description="项目名（用于归档）")
    description: str = Field(default="", description="补充说明")
    worker_model: str | None = Field(default=None, description="覆盖 worker 模型")
    architect_model: str | None = Field(default=None, description="覆盖 architect 模型")
    max_llm_calls: int = Field(default=60, ge=0, description="LLM 调用上限（0=不限）")
    max_tool_calls: int = Field(default=80, ge=0, description="工具调用上限（0=不限）")
    enable_scanners: bool = Field(default=True, description="启用静态分析线索（SAST）")
    token: str | None = Field(default=None, description="私有仓库访问令牌")


class ScheduleCreate(BaseModel):
    project: str
    interval_minutes: int = Field(default=1440, ge=5, description="检查间隔（分钟）")
    notify_on_change: bool = Field(default=True, description="威胁变化时推送 Webhook")


class WebhookCreate(BaseModel):
    name: str
    url: str
    kind: str = Field(default="generic", description="generic / feishu / wecom / dingtalk")


def _project_name(req: GenerateRequest | FullPipelineRequest) -> str:
    desc = (req.description or "").strip()
    return (req.project or "").strip() or ((desc[:24] + "…") if len(desc) > 24 else (desc or "未命名项目"))


def _settings(req) -> dict:
    return generation.resolve_model_settings({"provider": req.provider, "model": req.model})


def _attachment_headers(filename: str, fallback: str) -> dict:
    """Content-Disposition：ASCII 回退名 + RFC 5987 的 UTF-8 文件名。"""

    return {
        "Content-Disposition": (
            f"attachment; filename=\"{fallback}\"; filename*=UTF-8''{quote(filename)}"
        )
    }


def _report_threats(row: dict) -> list[dict]:
    """从报告 JSON 里取威胁列表（兼容威胁模型与代码审计两种结构）。"""
    try:
        data = json.loads(row.get("content_json") or "{}")
    except Exception:
        return []
    threats = list(data.get("threat_model") or [])
    if threats:
        return threats
    return [
        t for finding in (data.get("findings") or []) for t in (finding.get("threats") or [])
    ]


def _latest_threats_md(project: str) -> str:
    rows = store.list_reports(project=project, kind="threat_model", limit=1)
    if not rows:
        raise HTTPException(
            status_code=400,
            detail=f"项目「{project}」还没有威胁模型报告，无法生成依赖产物",
        )
    return rows[0]["content_md"]


def _enforce_quota(api_key_name: str) -> None:
    key_row = store.get_api_key_by_name(api_key_name) or {}
    allowed, reason = usage.check_api_quota(key_row)
    if not allowed:
        raise HTTPException(status_code=429, detail=reason)


def _generate_one(kind: str, req: GenerateRequest, api_key_name: str) -> dict:
    settings = _settings(req)
    project = _project_name(req)
    _enforce_quota(api_key_name)
    usage.set_call_context(actor=f"api:{api_key_name}", source="api", project=project)
    threats_md = req.threats_md or ""
    if kind in generation.DEPENDENT_KINDS and not threats_md:
        threats_md = _latest_threats_md(project)
    try:
        prompt = generation.build_prompt(kind, req.profile.model_dump(), req.description, threats_md)
        content_md, content_json = generation.run_generation(kind, prompt, settings)
    except generation.GenerationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"模型调用失败：{exc}") from exc

    report_id = None
    if req.save:
        report_id = generation.archive_result(
            kind,
            content_md,
            content_json,
            project=project,
            description=req.description,
            provider=settings.get("provider", ""),
            model=settings.get("model", ""),
        )
    response = {
        "ok": True,
        "kind": kind,
        "project": project,
        "report_id": report_id,
        "provider": settings.get("provider"),
        "model": settings.get("model"),
        "requested_by": api_key_name,
        "markdown": content_md,
        "json": content_json,
    }
    if kind == "threat_model" and isinstance(content_json, dict):
        threats = list(content_json.get("threat_model") or [])
        response["coverage"] = generation.stride_coverage(threats)
        if generation.verification_enabled() and threats:
            try:
                response["verification"] = generation.verify_and_store(project, threats)
            except Exception as exc:
                response["verification_error"] = str(exc)
    return response


# ---------------------------------------------------------------------------
# 基础
# ---------------------------------------------------------------------------


@app.get("/api/v1/health", summary="健康检查（无需鉴权）")
def health() -> dict:
    return {"ok": True, "service": "weiyun-stride-gpt", "version": VERSION}


@app.get("/api/v1/config", summary="查看当前模型配置状态")
def get_config(api_key_name: str = Depends(require_api_key)) -> dict:
    settings = generation.resolve_model_settings()
    return {
        "provider": settings["provider"],
        "model": settings["model"],
        "api_key_configured": bool(settings.get("api_key")),
        "api_base": settings.get("api_base"),
    }


# ---------------------------------------------------------------------------
# 生成接口
# ---------------------------------------------------------------------------


@app.post("/api/v1/threat-model", summary="生成 STRIDE 威胁模型")
def api_threat_model(req: GenerateRequest, api_key_name: str = Depends(require_api_key)) -> dict:
    return _generate_one("threat_model", req, api_key_name)


@app.post("/api/v1/dfd", summary="生成数据流图（Mermaid）")
def api_dfd(req: GenerateRequest, api_key_name: str = Depends(require_api_key)) -> dict:
    return _generate_one("dfd", req, api_key_name)


@app.post("/api/v1/attack-tree", summary="生成攻击树（Mermaid）")
def api_attack_tree(req: GenerateRequest, api_key_name: str = Depends(require_api_key)) -> dict:
    return _generate_one("attack_tree", req, api_key_name)


@app.post("/api/v1/mitigations", summary="生成缓解措施")
def api_mitigations(req: GenerateRequest, api_key_name: str = Depends(require_api_key)) -> dict:
    return _generate_one("mitigations", req, api_key_name)


@app.post("/api/v1/dread", summary="生成 DREAD 风险评估")
def api_dread(req: GenerateRequest, api_key_name: str = Depends(require_api_key)) -> dict:
    return _generate_one("dread", req, api_key_name)


@app.post("/api/v1/test-cases", summary="生成 Gherkin 测试用例")
def api_test_cases(req: GenerateRequest, api_key_name: str = Depends(require_api_key)) -> dict:
    return _generate_one("test_cases", req, api_key_name)


@app.post("/api/v1/full-pipeline", summary="一键生成全套产物")
def api_full_pipeline(req: FullPipelineRequest, api_key_name: str = Depends(require_api_key)) -> dict:
    settings = _settings(req)
    project = _project_name(req)
    _enforce_quota(api_key_name)
    usage.set_call_context(actor=f"api:{api_key_name}", source="api", project=project)
    results = generation.run_full_pipeline(
        description=req.description,
        profile=req.profile.model_dump(),
        project=project,
        settings=settings,
    )
    return {
        "ok": all(item.get("ok") for item in results),
        "project": project,
        "provider": settings.get("provider"),
        "model": settings.get("model"),
        "requested_by": api_key_name,
        "steps": results,
    }


# ---------------------------------------------------------------------------
# 报告 / 项目 / 台账
# ---------------------------------------------------------------------------


@app.get("/api/v1/reports", summary="报告列表")
def api_reports(
    project: str | None = None,
    kind: str | None = None,
    search: str | None = None,
    limit: int = 100,
    api_key_name: str = Depends(require_api_key),
) -> dict:
    rows = store.list_reports(kind=kind, project=project, search=search, limit=limit)
    for r in rows:
        r.pop("content_md", None)
        r.pop("content_json", None)
    return {"ok": True, "count": len(rows), "reports": rows}


@app.get("/api/v1/reports/{report_id}", summary="报告详情")
def api_report(report_id: int, api_key_name: str = Depends(require_api_key)) -> dict:
    row = store.get_report(report_id)
    if not row:
        raise HTTPException(status_code=404, detail="报告不存在")
    return {"ok": True, "report": row}


@app.delete("/api/v1/reports/{report_id}", summary="删除报告")
def api_delete_report(report_id: int, api_key_name: str = Depends(require_api_key)) -> dict:
    if not store.get_report(report_id):
        raise HTTPException(status_code=404, detail="报告不存在")
    store.delete_report(report_id)
    return {"ok": True, "deleted": report_id}


@app.get("/api/v1/reports/{report_id}/threat-dragon", summary="导出为 Threat Dragon 模型")
def api_report_threat_dragon(report_id: int, api_key_name: str = Depends(require_api_key)) -> dict:
    row = store.get_report(report_id)
    if not row:
        raise HTTPException(status_code=404, detail="报告不存在")
    if row["kind"] not in ("threat_model", "code_analysis"):
        raise HTTPException(status_code=400, detail="仅威胁模型 / 代码审计报告支持导出")
    from common import interop

    return interop.to_threat_dragon(row.get("project") or "", _report_threats(row), description="")


@app.get("/api/v1/reports/{report_id}/stix", summary="导出报告为 STIX 2.1")
def api_report_stix(report_id: int, api_key_name: str = Depends(require_api_key)) -> dict:
    row = store.get_report(report_id)
    if not row:
        raise HTTPException(status_code=404, detail="报告不存在")
    if row["kind"] not in ("threat_model", "code_analysis"):
        raise HTTPException(status_code=400, detail="仅威胁模型 / 代码审计报告支持 STIX 导出")
    from common import standards

    return standards.threats_to_stix(
        _report_threats(row), project=row.get("project") or "", description=""
    )


@app.get("/api/v1/reports/{report_id}/docx", summary="导出报告为 Word")
def api_report_docx(report_id: int, api_key_name: str = Depends(require_api_key)):
    row = store.get_report(report_id)
    if not row:
        raise HTTPException(status_code=404, detail="报告不存在")
    from common import exporters
    from fastapi import Response

    data = exporters.markdown_to_docx(row)
    return Response(
        content=data,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers=_attachment_headers(
            exporters.suggested_filename(row, "docx"), f"report-{row['id']}.docx"
        ),
    )


@app.get("/api/v1/reports/{report_id}/pdf", summary="导出报告为 PDF（需服务端安装 Chrome）")
def api_report_pdf(report_id: int, api_key_name: str = Depends(require_api_key)):
    row = store.get_report(report_id)
    if not row:
        raise HTTPException(status_code=404, detail="报告不存在")
    from common import exporters
    from fastapi import Response

    try:
        data = exporters.report_to_pdf(row)
    except RuntimeError as exc:
        raise HTTPException(status_code=501, detail=str(exc)) from exc
    return Response(
        content=data,
        media_type="application/pdf",
        headers=_attachment_headers(
            exporters.suggested_filename(row, "pdf"), f"report-{row['id']}.pdf"
        ),
    )


@app.get("/api/v1/reports/{report_id}/sarif", summary="导出报告为 SARIF（仅威胁模型）")
def api_report_sarif(report_id: int, api_key_name: str = Depends(require_api_key)) -> dict:
    row = store.get_report(report_id)
    if not row:
        raise HTTPException(status_code=404, detail="报告不存在")
    if row["kind"] != "threat_model":
        raise HTTPException(status_code=400, detail="仅威胁模型报告支持 SARIF 导出")
    data = json.loads(row.get("content_json") or "{}")
    return generation.threat_model_to_sarif(
        list(data.get("threat_model") or []),
        project=row.get("project") or "",
        description="",
        tool_version=VERSION,
    )


@app.get("/api/v1/projects", summary="项目列表")
def api_projects(api_key_name: str = Depends(require_api_key)) -> dict:
    store.sync_projects_from_reports()
    return {"ok": True, "projects": store.list_projects()}


@app.get("/api/v1/projects/{name}/threats", summary="项目威胁台账")
def api_project_threats(
    name: str,
    status: str | None = None,
    search: str | None = None,
    api_key_name: str = Depends(require_api_key),
) -> dict:
    rows = store.list_threats(project=name, status=status, search=search)
    return {"ok": True, "count": len(rows), "threats": rows}


@app.get("/api/v1/usage", summary="用量与成本统计")
def api_usage(
    since: str | None = None,
    until: str | None = None,
    api_key_name: str = Depends(require_api_key),
) -> dict:
    summary = store.usage_summary(since, until)
    return {"ok": True, **summary, "budget": usage.budget_status()}


@app.post("/api/v1/projects/{name}/verify", summary="重新做对抗式复核")
def api_verify_project(name: str, api_key_name: str = Depends(require_api_key)) -> dict:
    _enforce_quota(api_key_name)
    usage.set_call_context(actor=f"api:{api_key_name}", source="api", project=name)
    models = generation.latest_threat_models(name, limit=1)
    if not models:
        raise HTTPException(status_code=404, detail=f"项目「{name}」还没有威胁模型报告")
    stats = generation.verify_and_store(name, models[0])
    return {"ok": True, "project": name, "verification": stats}


@app.get("/api/v1/projects/{name}/coverage", summary="STRIDE 覆盖度（最近一次威胁模型）")
def api_project_coverage(name: str, api_key_name: str = Depends(require_api_key)) -> dict:
    models = generation.latest_threat_models(name, limit=1)
    if not models:
        raise HTTPException(status_code=404, detail=f"项目「{name}」还没有威胁模型报告")
    return {"ok": True, "project": name, "coverage": generation.stride_coverage(models[0])}


@app.get("/api/v1/projects/{name}/diff", summary="最近两次威胁模型差异（drift）")
def api_project_diff(name: str, api_key_name: str = Depends(require_api_key)) -> dict:
    diff = generation.diff_latest_threat_models(name)
    if diff is None:
        raise HTTPException(status_code=400, detail="至少需要两次威胁模型报告才能对比")
    return {"ok": True, **diff}


@app.patch("/api/v1/threats/{threat_id}", summary="更新威胁台账条目")
def api_patch_threat(
    threat_id: int,
    patch: ThreatPatch,
    api_key_name: str = Depends(require_api_key),
) -> dict:
    rows = [t for t in store.list_threats() if t["id"] == threat_id]
    if not rows:
        raise HTTPException(status_code=404, detail="威胁条目不存在")
    current = rows[0]
    store.update_threats(
        [
            {
                "id": threat_id,
                "status": patch.status or current["status"],
                "owner": patch.owner if patch.owner is not None else current["owner"],
                "note": patch.note if patch.note is not None else current["note"],
            }
        ]
    )
    return {"ok": True, "threat_id": threat_id}


@app.post("/api/v1/projects/{name}/webhooks/push", summary="推送项目威胁台账到 Webhook")
def api_push_webhooks(name: str, api_key_name: str = Depends(require_api_key)) -> dict:
    threats = store.list_threats(project=name)
    if not threats:
        raise HTTPException(status_code=400, detail="该项目暂无威胁条目")
    outcomes = generation.push_webhooks(name, threats)
    return {"ok": all(o.get("ok") for o in outcomes), "outcomes": outcomes}


# ---------------------------------------------------------------------------
# 代码审计任务（后台线程 + 进度）
# ---------------------------------------------------------------------------

_JOBS: dict[str, dict] = {}
_JOBS_LOCK = threading.Lock()
_MAX_JOBS = 50


def _job_public(job: dict) -> dict:
    return {
        "job_id": job["job_id"],
        "status": job["status"],
        "project": job["project"],
        "source": job["source"],
        "created_at": job["created_at"],
        "finished_at": job.get("finished_at"),
        "error": job.get("error"),
        "result": job.get("result"),
        "progress": job.get("progress", [])[-30:],
    }


def _start_job(
    *,
    source: str,
    project: str,
    description: str,
    api_key_name: str,
    worker_model: str | None,
    architect_model: str | None,
    max_llm_calls: int,
    max_tool_calls: int,
    enable_scanners: bool = True,
    zip_bytes: bytes | None = None,
    repo_url: str | None = None,
    token: str | None = None,
) -> str:
    job_id = uuid.uuid4().hex[:12]
    job = {
        "job_id": job_id,
        "status": "running",
        "project": project,
        "source": source,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "progress": [],
        "cancel_requested": False,
    }
    with _JOBS_LOCK:
        _JOBS[job_id] = job
        # 只保留最近的任务
        while len(_JOBS) > _MAX_JOBS:
            for old_id, old in list(_JOBS.items()):
                if old["status"] != "running":
                    _JOBS.pop(old_id, None)
                    break
            else:
                break

    def _event(kind: str, payload: dict) -> None:
        with _JOBS_LOCK:
            job["progress"].append({"kind": kind, **payload})

    def _cancel_check() -> bool:
        return bool(job.get("cancel_requested"))

    def _worker() -> None:
        usage.set_call_context(actor=f"api:{api_key_name}", source="api", project=project)
        try:
            models = agentic.build_model_pair(
                worker_model=worker_model, architect_model=architect_model
            )
            common = {
                "project": project,
                "description": description,
                "models": models,
                "max_llm_calls": max_llm_calls,
                "max_tool_calls": max_tool_calls,
                "enable_scanners": enable_scanners,
                "on_event": _event,
                "cancel_check": _cancel_check,
            }
            if zip_bytes is not None:
                result = agentic.audit_zip(zip_bytes, **common)
            else:
                result = agentic.audit_repo(repo_url or "", token=token, **common)
            with _JOBS_LOCK:
                job.update(
                    status="done",
                    finished_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    result={
                        "report_id": result["report_id"],
                        "threats_inserted": result["threats_inserted"],
                        "threats_total": result["threats_total"],
                        "run_status": result["status"],
                        "scanner_summary": result.get("scanner_summary") or {"total": 0},
                    },
                    summary=result["markdown"][:2000],
                )
        except agentic.AgenticCancelledError:
            with _JOBS_LOCK:
                job.update(
                    status="cancelled",
                    finished_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                )
        except Exception as exc:
            with _JOBS_LOCK:
                job.update(
                    status="failed",
                    finished_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    error=f"{type(exc).__name__}: {exc}",
                )

    threading.Thread(target=_worker, name=f"code-audit-{job_id}", daemon=True).start()
    return job_id


@app.post("/api/v1/code-audit", summary="提交代码审计任务（Git 仓库）", status_code=202)
def api_code_audit(
    body: CodeAuditRequest, api_key_name: str = Depends(require_api_key)
) -> dict:
    _enforce_quota(api_key_name)
    project = body.project.strip() or body.repo_url.rstrip("/").split("/")[-1].removesuffix(".git")
    job_id = _start_job(
        source="repo",
        project=project,
        description=body.description,
        api_key_name=api_key_name,
        worker_model=body.worker_model,
        architect_model=body.architect_model,
        max_llm_calls=body.max_llm_calls,
        max_tool_calls=body.max_tool_calls,
        enable_scanners=body.enable_scanners,
        repo_url=body.repo_url.strip(),
        token=body.token,
    )
    return {"ok": True, "job_id": job_id, "project": project, "status": "running"}


@app.post("/api/v1/code-audit/upload", summary="提交代码审计任务（ZIP 上传）", status_code=202)
def api_code_audit_upload(
    file: UploadFile = File(..., description="代码 ZIP"),
    project: str = Form(default=""),
    description: str = Form(default=""),
    worker_model: str | None = Form(default=None),
    architect_model: str | None = Form(default=None),
    max_llm_calls: int = Form(default=60),
    max_tool_calls: int = Form(default=80),
    enable_scanners: bool = Form(default=True),
    api_key_name: str = Depends(require_api_key),
) -> dict:
    _enforce_quota(api_key_name)
    data = file.file.read()
    if not data:
        raise HTTPException(status_code=400, detail="上传文件为空")
    job_id = _start_job(
        source="zip",
        project=project.strip() or (file.filename or "upload").removesuffix(".zip"),
        description=description,
        api_key_name=api_key_name,
        worker_model=worker_model,
        architect_model=architect_model,
        max_llm_calls=max_llm_calls,
        max_tool_calls=max_tool_calls,
        enable_scanners=enable_scanners,
        zip_bytes=data,
    )
    return {"ok": True, "job_id": job_id, "status": "running"}


@app.get("/api/v1/code-audit/jobs", summary="代码审计任务列表")
def api_code_audit_jobs(api_key_name: str = Depends(require_api_key)) -> dict:
    with _JOBS_LOCK:
        jobs = [_job_public(job) for job in reversed(list(_JOBS.values()))]
    for job in jobs:
        job.pop("progress", None)
    return {"ok": True, "count": len(jobs), "jobs": jobs}


@app.get("/api/v1/code-audit/jobs/{job_id}", summary="代码审计任务详情")
def api_code_audit_job(job_id: str, api_key_name: str = Depends(require_api_key)) -> dict:
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="任务不存在")
        return {"ok": True, **_job_public(job)}


@app.delete("/api/v1/code-audit/jobs/{job_id}", summary="取消代码审计任务")
def api_code_audit_cancel(job_id: str, api_key_name: str = Depends(require_api_key)) -> dict:
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="任务不存在")
        if job["status"] == "running":
            job["cancel_requested"] = True
    return {"ok": True, "job_id": job_id, "status": job["status"]}


# ---------------------------------------------------------------------------
# 定时分析计划
# ---------------------------------------------------------------------------


@app.get("/api/v1/schedules", summary="定时分析计划列表")
def api_list_schedules(api_key_name: str = Depends(require_api_key)) -> dict:
    return {"ok": True, "schedules": store.list_schedules()}


@app.post("/api/v1/schedules", summary="创建或启用定时分析计划")
def api_add_schedule(body: ScheduleCreate, api_key_name: str = Depends(require_api_key)) -> dict:
    schedule_id = store.add_schedule(body.project, body.interval_minutes, body.notify_on_change)
    return {"ok": True, "schedule_id": schedule_id}


@app.delete("/api/v1/schedules/{schedule_id}", summary="删除定时分析计划")
def api_delete_schedule(schedule_id: int, api_key_name: str = Depends(require_api_key)) -> dict:
    store.delete_schedule(schedule_id)
    return {"ok": True, "deleted": schedule_id}


@app.post("/api/v1/schedules/{schedule_id}/run", summary="立即执行一次计划")
def api_run_schedule(schedule_id: int, api_key_name: str = Depends(require_api_key)) -> dict:
    schedule = store.get_schedule(schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="计划不存在")
    result = generation.run_scheduled_analysis(schedule)
    return {"ok": result.get("status") == "ok", **result}


# ---------------------------------------------------------------------------
# Webhook 配置
# ---------------------------------------------------------------------------


@app.get("/api/v1/webhooks", summary="Webhook 列表")
def api_list_webhooks(api_key_name: str = Depends(require_api_key)) -> dict:
    return {"ok": True, "webhooks": store.list_webhooks()}


@app.post("/api/v1/webhooks", summary="新增 Webhook")
def api_add_webhook(body: WebhookCreate, api_key_name: str = Depends(require_api_key)) -> dict:
    if body.kind not in store.WEBHOOK_KINDS:
        raise HTTPException(status_code=400, detail=f"kind 必须是 {store.WEBHOOK_KINDS}")
    webhook_id = store.add_webhook(body.name, body.url, body.kind)
    return {"ok": True, "webhook_id": webhook_id}


@app.delete("/api/v1/webhooks/{webhook_id}", summary="删除 Webhook")
def api_delete_webhook(webhook_id: int, api_key_name: str = Depends(require_api_key)) -> dict:
    store.delete_webhook(webhook_id)
    return {"ok": True, "deleted": webhook_id}
