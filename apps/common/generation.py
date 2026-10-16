"""无 Streamlit 依赖的生成编排层：供 Web 界面与 REST API 共用。

职责：
  - 模型配置解析（请求参数 > 服务端保存配置 > 环境变量）
  - 六类产物的提示词构造与生成（复用 stride_gpt.core 的生成函数）
  - 结果归档（报告入库、项目登记、威胁台账提取、DREAD 分数回填）
  - 全流程编排、威胁模型 → SARIF 转换、Webhook 推送
"""

from __future__ import annotations

import json
import os

import httpx

from stride_gpt.core.attack_tree import generate_attack_tree
from stride_gpt.core.dfd import generate_dfd
from stride_gpt.core.dread import generate_dread_assessment
from stride_gpt.core.mitigations import generate_mitigations
from stride_gpt.core.prompts import create_dfd_prompt, create_threat_model_prompt
from stride_gpt.core.schemas import LLMConfig
from stride_gpt.core.test_cases import generate_test_cases
from stride_gpt.core.threat_model import generate_threat_model
from stride_gpt.models import PROVIDERS, get_models_for_provider

from . import store
from .text import (
    create_attack_tree_prompt,
    create_dread_assessment_prompt,
    create_mitigations_prompt,
    create_test_cases_prompt,
    dread_json_to_markdown,
    json_to_markdown,
)

KINDS = ["threat_model", "dfd", "attack_tree", "mitigations", "dread", "test_cases"]

# 依赖威胁模型的步骤（威胁模型失败时跳过）
DEPENDENT_KINDS = {"mitigations", "dread", "test_cases"}

_PROVIDER_CONFIG_KEY = {
    "OpenAI API": "openai_api_key",
    "Anthropic API": "anthropic_api_key",
    "Google AI API": "google_api_key",
    "Mistral API": "mistral_api_key",
    "Groq API": "groq_api_key",
    "DeepSeek API": "deepseek_api_key",
    "LM Studio Server": "lm_studio_api_key",
}

# PROVIDERS 以显示名（"OpenAI"）为键，这里按 provider_key（"OpenAI API"）建索引
_PROVIDER_BY_KEY = {provider.provider_key: provider for provider in PROVIDERS.values()}

_PROVIDER_ENV = {
    provider.provider_key: provider.env_var
    for provider in PROVIDERS.values()
    if provider.env_var
}


class GenerationError(RuntimeError):
    """生成失败（配置缺失、提供商不支持、模型调用异常等）。"""


def resolve_model_settings(overrides: dict | None = None) -> dict:
    """合并配置：请求参数 > 服务端保存配置 > 环境变量。"""
    overrides = overrides or {}
    saved = store.load_config()
    provider = (
        overrides.get("provider")
        or saved.get("model_provider")
        or os.getenv("STRIDE_GPT_PROVIDER")
        or "OpenAI API"
    )
    models = get_models_for_provider(provider)
    model = overrides.get("model") or (
        saved.get("selected_model") if saved.get("model_provider") == provider else None
    )
    if not model:
        model = models[0].model_id if models else ""
    api_base = overrides.get("api_base")
    api_key = overrides.get("api_key")
    config_key = _PROVIDER_CONFIG_KEY.get(provider)
    if provider == "LM Studio Server":
        api_base = (
            api_base
            or saved.get("lm_studio_endpoint")
            or os.getenv("LM_STUDIO_ENDPOINT")
            or "http://localhost:1234"
        )
    if not api_key and config_key:
        api_key = saved.get(config_key) or os.getenv(_PROVIDER_ENV.get(provider, ""), "")
    return {
        "provider": provider,
        "model": model,
        "api_key": api_key or "",
        "api_base": api_base,
    }


def build_llm_config(settings: dict) -> LLMConfig:
    provider = settings.get("provider") or "OpenAI API"
    if not settings.get("model"):
        raise GenerationError("未指定模型：请先在系统配置中保存默认模型")
    provider_info = _PROVIDER_BY_KEY.get(provider)
    needs_key = bool(provider_info and provider_info.needs_api_key)
    if needs_key and not settings.get("api_key"):
        raise GenerationError(f"{provider} 未配置 API Key，请在系统配置中填写后重试")
    return LLMConfig(
        provider=provider,
        model_name=str(settings["model"]),
        api_key=str(settings.get("api_key") or ""),
        api_base=settings.get("api_base"),
    )


def build_prompt(kind: str, profile: dict, description: str, threats_md: str = "") -> str:
    """构造某一类产物的用户提示词。"""
    app_type = profile.get("app_type") or "Web application"
    authentication = profile.get("authentication") or []
    internet_facing = profile.get("internet_facing") or ""
    sensitive_data = profile.get("sensitive_data") or ""
    dfd = profile.get("dfd")
    if kind == "threat_model":
        return create_threat_model_prompt(
            app_type, authentication, internet_facing, sensitive_data, description, confirmed_dfd=dfd
        )
    if kind == "dfd":
        return create_dfd_prompt(app_type, authentication, internet_facing, sensitive_data, description)
    if kind == "attack_tree":
        return create_attack_tree_prompt(
            app_type, authentication, internet_facing, sensitive_data, description, confirmed_dfd=dfd
        )
    is_genai = app_type in ("Generative AI application", "Agentic AI application")
    is_agentic = app_type == "Agentic AI application"
    if kind == "mitigations":
        return create_mitigations_prompt(threats_md, is_genai=is_genai, is_agentic=is_agentic)
    if kind == "dread":
        return create_dread_assessment_prompt(threats_md, is_genai=is_genai, is_agentic=is_agentic)
    if kind == "test_cases":
        return create_test_cases_prompt(threats_md, is_genai=is_genai, is_agentic=is_agentic)
    raise GenerationError(f"未知的产物类型：{kind}")


def run_generation(kind: str, prompt: str, settings: dict) -> tuple[str, dict | None]:
    """调用模型生成一类产物，返回 (markdown, json_data)。"""
    apply_policies()
    config = build_llm_config(settings)
    if kind == "threat_model":
        parsed, _resp = generate_threat_model(config, prompt)
        md = json_to_markdown(parsed.threat_model, parsed.improvement_suggestions)
        return md, {
            "threat_model": parsed.threat_model,
            "improvement_suggestions": parsed.improvement_suggestions,
        }
    if kind == "dfd":
        mermaid, _resp = generate_dfd(config, prompt)
        return f"```mermaid\n{mermaid}\n```", {"mermaid": mermaid}
    if kind == "attack_tree":
        mermaid, _resp = generate_attack_tree(config, prompt)
        return f"```mermaid\n{mermaid}\n```", {"mermaid": mermaid}
    if kind == "mitigations":
        content, _resp = generate_mitigations(config, prompt)
        return content, None
    if kind == "dread":
        parsed, _resp = generate_dread_assessment(config, prompt)
        return dread_json_to_markdown(parsed), parsed
    if kind == "test_cases":
        content, _resp = generate_test_cases(config, prompt)
        return content, None
    raise GenerationError(f"未知的产物类型：{kind}")


def archive_result(
    kind: str,
    content_md: str,
    content_json: dict | None = None,
    *,
    project: str,
    description: str = "",
    provider: str = "",
    model: str = "",
) -> int:
    """写入报告库并同步项目 / 威胁台账 / DREAD 分数。返回报告 ID。"""
    report_id = store.save_report(
        kind=kind,
        title=f"{store.KIND_LABELS.get(kind, kind)} · {project}",
        project=project,
        content_md=content_md,
        content_json=json.dumps(content_json, ensure_ascii=False) if content_json else None,
        provider=provider,
        model=model,
    )
    store.upsert_project(project, description)
    if kind == "threat_model" and isinstance(content_json, dict):
        store.add_threats(project, report_id, list(content_json.get("threat_model") or []))
    if kind == "dread" and isinstance(content_json, dict):
        store.apply_dread_scores(project, content_json)
    return report_id


def run_full_pipeline(
    *,
    description: str,
    profile: dict,
    project: str,
    settings: dict | None = None,
    on_step=None,
) -> list[dict]:
    """顺序生成六类产物并归档。返回每一步的结果列表。"""
    settings = settings or resolve_model_settings()
    results: list[dict] = []
    threats_md = ""
    for kind in KINDS:
        if kind in DEPENDENT_KINDS and not threats_md:
            results.append({"kind": kind, "ok": False, "skipped": True, "error": "威胁模型未生成成功"})
            if on_step:
                on_step(results[-1])
            continue
        try:
            prompt = build_prompt(kind, profile, description, threats_md)
            content_md, content_json = run_generation(kind, prompt, settings)
            report_id = archive_result(
                kind,
                content_md,
                content_json,
                project=project,
                description=description,
                provider=settings.get("provider", ""),
                model=settings.get("model", ""),
            )
            if kind == "threat_model":
                threats_md = content_md
            item = {"kind": kind, "ok": True, "report_id": report_id}
        except Exception as exc:
            item = {"kind": kind, "ok": False, "error": f"{type(exc).__name__}: {exc}"}
        results.append(item)
        if on_step:
            on_step(item)
    return results


# ---------------------------------------------------------------------------
# SARIF（供 CI / 代码扫描平台导入）
# ---------------------------------------------------------------------------

_SARIF_LEVEL = {
    "Elevation of Privilege": "error",
    "Spoofing": "warning",
    "Tampering": "warning",
    "Information Disclosure": "warning",
    "Repudiation": "note",
    "Denial of Service": "note",
}


def threat_model_to_sarif(
    threats: list[dict],
    *,
    project: str = "",
    description: str = "",
    tool_version: str = "0.20.0",
) -> dict:
    """把威胁模型转成 SARIF 2.1.0（GitHub/GitLab/Azure DevOps 可导入）。"""
    rules: dict[str, dict] = {}
    results = []
    for threat in threats or []:
        ttype = str(threat.get("Threat Type") or threat.get("threat_type") or "Threat")
        rule_id = "WY-" + "".join(w[0] for w in ttype.split()).upper()
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": ttype,
                "shortDescription": {"text": f"STRIDE: {ttype}"},
                "fullDescription": {"text": f"威云-风险建模智能体识别出的 {ttype} 类威胁"},
            },
        )
        scenario = str(threat.get("Scenario") or threat.get("scenario") or "")
        impact = str(threat.get("Potential Impact") or threat.get("impact") or "")
        message = scenario if not impact else f"{scenario}\n\n潜在影响：{impact}"
        result = {
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(ttype, "warning"),
            "message": {"text": message.strip()},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "threat-model"},
                        "region": {"startLine": 1},
                    }
                }
            ],
            "properties": {"stride": ttype},
        }
        props = result["properties"]
        if threat.get("OWASP_LLM"):
            props["owasp_llm"] = threat["OWASP_LLM"]
        if threat.get("OWASP_ASI"):
            props["owasp_asi"] = threat["OWASP_ASI"]
        if threat.get("MITRE_ATTACK"):
            props["mitre_attack"] = threat["MITRE_ATTACK"]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "威云-风险建模智能体",
                        "informationUri": "https://github.com/mrwadams/stride-gpt",
                        "version": tool_version,
                        "rules": list(rules.values()),
                    }
                },
                "properties": {"project": project, "description": description[:500]},
                "results": results,
            }
        ],
    }


# ---------------------------------------------------------------------------
# Webhook 推送
# ---------------------------------------------------------------------------


def push_webhooks(project: str, threats: list[dict], webhooks: list[dict] | None = None) -> list[dict]:
    """把威胁台账推送到已启用的 webhook（飞书/企微/钉钉/通用）。"""
    hooks = webhooks if webhooks is not None else store.list_webhooks()
    outcomes = []
    for hook in hooks:
        if not hook.get("enabled", True) or not hook.get("url"):
            continue
        payload = store.threat_webhook_payload(hook.get("kind") or "generic", project, threats)
        try:
            resp = httpx.post(hook["url"], json=payload, timeout=10)
            outcomes.append(
                {
                    "name": hook.get("name"),
                    "ok": resp.status_code < 400,
                    "status": resp.status_code,
                }
            )
        except Exception as exc:
            outcomes.append({"name": hook.get("name"), "ok": False, "error": str(exc)})
    if not outcomes:
        outcomes.append({"ok": False, "error": "未配置启用的 Webhook"})
    return outcomes


# ---------------------------------------------------------------------------
# STRIDE 覆盖度 / 报告差异对比 / 可选策略（基线注入与脱敏）
# ---------------------------------------------------------------------------

STRIDE_TYPES = [
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
]


def stride_coverage(threats: list[dict] | None) -> dict:
    """统计 STRIDE 六类覆盖情况，返回计数与缺失类别。"""
    counts = dict.fromkeys(STRIDE_TYPES, 0)
    other = 0
    for threat in threats or []:
        raw = str(threat.get("Threat Type") or threat.get("threat_type") or "").strip()
        matched = next((t for t in STRIDE_TYPES if t.lower() == raw.lower()), None)
        if matched:
            counts[matched] += 1
        else:
            other += 1
    return {
        "counts": counts,
        "missing": [t for t in STRIDE_TYPES if counts[t] == 0],
        "other": other,
        "total": sum(counts.values()) + other,
    }


def _threat_fp(threat: dict) -> str:
    ttype = str(threat.get("Threat Type") or threat.get("threat_type") or "").strip().lower()
    scenario = str(threat.get("Scenario") or threat.get("scenario") or "").strip().lower()
    return f"{ttype}|{scenario}"


def diff_threats(old: list[dict] | None, new: list[dict] | None) -> dict:
    """按（类型+场景）指纹对比两次威胁模型，返回新增/消失/未变。"""
    old_map = {_threat_fp(t): t for t in (old or []) if _threat_fp(t) != "|"}
    new_map = {_threat_fp(t): t for t in (new or []) if _threat_fp(t) != "|"}
    added = [new_map[k] for k in new_map if k not in old_map]
    removed = [old_map[k] for k in old_map if k not in new_map]
    unchanged = [k for k in new_map if k in old_map]
    return {
        "added": added,
        "removed": removed,
        "added_count": len(added),
        "removed_count": len(removed),
        "unchanged_count": len(unchanged),
    }


def latest_threat_models(project: str, limit: int = 2) -> list[list[dict]]:
    """取项目最近 N 次威胁模型的威胁列表（新→旧）。"""
    reports = store.list_reports(project=project, kind="threat_model", limit=limit)
    result = []
    for row in reports:
        try:
            data = json.loads(row.get("content_json") or "{}")
        except Exception:
            data = {}
        result.append(list(data.get("threat_model") or []))
    return result


def diff_latest_threat_models(project: str) -> dict | None:
    """对比项目最近两次威胁模型；不足两次时返回 None。"""
    models = latest_threat_models(project, limit=2)
    if len(models) < 2:
        return None
    diff = diff_threats(models[1], models[0])
    return {
        "project": project,
        "latest_count": len(models[0]),
        "previous_count": len(models[1]),
        **{k: diff[k] for k in ("added_count", "removed_count", "unchanged_count")},
        "added": diff["added"],
        "removed": diff["removed"],
    }


def apply_policies() -> dict:
    """把服务端配置中的企业基线 / 脱敏策略应用到 LLM 调用层。"""
    from stride_gpt.core.llm import set_extra_system_instruction, set_prompt_scrubber

    saved = store.load_config()
    baseline = (saved.get("security_baseline") or "").strip()
    set_extra_system_instruction(baseline or None)
    if saved.get("scrub_enabled", True):
        from .scrub import scrub_text

        set_prompt_scrubber(scrub_text)
    else:
        set_prompt_scrubber(None)
    return {"baseline": bool(baseline), "scrubbing": bool(saved.get("scrub_enabled", True))}
