"""成本估算与配额：价格表、费用估算、用量记录、配额检查。

价格是公开标价的近似值（美元 / 每 100 万 token），仅用于内部估算；
未知模型返回 None（只统计 token，不猜价格）。
"""

from __future__ import annotations

import threading

from . import store

_CTX = threading.local()


def set_call_context(*, actor: str = "", source: str = "web", project: str = "") -> None:
    """设置当前线程的调用上下文（Web 会话 / API 请求 / 调度器各自设置）。"""
    _CTX.actor = actor or ""
    _CTX.source = source or "web"
    _CTX.project = project or ""


def current_context() -> dict:
    return {
        "actor": getattr(_CTX, "actor", "") or "",
        "source": getattr(_CTX, "source", "web") or "web",
        "project": getattr(_CTX, "project", "") or "",
    }


def record_from_response(config, response) -> None:
    """核心 LLM 层的用量记录钩子（LLMConfig, LLMResponse）。

    测试环境直接跳过：单元测试会用 mock 的 litellm 响应，若写入真实库会污染统计。
    """
    import os

    if os.environ.get("PYTEST_CURRENT_TEST"):
        return
    ctx = current_context()
    store.log_usage(
        actor=ctx["actor"],
        source=ctx["source"],
        provider=getattr(config, "provider", "") or "",
        model=getattr(config, "model_name", "") or "",
        kind="",
        project=ctx["project"],
        prompt_tokens=getattr(response, "prompt_tokens", None),
        completion_tokens=getattr(response, "completion_tokens", None),
        cost=estimate_cost(
            getattr(config, "model_name", "") or "",
            getattr(response, "prompt_tokens", None),
            getattr(response, "completion_tokens", None),
        ),
    )

# (输入价, 输出价) USD / 1M tokens
_PRICING: list[tuple[str, tuple[float, float]]] = [
    ("claude-opus", (15.0, 75.0)),
    ("claude-sonnet", (3.0, 15.0)),
    ("claude-haiku", (0.8, 4.0)),
    ("claude-fable", (3.0, 15.0)),
    ("gpt-6", (2.5, 15.0)),
    ("gpt-5", (1.25, 10.0)),
    ("gpt-4", (2.5, 10.0)),
    ("gemini-3.1-pro", (1.25, 10.0)),
    ("gemini-3.8", (0.3, 2.5)),
    ("gemini-3.5", (0.3, 2.5)),
    ("gemini-3", (0.3, 2.5)),
    ("gemini-2.5", (0.3, 2.5)),
    ("deepseek", (0.27, 1.1)),
    ("mistral-large", (2.0, 6.0)),
    ("mistral-medium", (0.4, 2.0)),
    ("magistral", (0.4, 2.0)),
    ("mistral-small", (0.1, 0.3)),
    ("ministral", (0.1, 0.3)),
    ("llama", (0.2, 0.6)),
    ("qwen", (0.2, 0.6)),
    ("gpt-oss", (0.2, 0.6)),
    ("kimi", (0.6, 2.5)),
]


def price_for(model: str) -> tuple[float, float] | None:
    name = (model or "").lower()
    for prefix, price in _PRICING:
        if prefix in name:
            return price
    return None


def estimate_cost(model: str, prompt_tokens: int | None, completion_tokens: int | None) -> float | None:
    """估算单次调用成本（美元）；价格未知时返回 None。"""
    price = price_for(model)
    if price is None:
        return None
    p_in, p_out = price
    return round(
        (int(prompt_tokens or 0) / 1_000_000) * p_in
        + (int(completion_tokens or 0) / 1_000_000) * p_out,
        6,
    )


def record_usage(
    *,
    actor: str,
    source: str,
    provider: str,
    model: str,
    kind: str,
    project: str,
    prompt_tokens: int | None,
    completion_tokens: int | None,
) -> None:
    """记录一次调用（含成本估算）。"""
    store.log_usage(
        actor=actor,
        source=source,
        provider=provider,
        model=model,
        kind=kind,
        project=project,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        cost=estimate_cost(model, prompt_tokens, completion_tokens),
    )


def check_api_quota(api_key: dict) -> tuple[bool, str]:
    """检查 API Key 的日 token 配额与月费用配额。返回 (是否允许, 原因)。"""
    name = api_key.get("name") or ""
    actor = f"api:{name}"
    daily_limit = int(api_key.get("daily_token_limit") or 0)
    if daily_limit:
        today = store.usage_for_actor_today(actor)
        if today["tokens"] >= daily_limit:
            return False, f"今日 token 配额已用尽（{today['tokens']}/{daily_limit}）"
    monthly_limit = float(api_key.get("monthly_cost_limit") or 0)
    if monthly_limit:
        month = store.usage_for_actor_month(actor)
        if month["cost"] >= monthly_limit:
            return False, f"本月费用配额已用尽（${month['cost']:.2f}/${monthly_limit:.2f}）"
    return True, ""


def budget_status() -> dict:
    """全局月度预算状态（配置项 monthly_budget，0 表示不限）。"""
    saved = store.load_config()
    budget = float(saved.get("monthly_budget") or 0)
    summary = store.usage_summary(since=store._now()[:8] + "01 00:00:00")
    spent = summary["totals"]["cost"]
    ratio = (spent / budget) if budget else 0.0
    return {
        "budget": budget,
        "spent": round(spent, 4),
        "ratio": round(ratio, 4),
        "tokens": summary["totals"]["total_tokens"],
        "calls": summary["totals"]["calls"],
        "over": bool(budget and spent >= budget),
    }
