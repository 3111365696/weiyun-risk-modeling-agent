"""Unified model registry — single source of truth for providers and models.

To add or update a model, edit the MODELS list below. No other files need to change.
Last reviewed: 2026-09-26

Provider model listing pages:
  - Anthropic:  https://platform.claude.com/docs/en/about-claude/models/overview
  - OpenAI:     https://developers.openai.com/api/docs/models
  - Google AI:  https://ai.google.dev/gemini-api/docs/models
  - Mistral:    https://docs.mistral.ai/getting-started/models/models_overview
  - Groq:       https://console.groq.com/docs/models
  - DeepSeek:   https://api-docs.deepseek.com/quick_start/models
  - OpenRouter: https://openrouter.ai/models
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderInfo:
    """Provider-level metadata (auth, routing, UI text)."""

    name: str  # Display name: "OpenAI", "Anthropic", etc.
    provider_key: str  # Routing key used in LLMConfig.provider
    litellm_prefix: str  # Prefix for LiteLLM model routing
    env_var: str | None = None
    needs_api_key: bool = True
    needs_api_base: bool = False
    default_api_base: str | None = None
    api_key_url: str = ""
    setup_instructions: str = ""


@dataclass(frozen=True)
class ModelInfo:
    """Per-model metadata."""

    model_id: str  # API model identifier
    provider_key: str  # Must match a ProviderInfo.provider_key
    default_tokens: int = 64000
    max_tokens: int = 128000
    uses_max_completion_tokens: bool = False  # OpenAI reasoning models
    supports_thinking: bool = False  # Anthropic/Gemini extended thinking
    supports_tools: bool = True
    help_text: str = ""


# ---------------------------------------------------------------------------
# Provider registry — keyed by display name
# ---------------------------------------------------------------------------

PROVIDERS: dict[str, ProviderInfo] = {
    "OpenAI": ProviderInfo(
        name="OpenAI",
        provider_key="OpenAI API",
        litellm_prefix="",
        env_var="OPENAI_API_KEY",
        api_key_url="https://platform.openai.com/account/api-keys",
        setup_instructions=(
            "1. 在下方输入你的 [OpenAI API Key](https://platform.openai.com/account/api-keys) 并选择模型\n2. 填写你想要进行威胁建模的应用信息\n3. 生成威胁列表、攻击树和/或缓解控制措施"
        ),
    ),
    "Anthropic": ProviderInfo(
        name="Anthropic",
        provider_key="Anthropic API",
        litellm_prefix="anthropic/",
        env_var="ANTHROPIC_API_KEY",
        api_key_url="https://console.anthropic.com/settings/keys",
        setup_instructions=(
            "1. 在下方输入你的 [Anthropic API Key](https://console.anthropic.com/settings/keys) 并选择模型\n2. 填写你想要进行威胁建模的应用信息\n3. 生成威胁列表、攻击树和/或缓解控制措施"
        ),
    ),
    "Google AI": ProviderInfo(
        name="Google AI",
        provider_key="Google AI API",
        litellm_prefix="gemini/",
        env_var="GOOGLE_API_KEY",
        api_key_url="https://makersuite.google.com/app/apikey",
        setup_instructions=(
            "1. 在下方输入你的 [Google AI API Key](https://makersuite.google.com/app/apikey) 并选择模型\n2. 填写你想要进行威胁建模的应用信息\n3. 生成威胁列表、攻击树和/或缓解控制措施"
        ),
    ),
    "Mistral": ProviderInfo(
        name="Mistral",
        provider_key="Mistral API",
        litellm_prefix="mistral/",
        env_var="MISTRAL_API_KEY",
        api_key_url="https://console.mistral.ai/api-keys/",
        setup_instructions=(
            "1. 在下方输入你的 [Mistral API Key](https://console.mistral.ai/api-keys/) 并选择模型\n2. 填写你想要进行威胁建模的应用信息\n3. 生成威胁列表、攻击树和/或缓解控制措施"
        ),
    ),
    "Groq": ProviderInfo(
        name="Groq",
        provider_key="Groq API",
        litellm_prefix="groq/",
        env_var="GROQ_API_KEY",
        api_key_url="https://console.groq.com/keys",
        setup_instructions=(
            "1. 在下方输入你的 [Groq API Key](https://console.groq.com/keys) 并选择模型\n2. 填写你想要进行威胁建模的应用信息\n3. 生成威胁列表、攻击树和/或缓解控制措施"
        ),
    ),
    "DeepSeek": ProviderInfo(
        name="DeepSeek",
        provider_key="DeepSeek API",
        litellm_prefix="deepseek/",
        env_var="DEEPSEEK_API_KEY",
        api_key_url="https://platform.deepseek.com/api_keys",
        setup_instructions=(
            "1. 在下方输入你的 [DeepSeek API Key](https://platform.deepseek.com/api_keys) 并选择模型\n2. 填写你想要进行威胁建模的应用信息\n3. 生成威胁列表、攻击树和/或缓解控制措施"
        ),
    ),
    "OpenRouter": ProviderInfo(
        name="OpenRouter",
        provider_key="OpenRouter API",
        litellm_prefix="openrouter/",
        env_var="OPENROUTER_API_KEY",
        api_key_url="https://openrouter.ai/settings/keys",
        setup_instructions=(
            "1. 在下方输入你的 [OpenRouter API Key](https://openrouter.ai/settings/keys) 并选择模型\n2. 填写你想要进行威胁建模的应用信息\n3. 生成威胁列表、攻击树和/或缓解控制措施"
        ),
    ),
    "LM Studio": ProviderInfo(
        name="LM Studio",
        provider_key="LM Studio Server",
        litellm_prefix="openai/",
        env_var=None,
        needs_api_key=False,
        needs_api_base=True,
        default_api_base="http://localhost:1234",
        setup_instructions=(
            "1. 在下方配置 LM Studio Server 端点（默认 http://localhost:1234）\n2. 如果服务器需要鉴权，可选填 API Key\n3. 填写你想要进行威胁建模的应用信息\n4. 生成威胁列表、攻击树和/或缓解控制措施"
        ),
    ),
}


# ---------------------------------------------------------------------------
# Model registry — order determines UI display order per provider
# ---------------------------------------------------------------------------

MODELS: list[ModelInfo] = [
    # --- OpenAI ---
    ModelInfo(
        model_id="gpt-6-astra",
        provider_key="OpenAI API",
        default_tokens=128000,
        max_tokens=1050000,
        uses_max_completion_tokens=True,
        help_text="GPT-6 Astra 是 OpenAI 能力最强的模型，为最艰巨的端到端任务而打造。",
    ),
    ModelInfo(
        model_id="gpt-6-sol",
        provider_key="OpenAI API",
        default_tokens=128000,
        max_tokens=1050000,
        uses_max_completion_tokens=True,
        help_text="GPT-6 Sol 在智能与成本之间取得平衡，适合复杂编码与智能体工作流。",
    ),
    ModelInfo(
        model_id="gpt-6-luna",
        provider_key="OpenAI API",
        default_tokens=128000,
        max_tokens=1050000,
        uses_max_completion_tokens=True,
        help_text="GPT-6 Luna 是专注型高并发任务中最经济的选择。",
    ),
    # --- Anthropic ---
    # supports_thinking marks models that accept the legacy extended-thinking
    # kwarg, thinking={"type": "enabled", "budget_tokens": N}. Claude 4.7 and
    # later reject it with a 400; those models think adaptively by default and
    # are steered with the `effort` parameter instead, so the flag stays False.
    ModelInfo(
        model_id="claude-sonnet-5",
        provider_key="Anthropic API",
        default_tokens=64000,
        max_tokens=1000000,
        help_text="Claude Sonnet 5 在速度与智能之间取得最佳平衡。",
    ),
    ModelInfo(
        model_id="claude-opus-5-5",
        provider_key="Anthropic API",
        default_tokens=64000,
        max_tokens=1000000,
        help_text="Claude Opus 5.5 是当前 Opus 模型，为长时间运行的智能体任务而打造。",
    ),
    ModelInfo(
        model_id="claude-fable-5-1",
        provider_key="Anthropic API",
        default_tokens=64000,
        max_tokens=1000000,
        help_text="Claude Fable 5.1 面向高难度推理与长时程智能体任务。",
    ),
    ModelInfo(
        model_id="claude-opus-4-8",
        provider_key="Anthropic API",
        default_tokens=64000,
        max_tokens=1000000,
        help_text="Claude Opus 4.8 是上一代 Opus，仍可供正在使用中的用户选择。",
    ),
    ModelInfo(
        model_id="claude-haiku-4-5-20251001",
        provider_key="Anthropic API",
        default_tokens=64000,
        max_tokens=200000,
        supports_thinking=True,
        help_text="Claude Haiku 4.5 是速度最快、成本效益最高的 Claude 模型。",
    ),
    # --- Google AI ---
    ModelInfo(
        model_id="gemini-3.8-flash",
        provider_key="Google AI API",
        default_tokens=200000,
        max_tokens=1000000,
        supports_thinking=True,
        help_text="Gemini 3.8 Flash 是 Google 的最新模型，针对长时程智能体任务调优。",
    ),
    ModelInfo(
        model_id="gemini-3.1-pro-preview",
        provider_key="Google AI API",
        default_tokens=200000,
        max_tokens=1000000,
        supports_thinking=True,
        help_text="Gemini 3.1 Pro 是 Google 能力最强的模型，支持 1M 上下文。",
    ),
    ModelInfo(
        model_id="gemini-3.5-flash",
        provider_key="Google AI API",
        default_tokens=200000,
        max_tokens=1000000,
        supports_thinking=True,
        help_text="Gemini 3.5 Flash 是支持 1M 上下文的快速模型。",
    ),
    ModelInfo(
        model_id="gemini-3.1-flash-lite",
        provider_key="Google AI API",
        default_tokens=200000,
        max_tokens=1000000,
        supports_thinking=True,
        help_text="Gemini 3.1 Flash Lite 是成本最低的选择，支持 1M 上下文。",
    ),
    ModelInfo(
        model_id="gemini-3-flash-preview",
        provider_key="Google AI API",
        default_tokens=200000,
        max_tokens=1000000,
        supports_thinking=True,
        help_text="Gemini 3 Flash 针对速度优化，支持 1M 上下文。",
    ),
    # --- Mistral ---
    ModelInfo(
        model_id="mistral-large-2512",
        provider_key="Mistral API",
        default_tokens=64000,
        max_tokens=128000,
        help_text="Mistral Large 3 提供旗舰级能力。",
    ),
    ModelInfo(
        model_id="mistral-small-2603",
        provider_key="Mistral API",
        default_tokens=64000,
        max_tokens=256000,
        help_text="Mistral Small 4 在 256k 上下文中融合推理、视觉与编码能力。",
    ),
    ModelInfo(
        model_id="mistral-medium-3-5",
        provider_key="Mistral API",
        default_tokens=64000,
        max_tokens=256000,
        help_text="Mistral Medium 3.5 是面向智能体与编码的前沿多模态模型。",
    ),
    # --- Groq ---
    ModelInfo(
        model_id="openai/gpt-oss-120b",
        provider_key="Groq API",
        default_tokens=64000,
        max_tokens=131072,
        help_text="GPT-OSS 120B 是 Groq 上的开源推理模型。",
    ),
    ModelInfo(
        model_id="openai/gpt-oss-20b",
        provider_key="Groq API",
        default_tokens=64000,
        max_tokens=131072,
        help_text="GPT-OSS 20B 是 Groq 上的快速开源模型。",
    ),
    ModelInfo(
        model_id="llama-3.3-70b-versatile",
        provider_key="Groq API",
        default_tokens=64000,
        max_tokens=131072,
        help_text="Llama 3.3 70B 擅长通用任务。",
    ),
    ModelInfo(
        model_id="qwen/qwen3.8-27b",
        provider_key="Groq API",
        default_tokens=64000,
        max_tokens=131072,
        help_text="Qwen3.8 27B 是 Groq 预览版多模态模型。",
    ),
    # --- DeepSeek ---
    ModelInfo(
        model_id="deepseek-flash",
        provider_key="DeepSeek API",
        default_tokens=64000,
        max_tokens=1000000,
        help_text="DeepSeek Flash (V4.1) 是 DeepSeek 推荐的默认选择：快速、便宜、1M 上下文。",
    ),
    ModelInfo(
        model_id="deepseek-v4-pro",
        provider_key="DeepSeek API",
        default_tokens=64000,
        max_tokens=1000000,
        help_text="DeepSeek V4 Pro 是更大规模的版本，推理与编码能力更强。",
    ),
    # --- OpenRouter ---
    # A shortlist of tool-capable models; the wizard's "Custom" option takes any
    # other slug from https://openrouter.ai/models. Context lengths are
    # OpenRouter's, which can differ from the upstream provider's.
    ModelInfo(
        model_id="anthropic/claude-opus-5.5",
        provider_key="OpenRouter API",
        default_tokens=64000,
        max_tokens=1000000,
        help_text="Claude Opus 5.5（经由 OpenRouter 路由）。",
    ),
    ModelInfo(
        model_id="anthropic/claude-sonnet-5",
        provider_key="OpenRouter API",
        default_tokens=64000,
        max_tokens=1000000,
        help_text="Claude Sonnet 5（经由 OpenRouter 路由）。",
    ),
    ModelInfo(
        model_id="openai/gpt-6-astra",
        provider_key="OpenRouter API",
        default_tokens=128000,
        max_tokens=1050000,
        help_text="GPT-6 Astra（经由 OpenRouter 路由）。",
    ),
    ModelInfo(
        model_id="google/gemini-3.8-flash",
        provider_key="OpenRouter API",
        default_tokens=64000,
        max_tokens=1048576,
        help_text="Gemini 3.8 Flash（经由 OpenRouter 路由）：快速且便宜。",
    ),
    ModelInfo(
        model_id="deepseek/deepseek-v4.1-flash",
        provider_key="OpenRouter API",
        default_tokens=64000,
        max_tokens=1048576,
        help_text="DeepSeek V4.1 Flash（经由 OpenRouter 路由）。",
    ),
    ModelInfo(
        model_id="moonshotai/kimi-k3",
        provider_key="OpenRouter API",
        default_tokens=64000,
        max_tokens=1048576,
        help_text="Kimi K3（经由 OpenRouter 路由）。",
    ),
    # --- LM Studio (no static models — discovered at runtime) ---
]

# Build lookup indexes at import time
_PROVIDER_BY_KEY: dict[str, ProviderInfo] = {
    p.provider_key: p for p in PROVIDERS.values()
}
_MODEL_LOOKUP: dict[tuple[str, str], ModelInfo] = {
    (m.provider_key, m.model_id): m for m in MODELS
}
_COMPLETION_TOKEN_IDS: set[str] = {
    m.model_id for m in MODELS if m.uses_max_completion_tokens
}
_THINKING_LOOKUP: set[tuple[str, str]] = {
    (m.provider_key, m.model_id) for m in MODELS if m.supports_thinking
}


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------


def get_models_for_provider(provider_key: str) -> list[ModelInfo]:
    """Return models for a provider, in UI display order."""
    return [m for m in MODELS if m.provider_key == provider_key]


def get_model(provider_key: str, model_id: str) -> ModelInfo | None:
    """Look up a specific model by provider key and model ID."""
    return _MODEL_LOOKUP.get((provider_key, model_id))


def get_provider_by_key(provider_key: str) -> ProviderInfo | None:
    """Look up a provider by its routing key (e.g. 'OpenAI API')."""
    return _PROVIDER_BY_KEY.get(provider_key)


def get_litellm_prefix(provider_key: str) -> str:
    """Return the LiteLLM model prefix for a provider key."""
    provider = _PROVIDER_BY_KEY.get(provider_key)
    return provider.litellm_prefix if provider else ""


def model_uses_completion_tokens(model_id: str) -> bool:
    """True if this model uses max_completion_tokens instead of max_tokens."""
    return model_id in _COMPLETION_TOKEN_IDS


def model_supports_thinking(provider_key: str, model_id: str) -> bool:
    """True if this model supports extended thinking / reasoning mode."""
    return (provider_key, model_id) in _THINKING_LOOKUP
