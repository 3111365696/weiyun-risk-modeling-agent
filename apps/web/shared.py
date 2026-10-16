"""Web 层共享底座：公共导入、常量、会话状态与通用小工具。

从 main.py 拆分（P7）。所有页面模块只依赖本模块，避免页面互相 import 造成环。
"""

from __future__ import annotations

# 环境准备：必须在导入 streamlit 之前
import os as _os

_os.environ.setdefault("ARROW_DEFAULT_MEMORY_POOL", "system")

import sys
from pathlib import Path

_APP_DIR = Path(__file__).resolve().parent
_APPS_DIR = _APP_DIR.parent
_REPO_ROOT = _APPS_DIR.parent
for _p in (_REPO_ROOT, _APPS_DIR, _APP_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import base64
import hashlib
import hmac
import html
import json
import os
import os as _os
import platform
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import requests
import streamlit as st
import tiktoken
from attack_tree import (
    create_attack_tree_prompt,
    get_attack_tree,
    get_attack_tree_anthropic,
    get_attack_tree_deepseek,
    get_attack_tree_google,
    get_attack_tree_groq,
    get_attack_tree_lm_studio,
    get_attack_tree_mistral,
)
from common import agentic as _agentic
from common import backup as _backup
from common import exporters as _exporters
from common import generation as _generation
from common import i18n as _i18n
from common import interop as _interop
from common import logging_setup as _logging
from common import scanners as _scanners
from common import standards as _standards
from common import store
from common import usage as _usage
from common.store import (
    KIND_LABELS,
    PERSIST_KEYS,
    SESSION_COOKIE,
    THREAT_STATUSES,
    VERDICTS,
    backfill_project,
    clear_config,
    config_saved_at,
    delete_report,
    export_zip,
    get_report,
    list_projects,
    list_reports,
    list_threats,
    load_config,
    load_draft,
    make_session_token,
    report_count,
    report_to_html,
    save_config,
    save_draft,
    sync_projects_from_reports,
    threat_stats,
    update_project_description,
    update_threats,
    verify_session_token,
)
from components.drawio_editor import drawio_editor_component
from dfd import (
    get_dfd_anthropic,
    get_dfd_deepseek,
    get_dfd_from_image_anthropic,
    get_dfd_from_image_google,
    get_dfd_from_image_openai,
    get_dfd_google,
    get_dfd_groq,
    get_dfd_lm_studio,
    get_dfd_mistral,
    get_dfd_openai,
)
from dotenv import load_dotenv
from dread import (
    create_dread_assessment_prompt,
    dread_json_to_markdown,
    get_dread_assessment,
    get_dread_assessment_anthropic,
    get_dread_assessment_deepseek,
    get_dread_assessment_google,
    get_dread_assessment_groq,
    get_dread_assessment_lm_studio,
    get_dread_assessment_mistral,
)
from error_boundary import guard, guard_block
from github import Github, GithubException
from mitigations import (
    create_mitigations_prompt,
    get_mitigations,
    get_mitigations_anthropic,
    get_mitigations_deepseek,
    get_mitigations_google,
    get_mitigations_groq,
    get_mitigations_lm_studio,
    get_mitigations_mistral,
)
from openai import OpenAI
from provider_keys import PROVIDER_API_KEY_STATE
from test_cases import (
    create_test_cases_prompt,
    get_test_cases,
    get_test_cases_anthropic,
    get_test_cases_deepseek,
    get_test_cases_google,
    get_test_cases_groq,
    get_test_cases_lm_studio,
    get_test_cases_mistral,
)
from threat_model import (
    create_image_analysis_prompt,
    create_threat_model_prompt,
    get_image_analysis,
    get_image_analysis_anthropic,
    get_image_analysis_google,
    get_threat_model,
    get_threat_model_anthropic,
    get_threat_model_deepseek,
    get_threat_model_google,
    get_threat_model_groq,
    get_threat_model_lm_studio,
    get_threat_model_mistral,
    json_to_markdown,
)

from stride_gpt.core.drawio_parser import drawio_to_prompt_section
from stride_gpt.core.json_extract import extract_json_object
from stride_gpt.core.llm import call_llm
from stride_gpt.core.prompts import create_dfd_prompt
from stride_gpt.core.schemas import LLMConfig
from stride_gpt.models import PROVIDERS as _PROVIDERS
from stride_gpt.models import get_model, get_models_for_provider, model_supports_thinking

try:
    from importlib.metadata import version as _pkg_version

    _APP_VERSION = _pkg_version("stride-gpt")
except Exception:  # pragma: no cover - 包元数据缺失时回退
    _APP_VERSION = "0.20.0"

_t = _i18n.t

_APP_TYPE_LABELS = {
    "Web application": "Web 应用",
    "Mobile application": "移动应用",
    "Desktop application": "桌面应用",
    "Cloud application": "云应用",
    "IoT application": "IoT 应用",
    "Generative AI application": "生成式 AI 应用",
    "Agentic AI application": "智能体 AI 应用",
    "Other": "其他",
}

_APP_TYPE_LABELS_EN = {
    "Web application": "Web",
    "Mobile application": "Mobile",
    "Desktop application": "Desktop",
    "Cloud application": "Cloud",
    "IoT application": "IoT",
    "Generative AI application": "Generative AI",
    "Agentic AI application": "Agentic AI",
    "Other": "Other",
}

_AUTH_LABELS = {
    "SSO": "SSO",
    "MFA": "MFA",
    "OAUTH2": "OAuth2",
    "Basic": "基本认证",
    "None": "无",
}

_AUTH_LABELS_EN = {"SSO": "SSO", "MFA": "MFA", "OAUTH2": "OAuth2", "Basic": "Basic", "None": "None"}

_ROLE_LABELS = {"admin": "系统管理员", "user": "普通用户"}

_ROLE_LABELS_EN = {"admin": "Administrator", "user": "User"}

_YES_NO_LABELS = {"Yes": "是", "No": "否"}

_YES_NO_LABELS_EN = {"Yes": "Yes", "No": "No"}

_SENSITIVE_DATA_LABELS = {
    "Top Secret": "绝密",
    "Secret": "机密",
    "Confidential": "保密",
    "Restricted": "受限",
    "Unclassified": "非密级",
    "None": "无",
}

_SENSITIVE_DATA_LABELS_EN = {
    "Top Secret": "Top Secret",
    "Secret": "Secret",
    "Confidential": "Confidential",
    "Restricted": "Restricted",
    "Unclassified": "Unclassified",
    "None": "None",
}

_KIND_LABELS_EN = {
    "code_analysis": "Code Audit",
    "threat_model": "Threat Model",
    "attack_tree": "Attack Tree",
    "dfd": "Data Flow Diagram",
    "mitigations": "Mitigations",
    "dread": "DREAD Assessment",
    "test_cases": "Test Cases",
}

_KEY_BY_PROVIDER = {
    "OpenAI API": "openai_api_key",
    "Anthropic API": "anthropic_api_key",
    "Google AI API": "google_api_key",
    "Mistral API": "mistral_api_key",
    "Groq API": "groq_api_key",
    "DeepSeek API": "deepseek_api_key",
    "LM Studio Server": None,
}

GUIDED_DESCRIPTION_FIELDS = [
    {
        "key": "guided_purpose",
        "label": "1）这个应用是做什么的？核心用户操作有哪些？",
        "placeholder": "示例：客户上传发票，审批人审核，财务导出付款。",
    },
    {
        "key": "guided_users",
        "label": "2）主要用户是谁？他们分别拥有哪些访问级别？",
        "placeholder": "示例：终端用户、支持管理员、财务管理员、服务账号。",
    },
    {
        "key": "guided_components",
        "label": "3）有哪些关键组件和技术栈？",
        "placeholder": "示例：React 前端、FastAPI 后端、PostgreSQL、Redis、S3。",
    },
    {
        "key": "guided_data",
        "label": "4）会处理或存储哪些敏感数据？",
        "placeholder": "示例：个人信息（PII）、支付详情、API 令牌、上传的文件。",
    },
    {
        "key": "guided_flows",
        "label": "5）数据如何在系统中流转？",
        "placeholder": "示例：浏览器 -> API -> 消息队列 -> 工作进程 -> 数据库 -> 分析系统。",
    },
    {
        "key": "guided_integrations",
        "label": "6）集成了哪些外部系统或第三方服务？",
        "placeholder": "示例：Okta、Stripe、GitHub、Slack、云对象存储。",
    },
    {
        "key": "guided_auth",
        "label": "7）如何进行身份认证和授权？",
        "placeholder": "示例：启用 MFA 的 SSO、RBAC 角色、限定范围的 API 令牌。",
    },
    {
        "key": "guided_trust_boundaries",
        "label": "8）存在哪些信任边界或面向互联网的入口？",
        "placeholder": "示例：公网 API 网关、管理后台、私有 VPC 服务。",
    },
    {
        "key": "guided_deployment",
        "label": "9）应用部署和运行在哪里？",
        "placeholder": "示例：AWS ECS 双区域、托管 PostgreSQL、私有子网。",
    },
    {
        "key": "guided_controls",
        "label": "10）目前已经有哪些安全控制？",
        "placeholder": "示例：WAF、速率限制、加密、审计日志、密钥管理服务。",
    },
]

_AUTOFOCUS_JS = """
<script>
setTimeout(function () {
  try {
    var doc = window.parent.document;
    var el = doc.querySelector('input[type="text"]');
    if (el && !el.value) { el.focus(); }
  } catch (e) {}
}, 500);
</script>
"""

_LOGIN_CSS = """
<style>
/* ---------- 登录页：控制台风格 ---------- */
[data-testid="stAppViewContainer"] {
  position: relative;
  background-color: #0C0A12;
  background-image:
    radial-gradient(900px 520px at 12% 8%, rgba(124,107,214,.20), transparent 62%),
    radial-gradient(760px 520px at 88% 92%, rgba(78,125,232,.14), transparent 60%),
    linear-gradient(rgba(124,107,214,.05) 1px, transparent 1px),
    linear-gradient(90deg, rgba(124,107,214,.05) 1px, transparent 1px);
  background-size: auto, auto, 46px 46px, 46px 46px;
}
/* 底部透视网格 */
[data-testid="stAppViewContainer"]::after {
  content: ""; position: absolute; left: -10%; right: -10%; bottom: 0; height: 42%;
  background-image:
    linear-gradient(rgba(124,107,214,.20) 1px, transparent 1px),
    linear-gradient(90deg, rgba(124,107,214,.20) 1px, transparent 1px);
  background-size: 52px 52px;
  transform: perspective(460px) rotateX(63deg);
  transform-origin: bottom center;
  -webkit-mask-image: linear-gradient(to top, rgba(0,0,0,.85), transparent 85%);
  mask-image: linear-gradient(to top, rgba(0,0,0,.85), transparent 85%);
  pointer-events: none; z-index: 0;
}
/* 扫描线 */
[data-testid="stAppViewContainer"]::before {
  content: ""; position: fixed; left: 0; right: 0; top: 0; height: 1px;
  background: linear-gradient(90deg, transparent, rgba(169,154,240,.55), transparent);
  animation: sg-scan 7.5s linear infinite; pointer-events: none; z-index: 3;
}
@keyframes sg-scan {
  0% { transform: translateY(0); opacity: 0; }
  8% { opacity: .7; }
  92% { opacity: .25; }
  100% { transform: translateY(100vh); opacity: 0; }
}
[data-testid="stMain"], .block-container { position: relative; z-index: 2; }

/* 左侧品牌区 */
.sg-hero { padding: 13vh 0 0 4vw; }
.sg-kicker {
  font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  font-size: .86rem; letter-spacing: .32em; color: #8E82C8;
}
.sg-mark { width: 152px; height: 152px; margin: 1.5rem 0 .9rem; filter: drop-shadow(0 0 28px rgba(124,107,214,.42)); }
.sg-shield { stroke-dasharray: 580; stroke-dashoffset: 580; animation: sg-draw 2.4s cubic-bezier(.4,0,.2,1) forwards; }
.sg-wire { stroke: rgba(169,154,240,.5); stroke-width: 1.2; stroke-dasharray: 5 6; animation: sg-flow 3.2s linear infinite; }
.sg-node { fill: #C3B8FF; animation: sg-pulse 2.6s ease-in-out infinite; }
.sg-node:nth-of-type(2) { animation-delay: .45s; }
.sg-node:nth-of-type(3) { animation-delay: .9s; }
.sg-node:nth-of-type(4) { animation-delay: 1.35s; }
.sg-node:nth-of-type(5) { animation-delay: 1.8s; }
@keyframes sg-draw { to { stroke-dashoffset: 0; } }
@keyframes sg-flow { to { stroke-dashoffset: -22; } }
@keyframes sg-pulse { 0%,100% { opacity: .45; } 50% { opacity: 1; } }
.sg-hero-title {
  font-size: 3.4rem; font-weight: 700; line-height: 1.2; letter-spacing: .01em; margin: .3rem 0 1rem;
  background: linear-gradient(115deg, #FFFFFF 0%, #D6CDFF 52%, #9B8BEA 100%);
  -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;
}
.sg-hero-desc { color: #A29BB8; font-size: 1.16rem; line-height: 1.9; max-width: 41rem; margin: 0 0 1.4rem; }

/* 能力卡片 2x2 */
.sg-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: .95rem; max-width: 47rem; margin-top: .6rem; }
.sg-tile {
  border: 1px solid rgba(124,107,214,.18); background: rgba(24,21,34,.55);
  border-radius: 12px; padding: 1.15rem 1.3rem; transition: border-color .15s ease, background .15s ease;
}
.sg-tile:hover { border-color: rgba(124,107,214,.42); background: rgba(30,26,44,.7); }
.sg-tile-title { display: flex; align-items: center; gap: .55rem; font-size: 1.06rem; font-weight: 600; color: #E4E0F0; margin-bottom: .38rem; }
.sg-tile-dot { width: 7px; height: 7px; border-radius: 50%; background: #7C6BD6; box-shadow: 0 0 9px rgba(124,107,214,.95); flex: none; }
.sg-tile-desc { font-size: .9rem; color: #9993AC; line-height: 1.7; }

/* 控制台就绪行 */
.sg-console {
  margin-top: 1.9rem; font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  font-size: .9rem; color: #7A7490;
}
.sg-console .ok { color: #38B26A; }
.sg-cursor {
  display: inline-block; width: .55em; height: 1em; background: #A99AF0;
  margin-left: .35em; vertical-align: -2px; animation: sg-blink 1.1s steps(1) infinite;
}
.sg-status {
  display: flex; gap: 2.2rem; align-items: center; margin-top: 2.9rem;
  font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: .88rem; color: #7F7A93;
}
.sg-dot {
  display: inline-block; width: 7px; height: 7px; border-radius: 50%;
  background: #30A46C; margin-right: .45rem; box-shadow: 0 0 10px rgba(48,164,108,.95);
  animation: sg-blink 2.6s ease-in-out infinite;
}
@keyframes sg-blink { 0%,100% { opacity: 1; } 50% { opacity: .3; } }

/* 右侧登录卡片 */
.st-key-login_card {
  margin-top: 13vh !important;
  padding: 2.7rem 2.8rem 2.1rem !important;
  background: rgba(24, 21, 34, .74) !important;
  backdrop-filter: blur(12px);
  border: 1px solid rgba(124, 107, 214, .26) !important;
  border-radius: 14px !important;
  box-shadow: 0 28px 80px rgba(0,0,0,.52), inset 0 1px 0 rgba(255,255,255,.05) !important;
  position: relative; overflow: hidden;
}
.st-key-login_card::before {
  content: ""; position: absolute; top: 0; left: 0; right: 0; height: 2px;
  background: linear-gradient(90deg, transparent, #7C6BD6 45%, #A99AF0 55%, transparent);
}
/* 自动聚焦用的隐形 iframe */
[data-testid="stIFrame"], iframe { display: none !important; }
/* 隐藏 Streamlit 内置英文提示（仅登录页） */
[data-testid="InputInstructions"] { display: none !important; }
.sg-card-title { font-size: 2.35rem; font-weight: 650; color: #F1EFF8; margin: .55rem 0 .3rem; }
.sg-card-sub { color: #948EA8; font-size: 1.06rem; margin-bottom: 1.7rem; }
.sg-card-foot {
  margin-top: 1.7rem; text-align: center; font-size: .85rem; color: #6E6883;
  font-family: ui-monospace, "SF Mono", Menlo, monospace; letter-spacing: .04em;
}
/* 表单控件整体放大 */
[data-baseweb="input"] { min-height: 3.5rem; }
[data-testid="stTextInput"] input { font-size: 1.12rem; }
[data-testid="stTextInput"] label p { font-size: .98rem; }
[data-testid="stBaseButton-primaryFormSubmit"] { min-height: 3.7rem; font-size: 1.18rem; }
/* 登录页内容区更宽、给底栏留位 */
[data-testid="stMain"] .block-container { max-width: 1620px; padding-bottom: 6rem; }
/* 底栏 */
.sg-footbar {
  position: fixed; left: 0; right: 0; bottom: 0; z-index: 5;
  display: flex; justify-content: space-between; gap: 1rem; align-items: center;
  padding: .85rem 2.8rem; font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  font-size: .83rem; color: #6E6883;
  background: rgba(12,10,18,.72); backdrop-filter: blur(10px);
  border-top: 1px solid rgba(124,107,214,.16);
}
[data-testid="stBaseButton-primary"] {
  box-shadow: 0 0 0 1px rgba(124,107,214,.35), 0 8px 26px rgba(124,107,214,.28) !important;
}
[data-testid="stBaseButton-primary"]:hover {
  box-shadow: 0 0 0 1px rgba(124,107,214,.6), 0 10px 32px rgba(124,107,214,.4) !important;
}
</style>
"""

_AUTH_USERNAME = os.getenv("STRIDE_GPT_USERNAME", "admin")

_AUTH_PASSWORD = os.getenv("STRIDE_GPT_PASSWORD", "admin123")

_t = _i18n.t

def _ui_label(zh_map: dict, en_map: dict, key: str) -> str:
    """按语言选择下拉显示标签。"""
    labels = en_map if _i18n.current_language() == "en" else zh_map
    return labels.get(key, key)

def _role_display() -> str:
    role = st.session_state.get("role", "user")
    labels = _ROLE_LABELS_EN if _i18n.current_language() == "en" else _ROLE_LABELS
    return labels.get(role, role)

def _is_admin() -> bool:
    return st.session_state.get("role") == "admin"

def _usage_month_groups(limit: int = 8) -> list[dict]:
    """本月按模型的用量（设置页与仪表盘共用）。"""
    month_start = datetime.now().strftime("%Y-%m") + "-01 00:00:00"
    summary = store.usage_summary(since=month_start)
    rows = [{"key": key, **value} for key, value in summary["groups"]["model"].items()]
    rows.sort(key=lambda r: -r["tokens"])
    return rows[:limit]


# ---------------------------------------------------------------------------
# 会话状态读取（P7：原先的模块级快照改为动态读取，跨 rerun 不过期）
# ---------------------------------------------------------------------------

_SESSION_DEFAULTS: dict = {
    "model_provider": "OpenAI API",
    "selected_model": "",
    "app_input": "",
    "app_type": "Web application",
    "sensitive_data": "",
    "internet_facing": "",
    "authentication": [],
    "openai_api_key": "",
    "anthropic_api_key": "",
    "google_api_key": "",
    "mistral_api_key": "",
    "groq_api_key": "",
    "deepseek_api_key": "",
}


def _state(key: str, default=None):
    """读取会话状态（含默认值）；供从 main.py 拆出的页面模块使用。"""
    return st.session_state.get(key, _SESSION_DEFAULTS.get(key, default))


# Web 进程启动时间与 API 探测地址（状态页使用）
_STARTED_AT = datetime.now()
_API_BASE = os.environ.get("STRIDE_GPT_API_URL", "http://127.0.0.1:8000").rstrip("/")

__all__ = [
    "GUIDED_DESCRIPTION_FIELDS",
    "KIND_LABELS",
    "PERSIST_KEYS",
    "PROVIDER_API_KEY_STATE",
    "SESSION_COOKIE",
    "THREAT_STATUSES",
    "VERDICTS",
    "_APP_TYPE_LABELS",
    "_APP_TYPE_LABELS_EN",
    "_AUTH_LABELS",
    "_AUTH_LABELS_EN",
    "_AUTH_PASSWORD",
    "_AUTH_USERNAME",
    "_AUTOFOCUS_JS",
    "_KEY_BY_PROVIDER",
    "_KIND_LABELS_EN",
    "_LOGIN_CSS",
    "_PROVIDERS",
    "_ROLE_LABELS",
    "_ROLE_LABELS_EN",
    "_SENSITIVE_DATA_LABELS",
    "_SENSITIVE_DATA_LABELS_EN",
    "_SESSION_DEFAULTS",
    "_YES_NO_LABELS",
    "_YES_NO_LABELS_EN",
    "Github",
    "GithubException",
    "LLMConfig",
    "OpenAI",
    "Path",
    "_agentic",
    "_backup",
    "_exporters",
    "_generation",
    "_i18n",
    "_interop",
    "_is_admin",
    "_logging",
    "_os",
    "_role_display",
    "_scanners",
    "_standards",
    "_state",
    "_t",
    "_ui_label",
    "_usage",
    "_usage_month_groups",
    "backfill_project",
    "base64",
    "call_llm",
    "clear_config",
    "config_saved_at",
    "create_attack_tree_prompt",
    "create_dfd_prompt",
    "create_dread_assessment_prompt",
    "create_image_analysis_prompt",
    "create_mitigations_prompt",
    "create_test_cases_prompt",
    "create_threat_model_prompt",
    "datetime",
    "defaultdict",
    "delete_report",
    "drawio_editor_component",
    "drawio_to_prompt_section",
    "dread_json_to_markdown",
    "export_zip",
    "extract_json_object",
    "get_attack_tree",
    "get_attack_tree_anthropic",
    "get_attack_tree_deepseek",
    "get_attack_tree_google",
    "get_attack_tree_groq",
    "get_attack_tree_lm_studio",
    "get_attack_tree_mistral",
    "get_dfd_anthropic",
    "get_dfd_deepseek",
    "get_dfd_from_image_anthropic",
    "get_dfd_from_image_google",
    "get_dfd_from_image_openai",
    "get_dfd_google",
    "get_dfd_groq",
    "get_dfd_lm_studio",
    "get_dfd_mistral",
    "get_dfd_openai",
    "get_dread_assessment",
    "get_dread_assessment_anthropic",
    "get_dread_assessment_deepseek",
    "get_dread_assessment_google",
    "get_dread_assessment_groq",
    "get_dread_assessment_lm_studio",
    "get_dread_assessment_mistral",
    "get_image_analysis",
    "get_image_analysis_anthropic",
    "get_image_analysis_google",
    "get_mitigations",
    "get_mitigations_anthropic",
    "get_mitigations_deepseek",
    "get_mitigations_google",
    "get_mitigations_groq",
    "get_mitigations_lm_studio",
    "get_mitigations_mistral",
    "get_model",
    "get_models_for_provider",
    "get_report",
    "get_test_cases",
    "get_test_cases_anthropic",
    "get_test_cases_deepseek",
    "get_test_cases_google",
    "get_test_cases_groq",
    "get_test_cases_lm_studio",
    "get_test_cases_mistral",
    "get_threat_model",
    "get_threat_model_anthropic",
    "get_threat_model_deepseek",
    "get_threat_model_google",
    "get_threat_model_groq",
    "get_threat_model_lm_studio",
    "get_threat_model_mistral",
    "guard",
    "guard_block",
    "hashlib",
    "hmac",
    "html",
    "json",
    "json_to_markdown",
    "list_projects",
    "list_reports",
    "list_threats",
    "load_config",
    "load_dotenv",
    "load_draft",
    "make_session_token",
    "model_supports_thinking",
    "os",
    "platform",
    "re",
    "report_count",
    "report_to_html",
    "requests",
    "save_config",
    "save_draft",
    "st",
    "store",
    "sync_projects_from_reports",
    "sys",
    "threat_stats",
    "tiktoken",
    "update_project_description",
    "update_threats",
    "urlparse",
    "verify_session_token",
]
