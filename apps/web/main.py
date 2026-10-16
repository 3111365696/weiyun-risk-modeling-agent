# main.py —— 启动装配：环境准备 → 共享底座 → 登录门 → 侧边栏/顶栏 → 页面路由
# 页面实现见 pages/，公共组件见 widgets.py / services.py，共享底座见 shared.py。

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

import html

import streamlit as st
from auth import (
    _cookie_js,
    _logout_dialog,
    _resolve_role,
    render_login,
)
from pages.attack_tree import (
    _page_attack_tree,
)
from pages.code_audit import (
    _page_code_audit,
)
from pages.data_flow import (
    _page_data_flow,
)
from pages.dread import (
    _page_dread,
)
from pages.mitigations import (
    _page_mitigations,
)
from pages.overview import (
    _page_overview,
)
from pages.projects import (
    _page_projects,
)
from pages.reports import (
    _page_reports,
)
from pages.settings import (
    render_settings,
)
from pages.status import (
    render_status,
)
from pages.test_cases import (
    _page_test_cases,
)
from pages.threat_model import (
    _page_threat_model,
)
from pages.users import (
    _page_users,
)
from shared import (
    PERSIST_KEYS,
    SESSION_COOKIE,
    _generation,
    _i18n,
    _is_admin,
    _logging,
    _role_display,
    _t,
    _usage,
    datetime,
    get_models_for_provider,
    guard,
    guard_block,
    load_config,
    load_draft,
    make_session_token,
    save_config,
    urlparse,
    verify_session_token,
)
from theme import inject_theme
from widgets import (
    load_env_variables,
)

load_env_variables()

_logging.setup("web")

_logging.set_context(source="web", trace=_logging.new_trace("web"))

if not st.session_state.get("_config_loaded"):
    for _cfg_key, _cfg_val in load_config().items():
        if _cfg_val not in (None, ""):
            st.session_state[_cfg_key] = _cfg_val
    st.session_state["_config_loaded"] = True
    _generation.apply_policies()  # 企业安全基线 + 脱敏策略

_i18n.set_language(st.session_state.get("ui_language") or "zh")

if "model_provider" not in st.session_state:
    st.session_state["model_provider"] = "OpenAI API"

if "selected_model" not in st.session_state:
    _default_models = get_models_for_provider(st.session_state["model_provider"])
    st.session_state["selected_model"] = (
        _default_models[0].model_id if _default_models else "local-model"
    )
    st.session_state["token_limit"] = (
        _default_models[0].default_tokens if _default_models else 8000
    )

if "token_limit" not in st.session_state:
    st.session_state["token_limit"] = 64000

model_provider = st.session_state.get("model_provider", "OpenAI API")

selected_model = st.session_state.get("selected_model", "")

if "app_input" not in st.session_state:
    st.session_state["app_input"] = ""

app_input = st.session_state.get("app_input", "")

app_type = st.session_state.get("app_type", "Web application")

sensitive_data = st.session_state.get("sensitive_data", "")

internet_facing = st.session_state.get("internet_facing", "")

authentication = st.session_state.get("authentication", [])

st.set_page_config(
    page_title=_t("威云-风险建模智能体", "Weiyun Risk Modeling Agent"),
    page_icon=":shield:",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ------------------ 主题样式 ------------------ #
inject_theme()

if not st.session_state.get("authenticated") and not st.session_state.get("_skip_cookie_once"):
    try:
        _cookie_token = st.context.cookies.get(SESSION_COOKIE)
    except Exception:
        _cookie_token = None
    _cookie_user = verify_session_token(_cookie_token)
    _cookie_role = _resolve_role(_cookie_user) if _cookie_user else None
    if _cookie_user and _cookie_role:
        st.session_state["authenticated"] = True
        st.session_state["user"] = _cookie_user
        st.session_state["role"] = _cookie_role
        st.session_state["login_at"] = datetime.now().strftime("%Y-%m-%d %H:%M")

if not st.session_state.get("authenticated"):
    # 记住深链目标（刷新 / 分享链接进入时），登录成功后跳转
    try:
        _pending_path = (urlparse(st.context.url or "").path or "/").strip("/")
    except Exception:
        _pending_path = ""
    if _pending_path:
        st.session_state["_pending_path"] = _pending_path
    if st.session_state.pop("_cookie_clear", False):
        with st.container(key="cookie_clear"):
            st.iframe(_cookie_js("", clear=True), height=1)
        st.session_state.pop("_skip_cookie_once", None)
    render_login()
    st.stop()

_logging.bind(user=st.session_state.get("user", ""))

if not st.session_state.get("_cookie_synced"):
    with st.container(key="cookie_sync"):
        st.iframe(_cookie_js(make_session_token(st.session_state.get("user", ""))), height=1)
    st.session_state["_cookie_synced"] = True

if not st.session_state.get("_draft_loaded"):
    _draft = load_draft("__default__")
    if _draft:
        for _k, _v in _draft.items():
            if _v not in (None, "", []) and not st.session_state.get(_k):
                st.session_state[_k] = _v
    st.session_state["_draft_loaded"] = True

st.sidebar.markdown(
    _t("<div class=\"sg-brand\">\n      <div class=\"sg-brand-mark\">威云</div>\n      <div class=\"sg-brand-name\">风险建模智能体</div>\n    </div>", "<div class=\"sg-brand\">\n      <div class=\"sg-brand-mark\">WEIYUN</div>\n      <div class=\"sg-brand-name\">RISK MODELING AGENT</div>\n    </div>"),
    unsafe_allow_html=True,
)

st.sidebar.caption(
    f"{_t('当前用户：', 'Signed in as: ')}{st.session_state.get('user', '')} · {_role_display()}"
)

if st.sidebar.button(_t("退出登录", "Sign out"), key="logout", use_container_width=True):
    st.session_state["confirm_logout"] = True

with st.sidebar:
    st.selectbox(
        "界面语言 / Language",
        options=list(_i18n.LANGUAGES),
        format_func=lambda key: _i18n.LANGUAGES[key],
        key="ui_language",
        on_change=lambda: save_config(
            {**{k: st.session_state.get(k) for k in PERSIST_KEYS},
             "ui_language": st.session_state.get("ui_language")}
        ),
    )

st.sidebar.header(_t("使用说明", "Getting started"))

with st.sidebar:
    st.markdown(
        _t("1. 在 **系统配置** 中填写模型 API Key 并选择模型\n2. 描述应用，或上传架构图 / 关联 GitHub 仓库\n3. 生成威胁模型、攻击树、数据流图、缓解措施等", "1. Set the model API key and model in **System settings**\n2. Describe the app, or upload a diagram / link a GitHub repo\n3. Generate threat models, attack trees, DFDs, mitigations and more")
    )
    st.caption(
        f"{_t('当前模型：', 'Current model: ')}{st.session_state.get('selected_model', '-')}"
    )
    if _is_admin() and st.button(
        _t("打开系统配置", "Open system settings"), key="sidebar_settings", use_container_width=True
    ):
        st.session_state["view"] = "settings"
        st.rerun()
    st.divider()

    # Add "About" section to the sidebar
    st.header(_t("关于", "About"))

    st.markdown(
        _t("欢迎使用威云-风险建模智能体——一款帮助团队为应用生成更好威胁模型的 AI 工具。", "Welcome to Weiyun Risk Modeling Agent — an AI tool that helps teams produce better threat models for their applications.")
    )
    st.markdown(
        _t("威胁建模是软件开发生命周期中的关键活动，但常被忽视或执行不力。本系统利用大语言模型（LLM）的能力，根据你提供的信息为应用生成威胁列表、攻击树和/或缓解控制措施，帮助团队产出更全面的威胁模型。", "Threat modeling is a key activity in the software development lifecycle, but it is often overlooked or poorly executed. This system leverages large language models to generate threat lists, attack trees and/or mitigating controls from the details you provide, helping teams produce more comprehensive threat models.")
    )
    st.markdown(_t("作者：[Matt Adams](https://www.linkedin.com/in/matthewrwadams/)。", "Created by [Matt Adams](https://www.linkedin.com/in/matthewrwadams/)."))

st.sidebar.header(_t("常见问题", "FAQ"))

with st.sidebar:
    st.markdown(
        _t("### **什么是 STRIDE？**\n    STRIDE 是一种威胁建模方法，用于识别和归类软件应用中的潜在安全风险。它代表 **S**poofing（仿冒）、**T**ampering（篡改）、**R**epudiation（抵赖）、**I**nformation Disclosure（信息泄露）、**D**enial of Service（拒绝服务）和 **E**levation of Privilege（权限提升）。", "### **What is STRIDE?**\n    STRIDE is a threat modeling methodology for identifying and categorizing security risks. It stands for **S**poofing, **T**ampering, **R**epudiation, **I**nformation Disclosure, **D**enial of Service, and **E**levation of Privilege.")
    )
    st.markdown(
        _t("### **威云-风险建模智能体如何工作？**\n    输入应用描述及其他相关信息后，工具会调用多家提供商（OpenAI、Anthropic、Google、Mistral、LM Studio 和 Groq）的先进 AI 模型为你生成威胁模型。所选模型会分析应用描述与细节，生成潜在威胁列表，并按 STRIDE 方法对每个威胁分类。", "### **How does it work?**\n    Given an application description and related details, the system calls advanced models from multiple providers (OpenAI, Anthropic, Google, Mistral, LM Studio, Groq) to produce a threat model. The selected model analyzes the description, lists potential threats, and categorizes each by STRIDE.")
    )
    st.markdown(
        _t("### **你们会存储我提供的应用信息吗？**\n    不会。本系统不存储你的应用描述或其他细节，所有输入的数据会在你关闭浏览器标签页后删除。", "### **Do you store the application details?**\n    No. Reports are archived locally by the administrator, but descriptions are not sent anywhere except the configured model provider.")
    )
    st.markdown(
        _t("### **为什么生成威胁模型需要那么久？**\n    生成时间受几个因素影响：\n\n    **API 速率限制：** 免费 API Key 有严格的速率限制，使用付费 API Key 会更快。\n\n    **推理模型：** 如果选择 GPT-5 系列模型，它们会先“思考”再回答，因此耗时更长，但分析更充分。\n\n    **更快出结果：** 可选择更小/更快的模型，例如：\n    - Gemini Flash 代替 Gemini Pro\n    - GPT-5-nano 代替 GPT-5.2\n    - Claude Haiku 代替 Claude Sonnet", "### **Why does generation take so long?**\n    Several factors affect timing:\n\n    **API rate limits:** free API keys are strictly limited; paid keys are faster.\n\n    **Reasoning models:** GPT-5 series models think before answering, which takes longer but yields deeper analysis.\n\n    **For faster results** choose smaller models:\n    - Gemini Flash instead of Gemini Pro\n    - GPT-5-nano instead of GPT-5.2\n    - Claude Haiku instead of Claude Sonnet")
    )
    st.markdown(
        _t("### **威胁模型是 100% 准确的吗？**\n    不是。STRIDE GPT 使用来自多家 AI 提供商的大语言模型（LLM）生成输出。这些模型虽然强大，但有时也会出错，并且容易产生“幻觉”（生成不相关或不准确的内容）。请仅将输出作为识别和应对应用潜在安全风险的起点。", "### **Are threat models 100% accurate?**\n    No. Large language models are powerful but can make mistakes and hallucinate. Treat the output as a starting point for identifying and addressing potential security risks.")
    )
    st.markdown(
        _t("### **如何提高威胁模型的准确性？**\n    提供详细的应用描述，并正确选择应用类型、认证方式及其他相关信息，可以提高准确性。你提供的信息越多，威胁模型就越准确。", "### **How can I improve accuracy?**\n    Provide a detailed application description and select the correct application type, authentication methods, and other details. The more context you provide, the better the threat model.")
    )

openai_api_key = st.session_state.get("openai_api_key", "")

anthropic_api_key = st.session_state.get("anthropic_api_key", "")

google_api_key = st.session_state.get("google_api_key", "")

mistral_api_key = st.session_state.get("mistral_api_key", "")

groq_api_key = st.session_state.get("groq_api_key", "")

deepseek_api_key = st.session_state.get("deepseek_api_key", "")



_top_left, _top_right = st.columns([6.4, 3.2], vertical_alignment="center")

with _top_left:
    st.markdown(
        _t("<div class=\"sg-topbar\">\n          <span class=\"sg-topbar-title\">威云-风险建模智能体</span>\n          <span class=\"sg-topbar-tag\">STRIDE 威胁建模</span>\n        </div>", "<div class=\"sg-topbar\">\n          <span class=\"sg-topbar-title\">Weiyun Risk Modeling Agent</span>\n          <span class=\"sg-topbar-tag\">STRIDE Threat Modeling</span>\n        </div>"),
        unsafe_allow_html=True,
    )

with _top_right:
    _user_name = st.session_state.get("user", "")
    _user_initial = (_user_name[:1] or "U").upper()
    _user_col, _status_col, _cfg_col, _btn_col = st.columns(
        [1.5, 1.0, 1.0, 0.9], vertical_alignment="center"
    )
    with _user_col:
        st.markdown(
            f"""
            <div class="sg-user">
              <span class="sg-avatar">{html.escape(_user_initial)}</span>
              <span>
                <span class="sg-user-name">{html.escape(_user_name)}</span><br/>
                <span class="sg-user-role">{_role_display()}</span>
              </span>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with _status_col:
        if _is_admin():
            _status_label = (
                _t("返回主页", "Back to home")
                if st.session_state.get("view") == "status"
                else _t("系统状态", "System status")
            )
            if st.button(_status_label, key="status_toggle", use_container_width=True):
                st.session_state["view"] = (
                    "main" if st.session_state.get("view") == "status" else "status"
                )
                st.rerun()
    with _cfg_col:
        if _is_admin():
            _cfg_label = (
                _t("返回主页", "Back to home")
                if st.session_state.get("view") == "settings"
                else _t("系统配置", "System settings")
            )
            if st.button(_cfg_label, key="settings_toggle", use_container_width=True):
                st.session_state["view"] = (
                    "main" if st.session_state.get("view") == "settings" else "settings"
                )
                st.rerun()
    with _btn_col:
        if st.button(_t("退出系统", "Sign out"), key="logout_top", use_container_width=True):
            st.session_state["confirm_logout"] = True

if st.session_state.get("confirm_logout"):
    _logout_dialog()

if st.session_state.get("view") == "settings" and _is_admin():
    with guard_block("settings"):
        render_settings()
    st.stop()

if st.session_state.get("view") == "status" and _is_admin():
    with guard_block("system-status"):
        render_status()
    st.stop()

_PAGE_HEADERS = {
    _t("概览", "Overview"): ("OVERVIEW", _t("概览", "Overview")),
    _t("威胁模型", "Threat Model"): ("THREAT MODEL", _t("威胁模型", "Threat Model")),
    _t("代码审计", "Code Audit"): ("CODE AUDIT", _t("代码审计", "Code Audit")),
    _t("项目工作区", "Projects"): ("PROJECTS", _t("项目工作区", "Projects")),
    _t("攻击树", "Attack Tree"): ("ATTACK TREE", _t("攻击树", "Attack Tree")),
    _t("数据流图", "Data Flow Diagram"): ("DATA FLOW DIAGRAM", _t("数据流图", "Data Flow Diagram")),
    _t("缓解措施", "Mitigations"): ("MITIGATIONS", _t("缓解措施", "Mitigations")),
    _t("DREAD 风险评估", "DREAD Assessment"): ("DREAD", _t("DREAD 风险评估", "DREAD Assessment")),
    _t("测试用例", "Test Cases"): ("TEST CASES", _t("测试用例", "Test Cases")),
    _t("报告历史", "Report History"): ("REPORTS", _t("报告历史", "Report History")),
    _t("用户与审计", "Users & Audit"): ("USERS & AUDIT", _t("用户与审计", "Users & Audit")),
}

_PAGE_PAGES = {
    _t("概览", "Overview"): st.Page(guard("overview")(_page_overview), title=_t("概览", "Overview"), url_path="overview", default=True),
    _t("威胁模型", "Threat Model"): st.Page(guard("threat-model")(_page_threat_model), title=_t("威胁模型", "Threat Model"), url_path="threat-model"),
    _t("代码审计", "Code Audit"): st.Page(guard("code-audit")(_page_code_audit), title=_t("代码审计", "Code Audit"), url_path="code-audit"),
    _t("项目工作区", "Projects"): st.Page(guard("projects")(_page_projects), title=_t("项目工作区", "Projects"), url_path="projects"),
    _t("攻击树", "Attack Tree"): st.Page(guard("attack-tree")(_page_attack_tree), title=_t("攻击树", "Attack Tree"), url_path="attack-tree"),
    _t("数据流图", "Data Flow Diagram"): st.Page(guard("data-flow-diagram")(_page_data_flow), title=_t("数据流图", "Data Flow Diagram"), url_path="data-flow-diagram"),
    _t("缓解措施", "Mitigations"): st.Page(guard("mitigations")(_page_mitigations), title=_t("缓解措施", "Mitigations"), url_path="mitigations"),
    _t("DREAD 风险评估", "DREAD Assessment"): st.Page(guard("dread")(_page_dread), title=_t("DREAD 风险评估", "DREAD Assessment"), url_path="dread"),
    _t("测试用例", "Test Cases"): st.Page(guard("test-cases")(_page_test_cases), title=_t("测试用例", "Test Cases"), url_path="test-cases"),
    _t("报告历史", "Report History"): st.Page(guard("reports")(_page_reports), title=_t("报告历史", "Report History"), url_path="reports"),
    _t("用户与审计", "Users & Audit"): st.Page(guard("users")(_page_users), title=_t("用户与审计", "Users & Audit"), url_path="users"),
}

_pg = st.navigation(list(_PAGE_PAGES.values()), position="hidden")

_usage.set_call_context(
    actor=st.session_state.get("user", ""),
    source="web",
    project=st.session_state.get("project_name", ""),
)

_PATH_TO_TITLE = {
    "overview": _t("概览", "Overview"),
    "threat-model": _t("威胁模型", "Threat Model"),
    "code-audit": _t("代码审计", "Code Audit"),
    "projects": _t("项目工作区", "Projects"),
    "attack-tree": _t("攻击树", "Attack Tree"),
    "data-flow-diagram": _t("数据流图", "Data Flow Diagram"),
    "mitigations": _t("缓解措施", "Mitigations"),
    "dread": _t("DREAD 风险评估", "DREAD Assessment"),
    "test-cases": _t("测试用例", "Test Cases"),
    "reports": _t("报告历史", "Report History"),
    "users": _t("用户与审计", "Users & Audit"),
}

_pending_path = st.session_state.pop("_pending_path", None)

if _pending_path:
    _target_title = _PATH_TO_TITLE.get(_pending_path)
    if _target_title and _target_title != _pg.title:
        st.switch_page(_PAGE_PAGES[_target_title])

if st.session_state.get("_current_page") != _pg.title:
    st.session_state["_current_page"] = _pg.title
    st.session_state["nav_page"] = _pg.title

_nav = st.segmented_control(
    "页面导航",
    list(_PAGE_PAGES),
    key="nav_page",
    label_visibility="collapsed",
)

if _nav and _nav != _pg.title:
    st.switch_page(_PAGE_PAGES[_nav])

_kicker, _title = _PAGE_HEADERS.get(_pg.title, _PAGE_HEADERS[_t("威胁模型", "Threat Model")])

st.markdown(
    f"""
    <div class="sg-page-head">
      <div class="sg-kicker">{_kicker}</div>
      <div class="sg-page-title">{_title}</div>
    </div>
    """,
    unsafe_allow_html=True,
)

_pg.run()
