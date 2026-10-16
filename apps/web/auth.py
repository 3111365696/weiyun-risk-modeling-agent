"""登录、会话 Cookie、退出与模型选择回调。（P7 从 main.py 拆分）。"""

from __future__ import annotations

import hmac
import html

import streamlit as st
from shared import (
    _APP_VERSION,
    _AUTH_PASSWORD,
    _AUTH_USERNAME,
    _AUTOFOCUS_JS,
    _LOGIN_CSS,
    SESSION_COOKIE,
    _role_display,
    _t,
    datetime,
    get_model,
    get_models_for_provider,
    store,
)


def _authenticate(username: str, password: str) -> dict | None:
    """校验凭据：环境变量管理员优先，其次数据库用户。返回 {username, role}。"""
    if hmac.compare_digest(
        (username or "").encode("utf-8"), _AUTH_USERNAME.encode("utf-8")
    ) and hmac.compare_digest(
        (password or "").encode("utf-8"), _AUTH_PASSWORD.encode("utf-8")
    ):
        return {"username": username, "role": "admin"}
    return store.verify_user(username or "", password or "")


def _resolve_role(username: str) -> str | None:
    """cookie 自动登录时解析角色；用户已被删除则返回 None。"""
    if username == _AUTH_USERNAME:
        return "admin"
    user = store.get_user(username)
    return user["role"] if user else None


def render_login() -> None:
    """渲染登录页：控制台风格分屏布局（紫色主题）。"""
    st.markdown(_LOGIN_CSS, unsafe_allow_html=True)
    left, right = st.columns([1.15, 1], gap="large")
    with left:
        st.markdown(
            f"""
            <div class="sg-hero">
              <div class="sg-kicker">SECURE CONSOLE</div>
              <svg class="sg-mark" viewBox="0 0 120 120" fill="none" aria-hidden="true">
                <defs>
                  <linearGradient id="sgGrad" x1="0" y1="0" x2="1" y2="1">
                    <stop offset="0%" stop-color="#C3B8FF"/>
                    <stop offset="100%" stop-color="#6C59C9"/>
                  </linearGradient>
                </defs>
                <path class="sg-shield" d="M60 6 L106 24 V58 C106 85 87 106 60 114 C33 106 14 85 14 58 V24 Z"
                      stroke="url(#sgGrad)" stroke-width="1.6"/>
                <path class="sg-wire" d="M40 46 H58 V64 H82"/>
                <path class="sg-wire" d="M44 78 H76"/>
                <path class="sg-wire" d="M60 34 V46"/>
                <circle class="sg-node" cx="40" cy="46" r="3"/>
                <circle class="sg-node" cx="82" cy="64" r="3"/>
                <circle class="sg-node" cx="60" cy="34" r="3"/>
                <circle class="sg-node" cx="44" cy="78" r="3"/>
                <circle class="sg-node" cx="76" cy="78" r="3"/>
              </svg>
              <h1 class="sg-hero-title">威云-风险建模智能体</h1>
              <p class="sg-hero-desc">面向研发与安全团队的 STRIDE 威胁建模控制台：从代码库或架构描述出发，自动产出威胁模型、攻击树、数据流图与 DREAD 风险评估。</p>
              <div class="sg-grid">
                <div class="sg-tile">
                  <div class="sg-tile-title"><span class="sg-tile-dot"></span>Agentic 代码审计</div>
                  <div class="sg-tile-desc">自动探索代码库，威胁逐条附带证据与行号</div>
                </div>
                <div class="sg-tile">
                  <div class="sg-tile-title"><span class="sg-tile-dot"></span>全栈威胁覆盖</div>
                  <div class="sg-tile-desc">STRIDE · OWASP LLM/ASI · MITRE ATT&amp;CK/ATLAS</div>
                </div>
                <div class="sg-tile">
                  <div class="sg-tile-title"><span class="sg-tile-dot"></span>报告与集成</div>
                  <div class="sg-tile-desc">Markdown · JSON · SARIF · HTML，接入 CI 流程</div>
                </div>
                <div class="sg-tile">
                  <div class="sg-tile-title"><span class="sg-tile-dot"></span>多模型接入</div>
                  <div class="sg-tile-desc">OpenAI · Anthropic · Gemini · DeepSeek · 本地</div>
                </div>
              </div>
              <div class="sg-console">&gt; 系统就绪 · threat-engine online · 等待授权<span class="sg-cursor"></span></div>
              <div class="sg-status">
                <span><span class="sg-dot"></span>服务运行正常</span>
                <span>v{_APP_VERSION}</span>
                <span>内网部署</span>
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with right, st.container(border=True, key="login_card"):
            st.markdown(
                _t("<div class=\"sg-kicker\">ACCESS CONTROL</div>\n                <div class=\"sg-card-title\">登录</div>\n                <div class=\"sg-card-sub\">请使用授权账号访问控制台</div>", "<div class=\"sg-kicker\">ACCESS CONTROL</div>\n                <div class=\"sg-card-title\">Sign in</div>\n                <div class=\"sg-card-sub\">Use an authorized account to access the console</div>"),
                unsafe_allow_html=True,
            )
            with st.form("login_form", border=False):
                username = st.text_input(_t("用户名", "Username"), key="login_user", placeholder=_t("请输入用户名", "Enter your username"))
                password = st.text_input(
                    _t("密码", "Password"), type="password", key="login_password", placeholder=_t("请输入密码", "Enter your password")
                )
                submitted = st.form_submit_button(
                    _t("登 录", "Sign in"), use_container_width=True, type="primary"
                )
            _identifier = (username or "").strip() or "未知用户"
            _lock = store.login_lock_status(_identifier)
            if _lock["locked"]:
                st.error(
                    _t(
                        f"失败次数过多，已临时锁定；请 {_lock['minutes']} 分钟后重试。",
                        f"Too many failed attempts — temporarily locked. Retry in {_lock['minutes']} minute(s).",
                    )
                )
            if submitted:
                if _lock["locked"]:
                    store.log_action(_identifier, "登录被拒", "账号处于锁定状态")
                else:
                    _account = _authenticate(username, password)
                    if _account:
                        store.clear_login_failures(_identifier)
                        st.session_state["authenticated"] = True
                        st.session_state["user"] = _account["username"]
                        st.session_state["role"] = _account["role"]
                        st.session_state["login_at"] = datetime.now().strftime("%Y-%m-%d %H:%M")
                        store.log_action(_account["username"], "登录", "密码登录")
                        st.rerun()
                    else:
                        _after = store.record_login_failure(_identifier)
                        store.log_action(
                            _identifier,
                            "登录失败",
                            f"第 {_after['fails']} 次"
                            + ("（已锁定）" if _after["locked"] else ""),
                        )
                        if _after["locked"]:
                            st.error(
                                _t(
                                    f"用户名或密码错误；失败次数过多，已锁定 {_after['minutes']} 分钟。",
                                    f"Incorrect credentials; too many failures — locked for {_after['minutes']} minute(s).",
                                )
                            )
                        elif _after["fails_left"] <= 2:
                            st.warning(
                                _t(
                                    f"用户名或密码错误；再失败 {_after['fails_left']} 次将临时锁定。",
                                    f"Incorrect credentials; {_after['fails_left']} attempt(s) left before a temporary lock.",
                                )
                            )
                        else:
                            st.error(
                                _t("用户名或密码错误，请重试", "Incorrect username or password, please retry")
                            )
            st.markdown(
                _t("<div class=\"sg-card-foot\">仅限授权人员访问 · 登录行为将被记录</div>", "<div class=\"sg-card-foot\">Authorized personnel only · Login activity is recorded</div>"),
                unsafe_allow_html=True,
            )
    st.iframe(_AUTOFOCUS_JS, height=1)
    st.markdown(
        _t("<div class=\"sg-footbar\">\n          <span>© 2026 威云安全 · 风险建模智能体</span>\n          <span>STRIDE · OWASP LLM/ASI · MITRE ATT&amp;CK/ATLAS</span>\n          <span>TLS 加密传输 · 会话隔离</span>\n        </div>", "<div class=\"sg-footbar\">\n          <span>© 2026 Weiyun Security · Risk Modeling Agent</span>\n          <span>STRIDE · OWASP LLM/ASI · MITRE ATT&amp;CK/ATLAS</span>\n          <span>TLS encrypted · Session isolation</span>\n        </div>"),
        unsafe_allow_html=True,
    )


def _do_logout() -> None:
    """清除登录态并回到登录页。

    注意：必须先记录审计，再清会话；并设置 _skip_cookie_once，
    否则下一轮会因为浏览器里尚未清除的 cookie 立刻自动登录回原账号，
    导致清 cookie 的代码永远不会执行。
    """
    _logout_user = st.session_state.get("user", "")
    store.log_action(_logout_user, _t("退出登录", "Sign out"))
    if _logout_user:
        store.bump_session_epoch(_logout_user)  # 旧 cookie 立即失效
    for key in (
        "authenticated",
        "user",
        "role",
        "login_at",
        "login_user",
        "login_password",
        "confirm_logout",
        "_cookie_synced",
    ):
        st.session_state.pop(key, None)
    st.session_state["_cookie_clear"] = True
    st.session_state["_skip_cookie_once"] = True
    st.rerun()


@st.dialog(_t("退出系统", "Sign out"), icon=":material/logout:")
def _logout_dialog() -> None:
    """退出系统确认弹窗。"""
    _user = st.session_state.get("user", "")
    _role = _role_display()
    _at = st.session_state.get("login_at", "")
    st.markdown(f"当前用户：**{html.escape(_user)}** · {html.escape(_role)}")
    if _at:
        st.caption(f"本次登录时间：{_at}")
    st.markdown(_t("确认要退出系统吗？未保存的表单内容将丢失。", "Sign out? Unsaved form content will be lost."))
    _c1, _c2 = st.columns(2)
    with _c1:
        if st.button(_t("确认退出", "Sign out"), type="primary", use_container_width=True, key="logout_confirm_yes"):
            _do_logout()
    with _c2:
        if st.button(_t("取消", "Cancel"), use_container_width=True, key="logout_confirm_no"):
            st.session_state.pop("confirm_logout", None)
            st.rerun()


def _cookie_js(token: str, *, clear: bool = False) -> str:
    """通过 iframe 在父页面写入/清除会话 cookie。

    有效期可在「系统配置 → 安全策略」调整；HTTPS 部署时设置
    STRIDE_GPT_SECURE_COOKIE=1 会追加 Secure 标记。
    """
    _secure = "; Secure" if store.secure_cookie() else ""
    if clear:
        cookie = f"{SESSION_COOKIE}=; path=/; max-age=0; SameSite=Lax{_secure}"
    else:
        _max_age = store.session_days() * 86400
        cookie = f"{SESSION_COOKIE}={token}; path=/; max-age={_max_age}; SameSite=Lax{_secure}"
    return f'<script>try {{ window.parent.document.cookie = "{cookie}"; }} catch (e) {{}}</script>'


def on_model_provider_change():
    """Update token limit and selected model when model provider changes"""
    new_provider = st.session_state.model_provider

    # Set default model and token limit from registry
    models = get_models_for_provider(new_provider)
    if models:
        st.session_state.selected_model = models[0].model_id
        st.session_state.token_limit = models[0].default_tokens
    else:
        # LM Studio or unknown — conservative default
        st.session_state.token_limit = 8000

    # Reset the current_model_key to force token limit update in Advanced Settings
    if "current_model_key" in st.session_state:
        del st.session_state.current_model_key


def on_model_selection_change():
    """Update token limit when specific model is selected"""
    if "model_provider" not in st.session_state or "selected_model" not in st.session_state:
        return

    model_info = get_model(st.session_state.model_provider, st.session_state.selected_model)
    if model_info:
        st.session_state.token_limit = model_info.default_tokens

    # Reset the current_model_key to force token limit update in Advanced Settings
    if "current_model_key" in st.session_state:
        del st.session_state.current_model_key
