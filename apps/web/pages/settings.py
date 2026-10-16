"""系统配置页面（模型、模板、配额、Webhook）。（P7 从 main.py 拆分）。"""

from __future__ import annotations

import streamlit as st
from auth import (
    on_model_provider_change,
    on_model_selection_change,
)
from shared import (
    _PROVIDERS,
    PERSIST_KEYS,
    PROVIDER_API_KEY_STATE,
    _generation,
    _is_admin,
    _t,
    _usage,
    _usage_month_groups,
    clear_config,
    config_saved_at,
    get_model,
    get_models_for_provider,
    model_supports_thinking,
    save_config,
    store,
)
from widgets import (
    get_lm_studio_models,
)


def render_settings() -> None:
    """独立配置界面：模型服务、GitHub 集成、分析参数（仅管理员）。"""
    if not _is_admin():
        st.error(_t("需要管理员权限才能访问系统配置。", "Administrator privileges are required to access system settings."))
        return
    st.markdown(
        _t("<div class=\"sg-settings-head\">\n          <div class=\"sg-kicker\">SYSTEM CONFIGURATION</div>\n          <div class=\"sg-settings-title\">系统配置</div>\n          <div class=\"sg-settings-sub\">模型服务、GitHub 集成与分析参数，修改后即时生效。</div>\n        </div>", "<div class=\"sg-settings-head\">\n          <div class=\"sg-kicker\">SYSTEM CONFIGURATION</div>\n          <div class=\"sg-settings-title\">System settings</div>\n          <div class=\"sg-settings-sub\">Model service, GitHub integration and analysis parameters — changes take effect immediately.</div>\n        </div>"),
        unsafe_allow_html=True,
    )

    _cfg_left, _cfg_right = st.columns([1.15, 1], gap="large")

    with _cfg_left, st.container(border=True, key="settings_model"):
            st.markdown(_t("#### 模型服务", "#### Model service"))
            st.caption(_t("配置大模型提供商、API Key 与默认模型。API Key 仅保存在当前浏览器会话中。", "Configure the model provider, API key, and default model. API keys are kept in the current browser session only."))

            _provider_keys = [
                p.provider_key for p in _PROVIDERS.values() if p.provider_key != "OpenRouter API"
            ]
            _provider = st.selectbox(
                _t("模型提供商", "Model provider"),
                _provider_keys,
                key="model_provider",
                on_change=on_model_provider_change,
                help=_t("选择要使用的模型提供商，这将决定可选的模型列表。", "Choose the model provider; this determines the available models."),
            )

            if _provider == "LM Studio Server":
                _provider_info = _PROVIDERS["LM Studio"]
                st.markdown(_provider_info.setup_instructions)
                _endpoint = st.text_input(
                    _t("LM Studio Server 端点", "LM Studio Server endpoint"),
                    key="lm_studio_endpoint",
                    help=_t("你的 LM Studio Server 实例 URL。本地安装默认是 http://localhost:1234。", "URL of your LM Studio Server instance. Local installs default to http://localhost:1234."),
                )
                st.text_input(
                    _t("LM Studio API Key（可选）", "LM Studio API key (optional)"),
                    type="password",
                    key="lm_studio_api_key",
                    help=_t("如果服务器不需要鉴权，请留空。", "Leave empty if your server does not require authentication."),
                )
                _available = ["local-model"]
                if _endpoint:
                    if not _endpoint.startswith(("http://", "https://")):
                        st.error(_t("端点 URL 必须以 http:// 或 https:// 开头", "Endpoint URL must start with http:// or https://"))
                    else:
                        _available = get_lm_studio_models(
                            _endpoint, st.session_state.get("lm_studio_api_key", "")
                        )
                st.selectbox(
                    _t("默认模型", "Default model"),
                    _available,
                    key="selected_model",
                    on_change=on_model_selection_change,
                    help=_t("从本地 LM Studio Server 中选择模型。", "Select a model from your local LM Studio Server."),
                )
            else:
                _info = next(p for p in _PROVIDERS.values() if p.provider_key == _provider)
                st.markdown(_info.setup_instructions)
                _session_key = PROVIDER_API_KEY_STATE.get(_provider, "")
                if _session_key:
                    st.text_input(
                        f"{_info.name} API Key",
                        type="password",
                        key=_session_key,
                        help=_t(
                            f"你可以在以下位置找到 API Key：[{_info.name}]({_info.api_key_url})。",
                            f"Find your API key at [{_info.name}]({_info.api_key_url}).",
                        ),
                    )
                _model_list = get_models_for_provider(_provider)
                st.selectbox(
                    _t("默认模型", "Default model"),
                    [m.model_id for m in _model_list],
                    key="selected_model",
                    on_change=on_model_selection_change,
                    help=" | ".join(
                        f"{m.model_id}: {m.help_text}" for m in _model_list if m.help_text
                    ) or None,
                )
                if _provider == "Anthropic API" and model_supports_thinking(
                    _provider, st.session_state.get("selected_model", "")
                ):
                    st.checkbox(
                        _t("启用扩展思考", "Enable extended thinking"),
                        value=st.session_state.get("use_thinking", False),
                        key="use_thinking",
                        help=_t("扩展思考为 Claude 提供更强的复杂任务推理能力，但可能增加响应时间和 token 消耗。", "Extended thinking gives Claude stronger reasoning for complex tasks, but may increase response time and token usage."),
                    )
                elif st.session_state.get("use_thinking"):
                    st.session_state["use_thinking"] = False

    with _cfg_right:
        with st.container(border=True, key="settings_status"):
            st.markdown(_t("#### 当前配置", "#### Current configuration"))
            _prov = st.session_state.get("model_provider", "OpenAI API")
            _model = st.session_state.get("selected_model", "-")
            _skey = PROVIDER_API_KEY_STATE.get(_prov, "")
            _has_key = (
                bool(st.session_state.get(_skey, "")) if _skey else _prov == "LM Studio Server"
            )
            st.markdown(
                _t(
                    f"- 提供商：**{_prov}**\n"
                    f"- 默认模型：**{_model}**\n"
                    f"- 大模型 API Key：**{'已配置' if _has_key else '未配置'}**\n"
                    f"- GitHub API Key：**{'已配置' if st.session_state.get('github_api_key') else '未配置'}**",
                    f"- Provider: **{_prov}**\n"
                    f"- Default model: **{_model}**\n"
                    f"- LLM API key: **{'configured' if _has_key else 'not set'}**\n"
                    f"- GitHub API key: **{'configured' if st.session_state.get('github_api_key') else 'not set'}**",
                )
            )

        with st.container(border=True, key="settings_github"):
            st.markdown(_t("#### GitHub 集成", "#### GitHub integration"))
            st.caption(_t("可选。配置后可直接分析 GitHub 仓库；细粒度令牌需具备 Contents: read-only 权限。", "Optional. Enables GitHub repository analysis; fine-grained tokens need Contents: read-only."))
            st.text_input(
                _t("GitHub API Key（可选）", "GitHub API key (optional)"),
                type="password",
                key="github_api_key",
                help=_t("在 GitHub 账户设置 Developer settings > Personal access tokens 中创建。", "Create one under GitHub account settings → Developer settings → Personal access tokens."),
            )

        with st.container(border=True, key="settings_advanced"):
            st.markdown(_t("#### 分析参数", "#### Analysis parameters"))
            _cur_provider = st.session_state.get("model_provider", "OpenAI API")
            _cur_model = st.session_state.get("selected_model", "")
            _model_key = f"{_cur_provider}:{_cur_model}"
            _model_info = get_model(_cur_provider, _cur_model)
            _max_tokens = _model_info.max_tokens if _model_info else 128000
            if (
                "token_limit" not in st.session_state
                or st.session_state.get("current_model_key", "") != _model_key
            ):
                st.session_state["token_limit"] = (
                    _model_info.default_tokens if _model_info else 64000
                )
                st.session_state["current_model_key"] = _model_key
            _token_limit = st.slider(
                _t("GitHub 分析最大 token 上限", "Max token budget for repo analysis"),
                min_value=4000,
                max_value=_max_tokens,
                value=st.session_state["token_limit"],
                step=1000,
                help=_t(
                    "设置 GitHub 仓库分析可用的最大 token 数，避免超出模型上下文窗口。",
                    "Maximum tokens used for repository analysis; keeps requests inside the model context window.",
                ),
            )
            st.session_state["token_limit"] = _token_limit

        _save_col, _clear_col = st.columns(2)
        with _save_col:
            if st.button(
                _t("保存配置到服务端", "Save configuration to server"), key="save_server_config", type="primary", use_container_width=True
            ):
                _saved_at = save_config({k: st.session_state.get(k) for k in PERSIST_KEYS})
                st.session_state["_config_saved_at"] = _saved_at
                _generation.apply_policies()
                store.log_action(st.session_state.get("user", ""), "保存配置")
                st.success(_t("配置已加密保存，重启服务后仍然生效。", "Configuration saved (encrypted); it survives restarts."))
        with _clear_col:
            if st.button(_t("清除已保存配置", "Clear saved configuration"), key="clear_server_config", use_container_width=True):
                clear_config()
                st.session_state["_config_saved_at"] = None
                store.log_action(st.session_state.get("user", ""), "清除配置")
                st.warning(_t("已清除服务端配置（当前会话中的值仍保留）。", "Server-side configuration cleared (current session values remain)."))
        _saved_at = st.session_state.get("_config_saved_at") or config_saved_at()
        st.caption(

                _t(
                    f"当前会话中的修改即时生效；上次保存到服务端：{_saved_at}。",
                    f"Changes apply immediately in this session; last saved to server: {_saved_at}.",
                )
                if _saved_at
                else _t(
                    "当前会话中的修改即时生效；点击「保存配置到服务端」后重启仍生效。",
                    "Changes apply immediately in this session; click “Save configuration to server” to survive restarts.",
                )

        )

        with st.container(border=True, key="settings_template"):
            st.markdown(_t("#### 报告模板", "#### Report template"))
            st.caption(_t("Word / PDF 报告的抬头与页脚信息（保存配置后生效）。", "Header and footer text for Word / PDF reports (takes effect after saving)."))
            _tm1, _tm2 = st.columns(2)
            with _tm1:
                st.text_input(
                    _t("报告抬头（品牌）", "Report header (brand)"),
                    key="report_brand",
                    placeholder=_t("威云-风险建模智能体", "Weiyun Risk Modeling Agent"),
                )
            with _tm2:
                st.text_input(
                    _t("页脚（保密标识）", "Footer (confidentiality mark)"),
                    key="report_footer",
                    placeholder=_t("内部资料 · 注意保密", "Internal use only · Confidential"),
                )

        with st.container(border=True, key="settings_policy"):
            st.markdown(_t("#### 安全策略", "#### Security policy"))
            st.caption(_t("企业安全基线会注入所有生成请求；脱敏在发送前替换密钥/令牌等敏感串。", "The enterprise baseline is injected into every request; scrubbing replaces secrets before sending."))
            st.text_area(
                _t("企业安全基线 / 自定义要求", "Enterprise security baseline / custom requirements"),
                key="security_baseline",
                height=120,
                placeholder=(
                    _t("例如：\n- 必须符合等保 2.0 三级要求\n- 统一使用公司 SSO（OIDC）与集中审计\n- 数据出网需经网关审批", "e.g.\n- Must comply with internal security baselines\n- Use company SSO (OIDC) and centralized audit\n- Data egress requires gateway approval")
                ),
                help=_t("保存配置后生效，将作为额外的系统指令附加到每次模型调用。", "Takes effect after saving; appended as an extra system instruction to every model call."),
            )
            st.checkbox(
                _t(
                    "生成威胁模型后自动对抗式复核（标注置信度）",
                    "Adversarially verify each threat after generation",
                ),
                key="verify_threats",
                value=bool(st.session_state.get("verify_threats", True)),
                help=_t(
                    "复核会额外调用一次模型，给出 已确认/存疑/已驳回 与置信度，并写回威胁台账。",
                    "Adds one extra model call and writes verdicts back to the threat register.",
                ),
            )
            st.checkbox(
                _t("发送前对密钥 / 令牌做脱敏", "Scrub secrets/tokens before sending"),
                key="scrub_enabled",
                value=bool(st.session_state.get("scrub_enabled", True)),
                help=_t("识别 OpenAI/Anthropic/GitHub/AWS/JWT/私钥等模式并替换为 [已脱敏:...]。", "Detects OpenAI/Anthropic/GitHub/AWS/JWT/private-key patterns and replaces them with [redacted:…]."),
            )
            if "session_days_input" not in st.session_state:
                st.session_state["session_days_input"] = store.session_days()
            st.number_input(
                _t("会话有效期（天）", "Session lifetime (days)"),
                min_value=1,
                max_value=30,
                step=1,
                key="session_days_input",
                on_change=lambda: store.set_meta(
                    "session_days", str(int(st.session_state.get("session_days_input") or 7))
                ),
                help=_t(
                    "浏览器免登录时长（1-30 天）；「退出所有设备」或改密码会立即失效。",
                    "How long the browser stays signed in (1-30 days); “sign out everywhere” or a password change invalidates it immediately.",
                ),
            )
            st.caption(
                _t(
                    "登录失败 5 次锁定 5 分钟（每 15 分钟滚动统计）；HTTPS 部署设置 STRIDE_GPT_SECURE_COOKIE=1 可启用 Secure Cookie。",
                    "5 failed sign-ins lock the account for 5 minutes (rolling 15-minute window); set STRIDE_GPT_SECURE_COOKIE=1 on HTTPS deployments to enable Secure cookies.",
                )
            )

        with st.container(border=True, key="settings_usage"):
            st.markdown(_t("#### 用量与成本", "#### Usage & cost"))
            _budget = _usage.budget_status()
            st.number_input(
                _t("月度预算（美元，0 = 不限）", "Monthly budget (USD, 0 = unlimited)"),
                min_value=0.0,
                value=float(st.session_state.get("monthly_budget") or 0.0),
                step=10.0,
                key="monthly_budget",
            )
            if _budget["budget"]:
                st.progress(
                    min(1.0, _budget["ratio"]),
                    text=_t(
                        f"本月已用 ${_budget['spent']:.2f} / ${_budget['budget']:.2f}",
                        f"${_budget['spent']:.2f} of ${_budget['budget']:.2f} spent this month",
                    ),
                )
            else:
                st.caption(
                    _t(
                        f"本月已用 ${_budget['spent']:.2f} · {_budget['tokens']:,} tokens ·"
                        f" {_budget['calls']} 次调用",
                        f"${_budget['spent']:.2f} · {_budget['tokens']:,} tokens ·"
                        f" {_budget['calls']} calls this month",
                    )
                )
            _model_rows = _usage_month_groups()
            if _model_rows:
                _lines = [
                    _t(
                        "| 模型 | 调用 | tokens | 估算成本 |",
                        "| Model | Calls | Tokens | Est. cost |",
                    ),
                    "|---|---|---|---|",
                ]
                _lines.extend(
                    f"| {_row['key']} | {_row['calls']} | {_row['tokens']:,} |"
                    f" ${_row['cost']:.2f} |"
                    for _row in _model_rows
                )
                st.markdown("\n".join(_lines))
            st.caption(
                _t(
                    "价格是公开标价的近似值，仅用于内部估算。",
                    "Prices are approximate list prices for internal estimation only.",
                )
            )

        with st.container(border=True, key="settings_api"):
            st.markdown(_t("#### API 访问", "#### API access"))
            st.caption(_t("供 REST API（apps/api）与 CI 调用；密钥仅在创建时显示一次。", "For the REST API (apps/api) and CI; the key is shown only once."))
            _new_key_name = st.text_input(
                _t("新密钥名称", "New key name"), key="api_key_name", placeholder=_t("如：CI 流水线", "e.g. CI pipeline")
            )
            _s1, _s2 = st.columns([1.4, 1])
            with _s1:
                _key_scopes = st.multiselect(
                    _t("作用域", "Scopes"),
                    options=["read", "write"],
                    default=["read", "write"],
                    key="new_key_scopes",
                    format_func=lambda sc: _t(
                        {"read": "read（只读）", "write": "write（可写）"}.get(sc, sc),
                        {"read": "read (read-only)", "write": "write (create/update/delete)"}.get(sc, sc),
                    ),
                    help=_t(
                        "只读密钥只能调用 GET 接口；生成/更新/删除需要 write。",
                        "Read-only keys may only call GET endpoints; generation/update/delete need write.",
                    ),
                )
            with _s2:
                _key_expires = st.number_input(
                    _t("有效期（天，0 = 不过期）", "Valid for (days, 0 = never expires)"),
                    min_value=0,
                    max_value=3650,
                    value=0,
                    step=30,
                    key="new_key_expires",
                )
            _q1, _q2 = st.columns(2)
            with _q1:
                _key_daily = st.number_input(
                    _t("日 token 配额（0 = 不限）", "Daily token quota (0 = unlimited)"),
                    min_value=0,
                    value=0,
                    step=100_000,
                    key="new_key_daily",
                )
            with _q2:
                _key_monthly = st.number_input(
                    _t("月费用配额（美元，0 = 不限）", "Monthly cost quota (USD, 0 = unlimited)"),
                    min_value=0.0,
                    value=0.0,
                    step=10.0,
                    key="new_key_monthly",
                )
            if st.button(_t("创建 API Key", "Create API key"), key="create_api_key", use_container_width=True):
                if not (_new_key_name or "").strip():
                    st.warning(_t("请先填写密钥名称", "Enter a key name first"))
                else:
                    st.session_state["_new_api_key"] = store.create_api_key(
                        _new_key_name.strip(),
                        scopes=_key_scopes or ["read"],
                        expires_days=int(_key_expires),
                        owner=st.session_state.get("user", ""),
                    )
                    _new_key_row = store.get_api_key_by_name(_new_key_name.strip())
                    if _new_key_row:
                        store.set_api_key_quota(
                            _new_key_row["id"], int(_key_daily), float(_key_monthly)
                        )
                    store.log_action(
                        st.session_state.get("user", ""), _t("创建 API Key", "Create API key"), _new_key_name.strip()
                    )
                    st.success(_t("已创建，请立即复制保存（只显示一次）", "Created — copy and store it now (shown only once)"))
            if st.session_state.get("_new_api_key"):
                st.code(st.session_state["_new_api_key"], language="text")
                st.caption(_t("刷新页面后不再显示。", "It will not be shown again after refresh."))
            _keys = store.list_api_keys()
            for _k in _keys:
                _kc1, _kc2, _kc3 = st.columns([3.6, 1.15, 1.15], vertical_alignment="center")
                with _kc1:
                    _bits = [f"`{_k.get('scopes') or 'read,write'}`"]
                    if _k.get("expires_at"):
                        _bits.append(
                            _t(
                                f"到期 {_k['expires_at'][:10]}",
                                f"expires {_k['expires_at'][:10]}",
                            )
                            + (_t("（已过期）", " (expired)") if _k.get("expired") else "")
                        )
                    else:
                        _bits.append(_t("不过期", "no expiry"))
                    if _k.get("daily_token_limit"):
                        _bits.append(f"{_k['daily_token_limit']:,} tokens/day")
                    if _k.get("monthly_cost_limit"):
                        _bits.append(f"${_k['monthly_cost_limit']:.2f}/month")
                    if _k.get("owner"):
                        _bits.append(_t(f"创建人 {_k['owner']}", f"owner {_k['owner']}"))
                    st.markdown(
                        f"**{_k['name']}**"
                        + (f"（{' · '.join(_bits)}）" if _bits else "")
                        + _t("  \n<span class='sg-rep-meta'>创建 ", "  \n<span class='sg-rep-meta'>Created ")
                        + f"{_k['created_at']}"
                        + _t(" · 最近使用 ", " · last used ")
                        + f"{_k['last_used_at'] or '—'}</span>",
                        unsafe_allow_html=True,
                    )
                with _kc2, st.popover(_t("轮换", "Rotate"), use_container_width=True):
                    st.caption(
                        _t(
                            "轮换会立即废弃当前密钥并生成新密钥（仅显示一次）。",
                            "Rotation invalidates the current key and issues a new one (shown once).",
                        )
                    )
                    if st.button(_t("确认轮换", "Confirm rotate"), key=f"rotate_btn_{_k['id']}"):
                        _rotated = store.rotate_api_key(_k["id"])
                        if _rotated:
                            st.session_state["_new_api_key"] = _rotated
                            store.log_action(
                                st.session_state.get("user", ""), "轮换 API Key", _k["name"]
                            )
                            st.rerun()
                with _kc3:
                    if st.button(_t("吊销", "Revoke"), key=f"revoke_key_{_k['id']}", use_container_width=True):
                        store.revoke_api_key(_k["id"])
                        store.log_action(st.session_state.get("user", ""), "吊销 API Key", _k["name"])
                        st.rerun()
            if not _keys:
                st.caption(_t("暂无 API Key。", "No API keys yet."))
            st.caption(_t("接口地址示例：`http://<服务器>:8000/api/v1/threat-model`（启动与示例见 docs/api.md）", "Endpoint example: `http://<server>:8000/api/v1/threat-model` (see docs/api.md)"))

        with st.container(border=True, key="settings_webhooks"):
            st.markdown(_t("#### 工单 / 通知集成", "#### Ticketing / notification integrations"))
            st.caption(
                _t("威胁台账可推送到飞书 / 企业微信 / 钉钉 / 通用 Webhook（Jira、禅道等可经通用 Webhook 中转）。", "Push the threat register to Feishu / WeCom / DingTalk / generic webhooks (Jira, ZenTao, etc. via generic webhook).")
            )
            _wh1, _wh2, _wh3 = st.columns([2, 3, 1.4])
            with _wh1:
                _wh_name = st.text_input(_t("名称", "Name"), key="wh_name")
            with _wh2:
                _wh_url = st.text_input("Webhook URL", key="wh_url")
            with _wh3:
                _wh_kind = st.selectbox(_t("类型", "Type"), store.WEBHOOK_KINDS, key="wh_kind")
            if st.button(_t("添加 Webhook", "Add webhook"), key="add_webhook"):
                if _wh_name and _wh_url:
                    store.add_webhook(_wh_name, _wh_url, _wh_kind)
                    store.log_action(
                        st.session_state.get("user", ""), _t("添加 Webhook", "Add webhook"), _wh_name
                    )
                    st.success(_t("已添加", "Added"))
                    st.rerun()
                else:
                    st.warning(_t("请填写名称与 URL", "Enter a name and URL"))
            for _w in store.list_webhooks():
                _wc1, _wc2 = st.columns([4, 1], vertical_alignment="center")
                with _wc1:
                    st.markdown(
                        f"**{_w['name']}**（{_w['kind']}）  \n"
                        f"<span class='sg-rep-meta'>{_w['url'][:70]}</span>",
                        unsafe_allow_html=True,
                    )
                with _wc2:
                    if st.button(_t("删除", "Delete"), key=f"del_webhook_{_w['id']}", use_container_width=True):
                        store.delete_webhook(_w["id"])
                        store.log_action(
                            st.session_state.get("user", ""), "删除 Webhook", _w["name"]
                        )
                        st.rerun()
