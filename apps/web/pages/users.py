"""用户与审计页面：我的账号（所有用户）+ 用户管理与审计日志（仅管理员）。"""

from __future__ import annotations

import streamlit as st
from shared import (
    _AUTH_USERNAME,
    _ROLE_LABELS,
    _is_admin,
    _t,
    store,
)

_POLICY_CODES = ("too_short", "need_classes", "contains_username", "too_common")


def _policy_text(code: str) -> str:
    return {
        "too_short": _t("至少 8 个字符", "at least 8 characters"),
        "need_classes": _t(
            "包含大小写字母 / 数字 / 符号中的至少两类",
            "use at least two of: lowercase, uppercase, digits, symbols",
        ),
        "contains_username": _t("不能包含用户名", "must not contain the username"),
        "too_common": _t("不能是常见弱口令", "must not be a common password"),
    }.get(code, code)


def _policy_message(exc: Exception) -> str:
    """把 store 返回的策略代码翻译成用户可读文案。"""
    text = str(exc)
    if "old_password_incorrect" in text:
        return _t("当前密码不正确。", "Current password is incorrect.")
    replaced = text
    for code in _POLICY_CODES:
        replaced = replaced.replace(code, _policy_text(code))
    if replaced == text and text:
        return _t("密码不符合策略：", "Password does not meet the policy: ") + text
    return replaced


def _policy_hint() -> str:
    return _t(
        "至少 8 位，含大小写/数字/符号中至少两类，不含用户名，非常见弱口令。",
        "At least 8 characters, two of (lower/upper/digit/symbol), no username, not a common password.",
    )


def _sign_out_self() -> None:
    """清会话并让当前 cookie 失效（用于“退出所有设备”后立即回到登录页）。"""
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


def _render_account() -> None:
    """我的账号：改密码 + 退出所有设备（所有登录用户可用）。"""
    _user = st.session_state.get("user", "")
    st.markdown(_t("#### 我的账号", "#### My account"))
    with st.container(border=True, key="account_self"):
        _left, _right = st.columns([1.15, 1], gap="large")
        with _left:
            if _user == _AUTH_USERNAME:
                st.caption(
                    _t(
                        "内置管理员的密码由环境变量 STRIDE_GPT_USERNAME / STRIDE_GPT_PASSWORD 管理，"
                        "请在部署配置中修改；修改后需重启服务。",
                        "The built-in admin password comes from STRIDE_GPT_USERNAME / STRIDE_GPT_PASSWORD; "
                        "change it in your deployment config and restart the service.",
                    )
                )
            else:
                with st.form("change_pw_form", border=False):
                    _old = st.text_input(
                        _t("当前密码", "Current password"), type="password", key="cp_old"
                    )
                    _new = st.text_input(
                        _t("新密码", "New password"),
                        type="password",
                        key="cp_new",
                        help=_policy_hint(),
                    )
                    _new2 = st.text_input(
                        _t("确认新密码", "Confirm new password"), type="password", key="cp_new2"
                    )
                    if st.form_submit_button(
                        _t("修改密码", "Change password"), type="primary", use_container_width=True
                    ):
                        if not _new:
                            st.error(_t("新密码不能为空。", "New password cannot be empty."))
                        elif _new != _new2:
                            st.error(_t("两次输入的新密码不一致。", "The two new passwords do not match."))
                        else:
                            try:
                                store.change_password(_user, _old, _new)
                                store.log_action(_user, _t("修改密码", "Change password"))
                                st.success(
                                    _t(
                                        "密码已修改，其它设备上的会话已失效。",
                                        "Password changed — sessions on other devices are now invalid.",
                                    )
                                )
                            except ValueError as exc:
                                st.error(_policy_message(exc))
            if st.button(
                _t("退出所有设备", "Sign out everywhere"),
                key="logout_all_devices",
                use_container_width=True,
            ):
                store.force_logout(_user)
                _sign_out_self()
        with _right:
            _info = store.get_user(_user) or {}
            st.markdown(
                f"- {_t('用户名', 'Username')}：**{_user}**\n"
                f"- {_t('角色', 'Role')}：**{_ROLE_LABELS.get(st.session_state.get('role'), st.session_state.get('role', ''))}**\n"
                f"- {_t('本次登录', 'This session')}：{st.session_state.get('login_at') or '—'}\n"
                f"- {_t('最近登录', 'Last sign-in')}：{_info.get('last_login') or '—'}"
            )
            st.caption(
                _t(
                    "会话有效期内可免登录；「退出所有设备」会立即失效其他设备上的登录状态。",
                    "Your session keeps you signed in; “Sign out everywhere” invalidates other devices immediately.",
                )
            )


def _render_my_audit() -> None:
    _user = st.session_state.get("user", "")
    st.markdown(_t("#### 我的操作记录", "#### My activity"))
    _rows = store.list_audit(limit=100, username=_user)
    if not _rows:
        st.caption(_t("暂无记录。", "No records yet."))
        return
    _lines = ["| " + _t("时间", "Time") + " | " + _t("操作", "Action") + " | " + _t("详情", "Detail") + " |", "|---|---|---|"]
    for _row in _rows:
        _detail = (_row["detail"] or "").replace("|", "\\|").replace("\n", " ")[:80]
        _lines.append(f"| {_row['ts']} | {_row['action']} | {_detail} |")
    st.markdown("\n".join(_lines))


def _render_admin_management() -> None:
    """管理员：创建用户、重置密码、强制下线、删除。"""
    st.markdown(_t("#### 用户管理", "#### User management"))
    with st.container(border=True, key="users_manage"):
        _u1, _u2, _u3 = st.columns([2, 2, 1.4])
        with _u1:
            _new_user = st.text_input(
                _t("用户名", "Username"), key="nu_name", placeholder=_t("如：zhangsan", "e.g. zhangsan")
            )
        with _u2:
            _new_pw = st.text_input(
                _t("初始密码", "Initial password"),
                type="password",
                key="nu_pw",
                placeholder=_t("至少 8 位", "At least 8 characters"),
                help=_policy_hint(),
            )
        with _u3:
            _new_role = st.selectbox(
                _t("角色", "Role"),
                ["user", "admin"],
                key="nu_role",
                format_func=lambda r: _ROLE_LABELS.get(r, r),
            )
        if st.button(_t("创建用户", "Create user"), key="create_user", use_container_width=True):
            try:
                store.create_user(_new_user, _new_pw, _new_role)
                store.log_action(
                    st.session_state.get("user", ""),
                    _t("创建用户", "Create user"),
                    f"{_new_user}（{_new_role}）",
                )
                st.success(_t(f"已创建用户 {_new_user}", f"User {_new_user} created"))
                st.rerun()
            except ValueError as exc:
                st.error(_policy_message(exc))

        st.markdown(
            f"**{_AUTH_USERNAME}**（{_t('内置管理员', 'built-in admin')}）  \n"
            f"<span class='sg-rep-meta'>{_t('由环境变量 STRIDE_GPT_USERNAME/PASSWORD 管理，不可在此修改', 'Managed by STRIDE_GPT_USERNAME/PASSWORD env vars; not editable here')}</span>",
            unsafe_allow_html=True,
        )
        for _u in store.list_users():
            _uc1, _uc2, _uc3, _uc4 = st.columns([3.6, 1.2, 1.2, 1], vertical_alignment="center")
            _lock = store.login_lock_status(_u["username"])
            _lock_note = (
                _t(f" · 登录锁定中（约 {_lock['minutes']} 分钟）", f" · locked (~{_lock['minutes']} min)")
                if _lock["locked"]
                else ""
            )
            with _uc1:
                st.markdown(
                    f"**{_u['username']}**（{_ROLE_LABELS.get(_u['role'], _u['role'])}）  \n"
                    f"<span class='sg-rep-meta'>{_t('创建', 'Created')} {_u['created_at']} · "
                    f"{_t('最近登录', 'Last sign-in')} {_u['last_login'] or '—'}{_lock_note}</span>",
                    unsafe_allow_html=True,
                )
            with _uc2, st.popover(_t("重置密码", "Reset password"), use_container_width=True):
                _rp = st.text_input(
                    _t("新密码", "New password"),
                    type="password",
                    key=f"rp_{_u['username']}",
                    help=_policy_hint(),
                )
                if st.button(_t("确认重置", "Confirm reset"), key=f"rp_btn_{_u['username']}"):
                    try:
                        store.set_user_password(_u["username"], _rp)
                        store.log_action(
                            st.session_state.get("user", ""),
                            _t("重置密码", "Reset password"),
                            _u["username"],
                        )
                        st.success(_t("已重置，该用户需重新登录", "Reset done — the user must sign in again"))
                    except ValueError as exc:
                        st.error(_policy_message(exc))
            with _uc3:
                if st.button(
                    _t("强制下线", "Force sign-out"),
                    key=f"kick_user_{_u['username']}",
                    use_container_width=True,
                ):
                    store.force_logout(_u["username"])
                    st.success(_t("该用户所有会话已失效", "All sessions for that user are invalidated"))
                    st.rerun()
            with _uc4:
                if st.button(
                    _t("删除", "Delete"), key=f"del_user_{_u['username']}", use_container_width=True
                ):
                    store.delete_user(_u["username"])
                    store.force_logout(_u["username"])
                    store.log_action(
                        st.session_state.get("user", ""), "删除用户", _u["username"]
                    )
                    st.rerun()


def _render_audit_log() -> None:
    st.markdown(_t("#### 审计日志", "#### Audit log"))
    _audit_filter = st.text_input(
        _t("按用户筛选", "Filter by user"),
        key="audit_filter",
        placeholder=_t("留空显示全部", "Empty shows all"),
    )
    _logs = store.list_audit(limit=200, username=(_audit_filter or "").strip() or None)
    if not _logs:
        st.caption(_t("暂无审计记录。", "No audit records yet."))
        return
    _lines = ["| " + _t("时间", "Time") + " | " + _t("用户", "User") + " | " + _t("操作", "Action") + " | " + _t("详情", "Detail") + " |", "|---|---|---|---|"]
    for _row in _logs:
        _detail = (_row["detail"] or "").replace("|", "\\|").replace("\n", " ")[:80]
        _lines.append(
            f"| {_row['ts']} | {_row['username']} | {_row['action']} | {_detail} |"
        )
    st.markdown("\n".join(_lines))


def _page_users() -> None:
    """我的账号（所有用户）+ 用户管理与审计日志（仅管理员）。"""
    _render_account()
    if not _is_admin():
        st.divider()
        _render_my_audit()
        return
    st.divider()
    _render_admin_management()
    st.divider()
    _render_audit_log()
