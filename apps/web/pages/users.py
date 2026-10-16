"""用户与审计页面。（P7 从 main.py 拆分）。"""

from __future__ import annotations

import streamlit as st
from shared import (
    _AUTH_USERNAME,
    _ROLE_LABELS,
    _is_admin,
    _t,
    store,
)


def _page_users() -> None:
    """用户与审计：账号管理（仅管理员）+ 操作审计日志。"""
    if not _is_admin():
        st.warning(_t("该页面仅管理员可用。", "This page is available to administrators only."))
        return

    st.markdown(_t("#### 用户管理", "#### User management"))
    with st.container(border=True, key="users_manage"):
        _u1, _u2, _u3 = st.columns([2, 2, 1.4])
        with _u1:
            _new_user = st.text_input(_t("用户名", "Username"), key="nu_name", placeholder=_t("如：zhangsan", "e.g. zhangsan"))
        with _u2:
            _new_pw = st.text_input(
                _t("初始密码", "Initial password"), type="password", key="nu_pw", placeholder=_t("至少 6 位", "At least 6 characters")
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
                st.success(f"已创建用户 {_new_user}")
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))

        st.markdown(
            f"**{_AUTH_USERNAME}**（内置管理员）  \n"
            "<span class='sg-rep-meta'>由环境变量 STRIDE_GPT_USERNAME/PASSWORD 管理，不可在此修改</span>",
            unsafe_allow_html=True,
        )
        for _u in store.list_users():
            _uc1, _uc2, _uc3 = st.columns([4, 1.4, 1], vertical_alignment="center")
            with _uc1:
                st.markdown(
                    f"**{_u['username']}**（{_ROLE_LABELS.get(_u['role'], _u['role'])}）  \n"
                    f"<span class='sg-rep-meta'>创建 {_u['created_at']} ·"
                    f" 最近登录 {_u['last_login'] or '—'}</span>",
                    unsafe_allow_html=True,
                )
            with _uc2, st.popover(_t("重置密码", "Reset password"), use_container_width=True):
                _rp = st.text_input(
                    _t("新密码", "New password"), type="password", key=f"rp_{_u['username']}"
                )
                if st.button(_t("确认重置", "Confirm reset"), key=f"rp_btn_{_u['username']}"):
                    try:
                        store.set_user_password(_u["username"], _rp)
                        store.log_action(
                            st.session_state.get("user", ""),
                            _t("重置密码", "Reset password"),
                            _u["username"],
                        )
                        st.success(_t("已重置", "Reset done"))
                    except ValueError as exc:
                        st.error(str(exc))
            with _uc3:
                if st.button(
                    _t("删除", "Delete"), key=f"del_user_{_u['username']}", use_container_width=True
                ):
                    store.delete_user(_u["username"])
                    store.log_action(
                        st.session_state.get("user", ""), "删除用户", _u["username"]
                    )
                    st.rerun()

    st.markdown(_t("#### 审计日志", "#### Audit log"))
    _audit_filter = st.text_input(_t("按用户筛选", "Filter by user"), key="audit_filter", placeholder=_t("留空显示全部", "Empty shows all"))
    _logs = store.list_audit(limit=200, username=(_audit_filter or "").strip() or None)
    if not _logs:
        st.caption(_t("暂无审计记录。", "No audit records yet."))
        return
    _lines = [
        "| 时间 | 用户 | 操作 | 详情 |",
        "|---|---|---|---|",
    ]
    for _row in _logs:
        _detail = (_row["detail"] or "").replace("|", "\\|").replace("\n", " ")[:80]
        _lines.append(
            f"| {_row['ts']} | {_row['username']} | {_row['action']} | {_detail} |"
        )
    st.markdown("\n".join(_lines))
