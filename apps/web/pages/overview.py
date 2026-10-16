"""概览仪表盘页面。（P7 从 main.py 拆分）。"""

from __future__ import annotations

import streamlit as st
from services import (
    _kind_label,
)
from shared import (
    _is_admin,
    _t,
    _usage,
    store,
)


def _page_overview() -> None:
    """概览仪表盘：全局风险态势、验证与用量、近期活动、快捷入口。"""
    store.sync_projects_from_reports()
    _projects = store.list_projects()
    _reports = store.list_reports(limit=2000)
    _threats = store.list_threats()
    _vstats = store.threat_verdict_stats()

    _open = sum(1 for t in _threats if t["status"] == "待处理")
    _fixed = sum(1 for t in _threats if t["status"] == "已修复")
    _risk = sorted(
        [t for t in _threats if t["risk_score"] is not None],
        key=lambda t: -float(t["risk_score"]),
    )[:5]

    _k1, _k2, _k3, _k4, _k5 = st.columns(5)
    _k1.metric(_t("项目", "Projects"), len(_projects))
    _k2.metric(_t("报告", "Reports"), len(_reports))
    _k3.metric(_t("威胁条目", "Threats"), len(_threats))
    _k4.metric(_t("待处理", "Open"), _open)
    _k5.metric(_t("已修复", "Fixed"), _fixed)

    _left, _right = st.columns([1.3, 1], gap="large")
    with _left:
        st.markdown(_t("#### 风险态势", "#### Risk posture"))
        _by_type: dict[str, int] = {}
        for _item in _threats:
            _by_type[_item["threat_type"]] = _by_type.get(_item["threat_type"], 0) + 1
        _by_type = dict(sorted(_by_type.items(), key=lambda kv: -kv[1]))
        if _by_type:
            st.bar_chart({_t("威胁数量", "Threats"): _by_type})
        else:
            st.caption(_t("暂无威胁数据。", "No threat data yet."))

        _status_series = {
            _t("待处理", "Open"): _open,
            _t("已修复", "Fixed"): _fixed,
            _t("其他", "Other"): max(0, len(_threats) - _open - _fixed),
        }
        _status_series = {k: v for k, v in _status_series.items() if v}
        if _status_series:
            st.bar_chart({_t("数量", "Count"): _status_series})

        if _risk:
            st.markdown(_t("#### 高风险 Top 5", "#### Top 5 risks"))
            _lines = [
                _t("| 风险分 | 类型 | 场景 | 状态 |", "| Score | Type | Scenario | Status |"),
                "|---|---|---|---|",
            ]
            for _item in _risk:
                _scene = (_item["scenario"] or "").replace("|", "\\|").replace("\n", " ")[:70]
                _lines.append(
                    f"| {float(_item['risk_score']):.1f} | {_item['threat_type']} | {_scene} |"
                    f" {_item['status']} |"
                )
            st.markdown("\n".join(_lines))

    with _right:
        st.markdown(_t("#### 验证与预算", "#### Verification & budget"))
        st.markdown(
            f"- {_t('已确认', 'Confirmed')}：**{_vstats.get('已确认', 0)}**\n"
            f"- {_t('存疑', 'Uncertain')}：**{_vstats.get('存疑', 0)}**\n"
            f"- {_t('已驳回', 'Refuted')}：**{_vstats.get('已驳回', 0)}**\n"
            f"- {_t('未验证', 'Unverified')}：**{_vstats.get('未验证', 0)}**"
        )
        _budget = _usage.budget_status()
        if _budget["budget"]:
            st.progress(
                min(1.0, _budget["ratio"]),
                text=f"${_budget['spent']:.2f} / ${_budget['budget']:.2f}",
            )
        else:
            st.caption(
                _t(
                    f"本月用量：${_budget['spent']:.2f} · {_budget['tokens']:,} tokens",
                    f"This month: ${_budget['spent']:.2f} · {_budget['tokens']:,} tokens",
                )
            )

        st.markdown(_t("#### 近期报告", "#### Recent reports"))
        if _reports:
            for _row in _reports[:5]:
                st.markdown(
                    f"- {_kind_label(_row['kind'])} · {_row['project'] or '—'}"
                    f"  \n<span class='sg-rep-meta'>{_row['created_at']}</span>",
                    unsafe_allow_html=True,
                )
        else:
            st.caption(_t("暂无报告。", "No reports yet."))

        st.markdown(_t("#### 快捷入口", "#### Quick actions"))
        _qa1, _qa2 = st.columns(2)
        with _qa1:
            if st.button(
                _t("生成威胁模型", "Threat model"), key="ov_tm", use_container_width=True
            ):
                st.session_state["nav_page"] = _t("威胁模型", "Threat Model")
                st.rerun()
            if st.button(_t("项目工作区", "Projects"), key="ov_proj", use_container_width=True):
                st.session_state["nav_page"] = _t("项目工作区", "Projects")
                st.rerun()
        with _qa2:
            if st.button(
                _t("报告历史", "Report history"), key="ov_rep", use_container_width=True
            ):
                st.session_state["nav_page"] = _t("报告历史", "Report History")
                st.rerun()
            if _is_admin() and st.button(
                _t("系统配置", "System settings"), key="ov_cfg", use_container_width=True
            ):
                st.session_state["view"] = "settings"
                st.rerun()
