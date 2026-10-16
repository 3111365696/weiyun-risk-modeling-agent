"""项目工作区页面（台账、看板、一键全流程）。（P7 从 main.py 拆分）。"""

from __future__ import annotations

import streamlit as st
from services import (
    _kind_label,
    _run_full_pipeline,
)
from shared import (
    THREAT_STATUSES,
    VERDICTS,
    _generation,
    _is_admin,
    _t,
    backfill_project,
    list_projects,
    list_reports,
    list_threats,
    store,
    sync_projects_from_reports,
    threat_stats,
    update_project_description,
    update_threats,
)


def _page_projects() -> None:
    """项目工作区：项目概览、产物、威胁台账、风险看板、一键全流程。"""
    sync_projects_from_reports()
    _projects = list_projects()
    if not _projects:
        st.info(_t("还没有项目。到「威胁模型」页填写应用描述并生成一次，系统会自动创建项目。", "No projects yet. Generate a threat model once and the project is created automatically."))
        return

    _sel = st.selectbox(_t("选择项目", "Select project"), [p["name"] for p in _projects], key="ws_project")
    _proj = next((p for p in _projects if p["name"] == _sel), None)
    if not _proj:
        return
    backfill_project(_sel)

    _stats = threat_stats(_sel)
    _m1, _m2, _m3, _m4 = st.columns(4)
    _m1.metric(_t("产物数量", "Artifacts"), _proj.get("report_count", 0))
    _m2.metric(_t("威胁总数", "Total threats"), _stats["total"])
    _m3.metric(_t("待处理", "Open"), _stats["by_status"].get(_t("待处理", "Open"), 0))
    _m4.metric(_t("已修复", "Fixed"), _stats["by_status"].get("已修复", 0))

    _tab_overview, _tab_register, _tab_board = st.tabs(
        [_t("项目概览", "Overview"), _t("威胁台账", "Threat register"), _t("风险看板", "Risk board")]
    )

    with _tab_overview:
        _latest_models = _generation.latest_threat_models(_sel, limit=1)
        if _latest_models:
            _cov = _generation.stride_coverage(_latest_models[0])
            st.caption(
                _t("STRIDE 覆盖度：", "STRIDE coverage: ")
                + " · ".join(f"{k} {v}" for k, v in _cov["counts"].items() if v)
                + (
                    _t(" · 缺失：", " · missing: ") + "、".join(_cov["missing"])
                    if _cov["missing"]
                    else _t(" · 六类齐全", " · all six covered")
                )
            )
        _diff = _generation.diff_latest_threat_models(_sel)
        if _diff:
            with st.expander(
                _t(
                    f"变更对比（最近两次威胁模型）：新增 {_diff['added_count']} · 消失 {_diff['removed_count']} · 未变 {_diff['unchanged_count']}",
                    f"Drift (last two threat models): {_diff['added_count']} added · {_diff['removed_count']} removed · {_diff['unchanged_count']} unchanged",
                )
            ):
                if _diff["added"]:
                    st.markdown(_t("**新增威胁**", "**New threats**"))
                    for _threat in _diff["added"]:
                        st.markdown(
                            f"- {_threat.get('Threat Type', '')} · {_threat.get('Scenario', '')}"
                        )
                if _diff["removed"]:
                    st.markdown(_t("**已消失威胁**", "**Resolved threats**"))
                    for _threat in _diff["removed"]:
                        st.markdown(
                            f"- {_threat.get('Threat Type', '')} · {_threat.get('Scenario', '')}"
                        )
                if not _diff["added"] and not _diff["removed"]:
                    st.caption(_t("两次威胁模型完全一致。", "The two threat models are identical."))
        _desc = st.text_area(
            _t("应用描述（用于分析与生成）", "Application description (used for analysis)"),
            value=_proj.get("description") or "",
            height=160,
            key=f"ws_desc_{_sel}",
        )
        _c1, _c2 = st.columns([1.2, 3])
        with _c1:
            if st.button(_t("保存描述", "Save description"), key="ws_save_desc", use_container_width=True):
                update_project_description(_sel, _desc)
                st.session_state["app_input"] = _desc
                st.session_state["app_desc"] = _desc
                st.session_state["project_name"] = _sel
                st.success(_t("已保存，并同步为当前分析输入。", "Saved and synced as the current analysis input."))
        with _c2:
            st.caption(_t("保存后，「威胁模型」页与一键全流程都会使用这段描述。", "After saving, the Threat model page and the full pipeline use this description."))
        if st.button(_t("一键全流程生成", "Run full pipeline"), type="primary", key="ws_pipeline"):
            _desc_effective = (_desc or _proj.get("description") or st.session_state.get("app_input") or "").strip()
            store.log_action(st.session_state.get("user", ""), _t("一键全流程生成", "Run full pipeline"), _sel)
            _run_full_pipeline(_sel, _desc_effective)

        st.markdown(_t("#### 定时自动分析", "#### Scheduled analysis"))
        _sched = next((s for s in store.list_schedules() if s["project"] == _sel), None)
        with st.container(border=True, key="ws_schedule"):
            _sc1, _sc2, _sc3 = st.columns([1.3, 1.3, 2.4], vertical_alignment="bottom")
            with _sc1:
                _interval_h = st.number_input(
                    _t("检查间隔（小时）", "Check interval (hours)"),
                    min_value=1,
                    max_value=168,
                    value=max(1, round((_sched or {}).get("interval_minutes", 1440) / 60)),
                    key=f"ws_interval_{_sel}",
                )
            with _sc2:
                _notify = st.checkbox(
                    _t("威胁变化时推送 Webhook", "Push webhook on threat changes"),
                    value=bool((_sched or {}).get("notify_on_change", 1)),
                    key=f"ws_notify_{_sel}",
                )
            with _sc3:
                _sb1, _sb2, _sb3, _sb4 = st.columns(4)
                with _sb1:
                    if st.button(_t("保存计划", "Save schedule"), key="ws_save_sched", use_container_width=True):
                        store.add_schedule(_sel, int(_interval_h) * 60, _notify)
                        store.log_action(
                            st.session_state.get("user", ""), "保存定时计划", _sel
                        )
                        st.success(_t("计划已保存", "Schedule saved"))
                        st.rerun()
                with _sb2:
                    if st.button(_t("立即执行", "Run now"), key="ws_run_sched", use_container_width=True):
                        store.add_schedule(_sel, int(_interval_h) * 60, _notify)
                        _cur = next(
                            (s for s in store.list_schedules() if s["project"] == _sel), None
                        )
                        with st.spinner(_t("正在执行计划…", "Running schedule…")):
                            _res = _generation.run_scheduled_analysis(_cur or {"project": _sel})
                        store.log_action(
                            st.session_state.get("user", ""), "手动执行定时计划", _sel
                        )
                        st.success(
                            _t(
                                f"执行完成：{_res.get('status')}（新增 {_res.get('added', 0)} / 消失 {_res.get('removed', 0)}）",
                                f"Run finished: {_res.get('status')} ({_res.get('added', 0)} added / {_res.get('removed', 0)} removed)",
                            )
                        )
                        st.rerun()
                with _sb3:
                    if _sched and _sched["enabled"]:
                        if st.button(_t("暂停", "Pause"), key="ws_pause_sched", use_container_width=True):
                            store.update_schedule(_sched["id"], enabled=0)
                            st.rerun()
                    elif _sched and st.button(
                        _t("启用", "Enable"), key="ws_resume_sched", use_container_width=True
                    ):
                        store.update_schedule(_sched["id"], enabled=1)
                        st.rerun()
                with _sb4:
                    if _sched and st.button(_t("删除", "Delete"), key="ws_del_sched", use_container_width=True):
                        store.delete_schedule(_sched["id"])
                        st.rerun()
            if _sched:
                st.caption(
                    _t(
                        f"上次执行：{_sched['last_run'] or '—'} · 状态：{_sched['last_status'] or '—'}"
                        f" · {'已启用' if _sched['enabled'] else '已暂停'}",
                        f"Last run: {_sched['last_run'] or '—'} · status: {_sched['last_status'] or '—'}"
                        f" · {'enabled' if _sched['enabled'] else 'paused'}",
                    )
                )
            else:
                st.caption(
                    _t("尚未配置计划。调度器进程：`uv run python -m apps.scheduler.main`（或外部 cron 调用 `--once`）。", "No schedule yet. Scheduler process: `uv run python -m apps.scheduler.main` (or external cron with `--once`).")
                )
        st.markdown(_t("#### 产物", "#### Artifacts"))
        _reports = list_reports(project=_sel, limit=100)
        if not _reports:
            st.caption(_t("暂无产物。点击上方按钮一键生成全套。", "No artifacts yet. Use the button above to generate the full set."))
        for _r in _reports:
            with st.expander(
                f"{_kind_label(_r['kind'])} · {_r['created_at']} · {_r['model']}"
            ):
                st.markdown(_r["content_md"])
                st.download_button(
                    _t("下载 Markdown", "Download Markdown"),
                    data=_r["content_md"],
                    file_name=f"report-{_r['id']}.md",
                    mime="text/markdown",
                    key=f"ws_md_{_r['id']}",
                )

    with _tab_register:
        _threats = list_threats(project=_sel)
        if not _threats:
            st.info(_t("暂无威胁条目。生成一次威胁模型后会自动写入台账。", "No threats yet. They are written to the register after a threat model run."))
        else:
            _f1, _f2, _f3 = st.columns([2, 2, 2])
            with _f1:
                _status_filter = st.multiselect(
                    _t("状态筛选", "Filter by status"),
                    THREAT_STATUSES,
                    key=f"ws_status_{_sel}",
                    placeholder=_t("选择状态…", "Select status…"),
                )
            with _f2:
                _verdict_filter = st.multiselect(
                    _t("验证筛选", "Filter by verdict"),
                    [*VERDICTS, _t("未验证", "Unverified")],
                    key=f"ws_verdict_{_sel}",
                    placeholder=_t("选择验证结论…", "Select verdict…"),
                )
            with _f3:
                _kw = st.text_input(
                    _t("搜索", "Search"),
                    key=f"ws_kw_{_sel}",
                    placeholder=_t("场景 / 类型 / 负责人", "Scenario / type / owner"),
                )
            if _is_admin() and st.button(
                _t("对最近一次威胁模型重新验证", "Re-verify latest threat model"),
                key="ws_reverify",
            ):
                _models = _generation.latest_threat_models(_sel, limit=1)
                if not _models:
                    st.warning(_t("该项目还没有威胁模型。", "No threat model for this project yet."))
                else:
                    with st.spinner(_t("正在对抗式复核…", "Adversarially reviewing…")):
                        _stats = _generation.verify_and_store(_sel, _models[0])
                    store.log_action(
                        st.session_state.get("user", ""), "重新验证威胁", _sel
                    )
                    st.success(
                        _t("复核完成：", "Review done: ")
                        + _t("已确认", "Confirmed")
                        + f" {_stats.get('已确认', 0)} · "
                        + _t("存疑", "Uncertain")
                        + f" {_stats.get('存疑', 0)} · "
                        + _t("已驳回", "Refuted")
                        + f" {_stats.get('已驳回', 0)}"
                    )
                    st.rerun()
            _rows = [
                t
                for t in _threats
                if (not _status_filter or t["status"] in _status_filter)
                and (
                    not _verdict_filter
                    or ((t.get("verdict") or _t("未验证", "Unverified")) in _verdict_filter)
                )
                and (
                    not _kw
                    or _kw.lower()
                    in ((t["scenario"] or "") + (t["threat_type"] or "") + (t["owner"] or "")).lower()
                )
            ]
            st.caption(_t("每条威胁可单独设置状态、负责人与备注，改完点下方按钮保存。", "Set status, owner and notes per threat, then save below."))
            for t in _rows:
                with st.container(border=True):
                    _rc1, _rc2 = st.columns([3, 2], vertical_alignment="center")
                    with _rc1:
                        _score = f"{float(t['risk_score']):.2f}" if t["risk_score"] is not None else "—"
                        _tags = " · ".join(
                            x
                            for x in [t["owasp_llm"], t["owasp_asi"], t["mitre"], t.get("cwe")]
                            if x
                        )
                        _verdict = t.get("verdict") or _t("未验证", "Unverified")
                        _conf = t.get("confidence") or ""
                        _verdict_badge = f" · {_verdict}" + (f"（{_conf}）" if _conf else "")
                        st.markdown(
                            f"**#{t['id']} {t['threat_type']}** · {_t('风险分', 'Risk')} {_score}"
                            f"{_verdict_badge}"
                            f"  \n<span class='sg-rep-meta'>{t['scenario']}</span>"
                            + (
                                f"  \n<span class='sg-rep-meta'>{_t('复核意见：', 'Review note: ')}"
                                f"{t.get('verification_note')}</span>"
                                if t.get("verification_note")
                                else ""
                            )
                            + (f"  \n<span class='sg-rep-meta'>{_tags}</span>" if _tags else ""),
                            unsafe_allow_html=True,
                        )
                        if t["impact"]:
                            st.caption(_t(f"影响：{t['impact']}", f"Impact: {t['impact']}"))
                    with _rc2:
                        _sc1, _sc2 = st.columns([1, 1])
                        with _sc1:
                            st.selectbox(
                                _t("状态", "Status"),
                                THREAT_STATUSES,
                                index=(
                                    THREAT_STATUSES.index(t["status"])
                                    if t["status"] in THREAT_STATUSES
                                    else 0
                                ),
                                key=f"th_status_{t['id']}",
                            )
                        with _sc2:
                            st.text_input(
                                _t("负责人", "Owner"), value=t["owner"], key=f"th_owner_{t['id']}"
                            )
                        st.text_input(_t("备注", "Notes"), value=t["note"], key=f"th_note_{t['id']}")
            _reg_c1, _reg_c2 = st.columns([1, 3])
            with _reg_c1:
                if st.button(_t("保存台账变更", "Save register changes"), type="primary", key="ws_save_threats"):
                    _edits = [
                        {
                            "id": t["id"],
                            "status": st.session_state.get(f"th_status_{t['id']}", t["status"]),
                            "owner": st.session_state.get(f"th_owner_{t['id']}", t["owner"]),
                            "note": st.session_state.get(f"th_note_{t['id']}", t["note"]),
                        }
                        for t in _rows
                    ]
                    _n = update_threats(_edits)
                    store.log_action(
                        st.session_state.get("user", ""), "更新威胁台账", f"{_sel}（{_n} 条）"
                    )
                    st.success(_t(f"已保存 {_n} 条变更。", f"Saved {_n} change(s)."))
                    st.rerun()
            with _reg_c2:
                if st.button(_t("推送到 Webhook", "Push to webhook"), key="ws_push_webhooks"):
                    _outcomes = _generation.push_webhooks(_sel, list_threats(project=_sel))
                    _ok = [o for o in _outcomes if o.get("ok")]
                    if _ok:
                        st.success(_t(f"已推送 {len(_ok)} 个 Webhook", f"Pushed to {len(_ok)} webhook(s)"))
                    else:
                        st.warning(
                            _t(
                                f"推送失败：{_outcomes[0].get('error') or _outcomes[0].get('status')}",
                                f"Push failed: {_outcomes[0].get('error') or _outcomes[0].get('status')}",
                            )
                        )

    with _tab_board:
        _by_type = dict(
            sorted(_stats["by_type"].items(), key=lambda kv: -kv[1])
        )
        _by_status = {k: v for k, v in _stats["by_status"].items() if v}
        _cc1, _cc2 = st.columns(2)
        with _cc1:
            st.markdown(_t("#### STRIDE 分布", "#### STRIDE distribution"))
            if _by_type:
                st.bar_chart({_t("数量", "Count"): _by_type})
            else:
                st.caption(_t("暂无数据", "No data yet"))
        with _cc2:
            st.markdown(_t("#### 台账状态分布", "#### Status distribution"))
            if _by_status:
                st.bar_chart({_t("数量", "Count"): _by_status})
            else:
                st.caption(_t("暂无数据", "No data yet"))
        st.markdown(_t("#### 高风险 Top 10（按 DREAD 评分）", "#### Top 10 risks (by DREAD score)"))
        _risky = sorted(
            [t for t in list_threats(project=_sel) if t["risk_score"] is not None],
            key=lambda t: -float(t["risk_score"]),
        )[:10]
        if _risky:
            _lines = [
                "| " + _t("风险分", "Score") + " | " + _t("类型", "Type") + " | "
                + _t("场景", "Scenario") + " | " + _t("状态", "Status") + " | "
                + _t("负责人", "Owner") + " |",
                "|---|---|---|---|---|",
            ]
            for t in _risky:
                _scene = (t["scenario"] or "").replace("|", "\\|").replace("\n", " ")
                _lines.append(
                    f"| {float(t['risk_score']):.2f} | {t['threat_type']} | {_scene} |"
                    f" {t['status']} | {t['owner'] or '—'} |"
                )
            st.markdown("\n".join(_lines))
        else:
            st.caption(_t("生成一次 DREAD 风险评估后，风险分会自动回填到台账。", "Risk scores are filled into the register after a DREAD assessment."))
