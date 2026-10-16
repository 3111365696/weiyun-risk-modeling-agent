"""报告历史页面。（P7 从 main.py 拆分）。"""

from __future__ import annotations

import streamlit as st
from services import (
    _kind_label,
    show_report_dialog,
)
from shared import (
    KIND_LABELS,
    _t,
    datetime,
    delete_report,
    export_zip,
    get_report,
    list_reports,
    report_count,
    report_to_html,
    store,
)


def _page_reports() -> None:
    """报告历史：查看、导出、删除历史生成结果。"""
    _rows = list_reports(limit=300)
    _projects = sorted({r["project"] for r in _rows if r["project"]})

    _f1, _f2, _f3, _f4 = st.columns([1.1, 1.3, 2, 1.3], vertical_alignment="bottom")
    with _f1:
        _kind_options = [_t("全部", "All")] + [_kind_label(k) for k in KIND_LABELS]
        _kind_choice = st.selectbox(_t("类型", "Type"), _kind_options, key="hist_kind")
    with _f2:
        _project = st.selectbox(
            _t("项目", "Project"), [_t("全部", "All"), *_projects], key="hist_project"
        )
    with _f3:
        _search = st.text_input(
            _t("搜索", "Search"), key="hist_search", placeholder=_t("按标题 / 项目 / 内容关键字", "Title / project / content keyword")
        )
    with _f4:
        st.download_button(
            _t("导出全部 (ZIP)", "Export all (ZIP)"),
            data=export_zip(_rows),
            file_name=f"weiyun-reports-{datetime.now().strftime('%Y%m%d-%H%M')}.zip",
            mime="application/zip",
            use_container_width=True,
            disabled=not _rows,
        )

    _kind_rev = {_kind_label(k): k for k in KIND_LABELS}
    _filtered = list_reports(
        kind=None if _kind_choice == _t("全部", "All") else _kind_rev.get(_kind_choice),
        project=None if _project == _t("全部", "All") else _project,
        search=_search or None,
        limit=300,
    )

    st.caption(
            _t(
                f"共 {len(_filtered)} 条记录（库内总计 {report_count()} 条）",
                f"{len(_filtered)} of {report_count()} reports shown",
            )
        )
    if not _filtered:
        st.info(_t("暂无历史报告。生成威胁模型、攻击树、数据流图等结果后会自动归档到这里。", "No reports yet. Generated threat models, attack trees, DFDs and more are archived here automatically."))
        return

    for _r in _filtered:
        with st.container(border=True):
            _c1, _c2 = st.columns([5, 2.6], vertical_alignment="center")
            with _c1:
                st.markdown(
                    f"**{_kind_label(_r['kind'])}** · {_r['project'] or _t('未命名', 'Untitled')}"
                    f"  \n<span class='sg-rep-meta'>{_r['created_at']} · "
                    f"{_r['provider']}/{_r['model']}</span>",
                    unsafe_allow_html=True,
                )
            with _c2:
                _b1, _b2, _b3, _b4 = st.columns(4)
                with _b1:
                    if st.button(_t("查看", "View"), key=f"view_{_r['id']}", use_container_width=True):
                        st.session_state["_report_view_id"] = _r["id"]
                        st.rerun()
                with _b2:
                    st.download_button(
                        "MD",
                        data=_r["content_md"],
                        file_name=f"report-{_r['id']}.md",
                        mime="text/markdown",
                        key=f"md_{_r['id']}",
                        use_container_width=True,
                    )
                with _b3:
                    st.download_button(
                        "HTML",
                        data=report_to_html(_r),
                        file_name=f"report-{_r['id']}.html",
                        mime="text/html",
                        key=f"html_{_r['id']}",
                        use_container_width=True,
                    )
                with _b4:
                    if st.button(_t("删除", "Delete"), key=f"del_{_r['id']}", use_container_width=True):
                        delete_report(_r["id"])
                        store.log_action(
                            st.session_state.get("user", ""), "删除报告", f"#{_r['id']}"
                        )
                        st.rerun()

    _view_id = st.session_state.get("_report_view_id")
    if _view_id:
        _rep = get_report(int(_view_id))
        if _rep:
            show_report_dialog(_rep)
        else:
            st.session_state.pop("_report_view_id", None)
