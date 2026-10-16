"""代码审计页面（ZIP/仓库 → agent 分析）。（P7 从 main.py 拆分）。"""

from __future__ import annotations

import json

import streamlit as st
from shared import (
    _agentic,
    _scanners,
    _t,
    store,
)


def _page_code_audit() -> None:
    """代码审计：上传 ZIP 或克隆 Git 仓库，运行 agentic 深度分析。"""
    st.markdown(
        _t(
            "深度代码审计由 agent 自主探索代码库：先规划子系统，再逐个读取代码、"
            "给出带**代码证据**的 STRIDE 威胁，最后跨子系统综合。"
            "分析会消耗较多 token，建议先用较小的仓库和调用上限试跑。",
            "Deep code audit lets the agent explore the codebase autonomously: it plans "
            "subsystems, reads code, and reports STRIDE threats with **code evidence**, "
            "then synthesizes across subsystems. It consumes many tokens — start with a "
            "small repo and a call cap.",
        )
    )

    _src = st.radio(
        _t("代码来源", "Source"),
        [_t("Git 仓库", "Git repository"), _t("上传 ZIP", "Upload ZIP")],
        horizontal=True,
        key="audit_source",
    )
    _left, _right = st.columns([1.2, 1], gap="large")
    with _left:
        _project = st.text_input(
            _t("项目名称（用于归档）", "Project name (for archiving)"),
            key="audit_project",
            placeholder=_t("如：订单服务", "e.g. order-service"),
        )
        _desc = st.text_area(
            _t("补充说明（可选）", "Additional notes (optional)"),
            key="audit_desc",
            height=80,
            placeholder=_t(
                "例如：这是公司核心支付服务，重点看鉴权与金额校验",
                "e.g. core payment service — focus on authz and amount validation",
            ),
        )
        if _src == _t("Git 仓库", "Git repository"):
            _url = st.text_input(
                _t("仓库地址（https）", "Repository URL (https)"),
                key="audit_url",
                placeholder="https://github.com/owner/repo",
            )
            _token = st.text_input(
                _t("访问令牌（私有仓库，可选）", "Access token (private repos, optional)"),
                type="password",
                key="audit_token",
            )
            _zip_file = None
        else:
            _zip_file = st.file_uploader(
                _t("上传代码 ZIP（≤300MB 解压）", "Upload code ZIP (≤300MB uncompressed)"),
                type=["zip"],
                key="audit_zip",
            )
            _url = ""
            _token = ""
    with _right:
        _default_model = st.session_state.get("selected_model", "")
        _worker = st.text_input(
            _t("Worker 模型（探索用，便宜快）", "Worker model (exploration)"),
            value=_default_model,
            key="audit_worker",
        )
        _architect = st.text_input(
            _t("Architect 模型（规划/综合，可选）", "Architect model (planning/synthesis, optional)"),
            value="",
            key="audit_architect",
        )
        _cap1, _cap2 = st.columns(2)
        with _cap1:
            _max_llm = st.number_input(
                _t("LLM 调用上限（0=不限）", "LLM call cap (0 = unlimited)"),
                min_value=0,
                value=60,
                step=10,
                key="audit_max_llm",
            )
        with _cap2:
            _max_tool = st.number_input(
                _t("工具调用上限（0=不限）", "Tool call cap (0 = unlimited)"),
                min_value=0,
                value=80,
                step=10,
                key="audit_max_tool",
            )
        st.caption(
            _t(
                "上限用于控制成本：达到上限的子系统会做一轮收尾后停止。",
                "Caps control cost: subsystems that hit the cap get one final round.",
            )
        )
        _scanner_probe = _scanners.probe()
        _available_names = [s["name"] for s in _scanner_probe if s["available"]]
        with st.expander(
            _t("静态分析线索（SAST）", "Static-analysis leads (SAST)")
            + f" · {' · '.join(_available_names) if _available_names else _t('无可用工具', 'none available')}",
            expanded=False,
        ):
            st.caption(
                _t(
                    "先用本机扫描工具产出候选线索，再交给 agent 逐条核实（线索可能含误报）。",
                    "Local scanners produce candidate leads first; the agent verifies them (leads may contain false positives).",
                )
            )
            for _s in _scanner_probe:
                st.markdown(
                    f"{'✅' if _s['available'] else '➖'} **{_s['name']}** · {_s['hint']}"
                    + (f"  \n<span class='sg-rep-meta'>{_s['install']}</span>" if _s["install"] else ""),
                    unsafe_allow_html=True,
                )
            st.checkbox(
                _t("启用静态分析线索", "Enable static-analysis leads"),
                value=bool(st.session_state.get("enable_scanners", True)),
                key="enable_scanners",
            )

    _confirm = st.checkbox(
        _t(
            "我已了解 agentic 分析会消耗较多 token，确认执行",
            "I understand agentic analysis consumes many tokens — run it",
        ),
        key="audit_confirm",
    )
    _ready = bool(_confirm) and bool((_project or "").strip())
    if _src == _t("Git 仓库", "Git repository"):
        _ready = _ready and bool((_url or "").strip())
    else:
        _ready = _ready and _zip_file is not None

    if st.button(
        _t("开始代码审计", "Start code audit"),
        type="primary",
        disabled=not _ready,
        key="audit_run",
    ):
        _status = st.status(_t("准备中…", "Preparing…"), expanded=True)
        _events: list[str] = []
        with _status:
            _line = st.empty()
            _bar = st.progress(0.0)
            _log = st.empty()

            def _on_event(kind: str, payload: dict) -> None:
                if kind == "phase":
                    _line.markdown(f"**{payload.get('phase')} · {payload.get('description')}**")
                elif kind == "status":
                    _line.markdown(str(payload.get("message", ""))[:200])
                elif kind == "subsystem_start":
                    _bar.progress(
                        max(0.0, (payload.get("index", 1) - 1) / max(1, payload.get("total", 1))),
                        text=f"{payload.get('name')}",
                    )
                elif kind == "subsystem_done":
                    _events.append(
                        f"- {payload.get('name')}：{payload.get('threat_count')} "
                        f"{_t('条威胁', 'threats')}（{payload.get('outcome')}）"
                    )
                    _log.markdown("\n".join(_events[-8:]))
                elif kind == "tool_call":
                    _line.markdown(
                        f"`{payload.get('name')}` {str(payload.get('args', ''))[:80]}"
                        + (_t("（缓存）", " (cached)") if payload.get("cached") else "")
                    )
                elif kind == "scanner_start":
                    _line.markdown(_t("正在运行静态分析扫描器…", "Running static-analysis scanners…"))
                elif kind == "scanner_done":
                    _summary = payload.get("summary") or {}
                    _by_tool = _summary.get("by_tool") or {}
                    _events.append(
                        "- "
                        + _t("静态分析线索：", "Static-analysis leads: ")
                        + f"{_summary.get('total', 0)}"
                        + _t(" 条（", " (")
                        + " · ".join(f"{k} {v}" for k, v in _by_tool.items())
                        + "）"
                    )
                    _log.markdown("\n".join(_events[-8:]))
                elif kind == "scanner_error":
                    _events.append(
                        "- " + _t("扫描器异常（已跳过）：", "Scanner error (skipped): ")
                        + str(payload.get("error", ""))[:80]
                    )
                    _log.markdown("\n".join(_events[-8:]))
                elif kind == "limit":
                    _events.append(
                        f"- {_t('达到上限', 'limit reached')}：{payload.get('kind')}"
                        f" {payload.get('current')}/{payload.get('maximum')}"
                    )
                    _log.markdown("\n".join(_events[-8:]))

        try:
            _models = _agentic.build_model_pair(
                worker_model=(_worker or "").strip() or None,
                architect_model=(_architect or "").strip() or None,
            )
            _common = {
                "project": _project.strip(),
                "description": _desc.strip(),
                "models": _models,
                "max_llm_calls": int(_max_llm),
                "max_tool_calls": int(_max_tool),
                "enable_scanners": bool(st.session_state.get("enable_scanners", True)),
                "on_event": _on_event,
            }
            with st.spinner(_t("正在分析代码库…", "Analyzing the codebase…")):
                if _src == _t("Git 仓库", "Git repository"):
                    _result = _agentic.audit_repo(
                        _url.strip(), token=(_token or "").strip() or None, **_common
                    )
                else:
                    _result = _agentic.audit_zip(_zip_file.getvalue(), **_common)
            _bar.progress(1.0, text=_t("完成", "Done"))
            _status.update(label=_t("代码审计完成", "Code audit complete"), state="complete")
            store.log_action(
                st.session_state.get("user", ""),
                "代码审计",
                f"{_project}（报告 #{_result['report_id']}）",
            )
            _scan_summary = _result.get("scanner_summary") or {}
            if _scan_summary.get("total"):
                st.caption(
                    _t("静态分析线索：", "Static-analysis leads: ")
                    + f"{_scan_summary['total']}"
                    + _t(" 条 · 按工具 ", " · by tool ")
                    + " · ".join(f"{k} {v}" for k, v in (_scan_summary.get("by_tool") or {}).items())
                )
            st.success(
                _t("报告已归档：", "Report archived: ")
                + f"#{_result['report_id']} · "
                + _t("新增威胁 ", "new threats ")
                + f"{_result['threats_inserted']}"
                + _t(" 条（共 ", " of ")
                + f"{_result['threats_total']}"
                + _t(" 条，含代码证据）", " with code evidence)")
            )
            _dl1, _dl2, _dl3 = st.columns(3)
            with _dl1:
                st.download_button(
                    _t("下载 Markdown", "Download Markdown"),
                    data=_result["markdown"],
                    file_name=f"code-audit-{_result['report_id']}.md",
                    mime="text/markdown",
                    key="audit_dl_md",
                )
            with _dl2:
                st.download_button(
                    _t("下载 SARIF", "Download SARIF"),
                    data=json.dumps(_result["sarif"], ensure_ascii=False, indent=2),
                    file_name=f"code-audit-{_result['report_id']}.sarif",
                    mime="application/json",
                    key="audit_dl_sarif",
                )
            with _dl3:
                st.download_button(
                    _t("下载 JSON", "Download JSON"),
                    data=json.dumps(_result["json"], ensure_ascii=False, indent=2),
                    file_name=f"code-audit-{_result['report_id']}.json",
                    mime="application/json",
                    key="audit_dl_json",
                )
            st.markdown(_result["markdown"])
        except _agentic.AgenticError as _exc:
            _status.update(label=_t("代码审计失败", "Code audit failed"), state="error")
            st.error(str(_exc))
        except Exception as _exc:
            _status.update(label=_t("代码审计失败", "Code audit failed"), state="error")
            st.error(_t("分析失败：", "Analysis failed: ") + f"{type(_exc).__name__}: {_exc}")
