"""系统状态页面（版本、健康、任务、备份）。（P7 从 main.py 拆分）。"""

from __future__ import annotations

import platform

import requests
import streamlit as st
from shared import (
    _API_BASE,
    _STARTED_AT,
    PROVIDER_API_KEY_STATE,
    _backup,
    _is_admin,
    _logging,
    _scanners,
    _t,
    datetime,
    store,
)


def render_status() -> None:
    """系统状态：版本、组件健康、任务与告警、备份（仅管理员）。"""
    if not _is_admin():
        st.error(
            _t(
                "需要管理员权限才能查看系统状态。",
                "Administrator privileges are required to view the system status.",
            )
        )
        return
    st.markdown(
        _t(
            '<div class="sg-settings-head">\n          <div class="sg-kicker">SYSTEM STATUS</div>\n          <div class="sg-settings-title">系统状态</div>\n          <div class="sg-settings-sub">版本、组件健康、最近任务与告警、数据备份。</div>\n        </div>',
            '<div class="sg-settings-head">\n          <div class="sg-kicker">SYSTEM STATUS</div>\n          <div class="sg-settings-title">System status</div>\n          <div class="sg-settings-sub">Version, component health, recent jobs and alerts, data backup.</div>\n        </div>',
        ),
        unsafe_allow_html=True,
    )

    _db = store.db_stats()
    _integrity = store.db_check()
    _api = _probe_api()
    _schedules = store.list_schedules()
    _scanner_info = _scanners.probe()
    _available_scanners = [item["name"] for item in _scanner_info if item["available"]]
    _jobs = store.list_jobs(limit=8, kind="code_audit")
    _errors = _logging.recent_errors(limit=8)
    _usage_month = store.usage_summary(since=datetime.now().strftime("%Y-%m") + "-01 00:00:00")

    _left, _right = st.columns([1.15, 1], gap="large")

    with _left:
        with st.container(border=True, key="status_runtime"):
            st.markdown(_t("#### 版本与运行环境", "#### Version & runtime"))
            _uptime = datetime.now() - _STARTED_AT
            _hours, _rest = divmod(int(_uptime.total_seconds()), 3600)
            st.markdown(
                f"- {_t('产品版本', 'Product version')}：**{_backup.tool_version()}**\n"
                f"- {_t('进程运行时长', 'Process uptime')}：**{_hours} {_t('小时', 'h')} {_rest // 60} {_t('分钟', 'min')}**\n"
                f"- Python：**{platform.python_version()}** · {platform.system()} {platform.machine()}\n"
                f"- {_t('数据目录', 'Data directory')}：`{store.DATA_DIR}`\n"
                f"- {_t('日志目录', 'Log directory')}：`{_logging.log_dir() or '—'}`"
            )

        with st.container(border=True, key="status_data"):
            st.markdown(_t("#### 数据概况", "#### Data overview"))
            _m1, _m2, _m3 = st.columns(3)
            _m1.metric(_t("项目", "Projects"), len(store.list_projects()))
            _m2.metric(_t("报告", "Reports"), len(store.list_reports(limit=100000)))
            _m3.metric(_t("威胁条目", "Threats"), len(store.list_threats()))
            _month_totals = _usage_month.get("totals") or {}
            st.caption(
                _t("本月用量：", "This month: ")
                + f"${float(_month_totals.get('cost') or 0):.2f} · "
                + f"{int(_month_totals.get('total_tokens') or 0):,} tokens · "
                + f"{int(_month_totals.get('calls') or 0)} "
                + _t("次调用", "calls")
            )

        with st.container(border=True, key="status_jobs"):
            st.markdown(_t("#### 最近任务", "#### Recent jobs"))
            if not _jobs:
                st.caption(_t("暂无代码审计任务。", "No code-audit jobs yet."))
            else:
                _status_label = {
                    "queued": _t("排队中", "Queued"),
                    "running": _t("运行中", "Running"),
                    "done": _t("完成", "Done"),
                    "failed": _t("失败", "Failed"),
                    "cancelled": _t("已取消", "Cancelled"),
                    "interrupted": _t("已中断", "Interrupted"),
                }
                _lines = [
                    "| " + _t("任务", "Job") + " | " + _t("状态", "Status") + " | "
                    + _t("项目", "Project") + " | " + _t("时间", "Time") + " |",
                    "|---|---|---|---|",
                ]
                _lines.extend(
                    f"| `{item['job_id'][:8]}` | {_status_label.get(item['status'], item['status'])} | "
                    f"{item['project'][:24]} | {item['created_at']} |"
                    for item in _jobs
                )
                st.markdown("\n".join(_lines))
                if any(item["status"] == "interrupted" for item in _jobs):
                    st.caption(
                        _t(
                            "「已中断」表示服务重启导致任务中止，可通过 API 重跑。",
                            "“Interrupted” means the service restarted mid-job; retry via the API.",
                        )
                    )

    with _right:
        with st.container(border=True, key="status_health"):
            st.markdown(_t("#### 组件健康", "#### Component health"))
            _status_line(
                _t("数据库", "Database"),
                _integrity.lower() == "ok",
                f"{_db.get('journal_mode', '?')} · {_fmt_bytes(_db.get('bytes', 0))} · "
                + _t("完整性", "integrity")
                + f" {_integrity}",
            )
            _prov = st.session_state.get("model_provider", "")
            _model = st.session_state.get("selected_model", "")
            _key_state = PROVIDER_API_KEY_STATE.get(_prov, "")
            _has_key = bool(st.session_state.get(_key_state, "")) if _key_state else _prov == "LM Studio Server"
            _status_line(
                _t("模型服务", "Model service"),
                (_has_key and bool(_model)) if _prov else None,
                f"{_prov or _t('未配置', 'not configured')} · {_model or '—'}",
            )
            _status_line(
                "REST API",
                bool(_api.get("ok")),
                (
                    f"{_API_BASE} · v{_api.get('version', '?')} · "
                    + _t("运行", "up")
                    + f" {_api.get('uptime_seconds', 0) // 60} "
                    + _t("分钟", "min")
                )
                if _api.get("ok")
                else f"{_API_BASE} · {_api.get('error', _t('离线', 'offline'))}",
            )
            if _schedules:
                _last = max((item.get("last_run") or "" for item in _schedules), default="")
                _failed = sum(1 for item in _schedules if str(item.get("last_status") or "") == "failed")
                _status_line(
                    _t("定时分析", "Scheduler"),
                    None if not _last else _failed == 0,
                    _t(f"{len(_schedules)} 个计划 · 最近运行 ", f"{len(_schedules)} schedules · last run ")
                    + (_last or _t("尚未运行", "never")),
                )
            else:
                _status_line(_t("定时分析", "Scheduler"), None, _t("无计划", "no schedules"))
            _status_line(
                _t("静态分析", "Static analysis"),
                None if not _available_scanners else True,
                " · ".join(_available_scanners) if _available_scanners else _t("无可用工具（不影响主流程）", "none available (non-blocking)"),
            )

        with st.container(border=True, key="status_alerts"):
            st.markdown(_t("#### 最近告警", "#### Recent alerts"))
            if not _errors:
                st.caption(_t("没有告警，一切正常。", "No alerts — all clear."))
            for item in _errors:
                _tail = item.get("error_id") or item.get("page") or item.get("kind") or ""
                st.markdown(
                    f"- `{item.get('ts', '')[:19]}` **{item.get('level', '')}** "
                    f"{str(item.get('msg', ''))[:60]}"
                    + (f" · `{_tail}`" if _tail else "")
                )

        with st.container(border=True, key="status_backup"):
            st.markdown(_t("#### 数据备份", "#### Data backup"))
            st.caption(
                _t(
                    "备份包含数据库、加密配置与会话密钥；恢复后需重启各服务。",
                    "Backup includes the database, encrypted config and session key; restart services after restoring.",
                )
            )
            _with_ws = st.checkbox(
                _t("包含工作区文件（体积可能较大）", "Include workspace files (may be large)"),
                key="backup_include_ws",
                value=False,
            )
            if st.button(
                _t("生成备份", "Create backup"), key="backup_create", use_container_width=True
            ):
                try:
                    st.session_state["_backup_bytes"] = _backup.create_backup_bytes(
                        include_workspaces=_with_ws
                    )
                    st.session_state["_backup_name"] = (
                        f"wy-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}.zip"
                    )
                    store.log_action(st.session_state.get("user", ""), "创建备份")
                    st.success(_t("备份已生成，点击下方下载。", "Backup created — download below."))
                except Exception as _backup_exc:
                    st.error(_t("备份失败：", "Backup failed: ") + str(_backup_exc))
            if st.session_state.get("_backup_bytes"):
                st.download_button(
                    _t("下载备份包", "Download backup"),
                    data=st.session_state["_backup_bytes"],
                    file_name=st.session_state.get("_backup_name") or "wy-backup.zip",
                    mime="application/zip",
                    key="backup_download",
                    use_container_width=True,
                )
            _rows = _backup.list_backups()
            if _rows:
                st.markdown(
                    _t("最近备份：", "Recent backups: ")
                    + " · ".join(
                        f"{item['name'].replace('backup-', '').replace('.zip', '')}"
                        for item in _rows[:3]
                    )
                )
            st.caption(
                _t(
                    "命令行：`PYTHONPATH=apps python -m common.backup create|list|verify|restore`",
                    "CLI: `PYTHONPATH=apps python -m common.backup create|list|verify|restore`",
                )
            )


def _status_line(label: str, ok: bool | None, detail: str = "") -> None:
    """一行组件状态：🟢 正常 / 🔴 异常 / ⚪ 未配置。"""
    icon = "🟢" if ok else ("🔴" if ok is False else "⚪")
    st.markdown(f"{icon} **{label}**" + (f" — {detail}" if detail else ""))


def _probe_api() -> dict:
    try:
        response = requests.get(f"{_API_BASE}/api/v1/health", timeout=2.5)
        if response.status_code == 200:
            data = response.json()
            return {"ok": bool(data.get("ok")), **data}
        return {"ok": False, "error": f"HTTP {response.status_code}"}
    except Exception as exc:
        return {"ok": False, "error": type(exc).__name__}


def _fmt_bytes(value: int) -> str:
    size = float(value)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{size:.1f} GB"
