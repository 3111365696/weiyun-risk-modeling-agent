"""报告归档与生成流程（多页面共用）。（P7 从 main.py 拆分）。"""

from __future__ import annotations

import streamlit as st
from shared import (
    _KEY_BY_PROVIDER,
    _KIND_LABELS_EN,
    KIND_LABELS,
    _exporters,
    _generation,
    _i18n,
    _interop,
    _standards,
    _t,
    create_attack_tree_prompt,
    create_dfd_prompt,
    create_dread_assessment_prompt,
    create_mitigations_prompt,
    create_test_cases_prompt,
    create_threat_model_prompt,
    dread_json_to_markdown,
    get_attack_tree,
    get_attack_tree_anthropic,
    get_attack_tree_deepseek,
    get_attack_tree_google,
    get_attack_tree_groq,
    get_attack_tree_lm_studio,
    get_attack_tree_mistral,
    get_dfd_anthropic,
    get_dfd_deepseek,
    get_dfd_google,
    get_dfd_groq,
    get_dfd_lm_studio,
    get_dfd_mistral,
    get_dfd_openai,
    get_dread_assessment,
    get_dread_assessment_anthropic,
    get_dread_assessment_deepseek,
    get_dread_assessment_google,
    get_dread_assessment_groq,
    get_dread_assessment_lm_studio,
    get_dread_assessment_mistral,
    get_mitigations,
    get_mitigations_anthropic,
    get_mitigations_deepseek,
    get_mitigations_google,
    get_mitigations_groq,
    get_mitigations_lm_studio,
    get_mitigations_mistral,
    get_test_cases,
    get_test_cases_anthropic,
    get_test_cases_deepseek,
    get_test_cases_google,
    get_test_cases_groq,
    get_test_cases_lm_studio,
    get_test_cases_mistral,
    get_threat_model,
    get_threat_model_anthropic,
    get_threat_model_deepseek,
    get_threat_model_google,
    get_threat_model_groq,
    get_threat_model_lm_studio,
    get_threat_model_mistral,
    json_to_markdown,
    report_to_html,
)


def _kind_label(kind: str) -> str:
    """报告类型的中英标签。"""
    if _i18n.current_language() == "en":
        return _KIND_LABELS_EN.get(kind, kind)
    return KIND_LABELS.get(kind, kind)


def _archive(
    kind: str,
    content_md: str,
    content_json=None,
    *,
    project: str | None = None,
    description: str | None = None,
) -> None:
    """把生成结果归档到「报告历史」，并同步项目/威胁台账（失败不影响展示）。

    返回实际使用的项目名（供调用方继续做验证等操作）。
    """
    _used_project = ""
    if not content_md:
        return _used_project
    try:
        _desc = (
            description if description is not None else st.session_state.get("app_input") or ""
        ).strip()
        _project = (project or st.session_state.get("project_name") or "").strip()
        if not _project:
            _project = (_desc[:24] + "…") if len(_desc) > 24 else (_desc or _t("未命名项目", "Untitled project"))
        _used_project = _project
        _generation.archive_result(
            kind,
            content_md,
            content_json,
            project=_project,
            description=_desc,
            provider=st.session_state.get("model_provider", ""),
            model=st.session_state.get("selected_model", ""),
        )
        st.toast(_t("已归档到「报告历史」", "Archived to report history"))
    except Exception:
        pass
    return _used_project


def _report_dialog(report: dict) -> None:
    """报告详情弹窗内容（由 show_report_dialog 动态套上 dialog，标题随语言切换）。"""
    st.caption(
        f"{_kind_label(report['kind'])} · {report['project'] or _t('未命名', 'Untitled')}"
        f" · {report['created_at']} · {report['provider']}/{report['model']}"
    )
    if report.get("kind") == "threat_model" and report.get("content_json"):
        import json as _json

        try:
            _cov = _generation.stride_coverage(
                _json.loads(report["content_json"]).get("threat_model") or []
            )
            st.caption(
                _t("STRIDE 覆盖度：", "STRIDE coverage: ")
                + " · ".join(f"{k} {v}" for k, v in _cov["counts"].items() if v)
                + (
                    _t(" · 缺失：", " · missing: ") + "、".join(_cov["missing"])
                    if _cov["missing"]
                    else _t(" · 六类齐全", " · all six covered")
                )
            )
        except Exception:
            pass
    st.markdown(report["content_md"])
    _dl1, _dl2, _dl3 = st.columns(3)
    with _dl1:
        st.download_button(
            _t("下载 Word", "Download Word"),
            data=_exporters.markdown_to_docx(report),
            file_name=_exporters.suggested_filename(report, "docx"),
            mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            key=f"dlg_docx_{report['id']}",
            use_container_width=True,
        )
    with _dl2:
        if st.button(_t("生成 PDF", "Generate PDF"), key=f"dlg_pdf_btn_{report['id']}", use_container_width=True):
            try:
                with st.spinner(_t("正在生成 PDF…", "Generating PDF…")):
                    st.session_state[f"_pdf_{report['id']}"] = _exporters.report_to_pdf(report)
            except Exception as _exc:
                st.error(_t(f"PDF 生成失败：{_exc}", f"PDF generation failed: {_exc}"))
    with _dl3:
        _pdf_bytes = st.session_state.get(f"_pdf_{report['id']}")
        if _pdf_bytes:
            st.download_button(
                _t("下载 PDF", "Download PDF"),
                data=_pdf_bytes,
                file_name=_exporters.suggested_filename(report, "pdf"),
                mime="application/pdf",
                key=f"dlg_pdf_dl_{report['id']}",
                use_container_width=True,
            )
    _d1, _d2, _d3, _d4, _d5 = st.columns(5)
    with _d1:
        st.download_button(
            _t("下载 Markdown", "Download Markdown"),
            data=report["content_md"],
            file_name=f"report-{report['id']}.md",
            mime="text/markdown",
            key=f"dlg_md_{report['id']}",
            use_container_width=True,
        )
    with _d2:
        st.download_button(
            _t("下载 HTML", "Download HTML"),
            data=report_to_html(report),
            file_name=f"report-{report['id']}.html",
            mime="text/html",
            key=f"dlg_html_{report['id']}",
            use_container_width=True,
        )
    with _d3:
        if report.get("content_json"):
            st.download_button(
                _t("下载 JSON", "Download JSON"),
                data=report["content_json"],
                file_name=f"report-{report['id']}.json",
                mime="application/json",
                key=f"dlg_json_{report['id']}",
                use_container_width=True,
            )
    with _d4:
        if report.get("kind") in ("threat_model", "code_analysis") and report.get("content_json"):
            import json as _json

            try:
                _raw = _json.loads(report["content_json"])
                _threats = list(_raw.get("threat_model") or [])
                if not _threats:
                    _threats = [
                        _t
                        for _f in (_raw.get("findings") or [])
                        for _t in (_f.get("threats") or [])
                    ]
            except Exception:
                _threats = []
            if _threats:
                st.download_button(
                    _t("下载 STIX", "Download STIX"),
                    data=_json.dumps(
                        _standards.threats_to_stix(
                            _threats, project=report.get("project") or "", description=""
                        ),
                        ensure_ascii=False,
                        indent=2,
                    ),
                    file_name=f"report-{report['id']}.stix.json",
                    mime="application/json",
                    key=f"dlg_stix_{report['id']}",
                    use_container_width=True,
                )
        if report.get("kind") == "threat_model" and report.get("content_json"):
            import json as _json

            try:
                _tm = _json.loads(report["content_json"]).get("threat_model") or []
            except Exception:
                _tm = []
            st.download_button(
                _t("下载 Threat Dragon", "Download Threat Dragon"),
                data=_json.dumps(
                    _interop.to_threat_dragon(report.get("project") or "", _tm),
                    ensure_ascii=False,
                    indent=2,
                ),
                file_name=f"report-{report['id']}.threat-dragon.json",
                mime="application/json",
                key=f"dlg_td_{report['id']}",
                use_container_width=True,
            )
            st.download_button(
                _t("下载 SARIF", "Download SARIF"),
                data=_json.dumps(
                    _generation.threat_model_to_sarif(
                        _tm, project=report.get("project") or "", description=""
                    ),
                    ensure_ascii=False,
                    indent=2,
                ),
                file_name=f"report-{report['id']}.sarif",
                mime="application/json",
                key=f"dlg_sarif_{report['id']}",
                use_container_width=True,
            )
    with _d5:
        if st.button(_t("关闭", "Close"), key=f"dlg_close_{report['id']}", use_container_width=True):
            st.session_state.pop("_report_view_id", None)
            st.rerun()


def _run_model(kind: str, prompt: str):
    """按当前会话配置调用对应提供商的生成函数（供一键全流程复用）。"""
    _provider = st.session_state.get("model_provider", "OpenAI API")
    _model = st.session_state.get("selected_model", "")
    _oai = st.session_state.get("openai_api_key", "")
    _ant = st.session_state.get("anthropic_api_key", "")
    _goo = st.session_state.get("google_api_key", "")
    _mis = st.session_state.get("mistral_api_key", "")
    _gro = st.session_state.get("groq_api_key", "")
    _dee = st.session_state.get("deepseek_api_key", "")
    _lm_ep = st.session_state.get("lm_studio_endpoint", "http://localhost:1234")
    _lm_key = st.session_state.get("lm_studio_api_key", "")

    _table = {
        "threat_model": {
            "OpenAI API": lambda: get_threat_model(_oai, _model, prompt),
            "Google AI API": lambda: get_threat_model_google(_goo, _model, prompt),
            "Mistral API": lambda: get_threat_model_mistral(_mis, _model, prompt),
            "Anthropic API": lambda: get_threat_model_anthropic(_ant, _model, prompt),
            "LM Studio Server": lambda: get_threat_model_lm_studio(_lm_ep, _model, prompt, _lm_key),
            "Groq API": lambda: get_threat_model_groq(_gro, _model, prompt),
            "DeepSeek API": lambda: get_threat_model_deepseek(_dee, _model, prompt),
        },
        "dfd": {
            "OpenAI API": lambda: get_dfd_openai(_oai, _model, prompt),
            "Google AI API": lambda: get_dfd_google(_goo, _model, prompt),
            "Mistral API": lambda: get_dfd_mistral(_mis, _model, prompt),
            "Anthropic API": lambda: get_dfd_anthropic(_ant, _model, prompt),
            "LM Studio Server": lambda: get_dfd_lm_studio(_lm_ep, _model, prompt, _lm_key),
            "Groq API": lambda: get_dfd_groq(_gro, _model, prompt),
            "DeepSeek API": lambda: get_dfd_deepseek(_dee, _model, prompt),
        },
        "attack_tree": {
            "OpenAI API": lambda: get_attack_tree(_oai, _model, prompt),
            "Google AI API": lambda: get_attack_tree_google(_goo, _model, prompt),
            "Mistral API": lambda: get_attack_tree_mistral(_mis, _model, prompt),
            "Anthropic API": lambda: get_attack_tree_anthropic(_ant, _model, prompt),
            "LM Studio Server": lambda: get_attack_tree_lm_studio(_lm_ep, _model, prompt, _lm_key),
            "Groq API": lambda: get_attack_tree_groq(_gro, _model, prompt),
            "DeepSeek API": lambda: get_attack_tree_deepseek(_dee, _model, prompt),
        },
        "mitigations": {
            "OpenAI API": lambda: get_mitigations(_oai, _model, prompt),
            "Google AI API": lambda: get_mitigations_google(_goo, _model, prompt),
            "Mistral API": lambda: get_mitigations_mistral(_mis, _model, prompt),
            "Anthropic API": lambda: get_mitigations_anthropic(_ant, _model, prompt),
            "LM Studio Server": lambda: get_mitigations_lm_studio(_lm_ep, _model, prompt, _lm_key),
            "Groq API": lambda: get_mitigations_groq(_gro, _model, prompt),
            "DeepSeek API": lambda: get_mitigations_deepseek(_dee, _model, prompt),
        },
        "dread": {
            "OpenAI API": lambda: get_dread_assessment(_oai, _model, prompt),
            "Google AI API": lambda: get_dread_assessment_google(_goo, _model, prompt),
            "Mistral API": lambda: get_dread_assessment_mistral(_mis, _model, prompt),
            "Anthropic API": lambda: get_dread_assessment_anthropic(_ant, _model, prompt),
            "LM Studio Server": lambda: get_dread_assessment_lm_studio(
                _lm_ep, _model, prompt, _lm_key
            ),
            "Groq API": lambda: get_dread_assessment_groq(_gro, _model, prompt),
            "DeepSeek API": lambda: get_dread_assessment_deepseek(_dee, _model, prompt),
        },
        "test_cases": {
            "OpenAI API": lambda: get_test_cases(_oai, _model, prompt),
            "Google AI API": lambda: get_test_cases_google(_goo, _model, prompt),
            "Mistral API": lambda: get_test_cases_mistral(_mis, _model, prompt),
            "Anthropic API": lambda: get_test_cases_anthropic(_ant, _model, prompt),
            "LM Studio Server": lambda: get_test_cases_lm_studio(_lm_ep, _model, prompt, _lm_key),
            "Groq API": lambda: get_test_cases_groq(_gro, _model, prompt),
            "DeepSeek API": lambda: get_test_cases_deepseek(_dee, _model, prompt),
        },
    }
    _fn = (_table.get(kind) or {}).get(_provider)
    if _fn is None:
        raise RuntimeError(
            _t(
                f"当前提供商（{_provider}）不支持「{kind}」生成",
                f"The current provider ({_provider}) does not support generating “{kind}”.",
            )
        )
    return _fn()


def _run_full_pipeline(project: str, description: str) -> None:
    """一键生成全套产物并归档到指定项目。"""
    _desc = (description or "").strip()
    if not _desc:
        st.warning(_t("请先填写并保存应用描述。", "Fill in and save the application description first."))
        return
    _provider = st.session_state.get("model_provider", "OpenAI API")
    _skey = _KEY_BY_PROVIDER.get(_provider)
    if _skey and not st.session_state.get(_skey):
        st.warning(_t("请先在「系统配置」中填写该提供商的 API Key。", "Enter the provider's API key in System settings first."))
        return

    _app_type = st.session_state.get("app_type", "Web application")
    _auth = st.session_state.get("authentication", [])
    _facing = st.session_state.get("internet_facing", "")
    _sens = st.session_state.get("sensitive_data", "")
    _is_genai = _app_type in ("Generative AI application", "Agentic AI application")
    _is_agentic = _app_type == "Agentic AI application"
    _dfd = st.session_state.get("confirmed_dfd")

    st.session_state["project_name"] = project
    st.session_state["app_input"] = _desc
    st.session_state["app_desc"] = _desc

    _steps = [_t("威胁模型", "Threat Model"), _t("数据流图", "Data Flow Diagram"), _t("攻击树", "Attack Tree"), _t("缓解措施", "Mitigations"), _t("DREAD 风险评估", "DREAD Assessment"), _t("测试用例", "Test Cases")]
    _bar = st.progress(0.0, text=_t("准备中…", "Preparing…"))
    _log = st.container()
    _tm_md = ""

    for _i, _label in enumerate(_steps, 1):
        _bar.progress((_i - 1) / len(_steps), text=_t(f"正在生成：{_label}", f"Generating: {_label}"))
        if _label in (_t("缓解措施", "Mitigations"), _t("DREAD 风险评估", "DREAD Assessment"), _t("测试用例", "Test Cases")) and not _tm_md:
            with _log:
                st.markdown(
                        _t(
                            f"- ⏭️ {_label}（跳过：威胁模型未生成成功）",
                            f"- ⏭️ {_label} (skipped: the threat model was not generated)",
                        )
                    )
            continue
        try:
            if _label == _t("威胁模型", "Threat Model"):
                _prompt = create_threat_model_prompt(
                    _app_type, _auth, _facing, _sens, _desc, confirmed_dfd=_dfd
                )
                _out = _run_model("threat_model", _prompt)
                _tm = _out.get("threat_model", [])
                _sug = _out.get("improvement_suggestions", [])
                _tm_md = json_to_markdown(_tm, _sug)
                st.session_state["threat_model"] = _tm
                st.session_state["improvement_suggestions"] = _sug
                st.session_state["threat_model_markdown"] = _tm_md
                _archive(
                    "threat_model",
                    _tm_md,
                    {"threat_model": _tm, "improvement_suggestions": _sug},
                    project=project,
                    description=_desc,
                )
            elif _label == _t("数据流图", "Data Flow Diagram"):
                _prompt = create_dfd_prompt(_app_type, _auth, _facing, _sens, _desc)
                _mermaid = _run_model("dfd", _prompt)
                st.session_state["dfd_mermaid"] = _mermaid
                _archive(
                    "dfd", f"```mermaid\n{_mermaid}\n```", project=project, description=_desc
                )
            elif _label == _t("攻击树", "Attack Tree"):
                _prompt = create_attack_tree_prompt(
                    _app_type, _auth, _facing, _sens, _desc, confirmed_dfd=_dfd
                )
                _mermaid = _run_model("attack_tree", _prompt)
                _archive(
                    "attack_tree",
                    f"```mermaid\n{_mermaid}\n```",
                    project=project,
                    description=_desc,
                )
            elif _label == _t("缓解措施", "Mitigations"):
                _prompt = create_mitigations_prompt(
                    _tm_md, is_genai=_is_genai, is_agentic=_is_agentic
                )
                _archive(
                    "mitigations",
                    _run_model("mitigations", _prompt),
                    project=project,
                    description=_desc,
                )
            elif _label == _t("DREAD 风险评估", "DREAD Assessment"):
                _prompt = create_dread_assessment_prompt(
                    _tm_md, is_genai=_is_genai, is_agentic=_is_agentic
                )
                _assessment = _run_model("dread", _prompt)
                st.session_state["dread_assessment"] = _assessment
                _archive(
                    "dread",
                    dread_json_to_markdown(_assessment),
                    _assessment,
                    project=project,
                    description=_desc,
                )
            elif _label == _t("测试用例", "Test Cases"):
                _prompt = create_test_cases_prompt(
                    _tm_md, is_genai=_is_genai, is_agentic=_is_agentic
                )
                _archive(
                    "test_cases",
                    _run_model("test_cases", _prompt),
                    project=project,
                    description=_desc,
                )
            with _log:
                st.markdown(f"- ✅ {_label}")
        except Exception as _e:
            with _log:
                st.markdown(_t(f"- ⚠️ {_label} 失败：{_e}", f"- ⚠️ {_label} failed: {_e}"))
        _bar.progress(_i / len(_steps), text=_t(f"{_label} 完成", f"{_label} done"))
    _bar.progress(1.0, text=_t("全流程完成", "Full pipeline done"))
    st.success(_t("全流程生成完成，结果已归档到本项目。", "Full pipeline finished; results archived to this project."))
    st.rerun()


def show_report_dialog(report: dict) -> None:
    """打开「报告详情」弹窗（标题随界面语言；装饰器方式会把标题固定在导入时）。"""
    st.dialog(_t("报告详情", "Report details"), width="large")(_report_dialog)(report)
