"""威胁模型页面（含图编辑器与引导式草稿）。（P7 从 main.py 拆分）。"""

from __future__ import annotations

import base64
import hashlib
import json

import streamlit as st
from services import (
    _archive,
)
from shared import (
    _APP_TYPE_LABELS,
    _APP_TYPE_LABELS_EN,
    _AUTH_LABELS,
    _AUTH_LABELS_EN,
    _SENSITIVE_DATA_LABELS,
    _SENSITIVE_DATA_LABELS_EN,
    _YES_NO_LABELS,
    _YES_NO_LABELS_EN,
    _generation,
    _interop,
    _state,
    _t,
    _ui_label,
    create_image_analysis_prompt,
    create_threat_model_prompt,
    drawio_editor_component,
    drawio_to_prompt_section,
    get_image_analysis,
    get_image_analysis_anthropic,
    get_image_analysis_google,
    get_threat_model,
    get_threat_model_anthropic,
    get_threat_model_deepseek,
    get_threat_model_google,
    get_threat_model_groq,
    get_threat_model_lm_studio,
    get_threat_model_mistral,
    json_to_markdown,
    save_draft,
)
from widgets import (
    render_app_description,
    render_github_repo_input,
    render_guided_description_builder,
)


def _page_threat_model() -> None:
    st.markdown(
        _t("威胁模型有助于识别和评估应用/系统面临的潜在安全威胁，提供系统化方法来理解可能的漏洞与攻击路径。\n使用此标签页可基于 STRIDE 方法生成威胁模型。", "Threat modeling identifies and evaluates potential security threats to an application or system, providing a systematic view of vulnerabilities and attack paths.\nUse this tab to generate a STRIDE threat model.")
    )
    st.markdown("""---""")

    # Editor renders full-width here (above the form columns) so it is
    # immediately visible after the button in col1 is clicked.
    if st.session_state.get("show_drawio_editor"):
        _hdr_l, _hdr_r = st.columns([1, 3])
        with _hdr_l:
            if st.button(_t("关闭图表编辑器", "Close diagram editor"), key="close_drawio", use_container_width=True):
                st.session_state["show_drawio_editor"] = False
                st.rerun()
        with _hdr_r:
            if st.session_state.get("drawio_xml"):
                st.success(_t("图表已保存，将用于生成威胁模型。", "Diagram saved; it will be used for threat model generation."))
        # The key carries a per-open nonce (bumped by "Open Diagram Editor"). A
        # stable key makes Streamlit replay the component's last return value when
        # it re-mounts on reopen, which re-fires the previous save/close and shuts
        # the editor before the saved diagram can load. A fresh key per open gives
        # a clean component that reloads the saved XML.
        _drawio_result = drawio_editor_component(
            xml=st.session_state.get("drawio_xml", ""),
            key=f"drawio_editor_widget_{st.session_state.get('drawio_editor_nonce', 0)}",
        )
        if _drawio_result:
            if _drawio_result.get("action") == "save" and _drawio_result.get("xml"):
                _xml = _drawio_result["xml"]
                st.session_state["drawio_xml"] = _xml
                _summary = drawio_to_prompt_section(_xml)
                if _summary:
                    st.session_state["app_input"] = _summary
                    st.session_state["_sync_app_desc"] = True
                st.session_state["show_drawio_editor"] = False
                st.rerun()
            elif _drawio_result.get("action") == "close":
                st.session_state["show_drawio_editor"] = False
                st.rerun()
        st.markdown("---")

    # Two column layout for the main app content
    col1, col2 = st.columns([1, 1])

    # Initialize app_input in the session state if it doesn't exist
    if "app_input" not in st.session_state:
        st.session_state["app_input"] = ""

    # Display image uploader for supported multimodal models
    with col1:
        supports_image = False
        # Get selected_model from session state
        selected_model = st.session_state.get("selected_model", "")

        if (
            (
                _state("model_provider") == "OpenAI API"
                and (selected_model.startswith("gpt-4") or selected_model.startswith("gpt-5"))
            )
            or _state("model_provider") == "Google AI API"
            or (_state("model_provider") == "Anthropic API" and selected_model.startswith("claude-"))
        ):
            supports_image = True

        # The application description is the primary input. GitHub analysis,
        # image upload, and the draw.io editor are all *sources* that seed that
        # description, so they're grouped as tabs of one section sitting above
        # the description text area. Each is a "writer" (sets app_input +
        # _sync_app_desc), so they must run before render_app_description()
        # instantiates the text area, which the top-to-bottom order guarantees.
        st.caption(
            _t("在下方描述你的应用。想快速起步，可从以下来源自动生成草稿：GitHub 仓库、上传的架构图、内置编辑器中绘制的图，或引导式构建器。生成后请检查并编辑。", "Describe your application below. To get a head start, auto-generate a draft from a GitHub repo, an uploaded diagram, a diagram drawn in the built-in editor, or the guided builder.")
        )
        with st.expander(
            _t("导入外部模型（Threat Dragon JSON）", "Import external model (Threat Dragon JSON)"),
            expanded=False,
        ):
            _td_file = st.file_uploader(
                _t("上传 Threat Dragon 模型", "Upload Threat Dragon model"),
                type=["json"],
                key="td_import_file",
            )
            if _td_file is not None and st.button(
                _t("导入为应用描述", "Import as description"), key="td_import_apply"
            ):
                try:
                    _td_desc = _interop.from_threat_dragon(
                        json.loads(_td_file.getvalue().decode("utf-8"))
                    )
                    st.session_state["app_input"] = _td_desc
                    st.session_state["app_desc"] = _td_desc
                    st.session_state["_sync_app_desc"] = True
                    st.success(_t("已导入，可在下方继续编辑", "Imported — edit below"))
                    st.rerun()
                except Exception as _td_exc:
                    st.error(_t("导入失败：", "Import failed: ") + str(_td_exc))
        _gh_tab, _img_tab, _draw_tab, _guided_tab = st.tabs(
            [
                _t("GitHub 仓库", "GitHub repo"),
                _t("上传图片", "Upload image"),
                _t("画架构图", "Draw diagram"),
                _t("引导式", "Guided"),
            ]
        )

        with _gh_tab:
            render_github_repo_input()

        with _img_tab:
            if not supports_image:
                st.info(
                    _t("图片上传需要支持视觉的模型（OpenAI、Google AI 或 Anthropic Claude 模型）。请在侧边栏切换模型，或使用 **画架构图** / **引导式** 标签页——它们适用于任何模型。", "Image upload needs a vision-capable model (OpenAI / Google AI / Anthropic Claude). Switch the model in the sidebar, or use the **Draw diagram** / **Guided** tabs, which work with any model.")
                )
            else:
                uploaded_file = st.file_uploader(
                    "上传架构图", type=["jpg", "jpeg", "png"]
                )

                if uploaded_file is not None:

                    def encode_image(uploaded_file):
                        return base64.b64encode(uploaded_file.read()).decode("utf-8")

                    base64_image = encode_image(uploaded_file)
                    image_analysis_prompt = create_image_analysis_prompt()

                    # Determine media type from file extension
                    file_type = uploaded_file.type
                    if file_type == "image/png":
                        media_type = "image/png"
                    elif file_type in ["image/jpeg", "image/jpg"]:
                        media_type = "image/jpeg"
                    else:
                        media_type = "image/jpeg"  # Default fallback

                    try:
                        if _state("model_provider") == "OpenAI API":
                            if not _state("openai_api_key"):
                                st.error(_t("请输入 OpenAI API Key 以分析图片。", "Enter your OpenAI API key to analyze the image."))
                                raise ValueError
                            image_analysis_output = get_image_analysis(
                                _state("openai_api_key"), selected_model, image_analysis_prompt, base64_image
                            )
                        elif _state("model_provider") == "Google AI API":
                            if not _state("google_api_key"):
                                st.error(_t("请输入 Google AI API Key 以分析图片。", "Enter your Google AI API key to analyze the image."))
                                raise ValueError
                            image_analysis_output = get_image_analysis_google(
                                _state("google_api_key"), selected_model, image_analysis_prompt, base64_image
                            )
                        elif _state("model_provider") == "Anthropic API":
                            if not _state("anthropic_api_key"):
                                st.error(_t("请输入 Anthropic API Key 以分析图片。", "Enter your Anthropic API key to analyze the image."))
                                raise ValueError
                            image_analysis_output = get_image_analysis_anthropic(
                                _state("anthropic_api_key"),
                                selected_model,
                                image_analysis_prompt,
                                base64_image,
                                media_type,
                            )
                        else:
                            image_analysis_output = None

                        if (
                            image_analysis_output
                            and "choices" in image_analysis_output
                            and image_analysis_output["choices"][0]["message"]["content"]
                        ):
                            image_analysis_content = image_analysis_output["choices"][0][
                                "message"
                            ]["content"]
                            st.session_state.image_analysis_content = image_analysis_content
                            st.session_state["app_input"] = image_analysis_content
                            st.session_state["_sync_app_desc"] = True
                        else:
                            st.error(
                                _t("图片分析失败，请检查 API Key 后重试。", "Image analysis failed; check the API key and retry.")
                            )
                    except Exception as e:
                        st.error(f"分析图片时发生错误：{e!s}")

        with _draw_tab:
            if st.button(_t("打开图表编辑器", "Open diagram editor"), key="toggle_drawio", use_container_width=True):
                st.session_state["show_drawio_editor"] = True
                # Fresh nonce -> fresh component key -> no stale save/close replay.
                st.session_state["drawio_editor_nonce"] = (
                    st.session_state.get("drawio_editor_nonce", 0) + 1
                )
                st.rerun()
            if st.session_state.get("drawio_xml"):
                st.success(_t("图表已保存，将用于生成威胁模型。", "Diagram saved; it will be used for threat model generation."))
                if st.button(_t("清除图表", "Clear diagram"), key="clear_drawio"):
                    st.session_state.pop("drawio_xml", None)
                    st.rerun()

        with _guided_tab:
            render_guided_description_builder()

        # Description text area renders last so every source above can sync into it.
        app_input = render_app_description()
        # Update session state only if the text area content has changed
        if app_input != st.session_state["app_input"]:
            st.session_state["app_input"] = app_input

    # Ensure app_input is always up to date in the session state
    app_input = st.session_state["app_input"]

    # Create input fields for additional details
    with col2:
        st.text_input(
            _t("项目名称（用于报告归档）", "Project name (for report archiving)"),
            key="project_name",
            placeholder=_t("留空则按应用描述自动取名", "Leave empty to auto-name from the description"),
            help=_t("生成结果会按项目名称归档到「报告历史」页面。", "Results are archived under this project in Report history."),
        )
        app_type = st.selectbox(
            label=_t("选择应用类型", "Application type"),
            options=[
                "Web application",
                "Mobile application",
                "Desktop application",
                "Cloud application",
                "IoT application",
                "Generative AI application",
                "Agentic AI application",
                "Other",
            ],
            key="app_type",
            format_func=lambda x: _ui_label(_APP_TYPE_LABELS, _APP_TYPE_LABELS_EN, x),
        )

        sensitive_data = st.selectbox(
            label=_t("应用处理的数据最高敏感级别是？", "Highest sensitivity of processed data?"),
            options=[
                "Top Secret",
                "Secret",
                "Confidential",
                "Restricted",
                "Unclassified",
                "None",
            ],
            key="sensitive_data",
            format_func=lambda x: _ui_label(_SENSITIVE_DATA_LABELS, _SENSITIVE_DATA_LABELS_EN, x),
        )

        # Create input fields for internet_facing and authentication
        internet_facing = st.selectbox(
            label=_t("应用是否面向互联网？", "Internet-facing?"),
            options=["Yes", "No"],
            key="internet_facing",
            format_func=lambda x: _ui_label(_YES_NO_LABELS, _YES_NO_LABELS_EN, x),
        )

        authentication = st.multiselect(
            _t("应用支持哪些身份认证方式？", "Supported authentication methods?"),
            ["SSO", "MFA", "OAUTH2", "Basic", "None"],
            key="authentication",
            placeholder=_t("选择认证方式…", "Select authentication methods…"),
            format_func=lambda x: _ui_label(_AUTH_LABELS, _AUTH_LABELS_EN, x),
        )

        # Show guidance for GenAI/Agentic applications
        if app_type == "Generative AI application":
            st.markdown("---")
            st.info(
                _t("**为获得更好的威胁覆盖，请在描述中包含：**\n- LLM 提供商与模型（如 OpenAI GPT-5、Claude、微调版 Llama）\n- 使用的功能（RAG、函数调用、代码生成、嵌入）\n- 数据来源（文档、数据库、API、用户上传）\n- 输出的使用方式（展示、存储、执行、发送到外部）", "**For better coverage, include in your description:**\n- LLM provider and model (e.g. OpenAI GPT-5, Claude, fine-tuned Llama)\n- Features used (RAG, function calling, code generation, embeddings)\n- Data sources (documents, databases, APIs, uploads)\n- How outputs are used (displayed, stored, executed, sent externally)")
            )

        if app_type == "Agentic AI application":
            st.markdown("---")
            st.info(
                _t("**为获得更好的威胁覆盖，请在描述中包含：**\n- 智能体框架（LangChain、CrewAI、AutoGen、自研）\n- 智能体能力（工具调用、代码执行、网页浏览、文件访问）\n- 如适用，多智能体细节（编排、通信）\n- 记忆/状态持久化机制\n- 人工监督级别（需审批、仅监控、完全自主）\n- 工具与集成（MCP 服务器、API、数据库）\n- 凭据访问（OAuth 令牌、API Key、服务账号）\n- 自主操作范围（无需审批能做什么？）", "**For better coverage, include in your description:**\n- Agent framework (LangChain, CrewAI, AutoGen, custom)\n- Agent capabilities (tool use, code execution, web browsing, file access)\n- Multi-agent details if applicable (orchestration, communication)\n- Memory/state persistence\n- Human oversight level (approval required, monitoring only, fully autonomous)\n- Tools and integrations (MCP servers, APIs, databases)\n- Credential access (OAuth tokens, API keys, service accounts)\n- Autonomous scope (what can it do without approval?)")
            )

    # 草稿自动保存（刷新后自动恢复）
    _draft_payload = {
        "app_input": st.session_state.get("app_input", ""),
        "app_type": st.session_state.get("app_type", ""),
        "sensitive_data": st.session_state.get("sensitive_data", ""),
        "internet_facing": st.session_state.get("internet_facing", ""),
        "authentication": st.session_state.get("authentication", []),
    }
    _draft_sig = hashlib.md5(
        json.dumps(_draft_payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()
    if st.session_state.get("_draft_sig") != _draft_sig:
        save_draft("__default__", _draft_payload)
        st.session_state["_draft_sig"] = _draft_sig

    # ------------------ Threat Model Generation ------------------ #

    # Create a submit button for Threat Modelling
    threat_model_submit_button = st.button(label=_t("生成威胁模型", "Generate threat model"))

    # If the Generate Threat Model button is clicked and the user has provided an application description
    if threat_model_submit_button and st.session_state.get("app_input"):
        app_input = st.session_state["app_input"]  # Retrieve from session state

        # If the user created a draw.io diagram, prepend extracted architecture
        # context (components, data flows, trust boundaries) to the app description
        # so the LLM has richer structural input for threat model generation.
        _effective_app_input = app_input
        if st.session_state.get("drawio_xml"):
            _drawio_ctx = drawio_to_prompt_section(st.session_state["drawio_xml"])
            if _drawio_ctx:
                _effective_app_input = _drawio_ctx + "\n\n" + app_input

        # Generate the prompt using the create_prompt function. If the user
        # has confirmed a DFD on the Data Flow Diagram tab, splice it in as
        # an authoritative system model so the threats align with the
        # diagram's components and trust boundaries.
        threat_model_prompt = create_threat_model_prompt(
            app_type,
            authentication,
            internet_facing,
            sensitive_data,
            _effective_app_input,
            confirmed_dfd=st.session_state.get("confirmed_dfd"),
        )

        # Clear thinking content when switching models or starting a new operation
        if _state("model_provider") != "Anthropic API" or "thinking" not in selected_model.lower():
            st.session_state.pop("last_thinking_content", None)

        # Show a spinner while generating the threat model
        with st.spinner(_t("正在分析潜在威胁……", "Analyzing potential threats…")):
            max_retries = 3
            retry_count = 0
            while retry_count < max_retries:
                try:
                    # Call the relevant get_threat_model function with the generated prompt
                    if _state("model_provider") == "OpenAI API":
                        model_output = get_threat_model(
                            _state("openai_api_key"), selected_model, threat_model_prompt
                        )
                    elif _state("model_provider") == "Google AI API":
                        model_output = get_threat_model_google(
                            _state("google_api_key"), selected_model, threat_model_prompt
                        )
                    elif _state("model_provider") == "Mistral API":
                        model_output = get_threat_model_mistral(
                            _state("mistral_api_key"), selected_model, threat_model_prompt
                        )
                    elif _state("model_provider") == "Anthropic API":
                        model_output = get_threat_model_anthropic(
                            _state("anthropic_api_key"), selected_model, threat_model_prompt
                        )
                        # Check if we got a fallback response
                        if (
                            model_output.get("threat_model")
                            and len(model_output["threat_model"]) == 1
                            and model_output["threat_model"][0].get("Threat Type") == "Error"
                        ):
                            st.warning(
                                _t("生成威胁模型时出现问题，模型返回的格式可能不符合预期。你可以尝试：", "There was an issue generating the threat model; the format may be unexpected. Try:")
                            )
                            st.markdown(_t("1. 重新运行生成", "1. Run the generation again"))
                            st.markdown(_t("2. 查看应用日志了解更多细节", "2. Check the application logs for details"))
                            st.markdown(_t("3. 如果问题仍然存在，换一个模型", "3. Try a different model if the issue persists"))
                    elif _state("model_provider") == "LM Studio Server":
                        model_output = get_threat_model_lm_studio(
                            st.session_state["lm_studio_endpoint"],
                            selected_model,
                            threat_model_prompt,
                            st.session_state.get("lm_studio_api_key", ""),
                        )
                    elif _state("model_provider") == "Groq API":
                        model_output = get_threat_model_groq(
                            _state("groq_api_key"), selected_model, threat_model_prompt
                        )
                    elif _state("model_provider") == "DeepSeek API":
                        model_output = get_threat_model_deepseek(
                            _state("deepseek_api_key"), selected_model, threat_model_prompt
                        )

                    # Access the threat model and improvement suggestions from the parsed content
                    threat_model = model_output.get("threat_model", [])
                    improvement_suggestions = model_output.get("improvement_suggestions", [])

                    # Save the threat model and suggestions to session state for later use
                    st.session_state["threat_model"] = threat_model
                    st.session_state["improvement_suggestions"] = improvement_suggestions

                    # Convert to Markdown and store in session state for persistent display
                    st.session_state["threat_model_markdown"] = json_to_markdown(
                        threat_model, improvement_suggestions
                    )
                    _archived_project = _archive(
                        "threat_model",
                        st.session_state["threat_model_markdown"],
                        {
                            "threat_model": threat_model,
                            "improvement_suggestions": improvement_suggestions,
                        },
                    )
                    st.session_state["threat_model_verification"] = None
                    if _generation.verification_enabled() and threat_model:
                        with st.spinner(_t("正在对抗式复核威胁…", "Adversarially reviewing threats…")):
                            try:
                                _vstats = _generation.verify_and_store(
                                    _archived_project, threat_model
                                )
                                st.session_state["threat_model_verification"] = _vstats
                            except Exception as _vexc:
                                st.warning(
                                    _t("威胁复核失败：", "Threat verification failed: ")
                                    + str(_vexc)
                                )
                    _cov = _generation.stride_coverage(threat_model)
                    if _cov["missing"]:
                        st.warning(
                            _t("STRIDE 覆盖度：缺少 ", "STRIDE coverage: missing ")
                            + "、".join(_cov["missing"])
                            + _t(" 类威胁", " categories")
                        )
                    else:
                        st.success(
                            _t(
                                "STRIDE 覆盖度：六类威胁均已覆盖",
                                "STRIDE coverage: all six categories covered",
                            )
                        )
                    _vstats = st.session_state.get("threat_model_verification")
                    if _vstats:
                        st.info(
                            _t("对抗式复核：", "Adversarial review: ")
                            + _t("已确认", "confirmed")
                            + f" {_vstats.get('已确认', 0)} · "
                            + _t("存疑", "uncertain")
                            + f" {_vstats.get('存疑', 0)} · "
                            + _t("已驳回", "refuted")
                            + f" {_vstats.get('已驳回', 0)}"
                        )
                    break  # Exit the loop if successful
                except Exception as e:
                    retry_count += 1
                    if retry_count == max_retries:
                        st.error(f"生成威胁模型失败，已重试 {max_retries} 次：{e}")
                        threat_model = []
                        improvement_suggestions = []
                    else:
                        st.warning(
                            f"生成威胁模型失败，正在重试第 {retry_count + 1}/{max_retries}..."
                        )

# Display threat model output on tab1 (must be in tab1 context to only show on that tab)
# （继续）显示威胁模型输出
    # If the submit button is clicked and the user has not provided an application description
    if threat_model_submit_button and not st.session_state.get("app_input"):
        st.error(_t("提交前请先输入应用详情。", "Enter application details before submitting."))

    # Display threat model from session state (persists across reruns)
    if st.session_state.get("threat_model_markdown"):
        # Display thinking content in an expander if available
        if (
            "last_thinking_content" in st.session_state
            and st.session_state["last_thinking_content"]
            and (
                (_state("model_provider") == "Anthropic API" and st.session_state.get("use_thinking", False))
                or (_state("model_provider") == "Google AI API" and ("gemini-2.5" in selected_model.lower() or "gemini-3" in selected_model.lower()))
            )
        ):
            thinking_model = "Claude" if _state("model_provider") == "Anthropic API" else "Gemini"
            with st.expander(f"查看 {thinking_model} 的思考过程"):
                st.markdown(st.session_state["last_thinking_content"])

        # Display the threat model in Markdown
        st.markdown(st.session_state["threat_model_markdown"])

        # Add a button to allow the user to download the output as a Markdown file
        st.download_button(
            label=_t("下载威胁模型", "Download threat model"),
            data=st.session_state["threat_model_markdown"],
            file_name="threat_model.md",
            mime="text/markdown",
        )
