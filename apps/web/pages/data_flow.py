"""数据流图页面。（P7 从 main.py 拆分）。"""

from __future__ import annotations

import base64

import streamlit as st
from services import (
    _archive,
)
from shared import (
    PROVIDER_API_KEY_STATE,
    _state,
    _t,
    create_dfd_prompt,
    get_dfd_anthropic,
    get_dfd_deepseek,
    get_dfd_from_image_anthropic,
    get_dfd_from_image_google,
    get_dfd_from_image_openai,
    get_dfd_google,
    get_dfd_groq,
    get_dfd_lm_studio,
    get_dfd_mistral,
    get_dfd_openai,
)
from widgets import (
    mermaid,
)


def _page_data_flow() -> None:
    st.markdown(
        _t("数据流图（DFD）让待分析的系统变得清晰可读：它列出每个外部实体、处理过程和数据存储，并展示它们之间的数据流。更关键的是，它能标出\n**信任边界**——攻击者必须跨越的界线。数据流图是威胁建模的基础；审阅数据流图是确认 STRIDE-GPT 与你对系统的理解一致的最直接方式。\n\n本标签页有三种用法：\n\n1. 从应用描述**生成 DFD**，然后编辑成符合你理解的样子。\n2. **上传已有的 DFD 图片**，转换为可编辑的 Mermaid 形式。\n3. 图表确认无误后，勾选 **将此 DFD 用于威胁模型**，将其注入后续的\n   威胁模型和攻击树分析。", "A Data Flow Diagram (DFD) makes the system legible: it names every external entity, process and data store, and shows the flows between them. Crucially, it marks **trust boundaries** — the lines an attacker must cross. DFDs are foundational to threat modeling.\n\nThree ways to use this tab:\n\n1. **Generate a DFD** from your description, then edit it to match your understanding.\n2. **Upload an existing DFD image** to convert it into editable Mermaid.\n3. Once the diagram looks right, tick **Use this DFD for the threat model** to feed it into the next Threat Model and Attack Tree runs.")
    )
    st.markdown("""---""")

    # --- Section 1: Inputs (generate from description OR parse an image) --- #

    dfd_input_col1, dfd_input_col2 = st.columns([1, 1])

    with dfd_input_col1:
        st.markdown(_t("**从描述生成**", "**Generate from description**"))
        dfd_generate_button = st.button(
            label=_t("生成 DFD", "Generate DFD"),
            help=_t("使用你的应用描述和侧边栏设置起草 DFD。", "Draft a DFD from your application description and sidebar settings."),
        )

    with dfd_input_col2:
        st.markdown(_t("**或解析已有的 DFD 图片**", "**Or parse an existing DFD image**"))
        # Vision support set is the same as for architecture diagrams.
        dfd_vision_supported = (
            (_state("model_provider") == "OpenAI API" and (
                _state("selected_model").startswith("gpt-4") or _state("selected_model").startswith("gpt-5")
            ))
            or _state("model_provider") == "Google AI API"
            or (_state("model_provider") == "Anthropic API" and _state("selected_model").startswith("claude"))
        )
        if dfd_vision_supported:
            uploaded_dfd_image = st.file_uploader(
                "上传 DFD 图片",
                type=["jpg", "jpeg", "png"],
                key="dfd_image_uploader",
                help="支持 PNG 或 JPEG。图表将解析为下方可编辑的 Mermaid 代码。",
            )
        else:
            uploaded_dfd_image = None
            st.caption(
                _t("图片解析需要支持视觉的模型（OpenAI GPT-4/5、Anthropic Claude 或 Google Gemini）。", "Image parsing requires a vision-capable model (OpenAI GPT-4/5, Anthropic Claude, or Google Gemini).")
            )

    # --- Section 2: Handle Generation --- #

    # API keys live in st.session_state once the sidebar has run (loaded from
    # .env in load_env_variables and/or typed into the password field). The
    # bare names openai_api_key / anthropic_api_key etc. are only ever local
    # to load_env_variables, so always go through session_state here.
    _dfd_api_key = st.session_state.get(
        PROVIDER_API_KEY_STATE.get(_state("model_provider"), ""),
        "",
    )

    if dfd_generate_button and st.session_state.get("app_input"):
        dfd_prompt = create_dfd_prompt(
            _state("app_type"),
            _state("authentication"),
            _state("internet_facing"),
            _state("sensitive_data"),
            st.session_state["app_input"],
        )
        if _state("model_provider") != "LM Studio Server" and not _dfd_api_key:
            st.error(
                f"请输入你的 {_state("model_provider")} Key（可在侧边栏填写，或写入 "
                ".env 文件）后再生成 DFD。"
            )
        else:
            with st.spinner(_t("正在生成数据流图……", "Generating data flow diagram…")):
                try:
                    if _state("model_provider") == "OpenAI API":
                        dfd_mermaid = get_dfd_openai(_dfd_api_key, _state("selected_model"), dfd_prompt)
                    elif _state("model_provider") == "Anthropic API":
                        dfd_mermaid = get_dfd_anthropic(_dfd_api_key, _state("selected_model"), dfd_prompt)
                    elif _state("model_provider") == "Google AI API":
                        dfd_mermaid = get_dfd_google(_dfd_api_key, _state("selected_model"), dfd_prompt)
                    elif _state("model_provider") == "Mistral API":
                        dfd_mermaid = get_dfd_mistral(_dfd_api_key, _state("selected_model"), dfd_prompt)
                    elif _state("model_provider") == "Groq API":
                        dfd_mermaid = get_dfd_groq(_dfd_api_key, _state("selected_model"), dfd_prompt)
                    elif _state("model_provider") == "DeepSeek API":
                        dfd_mermaid = get_dfd_deepseek(_dfd_api_key, _state("selected_model"), dfd_prompt)
                    elif _state("model_provider") == "LM Studio Server":
                        dfd_mermaid = get_dfd_lm_studio(
                            st.session_state["lm_studio_endpoint"],
                            _state("selected_model"),
                            dfd_prompt,
                            st.session_state.get("lm_studio_api_key", ""),
                        )
                    else:
                        dfd_mermaid = ""
                    # Generation invalidates any previous confirmation — the user
                    # needs to re-tick "Use this DFD" to opt back in.
                    st.session_state["dfd_mermaid"] = dfd_mermaid
                    st.session_state.pop("confirmed_dfd", None)
                    _archive("dfd", dfd_mermaid)
                except Exception as e:
                    st.error(f"生成 DFD 失败：{e}")
    elif dfd_generate_button and not st.session_state.get("app_input"):
        st.error(_t("请先在威胁模型标签页输入应用详情。", "Enter application details on the Threat model page first."))

    # --- Section 3: Handle Image Parsing --- #

    if uploaded_dfd_image is not None:
        # Re-parse on every change of the upload — the file_uploader returns
        # the same object across reruns, so we key on the file name + size.
        upload_key = f"{uploaded_dfd_image.name}:{uploaded_dfd_image.size}"
        if st.session_state.get("dfd_last_upload_key") != upload_key:
            if not _dfd_api_key:
                st.error(
                    f"请输入你的 {_state("model_provider")} Key（在侧边栏填写）后再上传 DFD 图片。"
                )
            else:
                with st.spinner(_t("正在解析 DFD 图片……", "Parsing DFD image…")):
                    try:
                        image_bytes = uploaded_dfd_image.read()
                        base64_image = base64.b64encode(image_bytes).decode("utf-8")
                        media_type = (
                            "image/png" if uploaded_dfd_image.type == "image/png" else "image/jpeg"
                        )
                        if _state("model_provider") == "OpenAI API":
                            dfd_mermaid = get_dfd_from_image_openai(
                                _dfd_api_key, _state("selected_model"), base64_image
                            )
                        elif _state("model_provider") == "Anthropic API":
                            dfd_mermaid = get_dfd_from_image_anthropic(
                                _dfd_api_key, _state("selected_model"), base64_image, media_type
                            )
                        elif _state("model_provider") == "Google AI API":
                            dfd_mermaid = get_dfd_from_image_google(
                                _dfd_api_key, _state("selected_model"), base64_image
                            )
                        else:
                            dfd_mermaid = ""
                        st.session_state["dfd_mermaid"] = dfd_mermaid
                        st.session_state["dfd_last_upload_key"] = upload_key
                        st.session_state.pop("confirmed_dfd", None)
                        _archive("dfd", dfd_mermaid)
                    except Exception as e:
                        st.error(f"解析 DFD 图片失败：{e}")

    # --- Section 4: Editor + Preview --- #

    st.markdown("---")
    st.markdown(_t("**Mermaid 源码**（可自由编辑——重新运行后预览会更新）：", "**Mermaid source** (edit freely — preview updates on rerun):"))
    dfd_editor_value = st.text_area(
        _t("DFD Mermaid 代码", "DFD Mermaid code"),
        value=st.session_state.get("dfd_mermaid", ""),
        height=260,
        key="dfd_editor",
        label_visibility="collapsed",
        placeholder=_t("还没有 DFD。点击“生成 DFD”或上传图片以填充此编辑器。", "No DFD yet. Use \"Generate DFD\" or upload an image to populate this editor."),
    )
    # Keep dfd_mermaid in sync with the editor so it survives reruns.
    st.session_state["dfd_mermaid"] = dfd_editor_value

    if dfd_editor_value.strip():
        st.markdown(_t("**图表预览：**", "**Diagram preview:**"))
        try:
            mermaid(dfd_editor_value)
        except Exception as e:
            st.warning(f"无法渲染预览：{e}")

        # --- Section 5: Confirm + Download --- #

        confirmed = st.checkbox(
            _t("将此 DFD 用于威胁模型", "Use this DFD for the threat model"),
            value=bool(st.session_state.get("confirmed_dfd")),
            help=(
                _t("勾选后，此 DFD 会包含在威胁模型和攻击树的提示词中，使分析结果与图表保持一致。", "When ticked, this DFD is included in the Threat Model and Attack Tree prompts so the analysis aligns with the diagram.")
            ),
            key="dfd_confirm_checkbox",
        )
        # Keep confirmed_dfd in lockstep with the checkbox AND the editor.
        if confirmed:
            st.session_state["confirmed_dfd"] = dfd_editor_value
            st.success(
                _t("DFD 已确认——将作为系统模型用于后续的威胁模型和攻击树分析。", "DFD confirmed — it will be the system model for subsequent Threat Model and Attack Tree runs.")
            )
        else:
            st.session_state.pop("confirmed_dfd", None)
            st.caption(
                _t("未启用。勾选上方复选框即可将此 DFD 注入下一次分析。", "Not in use. Tick the checkbox above to feed this DFD into the next analysis.")
            )

        dfd_dl_col1, dfd_dl_col2, _ = st.columns([1, 1, 3])
        with dfd_dl_col1:
            st.download_button(
                label=_t("下载图表代码", "Download diagram code"),
                data=dfd_editor_value,
                file_name="data_flow_diagram.md",
                mime="text/plain",
                help=_t("下载此 DFD 的 Mermaid 源码。", "Download the Mermaid source for this DFD."),
            )
        with dfd_dl_col2:
            st.link_button(_t("在 Mermaid Live 中打开", "Open in Mermaid Live"), "https://mermaid.live")
