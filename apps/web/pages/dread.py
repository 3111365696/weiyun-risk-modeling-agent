"""DREAD 风险评估页面。（P7 从 main.py 拆分）。"""

from __future__ import annotations

import streamlit as st
from services import (
    _archive,
)
from shared import (
    _state,
    _t,
    create_dread_assessment_prompt,
    dread_json_to_markdown,
    get_dread_assessment,
    get_dread_assessment_anthropic,
    get_dread_assessment_deepseek,
    get_dread_assessment_google,
    get_dread_assessment_groq,
    get_dread_assessment_lm_studio,
    get_dread_assessment_mistral,
    json_to_markdown,
)


def _page_dread() -> None:
    st.markdown(
        _t("DREAD 是一种评估和排序安全威胁风险的方法，从 **D**amage potential（潜在损害）、\n**R**eproducibility（可复现性）、**E**xploitability（可利用性）、**A**ffected users（受影响用户）和\n**D**iscoverability（可发现性）五个维度评估威胁，从而确定整体风险等级，\n优先处理最关键的威胁。使用此标签页对应用/系统进行 DREAD 风险评估。", "DREAD evaluates and prioritizes risks across **D**amage potential, **R**eproducibility, **E**xploitability, **A**ffected users and **D**iscoverability, helping focus on the most critical threats first.")
    )
    st.markdown("""---""")

    # Create a submit button for DREAD Risk Assessment
    dread_assessment_submit_button = st.button(label=_t("生成 DREAD 风险评估", "Generate DREAD risk assessment"))
    # If the Generate DREAD Risk Assessment button is clicked and the user has identified threats
    if dread_assessment_submit_button:
        # Check if threat_model data exists
        if st.session_state.get("threat_model"):
            # Convert the threat_model data into a Markdown list
            threats_markdown = json_to_markdown(st.session_state["threat_model"], [])
            # Check if this is a GenAI or agentic application
            is_genai = _state("app_type") in ["Generative AI application", "Agentic AI application"]
            is_agentic = _state("app_type") == "Agentic AI application"
            # Generate the prompt using the create_dread_assessment_prompt function
            dread_assessment_prompt = create_dread_assessment_prompt(threats_markdown, is_genai=is_genai, is_agentic=is_agentic)
            # Clear thinking content when switching models or starting a new operation
            if _state("model_provider") != "Anthropic API" or "thinking" not in _state("selected_model").lower():
                st.session_state.pop("last_thinking_content", None)

            # Show a spinner while generating DREAD Risk Assessment
            with st.spinner(_t("正在生成 DREAD 风险评估……", "Generating DREAD risk assessment…")):
                max_retries = 3
                retry_count = 0
                while retry_count < max_retries:
                    try:
                        # Call the relevant get_dread_assessment function with the generated prompt
                        if _state("model_provider") == "OpenAI API":
                            dread_assessment = get_dread_assessment(
                                _state("openai_api_key"), _state("selected_model"), dread_assessment_prompt
                            )
                        elif _state("model_provider") == "Google AI API":
                            dread_assessment = get_dread_assessment_google(
                                _state("google_api_key"), _state("selected_model"), dread_assessment_prompt
                            )
                        elif _state("model_provider") == "Mistral API":
                            dread_assessment = get_dread_assessment_mistral(
                                _state("mistral_api_key"), _state("selected_model"), dread_assessment_prompt
                            )
                        elif _state("model_provider") == "Anthropic API":
                            dread_assessment = get_dread_assessment_anthropic(
                                _state("anthropic_api_key"), _state("selected_model"), dread_assessment_prompt
                            )
                        elif _state("model_provider") == "LM Studio Server":
                            dread_assessment = get_dread_assessment_lm_studio(
                                st.session_state["lm_studio_endpoint"],
                                _state("selected_model"),
                                dread_assessment_prompt,
                                st.session_state.get("lm_studio_api_key", ""),
                            )
                        elif _state("model_provider") == "Groq API":
                            dread_assessment = get_dread_assessment_groq(
                                _state("groq_api_key"), _state("selected_model"), dread_assessment_prompt
                            )
                        elif _state("model_provider") == "DeepSeek API":
                            dread_assessment = get_dread_assessment_deepseek(
                                _state("deepseek_api_key"), _state("selected_model"), dread_assessment_prompt
                            )

                        # Save the DREAD assessment to the session state for later use in test cases
                        st.session_state["dread_assessment"] = dread_assessment
                        break  # Exit the loop if successful
                    except Exception as e:
                        retry_count += 1
                        if retry_count == max_retries:
                            st.error(
                                f"生成 DREAD 风险评估失败，已重试 {max_retries} 次：{e}"
                            )
                            dread_assessment = {"Risk Assessment": []}
                            # Add debug information
                            st.error(
                                _t("调试：响应中未找到威胁。请尝试重新生成威胁模型。", "Debug: no threats found in the response. Try regenerating the threat model.")
                            )
                        else:
                            st.warning(
                                f"生成 DREAD 风险评估失败，正在重试第 {retry_count + 1}/{max_retries}..."
                            )
            # Convert the DREAD assessment JSON to Markdown
            dread_assessment_markdown = dread_json_to_markdown(dread_assessment)
            _archive("dread", dread_assessment_markdown, dread_assessment)

            # Add debug information about the assessment
            if not dread_assessment.get("Risk Assessment"):
                st.warning(
                    _t("调试：DREAD 评估响应为空。请确认已先生成威胁模型。", "Debug: the DREAD response is empty. Ensure a threat model was generated first.")
                )

            # Display thinking content in an expander if available and using a model with thinking capabilities
            if (
                "last_thinking_content" in st.session_state
                and st.session_state["last_thinking_content"]
                and (
                    (_state("model_provider") == "Anthropic API" and st.session_state.get("use_thinking", False))
                    or (_state("model_provider") == "Google AI API" and ("gemini-2.5" in _state("selected_model").lower() or "gemini-3" in _state("selected_model").lower()))
                )
            ):
                thinking_model = "Claude" if _state("model_provider") == "Anthropic API" else "Gemini"
                with st.expander(f"查看 {thinking_model} 的思考过程"):
                    st.markdown(st.session_state["last_thinking_content"])

            # Display the DREAD assessment with a header
            st.markdown(_t("## DREAD 风险评估", "## DREAD risk assessment"))
            st.markdown(
                _t("下表展示每个已识别威胁的 DREAD 风险评估。风险评分取五个 DREAD 维度的平均值。", "The table below shows the DREAD assessment for each identified threat. Risk Score is the average of the five DREAD categories.")
            )

            # Display the DREAD assessment in Markdown format
            st.markdown(dread_assessment_markdown, unsafe_allow_html=False)

            # Add a button to allow the user to download the DREAD assessment as a Markdown file
            st.download_button(
                label=_t("下载 DREAD 风险评估", "Download DREAD risk assessment"),
                data=dread_assessment_markdown,
                file_name="dread_assessment.md",
                mime="text/markdown",
            )
        else:
            st.error(
                _t("请先生成威胁模型，再请求 DREAD 风险评估。", "Generate a threat model before requesting a DREAD assessment.")
            )
