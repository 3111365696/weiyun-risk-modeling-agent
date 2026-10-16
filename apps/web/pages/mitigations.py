"""缓解措施页面。（P7 从 main.py 拆分）。"""

from __future__ import annotations

import streamlit as st
from services import (
    _archive,
)
from shared import (
    _state,
    _t,
    create_mitigations_prompt,
    get_mitigations,
    get_mitigations_anthropic,
    get_mitigations_deepseek,
    get_mitigations_google,
    get_mitigations_groq,
    get_mitigations_lm_studio,
    get_mitigations_mistral,
    json_to_markdown,
)


def _page_mitigations() -> None:
    st.markdown(
        _t("使用此标签页为威胁模型中识别出的威胁生成潜在缓解措施。缓解措施是安全控制或\n对策，可帮助降低安全威胁发生的可能性或影响。生成的缓解措施可用于增强\n应用的安全防护能力，抵御潜在攻击。", "Use this tab to generate potential mitigations for the threats identified in the threat model. Mitigations are security controls or countermeasures that reduce the likelihood or impact of a threat.")
    )
    st.markdown("""---""")

    # Create a submit button for Mitigations
    mitigations_submit_button = st.button(label=_t("生成缓解措施", "Suggest mitigations"))

    # If the Suggest Mitigations button is clicked and the user has identified threats
    if mitigations_submit_button:
        # Check if threat_model data exists
        if st.session_state.get("threat_model"):
            # Convert the threat_model data into a Markdown list
            threats_markdown = json_to_markdown(st.session_state["threat_model"], [])
            # Check if this is a GenAI or agentic application
            app_type = st.session_state.get("app_type", "")
            is_genai = app_type in ["Generative AI application", "Agentic AI application"]
            is_agentic = app_type == "Agentic AI application"
            # Generate the prompt using the create_mitigations_prompt function
            mitigations_prompt = create_mitigations_prompt(threats_markdown, is_genai=is_genai, is_agentic=is_agentic)

            # Clear thinking content when switching models or starting a new operation
            if _state("model_provider") != "Anthropic API" or "thinking" not in _state("selected_model").lower():
                st.session_state.pop("last_thinking_content", None)

            # Show a spinner while suggesting mitigations
            with st.spinner(_t("正在生成缓解措施……", "Suggesting mitigations…")):
                max_retries = 3
                retry_count = 0
                while retry_count < max_retries:
                    try:
                        # Call the relevant get_mitigations function with the generated prompt
                        if _state("model_provider") == "OpenAI API":
                            mitigations_markdown = get_mitigations(
                                _state("openai_api_key"), _state("selected_model"), mitigations_prompt
                            )
                        elif _state("model_provider") == "Google AI API":
                            mitigations_markdown = get_mitigations_google(
                                _state("google_api_key"), _state("selected_model"), mitigations_prompt
                            )
                        elif _state("model_provider") == "Mistral API":
                            mitigations_markdown = get_mitigations_mistral(
                                _state("mistral_api_key"), _state("selected_model"), mitigations_prompt
                            )
                        elif _state("model_provider") == "Anthropic API":
                            mitigations_markdown = get_mitigations_anthropic(
                                _state("anthropic_api_key"), _state("selected_model"), mitigations_prompt
                            )
                        elif _state("model_provider") == "LM Studio Server":
                            mitigations_markdown = get_mitigations_lm_studio(
                                st.session_state["lm_studio_endpoint"],
                                _state("selected_model"),
                                mitigations_prompt,
                                st.session_state.get("lm_studio_api_key", ""),
                            )
                        elif _state("model_provider") == "Groq API":
                            mitigations_markdown = get_mitigations_groq(
                                _state("groq_api_key"), _state("selected_model"), mitigations_prompt
                            )
                        elif _state("model_provider") == "DeepSeek API":
                            mitigations_markdown = get_mitigations_deepseek(
                                _state("deepseek_api_key"), _state("selected_model"), mitigations_prompt
                            )

                        # Display thinking content in an expander if available and using a model with thinking capabilities
                        if (
                            "last_thinking_content" in st.session_state
                            and st.session_state["last_thinking_content"]
                            and (
                                (
                                    _state("model_provider") == "Anthropic API"
                                    and "thinking" in _state("selected_model").lower()
                                )
                                or (
                                    _state("model_provider") == "Google AI API"
                                    and ("gemini-2.5" in _state("selected_model").lower() or "gemini-3" in _state("selected_model").lower())
                                )
                            )
                        ):
                            thinking_model = (
                                "Claude" if _state("model_provider") == "Anthropic API" else "Gemini"
                            )
                            with st.expander(_t(f"查看 {thinking_model} 的思考过程", f"View reasoning of {thinking_model}")):
                                st.markdown(st.session_state["last_thinking_content"])

                        _archive("mitigations", mitigations_markdown)
                        # Display the suggested mitigations in Markdown
                        st.markdown(mitigations_markdown)

                        st.markdown("")

                        # Add a button to allow the user to download the mitigations as a Markdown file
                        st.download_button(
                            label=_t("下载缓解措施", "Download mitigations"),
                            data=mitigations_markdown,
                            file_name="mitigations.md",
                            mime="text/markdown",
                        )

                        break  # Exit the loop if successful
                    except Exception as e:
                        retry_count += 1
                        if retry_count == max_retries:
                            st.error(
                                _t(
                                    _t(
                                f"生成缓解措施失败，已重试 {max_retries} 次：{e}",
                                f"Failed to generate the mitigations after {max_retries} retries: {e}",
                            ),
                                    f"Failed to generate the mitigations after {max_retries} retries: {e}",
                                )
                            )
                            mitigations_markdown = ""
                        else:
                            st.warning(
                                _t(
                                    _t(
                                f"生成缓解措施失败，正在重试第 {retry_count + 1}/{max_retries}...",
                                f"Failed to generate the mitigations; retrying ({retry_count + 1}/{max_retries})...",
                            ),
                                    f"Failed to generate the mitigations; retrying ({retry_count + 1}/{max_retries})...",
                                )
                            )

            st.markdown("")
        else:
            st.error(_t("请先生成威胁模型，再生成缓解措施。", "Generate a threat model before suggesting mitigations."))
