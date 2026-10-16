"""测试用例页面。（P7 从 main.py 拆分）。"""

from __future__ import annotations

import streamlit as st
from services import (
    _archive,
)
from shared import (
    _state,
    _t,
    create_test_cases_prompt,
    get_test_cases,
    get_test_cases_anthropic,
    get_test_cases_deepseek,
    get_test_cases_google,
    get_test_cases_groq,
    get_test_cases_lm_studio,
    get_test_cases_mistral,
    json_to_markdown,
)


def _page_test_cases() -> None:
    st.markdown(
        _t("测试用例用于验证应用的安全性，确保潜在漏洞被发现并修复。此标签页可使用 Gherkin 语法生成测试用例。Gherkin 以 Given-When-Then 的简洁语法，\n用纯文本结构化地描述应用行为，便于编写清晰、可执行的测试场景。", "Test cases validate application security and ensure potential vulnerabilities are found and fixed. This tab generates Gherkin test cases using the Given-When-Then syntax.")
    )
    st.markdown("""---""")

    # Create a submit button for Test Cases
    test_cases_submit_button = st.button(label=_t("生成测试用例", "Generate test cases"))

    # If the Generate Test Cases button is clicked and the user has identified threats
    if test_cases_submit_button:
        # Check if threat_model data exists
        if st.session_state.get("threat_model"):
            # Convert the threat_model data into a Markdown list
            threats_markdown = json_to_markdown(st.session_state["threat_model"], [])
            # Check if this is a GenAI or agentic application
            is_genai = _state("app_type") in ["Generative AI application", "Agentic AI application"]
            is_agentic = _state("app_type") == "Agentic AI application"
            # Generate the prompt using the create_test_cases_prompt function
            test_cases_prompt = create_test_cases_prompt(threats_markdown, is_genai=is_genai, is_agentic=is_agentic)

            # Clear thinking content when switching models or starting a new operation
            if _state("model_provider") != "Anthropic API" or "thinking" not in _state("selected_model").lower():
                st.session_state.pop("last_thinking_content", None)

            # Show a spinner while generating test cases
            with st.spinner(_t("正在生成测试用例……", "Generating test cases…")):
                max_retries = 3
                retry_count = 0
                while retry_count < max_retries:
                    try:
                        # Call to the relevant get_test_cases function with the generated prompt
                        if _state("model_provider") == "OpenAI API":
                            test_cases_markdown = get_test_cases(
                                _state("openai_api_key"), _state("selected_model"), test_cases_prompt
                            )
                        elif _state("model_provider") == "Google AI API":
                            test_cases_markdown = get_test_cases_google(
                                _state("google_api_key"), _state("selected_model"), test_cases_prompt
                            )
                        elif _state("model_provider") == "Mistral API":
                            test_cases_markdown = get_test_cases_mistral(
                                _state("mistral_api_key"), _state("selected_model"), test_cases_prompt
                            )
                        elif _state("model_provider") == "Anthropic API":
                            test_cases_markdown = get_test_cases_anthropic(
                                _state("anthropic_api_key"), _state("selected_model"), test_cases_prompt
                            )
                        elif _state("model_provider") == "LM Studio Server":
                            test_cases_markdown = get_test_cases_lm_studio(
                                st.session_state["lm_studio_endpoint"],
                                _state("selected_model"),
                                test_cases_prompt,
                                st.session_state.get("lm_studio_api_key", ""),
                            )
                        elif _state("model_provider") == "Groq API":
                            test_cases_markdown = get_test_cases_groq(
                                _state("groq_api_key"), _state("selected_model"), test_cases_prompt
                            )
                        elif _state("model_provider") == "DeepSeek API":
                            test_cases_markdown = get_test_cases_deepseek(
                                _state("deepseek_api_key"), _state("selected_model"), test_cases_prompt
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
                            with st.expander(f"查看 {thinking_model} 的思考过程"):
                                st.markdown(st.session_state["last_thinking_content"])

                        _archive("test_cases", test_cases_markdown)
                        # Display the suggested mitigations in Markdown
                        st.markdown(test_cases_markdown)

                        st.markdown("")

                        # Add a button to allow the user to download the test cases as a Markdown file
                        st.download_button(
                            label=_t("下载测试用例", "Download test cases"),
                            data=test_cases_markdown,
                            file_name="test_cases.md",
                            mime="text/markdown",
                        )

                        break  # Exit the loop if successful
                    except Exception as e:
                        retry_count += 1
                        if retry_count == max_retries:
                            st.error(
                                f"生成测试用例失败，已重试 {max_retries} 次：{e}"
                            )
                            test_cases_markdown = ""
                        else:
                            st.warning(
                                f"生成测试用例失败，正在重试第 {retry_count + 1}/{max_retries}..."
                            )

            st.markdown("")

        else:
            st.error(_t("请先生成威胁模型，再请求测试用例。", "Generate a threat model before requesting test cases."))
