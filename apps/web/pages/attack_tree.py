"""攻击树页面。（P7 从 main.py 拆分）。"""

from __future__ import annotations

import streamlit as st
from services import (
    _archive,
)
from shared import (
    _state,
    _t,
    create_attack_tree_prompt,
    get_attack_tree,
    get_attack_tree_anthropic,
    get_attack_tree_deepseek,
    get_attack_tree_google,
    get_attack_tree_groq,
    get_attack_tree_lm_studio,
    get_attack_tree_mistral,
)
from widgets import (
    mermaid,
)


def _page_attack_tree() -> None:
    st.markdown(
        _t("攻击树是一种结构化的系统安全分析方法，以层级形式表示潜在攻击场景：树根是攻击者的最终目标，各分支是达成目标的不同路径。这有助于理解系统漏洞并确定缓解措施的优先级。", "Attack trees structure potential attack scenarios hierarchically: the root is the attacker's goal, and branches are alternative paths. They help understand vulnerabilities and prioritize mitigations.")
    )
    st.markdown("""---""")
    if _state("model_provider") == "Mistral API" and _state("selected_model") == "mistral-small-2506":
        st.warning(
            _t("Mistral Small 生成的 Mermaid 代码语法不一定正确。请使用 Mistral Large 生成攻击树，或选择其他模型提供商。", "Mistral Small may generate syntactically incorrect Mermaid. Use Mistral Large, or choose another provider.")
        )
    else:
        if _state("model_provider") == "LM Studio Server":
            st.warning(
                _t("使用本地 LLM 生成攻击树时可能出现语法错误。可以尝试不同的本地 LLM 以评估输出质量，或考虑使用云端模型提供商。", "Local LLMs may produce syntax errors in attack trees. Try different local models, or use a hosted provider.")
            )

        # Create a submit button for Attack Tree
        attack_tree_submit_button = st.button(label=_t("生成攻击树", "Generate attack tree"))

        # If the Generate Attack Tree button is clicked and the user has provided an application description
        if attack_tree_submit_button and st.session_state.get("app_input"):

            # Generate the prompt using the create_attack_tree_prompt function.
            # When a DFD has been confirmed on the Data Flow Diagram tab it
            # is appended so the attack paths reference the same components.
            attack_tree_prompt = create_attack_tree_prompt(
                _state("app_type"),
                _state("authentication"),
                _state("internet_facing"),
                _state("sensitive_data"),
                _state("app_input"),
                confirmed_dfd=st.session_state.get("confirmed_dfd"),
            )

            # Clear thinking content when switching models or starting a new operation
            if _state("model_provider") != "Anthropic API" or "thinking" not in _state("selected_model").lower():
                st.session_state.pop("last_thinking_content", None)

            # Show a spinner while generating the attack tree
            with st.spinner(_t("正在生成攻击树……", "Generating attack tree…")):
                try:
                    # Call the relevant get_attack_tree function with the generated prompt
                    if _state("model_provider") == "OpenAI API":
                        mermaid_code = get_attack_tree(
                            _state("openai_api_key"), _state("selected_model"), attack_tree_prompt
                        )
                    elif _state("model_provider") == "Google AI API":
                        mermaid_code = get_attack_tree_google(
                            _state("google_api_key"), _state("selected_model"), attack_tree_prompt
                        )
                    elif _state("model_provider") == "Mistral API":
                        mermaid_code = get_attack_tree_mistral(
                            _state("mistral_api_key"), _state("selected_model"), attack_tree_prompt
                        )
                    elif _state("model_provider") == "Anthropic API":
                        mermaid_code = get_attack_tree_anthropic(
                            _state("anthropic_api_key"), _state("selected_model"), attack_tree_prompt
                        )
                    elif _state("model_provider") == "LM Studio Server":
                        mermaid_code = get_attack_tree_lm_studio(
                            st.session_state["lm_studio_endpoint"],
                            _state("selected_model"),
                            attack_tree_prompt,
                            st.session_state.get("lm_studio_api_key", ""),
                        )
                    elif _state("model_provider") == "Groq API":
                        mermaid_code = get_attack_tree_groq(
                            _state("groq_api_key"), _state("selected_model"), attack_tree_prompt
                        )
                    elif _state("model_provider") == "DeepSeek API":
                        mermaid_code = get_attack_tree_deepseek(
                            _state("deepseek_api_key"), _state("selected_model"), attack_tree_prompt
                        )

                    # Display thinking content in an expander if available
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
                        thinking_model = "Claude" if _state("model_provider") == "Anthropic API" else "Gemini"
                        with st.expander(_t(f"查看 {thinking_model} 的思考过程", f"View reasoning of {thinking_model}")):
                            st.markdown(st.session_state["last_thinking_content"])

                    _archive("attack_tree", mermaid_code)
                    # Display the generated attack tree code
                    st.write(_t("攻击树代码：", "Attack tree code:"))
                    st.code(mermaid_code)

                    # Visualise the attack tree using the Mermaid custom component
                    st.write(_t("攻击树图预览：", "Attack tree preview:"))
                    mermaid(mermaid_code)

                    col1, col2, col3, col4, col5 = st.columns([1, 1, 1, 1, 1])

                    with col1:
                        # Add a button to allow the user to download the Mermaid code
                        st.download_button(
                            label=_t("下载图表代码", "Download diagram code"),
                            data=mermaid_code,
                            file_name="attack_tree.md",
                            mime="text/plain",
                            help=_t("下载攻击树的 Mermaid 代码。", "Download the Mermaid code for this attack tree."),
                        )

                    with col2:
                        # Add a button to allow the user to open the Mermaid Live editor
                        # Not assigned: a link button has no return value
                        # worth reading, it just renders.
                        st.link_button(_t("在 Mermaid Live 中打开", "Open in Mermaid Live"), "https://mermaid.live")

                    with col3:
                        # Blank placeholder
                        st.write("")

                    with col4:
                        # Blank placeholder
                        st.write("")

                    with col5:
                        # Blank placeholder
                        st.write("")

                except Exception as e:
                    st.error(_t(f"生成攻击树失败：{e}", f"Failed to generate attack tree: {e}"))
