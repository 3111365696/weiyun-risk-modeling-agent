import streamlit as st
from common import i18n as _i18n
from common.text import create_test_cases_prompt  # noqa: F401  (re-export 供 main.py 使用)

from stride_gpt.core.schemas import LLMConfig
from stride_gpt.core.test_cases import generate_test_cases

# Function to create a prompt to generate test cases


# Function to get test cases from the GPT response.
def get_test_cases(api_key, model_name, prompt):
    config = LLMConfig(provider="OpenAI API", model_name=model_name, api_key=api_key)
    content, _response = generate_test_cases(config, prompt)
    return content


# Function to get test cases from the Google model's response.
def get_test_cases_google(google_api_key, google_model, prompt):
    config = LLMConfig(provider="Google AI API", model_name=google_model, api_key=google_api_key)
    content, response = generate_test_cases(config, prompt)
    if response.thinking:
        st.session_state["last_thinking_content"] = response.thinking
    return content


# Function to get test cases from the Mistral model's response.
def get_test_cases_mistral(mistral_api_key, mistral_model, prompt):
    config = LLMConfig(provider="Mistral API", model_name=mistral_model, api_key=mistral_api_key)
    content, _response = generate_test_cases(config, prompt)
    return content


# Function to get test cases from the DeepSeek model's response.
def get_test_cases_deepseek(deepseek_api_key, deepseek_model, prompt):
    config = LLMConfig(provider="DeepSeek API", model_name=deepseek_model, api_key=deepseek_api_key)
    content, _response = generate_test_cases(config, prompt)
    return content


# Function to get test cases from the Anthropic model's response.
def get_test_cases_anthropic(anthropic_api_key, anthropic_model, prompt):
    config = LLMConfig(
        provider="Anthropic API",
        model_name=anthropic_model,
        api_key=anthropic_api_key,
        use_thinking=st.session_state.get("use_thinking", False),
    )
    content, response = generate_test_cases(config, prompt)
    if response.thinking:
        st.session_state["last_thinking_content"] = response.thinking
    return content


# Function to get test cases from LM Studio Server response.
def get_test_cases_lm_studio(lm_studio_endpoint, model_name, prompt, api_key="not-needed"):
    config = LLMConfig(
        provider="LM Studio Server",
        model_name=model_name,
        api_key=api_key,
        api_base=lm_studio_endpoint,
    )
    content, _response = generate_test_cases(config, prompt)
    return content


# Function to get test cases from the Groq model's response.
def get_test_cases_groq(groq_api_key, groq_model, prompt):
    config = LLMConfig(provider="Groq API", model_name=groq_model, api_key=groq_api_key)
    content, response = generate_test_cases(config, prompt)
    if response.reasoning:
        with st.expander(_i18n.t("查看模型推理过程", "View model reasoning"), expanded=False):
            st.write(response.reasoning)
    return content
