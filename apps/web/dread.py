import streamlit as st
from common.text import (  # noqa: F401  (re-export 供 main.py 使用)
    create_dread_assessment_prompt,
    dread_json_to_markdown,
)

from stride_gpt.core.dread import generate_dread_assessment
from stride_gpt.core.schemas import LLMConfig


def clean_json_response(response_text):
    import re

    # Remove markdown JSON code block if present
    json_pattern = r"```json\s*(.*?)\s*```"
    match = re.search(json_pattern, response_text, re.DOTALL)
    if match:
        return match.group(1).strip()
    # If no JSON code block, try to find content between any code blocks
    code_pattern = r"```\s*(.*?)\s*```"
    match = re.search(code_pattern, response_text, re.DOTALL)
    if match:
        return match.group(1).strip()
    # If no code blocks, return the original text
    return response_text.strip()


# Function to create a prompt to generate DREAD risk assessment


def get_dread_assessment(api_key, model_name, prompt):
    config = LLMConfig(provider="OpenAI API", model_name=model_name, api_key=api_key)
    parsed, _response = generate_dread_assessment(config, prompt)
    return parsed


# Function to get DREAD risk assessment from the Google model's response.
def get_dread_assessment_google(google_api_key, google_model, prompt):
    config = LLMConfig(provider="Google AI API", model_name=google_model, api_key=google_api_key)
    parsed, response = generate_dread_assessment(config, prompt)
    if response.thinking:
        st.session_state["last_thinking_content"] = response.thinking
    return parsed


# Function to get DREAD risk assessment from the Mistral model's response.
def get_dread_assessment_mistral(mistral_api_key, mistral_model, prompt):
    config = LLMConfig(provider="Mistral API", model_name=mistral_model, api_key=mistral_api_key)
    parsed, _response = generate_dread_assessment(config, prompt)
    return parsed


# Function to get DREAD risk assessment from the DeepSeek model's response.
def get_dread_assessment_deepseek(deepseek_api_key, deepseek_model, prompt):
    config = LLMConfig(provider="DeepSeek API", model_name=deepseek_model, api_key=deepseek_api_key)
    parsed, _response = generate_dread_assessment(config, prompt)
    return parsed


# Function to get DREAD risk assessment from the Anthropic model's response.
def get_dread_assessment_anthropic(anthropic_api_key, anthropic_model, prompt):
    config = LLMConfig(
        provider="Anthropic API",
        model_name=anthropic_model,
        api_key=anthropic_api_key,
        use_thinking=st.session_state.get("use_thinking", False),
    )
    parsed, response = generate_dread_assessment(config, prompt)
    if response.thinking:
        st.session_state["last_thinking_content"] = response.thinking
    return parsed


# Function to get DREAD risk assessment from LM Studio Server response.
def get_dread_assessment_lm_studio(lm_studio_endpoint, model_name, prompt, api_key="not-needed"):
    config = LLMConfig(
        provider="LM Studio Server",
        model_name=model_name,
        api_key=api_key,
        api_base=lm_studio_endpoint,
    )
    parsed, _response = generate_dread_assessment(config, prompt)
    return parsed


# Function to get DREAD risk assessment from the Groq model's response.
def get_dread_assessment_groq(groq_api_key, groq_model, prompt):
    config = LLMConfig(provider="Groq API", model_name=groq_model, api_key=groq_api_key)
    parsed, response = generate_dread_assessment(config, prompt)
    if response.reasoning:
        with st.expander("View model's reasoning process", expanded=False):
            st.write(response.reasoning)
    return parsed
