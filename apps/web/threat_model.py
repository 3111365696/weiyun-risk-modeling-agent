import streamlit as st
from common import i18n as _i18n
from common.text import json_to_markdown

from stride_gpt.core.prompts import (
    create_agentic_stride_prompt_section,
    create_llm_stride_prompt_section,
    create_threat_model_prompt,
)
from stride_gpt.core.schemas import LLMConfig
from stride_gpt.core.threat_model import analyze_image, generate_threat_model

__all__ = [
    "create_agentic_stride_prompt_section",
    "create_image_analysis_prompt",
    "create_llm_stride_prompt_section",
    "create_threat_model_prompt",
    "get_image_analysis",
    "get_image_analysis_anthropic",
    "get_image_analysis_google",
    "get_threat_model",
    "get_threat_model_anthropic",
    "get_threat_model_deepseek",
    "get_threat_model_google",
    "get_threat_model_groq",
    "get_threat_model_lm_studio",
    "get_threat_model_mistral",
    "json_to_markdown",
]


# Function to convert JSON to Markdown for display.


def create_image_analysis_prompt():
    return """
    You are a Senior Solution Architect tasked with explaining the following architecture diagram to
    a Security Architect to support the threat modelling of the system.

    In order to complete this task you must:

      1. Analyse the diagram
      2. Explain the system architecture to the Security Architect. Your explanation should cover the key
         components, their interactions, and any technologies used.

    Provide a direct explanation of the diagram in a clear, structured format, suitable for a professional
    discussion.

    IMPORTANT INSTRUCTIONS:
     - Do not include any words before or after the explanation itself. For example, do not start your
    explanation with "The image shows..." or "The diagram shows..." just start explaining the key components
    and other relevant details.
     - Do not infer or speculate about information that is not visible in the diagram. Only provide information that can be
    directly determined from the diagram itself.

    IMPORTANT: Write the explanation in Simplified Chinese (简体中文). Keep product
    names, protocol names, and component identifiers in their original form.
    """


# Function to get analyse uploaded architecture diagrams.
def get_image_analysis(api_key, model_name, prompt, base64_image):
    config = LLMConfig(provider="OpenAI API", model_name=model_name, api_key=api_key)
    response = analyze_image(config, base64_image)
    return {"choices": [{"message": {"content": response.content}}]}


# Function to get image analysis using Google Gemini models
def get_image_analysis_google(api_key, model_name, prompt, base64_image):
    config = LLMConfig(provider="Google AI API", model_name=model_name, api_key=api_key)
    response = analyze_image(config, base64_image)
    return {"choices": [{"message": {"content": response.content}}]}


# Function to get image analysis using Anthropic Claude models
def get_image_analysis_anthropic(
    api_key, model_name, prompt, base64_image, media_type="image/jpeg"
):
    config = LLMConfig(provider="Anthropic API", model_name=model_name, api_key=api_key)
    response = analyze_image(config, base64_image, media_type=media_type)
    return {"choices": [{"message": {"content": response.content}}]}


# Function to get threat model from the GPT response.
def get_threat_model(api_key, model_name, prompt):
    config = LLMConfig(provider="OpenAI API", model_name=model_name, api_key=api_key)
    result, _response = generate_threat_model(config, prompt)
    return {"threat_model": result.threat_model, "improvement_suggestions": result.improvement_suggestions}


# Function to get threat model from the Google response.
def get_threat_model_google(google_api_key, google_model, prompt):
    config = LLMConfig(provider="Google AI API", model_name=google_model, api_key=google_api_key)
    result, response = generate_threat_model(config, prompt)
    if response.thinking:
        st.session_state["last_thinking_content"] = response.thinking
    return {"threat_model": result.threat_model, "improvement_suggestions": result.improvement_suggestions}


# Function to get threat model from the Mistral response.
def get_threat_model_mistral(mistral_api_key, mistral_model, prompt):
    config = LLMConfig(provider="Mistral API", model_name=mistral_model, api_key=mistral_api_key)
    result, _response = generate_threat_model(config, prompt)
    return {"threat_model": result.threat_model, "improvement_suggestions": result.improvement_suggestions}


# Function to get threat model from the DeepSeek response.
def get_threat_model_deepseek(deepseek_api_key, deepseek_model, prompt):
    config = LLMConfig(provider="DeepSeek API", model_name=deepseek_model, api_key=deepseek_api_key)
    result, _response = generate_threat_model(config, prompt)
    return {"threat_model": result.threat_model, "improvement_suggestions": result.improvement_suggestions}


# Function to get threat model from the Claude response.
def get_threat_model_anthropic(anthropic_api_key, anthropic_model, prompt):
    config = LLMConfig(
        provider="Anthropic API",
        model_name=anthropic_model,
        api_key=anthropic_api_key,
        use_thinking=st.session_state.get("use_thinking", False),
    )
    result, response = generate_threat_model(config, prompt)
    if response.thinking:
        st.session_state["last_thinking_content"] = response.thinking
    return {"threat_model": result.threat_model, "improvement_suggestions": result.improvement_suggestions}


# Function to get threat model from LM Studio Server response.
def get_threat_model_lm_studio(lm_studio_endpoint, model_name, prompt, api_key="not-needed"):
    config = LLMConfig(
        provider="LM Studio Server",
        model_name=model_name,
        api_key=api_key,
        api_base=lm_studio_endpoint,
    )
    result, _response = generate_threat_model(config, prompt)
    return {"threat_model": result.threat_model, "improvement_suggestions": result.improvement_suggestions}


# Function to get threat model from the Groq response.
def get_threat_model_groq(groq_api_key, groq_model, prompt):
    config = LLMConfig(provider="Groq API", model_name=groq_model, api_key=groq_api_key)
    result, response = generate_threat_model(config, prompt)
    if response.reasoning:
        with st.expander(_i18n.t("查看模型推理过程", "View model reasoning"), expanded=False):
            st.write(response.reasoning)
    return {"threat_model": result.threat_model, "improvement_suggestions": result.improvement_suggestions}
