import re

import streamlit as st
from common import i18n as _i18n
from common.text import create_attack_tree_prompt  # noqa: F401  (re-export 供 main.py 使用)

from stride_gpt.core.attack_tree import generate_attack_tree
from stride_gpt.core.schemas import LLMConfig

# Function to create a prompt to generate an attack tree


def convert_tree_to_mermaid(tree_data):
    """
    Convert structured tree data to Mermaid syntax.

    Args:
        tree_data (dict): Dictionary containing the tree structure

    Returns:
        str: Mermaid diagram code
    """
    mermaid_lines = ["graph TD"]

    def process_node(node, parent_id=None):
        node_id = node["id"]
        node_label = node["label"]

        # Add quotes if label contains spaces or parentheses
        if " " in node_label or "(" in node_label or ")" in node_label:
            node_label = f'"{node_label}"'

        # Add the node definition
        mermaid_lines.append(f"    {node_id}[{node_label}]")

        # Add connection to parent if exists
        if parent_id:
            mermaid_lines.append(f"    {parent_id} --> {node_id}")

        # Process children
        if "children" in node:
            for child in node["children"]:
                process_node(child, node_id)

    # Process the root node(s)
    for root_node in tree_data["nodes"]:
        process_node(root_node)

    # Join lines with newlines
    return "\n".join(mermaid_lines)


def create_json_structure_prompt():
    """
    Creates a prompt for generating attack tree data in JSON format.
    """
    return """Your task is to analyze the application and create an attack tree structure in JSON format.

The JSON structure should follow this format:
{
    "nodes": [
        {
            "id": "root",
            "label": "Compromise Application",
            "children": [
                {
                    "id": "auth",
                    "label": "Gain Unauthorized Access",
                    "children": [
                        {
                            "id": "auth1",
                            "label": "Exploit OAuth2 Vulnerabilities"
                        }
                    ]
                }
            ]
        }
    ]
}

Rules:
- Use simple IDs (root, auth, auth1, data, etc.)
- Make labels clear and descriptive
- Include all attack paths and sub-paths
- Maintain proper parent-child relationships
- Ensure the JSON is properly formatted

ONLY RESPOND WITH THE JSON STRUCTURE, NO ADDITIONAL TEXT."""


def clean_json_response(response_text):
    """
    Clean JSON response by removing any markdown code block markers and finding the JSON content.

    Args:
        response_text (str): The raw response text that might contain JSON

    Returns:
        str: Cleaned JSON string
    """
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


def create_attack_tree_schema():
    """
    Creates a JSON schema for attack tree structure.
    """
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "attack_tree",
            "description": "A structured representation of an attack tree",
            "schema": {
                "type": "object",
                "properties": {"nodes": {"type": "array", "items": {"$ref": "#/$defs/node"}}},
                "$defs": {
                    "node": {
                        "type": "object",
                        "properties": {
                            "id": {
                                "type": "string",
                                "description": "Simple alphanumeric identifier for the node",
                            },
                            "label": {
                                "type": "string",
                                "description": "Description of the attack vector or goal",
                            },
                            "children": {"type": "array", "items": {"$ref": "#/$defs/node"}},
                        },
                        "required": ["id", "label", "children"],
                        "additionalProperties": False,
                    }
                },
                "required": ["nodes"],
                "additionalProperties": False,
            },
            "strict": True,
        },
    }


def create_attack_tree_schema_lm_studio():
    """
    Creates a non-recursive JSON schema for attack tree structure specifically for LM Studio.
    Limits the depth to 3 levels to avoid circular references.
    """
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "attack_tree",
            "description": "A structured representation of an attack tree",
            "schema": {
                "type": "object",
                "properties": {
                    "nodes": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": {
                                    "type": "string",
                                    "description": "Simple alphanumeric identifier for the root node",
                                },
                                "label": {
                                    "type": "string",
                                    "description": "Description of the attack vector or goal",
                                },
                                "children": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "id": {
                                                "type": "string",
                                                "description": "Simple alphanumeric identifier for the level 1 node",
                                            },
                                            "label": {
                                                "type": "string",
                                                "description": "Description of the attack vector or goal",
                                            },
                                            "children": {
                                                "type": "array",
                                                "items": {
                                                    "type": "object",
                                                    "properties": {
                                                        "id": {
                                                            "type": "string",
                                                            "description": "Simple alphanumeric identifier for the leaf node",
                                                        },
                                                        "label": {
                                                            "type": "string",
                                                            "description": "Description of the attack vector or goal",
                                                        },
                                                        "children": {
                                                            "type": "array",
                                                            "items": {},
                                                            "default": [],
                                                        },
                                                    },
                                                    "required": ["id", "label", "children"],
                                                    "additionalProperties": False,
                                                },
                                            },
                                        },
                                        "required": ["id", "label", "children"],
                                        "additionalProperties": False,
                                    },
                                },
                            },
                            "required": ["id", "label", "children"],
                            "additionalProperties": False,
                        },
                    }
                },
                "required": ["nodes"],
                "additionalProperties": False,
            },
            "strict": True,
        },
    }


# Function to get attack tree from the GPT response.
def get_attack_tree(api_key, model_name, prompt):
    config = LLMConfig(provider="OpenAI API", model_name=model_name, api_key=api_key)
    mermaid, _response = generate_attack_tree(config, prompt)
    return mermaid


# Function to get attack tree from the Mistral model's response.
def get_attack_tree_mistral(mistral_api_key, mistral_model, prompt):
    config = LLMConfig(provider="Mistral API", model_name=mistral_model, api_key=mistral_api_key)
    mermaid, _response = generate_attack_tree(config, prompt)
    return mermaid


# Function to get attack tree from the DeepSeek model's response.
def get_attack_tree_deepseek(deepseek_api_key, deepseek_model, prompt):
    config = LLMConfig(provider="DeepSeek API", model_name=deepseek_model, api_key=deepseek_api_key)
    mermaid, _response = generate_attack_tree(config, prompt)
    return mermaid


# Function to get attack tree from Anthropic's Claude model.
def get_attack_tree_anthropic(anthropic_api_key, anthropic_model, prompt):
    config = LLMConfig(
        provider="Anthropic API",
        model_name=anthropic_model,
        api_key=anthropic_api_key,
        use_thinking=st.session_state.get("use_thinking", False),
    )
    mermaid, response = generate_attack_tree(config, prompt)
    if response.thinking:
        st.session_state["last_thinking_content"] = response.thinking
    return mermaid


# Function to get attack tree from LM Studio Server response.
def get_attack_tree_lm_studio(lm_studio_endpoint, model_name, prompt, api_key="not-needed"):
    config = LLMConfig(
        provider="LM Studio Server",
        model_name=model_name,
        api_key=api_key,
        api_base=lm_studio_endpoint,
    )
    mermaid, _response = generate_attack_tree(config, prompt)
    return mermaid


# Function to get attack tree from the Groq model's response.
def get_attack_tree_groq(groq_api_key, groq_model, prompt):
    config = LLMConfig(provider="Groq API", model_name=groq_model, api_key=groq_api_key)
    mermaid, response = generate_attack_tree(config, prompt)
    if response.reasoning:
        with st.expander(_i18n.t("查看模型推理过程", "View model reasoning"), expanded=False):
            st.write(response.reasoning)
    return mermaid


# Function to get attack tree from the Google model's response.
def get_attack_tree_google(google_api_key, google_model, prompt):
    config = LLMConfig(provider="Google AI API", model_name=google_model, api_key=google_api_key)
    mermaid, response = generate_attack_tree(config, prompt)
    if response.thinking:
        st.session_state["last_thinking_content"] = response.thinking
    return mermaid
