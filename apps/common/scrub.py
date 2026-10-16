"""发送给模型前的敏感信息脱敏。

用于避免把应用描述/代码片段中的密钥、令牌、私钥原样传给第三方模型。
默认开启，可在「系统配置 → 分析参数」中关闭。
"""

from __future__ import annotations

import re

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("OpenAI Key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}")),
    ("Anthropic Key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{10,}")),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}")),
    ("AWS Access Key", re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_\-]{20,}")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("Bearer Token", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{20,}")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}")),
    (
        "Private Key",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"),
    ),
    (
        "Credential Assignment",
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token)\b"
            r"\s*[:=]\s*[\"']?[A-Za-z0-9_\-./+=]{8,}[\"']?"
        ),
    ),
]


def scrub_text(text: str) -> tuple[str, list[str]]:
    """返回 (脱敏后的文本, 命中的敏感类型列表)。"""
    if not text:
        return text, []
    hits: list[str] = []
    redacted = text
    for label, pattern in _PATTERNS:
        def _replace(match: re.Match[str], label: str = label) -> str:
            hits.append(label)
            return f"[已脱敏:{label}]"

        redacted = pattern.sub(_replace, redacted)
    return redacted, hits
