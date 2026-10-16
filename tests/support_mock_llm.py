"""测试辅助：进程内 OpenAI 兼容 Mock LLM。

用于端到端测试（无需外部服务）：按提示词内容返回威胁模型 / DFD / 攻击树 /
DREAD / 缓解措施 / Gherkin 测试用例等固定响应。
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

THREAT_MODEL = {
    "threat_model": [
        {
            "Threat Type": "Spoofing",
            "Scenario": "攻击者伪造会话 Cookie",
            "Potential Impact": "账户接管",
        },
        {
            "Threat Type": "Tampering",
            "Scenario": "篡改订单金额参数",
            "Potential Impact": "资金损失",
        },
        {
            "Threat Type": "Information Disclosure",
            "Scenario": "接口返回未脱敏手机号",
            "Potential Impact": "隐私泄露",
        },
        {
            "Threat Type": "Denial of Service",
            "Scenario": "批量请求打满线程池",
            "Potential Impact": "服务不可用",
        },
    ],
    "improvement_suggestions": ["补充会话轮换策略", "增加参数签名校验"],
}

DREAD = {
    "Risk Assessment": [
        {
            "Threat Type": "Spoofing",
            "Scenario": "攻击者伪造会话 Cookie",
            "Damage Potential": 9,
            "Reproducibility": 8,
            "Exploitability": 7,
            "Affected Users": 6,
            "Discoverability": 5,
        },
        {
            "Threat Type": "Tampering",
            "Scenario": "篡改订单金额参数",
            "Damage Potential": 8,
            "Reproducibility": 7,
            "Exploitability": 6,
            "Affected Users": 5,
            "Discoverability": 8,
        },
    ]
}

DFD = {
    "nodes": [
        {"id": "user", "label": "客户端", "type": "external_entity"},
        {"id": "api", "label": "API 服务", "type": "process"},
    ],
    "edges": [{"from": "user", "to": "api", "label": "登录凭据"}],
    "trust_boundaries": [{"name": "内网", "node_ids": ["api"]}],
}

ATTACK_TREE = {
    "nodes": [
        {
            "id": "root",
            "label": "攻陷应用",
            "children": [
                {"id": "auth", "label": "冒充合法用户", "children": []},
            ],
        }
    ]
}

MITIGATIONS = (
    "| 威胁类型 | 攻击场景 | 建议缓解措施 |\n|---|---|---|\n"
    "| Spoofing | 攻击者伪造会话 Cookie | 会话签名校验 + HttpOnly |\n"
    "| Tampering | 篡改订单金额参数 | 服务端重算金额 + 请求签名 |"
)

TEST_CASES = "```gherkin\nFeature: 会话安全\n  Scenario: 伪造 Cookie\n    Given 攻击者持有旧会话\n    Then 服务端应拒绝\n```"


def classify(text: str) -> str:
    low = text.lower()
    if "risk assessment" in low or "dread" in low:
        return json.dumps(DREAD, ensure_ascii=False)
    if "gherkin" in low:
        return TEST_CASES
    if "trust_boundaries" in low or "external_entity" in low or "data flow diagram" in low:
        return json.dumps(DFD, ensure_ascii=False)
    if "attack tree" in low:
        return json.dumps(ATTACK_TREE, ensure_ascii=False)
    if "improvement_suggestions" in low:
        return json.dumps(THREAT_MODEL, ensure_ascii=False)
    return MITIGATIONS


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        return

    def _json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if "models" in self.path:
            self._json(
                {
                    "object": "list",
                    "data": [
                        {"id": "mock-model", "object": "model", "created": 0, "owned_by": "mock"}
                    ],
                }
            )
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw)
        except ValueError:
            payload = {}
        messages = payload.get("messages") or []
        text = " ".join(
            m.get("content") if isinstance(m.get("content"), str) else "" for m in messages
        )
        self._json(
            {
                "id": "chatcmpl-mock",
                "object": "chat.completion",
                "created": 0,
                "model": payload.get("model", "mock-model"),
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": classify(text)},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 100, "completion_tokens": 100, "total_tokens": 200},
            }
        )


class MockLLM:
    """上下文管理器：启动/停止进程内 mock 服务。"""

    def __init__(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self) -> MockLLM:
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
