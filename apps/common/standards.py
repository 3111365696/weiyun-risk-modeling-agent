"""标准映射与导出：CWE 编号映射、STIX 2.1 导出。

- 威胁自动关联 CWE（先按关键词精确匹配，再回退到 STRIDE 类别的默认项）
- STIX 2.1 bundle：identity（本系统）+ 每条威胁一个 vulnerability + report 聚合，
  带 CWE 外部引用，便于导入威胁情报平台
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

TOOL_NAME = "威云-风险建模智能体"
_TOOL_VERSION = "0.20.0"

# STRIDE 类别 → 默认 CWE（回退用）
_STRIDE_CWE: dict[str, list[str]] = {
    "Spoofing": ["CWE-287"],  # Improper Authentication
    "Tampering": ["CWE-345"],  # Insufficient Verification of Data Authenticity
    "Repudiation": ["CWE-778"],  # Insufficient Logging
    "Information Disclosure": ["CWE-200"],  # Exposure of Sensitive Information
    "Denial of Service": ["CWE-400"],  # Uncontrolled Resource Consumption
    "Elevation of Privilege": ["CWE-269"],  # Improper Privilege Management
}

# 关键词 → 精确 CWE（按顺序匹配，命中即用）
_KEYWORD_CWE: list[tuple[tuple[str, ...], str]] = [
    (("sql", "结构化查询"), "CWE-89"),
    (("xss", "跨站脚本", "innerhtml", "dangerouslysetinnerhtml"), "CWE-79"),
    (
        ("命令注入", "shell=true", "os.system", "subprocess", "rce", "远程代码执行", "命令执行"),
        "CWE-78",
    ),
    (("反序列化", "pickle", "deserial", "unserialize"), "CWE-502"),
    (("路径穿越", "path traversal", "目录穿越", "../"), "CWE-22"),
    (("硬编码", "hardcoded", "明文口令", "明文密码", "写死在代码"), "CWE-798"),
    (("jwt", "令牌", "签名校验", "签名验证"), "CWE-347"),
    (("ssrf", "服务端请求伪造"), "CWE-918"),
    (("csrf", "跨站请求伪造"), "CWE-352"),
    (("越权", "权限提升", "role", "rbac", "authorization", "授权", "鉴权", "管理员接口"), "CWE-862"),
    (("日志", "审计缺失", "无法追责"), "CWE-532"),
    (("弱哈希", "md5", "sha1", "加密算法", "明文传输", "tls", "证书校验"), "CWE-327"),
    (("拒绝服务", "dos", "资源耗尽", "无限", "打满", "速率限制"), "CWE-770"),
    (("上传", "upload"), "CWE-434"),
    (("cors", "跨域"), "CWE-942"),
    (("脱敏", "敏感信息", "pii", "个人信息", "隐私"), "CWE-200"),
    (("注入", "injection"), "CWE-74"),
]

_CWE_NAMES: dict[str, str] = {
    "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory",
    "CWE-74": "Improper Neutralization of Special Elements in Output",
    "CWE-78": "Improper Neutralization of Special Elements used in an OS Command",
    "CWE-79": "Improper Neutralization of Input During Web Page Generation (XSS)",
    "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command",
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-269": "Improper Privilege Management",
    "CWE-287": "Improper Authentication",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-345": "Insufficient Verification of Data Authenticity",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-532": "Insertion of Sensitive Information into Log File",
    "CWE-778": "Insufficient Logging",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-862": "Missing Authorization",
    "CWE-918": "Server-Side Request Forgery",
    "CWE-942": "Permissive Cross-domain Policy with Untrusted Domains",
}


def cwe_name(cwe_id: str) -> str:
    return _CWE_NAMES.get(cwe_id, cwe_id)


def cwe_url(cwe_id: str) -> str:
    return f"https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[-1]}.html"


def cwe_for(threat_type: str, scenario: str = "", impact: str = "") -> list[str]:
    """为一条威胁推断 CWE 编号（关键词优先，STRIDE 类别兜底）。"""
    text = f"{threat_type} {scenario} {impact}".lower()
    hits: list[str] = []
    for keywords, cwe_id in _KEYWORD_CWE:
        if any(keyword in text for keyword in keywords) and cwe_id not in hits:
            hits.append(cwe_id)
    if not hits:
        hits = list(_STRIDE_CWE.get(threat_type.strip(), []))
    return hits[:3]


def annotate_threats(threats: list[dict]) -> list[dict]:
    """给威胁列表补上 CWE 字段（原地返回新列表，不修改入参）。"""
    out = []
    for threat in threats or []:
        ttype = str(threat.get("Threat Type") or threat.get("threat_type") or "")
        scenario = str(threat.get("Scenario") or threat.get("scenario") or "")
        impact = str(threat.get("Potential Impact") or threat.get("impact") or "")
        existing = threat.get("CWE") or threat.get("cwe")
        if existing:
            out.append(dict(threat))
            continue
        out.append({**threat, "CWE": cwe_for(ttype, scenario, impact)})
    return out


def threat_cwe(threat: dict) -> list[str]:
    """从已注解或原始威胁里取 CWE 列表。"""
    value = threat.get("CWE") or threat.get("cwe")
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str) and value.strip():
        return [part.strip() for part in value.split(",") if part.strip()]
    ttype = str(threat.get("Threat Type") or threat.get("threat_type") or "")
    scenario = str(threat.get("Scenario") or threat.get("scenario") or "")
    impact = str(threat.get("Potential Impact") or threat.get("impact") or "")
    return cwe_for(ttype, scenario, impact)


def _stix_id(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(uuid.NAMESPACE_URL, key)}"


def threats_to_stix(
    threats: list[dict],
    *,
    project: str,
    description: str = "",
    tool_version: str = _TOOL_VERSION,
) -> dict:
    """把威胁列表导出为 STIX 2.1 bundle。"""
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    identity_id = _stix_id("identity", TOOL_NAME)
    objects: list[dict] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": TOOL_NAME,
            "identity_class": "system",
            "description": f"版本 {tool_version}",
        }
    ]
    refs: list[str] = []
    for threat in threats or []:
        scenario = str(threat.get("Scenario") or threat.get("scenario") or "").strip()
        if not scenario:
            continue
        ttype = str(threat.get("Threat Type") or threat.get("threat_type") or "")
        impact = str(threat.get("Potential Impact") or threat.get("impact") or "").strip()
        cwes = threat_cwe(threat)
        vuln_id = _stix_id("vulnerability", f"{project}:{ttype}:{scenario}")
        vuln = {
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": vuln_id,
            "created": now,
            "modified": now,
            "created_by_ref": identity_id,
            "name": scenario[:120],
            "description": impact or scenario,
            "labels": [label for label in [ttype, str(threat.get("status") or "")] if label],
            "external_references": [
                {
                    "source_name": "cwe",
                    "external_id": cwe_id,
                    "description": cwe_name(cwe_id),
                    "url": cwe_url(cwe_id),
                }
                for cwe_id in cwes
            ]
            + (
                [
                    {
                        "source_name": "mitre-attack",
                        "external_id": str(threat.get("MITRE_ATTACK") or threat.get("mitre") or ""),
                    }
                ]
                if (threat.get("MITRE_ATTACK") or threat.get("mitre"))
                else []
            ),
        }
        objects.append(vuln)
        refs.append(vuln_id)

    report_id = _stix_id("report", f"{project}:{now[:10]}:{len(refs)}")
    objects.append(
        {
            "type": "report",
            "spec_version": "2.1",
            "id": report_id,
            "created": now,
            "modified": now,
            "created_by_ref": identity_id,
            "name": f"{project} · STRIDE 威胁模型",
            "description": (description or "")[:1000],
            "published": now,
            "report_types": ["threat-report"],
            "object_refs": refs,
        }
    )
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": objects,
    }
