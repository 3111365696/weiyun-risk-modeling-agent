"""与开源威胁建模工具的模型互通（当前：OWASP Threat Dragon）。

- 导出：把我们的威胁导出为 Threat Dragon v2 模型 JSON（可在 Threat Dragon 里继续编辑、分配负责人）
- 导入：解析 Threat Dragon JSON，生成结构化描述文本，作为分析输入（威胁模型 / 代码审计均可）
"""

from __future__ import annotations

from datetime import datetime

_SEVERITY_TO_TD = {"high": "High", "medium": "Medium", "low": "Low"}


def _severity(threat: dict) -> str:
    """由 DREAD 分数或验证置信度推断 Threat Dragon 严重度。"""
    score = threat.get("risk_score")
    if isinstance(score, (int, float)):
        if score >= 7:
            return "High"
        if score >= 4:
            return "Medium"
        return "Low"
    verdict = str(threat.get("verdict") or "")
    if verdict == "已确认":
        return "High"
    if verdict == "存疑":
        return "Medium"
    if verdict == "已驳回":
        return "Low"
    return "Medium"


def to_threat_dragon(
    project: str, threats: list[dict], *, description: str = ""
) -> dict:
    """导出为 Threat Dragon v2 模型（threats 位于模型级，图内元素留空）。"""
    td_threats = []
    for index, threat in enumerate(threats or [], 1):
        scenario = str(threat.get("Scenario") or threat.get("scenario") or "").strip()
        if not scenario:
            continue
        ttype = str(threat.get("Threat Type") or threat.get("threat_type") or "Spoofing")
        impact = str(threat.get("Potential Impact") or threat.get("impact") or "").strip()
        cwe = threat.get("cwe") or ""
        td_threats.append(
            {
                "id": index,
                "title": scenario[:200],
                "description": impact or scenario,
                "status": "Open",
                "severity": _severity(threat),
                "type": ttype,
                "modelType": "STRIDE",
                "mitigation": "",
                "cwe": cwe,
                "references": "",
                "score": "",
            }
        )
    return {
        "version": "2.0.0",
        "summary": {
            "title": project or "未命名系统",
            "owner": "",
            "description": description or "",
            "id": 0,
        },
        "detail": {
            "contributors": [],
            "diagrams": [
                {
                    "id": 0,
                    "title": project or "未命名系统",
                    "diagramType": "STRIDE",
                    "placeholder": "在此绘制数据流图（由威云-风险建模智能体导出）",
                    "thumbnail": "",
                    "version": "2.0.0",
                    "cells": [],
                    "boundaries": [],
                }
            ],
            "diagramTop": 1,
            "reviewer": "威云-风险建模智能体",
            "threatTop": len(td_threats),
        },
        "threats": td_threats,
    }


def from_threat_dragon(data: dict) -> str:
    """解析 Threat Dragon 模型，生成可读的结构化描述（供分析使用）。"""
    if not isinstance(data, dict):
        raise ValueError("不是有效的 Threat Dragon 模型 JSON")
    summary = data.get("summary") or {}
    detail = data.get("detail") or {}
    if not summary and not detail and not data.get("threats"):
        raise ValueError("不是有效的 Threat Dragon 模型 JSON")

    lines = ["## 外部导入的应用模型（OWASP Threat Dragon）", ""]
    title = str(summary.get("title") or "").strip()
    if title:
        lines += [f"**系统名称**：{title}", ""]
    desc = str(summary.get("description") or "").strip()
    if desc:
        lines += [f"**原有描述**：{desc}", ""]

    # 图内元素（组件/边界）名称
    names: list[str] = []
    boundaries: list[str] = []
    for diagram in detail.get("diagrams") or []:
        for cell in diagram.get("cells") or []:
            label = str(cell.get("data", {}).get("name") or cell.get("data", {}).get("label") or "").strip()
            if label and label not in names:
                names.append(label)
        for boundary in diagram.get("boundaries") or []:
            label = str(boundary.get("name") or boundary.get("label") or "").strip()
            if label and label not in boundaries:
                boundaries.append(label)
    if names:
        lines += ["**图中的组件/实体**：" + "、".join(names[:60]), ""]
    if boundaries:
        lines += ["**信任边界**：" + "、".join(boundaries[:20]), ""]

    threats = data.get("threats") or []
    if threats:
        lines += [f"**已有威胁（{len(threats)} 条，作为基线，请识别遗漏项）**：", ""]
        for threat in threats[:40]:
            ttype = str(threat.get("type") or "").strip()
            title_text = str(threat.get("title") or "").strip()
            severity = str(threat.get("severity") or "").strip()
            cwe = str(threat.get("cwe") or "").strip()
            suffix = " · ".join(x for x in [ttype, severity, cwe] if x)
            lines.append(f"- {title_text}" + (f"（{suffix}）" if suffix else ""))
    lines += ["", f"_导入时间：{datetime.now().strftime('%Y-%m-%d %H:%M')}_"]
    return "\n".join(lines)
