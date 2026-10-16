"""C/A 阶段测试：CWE 标准映射、STIX 2.1 导出、Threat Dragon 互通。"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from typing import ClassVar

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "apps"))

from common import interop, standards


class TestCweMapping:
    @pytest.mark.parametrize(
        ("threat_type", "scenario", "expected"),
        [
            ("Tampering", "SQL 语句直接拼接用户输入", "CWE-89"),
            ("Tampering", "页面直接输出未转义内容导致 XSS", "CWE-79"),
            ("Elevation of Privilege", "命令注入：shell 拼接外部参数", "CWE-78"),
            ("Tampering", "pickle 反序列化不可信数据", "CWE-502"),
            ("Information Disclosure", "路径穿越读取任意文件", "CWE-22"),
            ("Spoofing", "硬编码密钥写死在配置文件", "CWE-798"),
            ("Spoofing", "JWT 签名校验被关闭", "CWE-347"),
            ("Information Disclosure", "日志打印明文密码", "CWE-532"),
        ],
    )
    def test_keyword_rules(self, threat_type, scenario, expected):
        assert expected in standards.cwe_for(threat_type, scenario)

    @pytest.mark.parametrize(
        ("threat_type", "expected"),
        [
            ("Spoofing", "CWE-287"),
            ("Tampering", "CWE-345"),
            ("Repudiation", "CWE-778"),
            ("Information Disclosure", "CWE-200"),
            ("Denial of Service", "CWE-400"),
            ("Elevation of Privilege", "CWE-269"),
        ],
    )
    def test_stride_fallback(self, threat_type, expected):
        assert standards.cwe_for(threat_type, "常规描述") == [expected]

    def test_unknown_type_returns_empty(self):
        assert standards.cwe_for("Unknown", "无关键词") == []

    def test_at_most_three(self):
        result = standards.cwe_for(
            "Tampering", "SQL 注入 + XSS + 命令注入 + 反序列化 + 路径穿越"
        )
        assert len(result) == 3

    def test_names_and_urls(self):
        assert "SQL" in standards.cwe_name("CWE-89")
        assert standards.cwe_url("CWE-89").endswith("/89.html")

    def test_annotate_does_not_mutate_input(self):
        original = [{"Threat Type": "Spoofing", "Scenario": "伪造令牌"}]
        annotated = standards.annotate_threats(original)
        assert "CWE" not in original[0]
        assert annotated[0]["CWE"] == ["CWE-347"]

    def test_annotate_keeps_existing(self):
        annotated = standards.annotate_threats(
            [{"Threat Type": "Spoofing", "Scenario": "x", "CWE": ["CWE-999"]}]
        )
        assert annotated[0]["CWE"] == ["CWE-999"]

    def test_threat_cwe_parses_strings(self):
        assert standards.threat_cwe({"cwe": "CWE-89, CWE-79"}) == ["CWE-89", "CWE-79"]
        assert standards.threat_cwe({"cwe": ["CWE-22"]}) == ["CWE-22"]


class TestStix:
    THREATS: ClassVar[list[dict]] = [
        {
            "Threat Type": "Spoofing",
            "Scenario": "伪造 JWT 令牌",
            "Potential Impact": "账户接管",
            "MITRE_ATTACK": "T1550.001",
        },
        {"Threat Type": "Denial of Service", "Scenario": "未做限流的批量接口"},
        {"Scenario": ""},  # 空场景应跳过
    ]

    def test_bundle_structure(self):
        bundle = standards.threats_to_stix(self.THREATS, project="支付系统", description="说明")
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"
        types = [obj["type"] for obj in bundle["objects"]]
        assert types.count("identity") == 1
        assert types.count("vulnerability") == 2
        assert types.count("report") == 1

    def test_vulnerability_external_references(self):
        bundle = standards.threats_to_stix(self.THREATS, project="支付系统")
        vuln = next(o for o in bundle["objects"] if o["type"] == "vulnerability")
        refs = {r["source_name"]: r["external_id"] for r in vuln["external_references"]}
        assert refs["cwe"].startswith("CWE-")
        assert refs["mitre-attack"] == "T1550.001"

    def test_report_references_all_vulnerabilities(self):
        bundle = standards.threats_to_stix(self.THREATS, project="支付系统")
        report = next(o for o in bundle["objects"] if o["type"] == "report")
        vulns = [o["id"] for o in bundle["objects"] if o["type"] == "vulnerability"]
        assert report["object_refs"] == vulns
        assert report["report_types"] == ["threat-report"]

    def test_ids_are_deterministic(self):
        first = standards.threats_to_stix(self.THREATS, project="支付系统")
        second = standards.threats_to_stix(self.THREATS, project="支付系统")
        assert first["objects"][1]["id"] == second["objects"][1]["id"]
        assert first["id"] != second["id"]  # bundle 每次唯一

    def test_empty_threats(self):
        bundle = standards.threats_to_stix([], project="空")
        assert [o["type"] for o in bundle["objects"]] == ["identity", "report"]


class TestThreatDragon:
    THREATS: ClassVar[list[dict]] = [
        {"Scenario": "越权访问订单", "Threat Type": "Elevation of Privilege", "cwe": "CWE-862"},
        {
            "Scenario": "订单号可枚举",
            "Threat Type": "Information Disclosure",
            "risk_score": 8,
        },
    ]

    def test_export_shape(self):
        model = interop.to_threat_dragon("订单系统", self.THREATS, description="描述")
        assert model["version"] == "2.0.0"
        assert model["summary"]["title"] == "订单系统"
        assert model["detail"]["threatTop"] == 2
        assert len(model["detail"]["diagrams"]) == 1
        assert [t["title"] for t in model["threats"]] == ["越权访问订单", "订单号可枚举"]

    def test_export_severity_mapping(self):
        model = interop.to_threat_dragon("订单系统", self.THREATS)
        assert model["threats"][0]["severity"] == "Medium"
        assert model["threats"][1]["severity"] == "High"  # risk_score 8
        assert model["threats"][0]["modelType"] == "STRIDE"
        assert model["threats"][0]["status"] == "Open"

    def test_export_skips_empty_scenarios(self):
        model = interop.to_threat_dragon("x", [{"Scenario": ""}, {"Scenario": "ok"}])
        assert len(model["threats"]) == 1

    def test_roundtrip_import(self):
        model = interop.to_threat_dragon("订单系统", self.THREATS, description="订单服务")
        text = interop.from_threat_dragon(model)
        assert "订单系统" in text
        assert "越权访问订单" in text
        assert "CWE-862" in text

    def test_import_reads_cells_and_boundaries(self):
        model = {
            "summary": {"title": "网银", "description": "对外网银系统"},
            "detail": {
                "diagrams": [
                    {
                        "cells": [{"data": {"name": "Web 前端"}}, {"data": {"name": "支付网关"}}],
                        "boundaries": [{"name": "互联网边界"}],
                    }
                ]
            },
            "threats": [{"title": "重放攻击", "type": "Spoofing", "severity": "High"}],
        }
        text = interop.from_threat_dragon(model)
        assert "Web 前端" in text and "支付网关" in text
        assert "互联网边界" in text
        assert "重放攻击" in text

    def test_import_rejects_invalid(self):
        with pytest.raises(ValueError):
            interop.from_threat_dragon({})
        with pytest.raises(ValueError):
            interop.from_threat_dragon("not a dict")  # type: ignore[arg-type]


class TestPersistence:
    @pytest.fixture()
    def store_mod(self, tmp_path, monkeypatch):
        from common import store as store_module

        data_dir = tmp_path / "data"
        data_dir.mkdir()
        monkeypatch.setattr(store_module, "DATA_DIR", data_dir)
        monkeypatch.setattr(store_module, "CONFIG_FILE", data_dir / "web_config.json")
        monkeypatch.setattr(store_module, "KEY_FILE", data_dir / "web_key")
        monkeypatch.setattr(store_module, "DB_FILE", data_dir / "web.db")
        return store_module

    def test_cwe_persisted_with_threat(self, store_mod):
        store = store_mod
        report_id = store.save_report(
            kind="threat_model",
            project="CWE 项目",
            title="t",
            content_md="m",
            content_json="{}",
            model="mock",
        )
        annotated = standards.annotate_threats(
            [
                {
                    "Threat Type": "Tampering",
                    "Scenario": "SQL 拼接",
                    "Potential Impact": "拖库",
                }
            ]
        )
        inserted = store.add_threats("CWE 项目", report_id, annotated)
        assert inserted == 1
        threats = store.list_threats(project="CWE 项目")
        assert threats[0]["cwe"] == "CWE-89"


class TestApiEndpoints:
    @pytest.fixture()
    def api(self, tmp_path, monkeypatch):
        from common import store as store_module

        data_dir = tmp_path / "api-data"
        data_dir.mkdir()
        for name, value in [
            ("DATA_DIR", data_dir),
            ("CONFIG_FILE", data_dir / "web_config.json"),
            ("KEY_FILE", data_dir / "web_key"),
            ("DB_FILE", data_dir / "web.db"),
        ]:
            monkeypatch.setattr(store_module, name, value)
        module = importlib.import_module("api.main")
        monkeypatch.setattr(module, "store", store_module)
        return module, store_module

    def _report(self, store_mod, kind="threat_model", content=None):
        return store_mod.save_report(
            kind=kind,
            project="导出项目",
            title="t",
            content_md="m",
            content_json=__import__("json").dumps(content or {}),
            model="mock",
        )

    def test_stix_endpoint(self, api):
        module, store_mod = api
        report_id = self._report(
            store_mod,
            content={
                "threat_model": [{"Threat Type": "Spoofing", "Scenario": "伪造令牌"}]
            },
        )
        bundle = module.api_report_stix(report_id, api_key_name="test")
        assert bundle["type"] == "bundle"
        assert any(o["type"] == "vulnerability" for o in bundle["objects"])

    def test_threat_dragon_endpoint_reads_code_analysis(self, api):
        module, store_mod = api
        report_id = self._report(
            store_mod,
            kind="code_analysis",
            content={
                "findings": [
                    {"threats": [{"Scenario": "命令注入", "Threat Type": "Elevation of Privilege"}]}
                ]
            },
        )
        model = module.api_report_threat_dragon(report_id, api_key_name="test")
        assert model["threats"][0]["title"] == "命令注入"

    def test_endpoints_reject_wrong_kind(self, api):
        from fastapi import HTTPException

        module, store_mod = api
        report_id = self._report(store_mod, kind="dread", content={})
        for func in (module.api_report_stix, module.api_report_threat_dragon):
            with pytest.raises(HTTPException) as excinfo:
                func(report_id, api_key_name="test")
            assert excinfo.value.status_code == 400
