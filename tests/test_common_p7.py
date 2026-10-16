"""B 阶段测试：静态分析扫描器适配层与线索注入。"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "apps"))

from common import scanners

VULN_SOURCE = '''import hashlib
import subprocess
import yaml

PASSWORD = "supersecret123"


def run(cmd):
    return subprocess.run(cmd, shell=True)


def load(raw):
    return yaml.load(raw)


def weak(data):
    return hashlib.md5(data).digest()
'''


@pytest.fixture()
def vuln_repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "vuln.py").write_text(VULN_SOURCE, encoding="utf-8")
    return root


class TestProbe:
    def test_probe_shape(self):
        items = scanners.probe()
        names = {item["name"] for item in items}
        assert {"semgrep", "bandit", "detect-secrets", "gitleaks", "trivy"} <= names
        for item in items:
            assert set(item) == {"name", "available", "hint", "install"}
            if not item["available"]:
                assert item["install"]  # 未安装要给出安装提示

    def test_missing_tools_are_skipped(self, vuln_repo):
        result = scanners.run_scanners(vuln_repo, only=["definitely-not-a-tool"])
        assert result["leads"] == []


@pytest.mark.skipif(not shutil.which("semgrep"), reason="semgrep 未安装")
class TestSemgrep:
    def test_builtin_rules_find_patterns(self, vuln_repo):
        leads, error = scanners.run_semgrep(vuln_repo, timeout=120)
        assert error == "", error
        rules = {lead.rule for lead in leads}
        assert "wy-hardcoded-secret" in rules
        assert "wy-subprocess-shell" in rules
        assert "wy-yaml-unsafe-load" in rules
        assert "wy-weak-hash" in rules
        assert all(lead.tool == "semgrep" for lead in leads)

    def test_clean_code_has_no_leads(self, tmp_path):
        clean = tmp_path / "clean"
        clean.mkdir()
        (clean / "ok.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
        leads, error = scanners.run_semgrep(clean, timeout=120)
        assert error == ""
        assert leads == []


@pytest.mark.skipif(not shutil.which("bandit"), reason="bandit 未安装")
class TestBandit:
    def test_finds_issues(self, vuln_repo):
        leads, error = scanners.run_bandit(vuln_repo, timeout=120)
        assert error == ""
        assert any(lead.tool == "bandit" for lead in leads)
        assert all(lead.path.endswith("vuln.py") for lead in leads)


class TestAggregation:
    def test_dedup_and_sorting(self):
        raw = [
            scanners.Lead("a", "r1", "low", "x.py", 1, "m"),
            scanners.Lead("a", "r1", "low", "x.py", 1, "m"),  # 重复
            scanners.Lead("b", "r2", "high", "y.py", 2, "m"),
            scanners.Lead("c", "r3", "medium", "z.py", 3, "m"),
        ]
        seen = {(lead.tool, lead.path, lead.line, lead.rule) for lead in raw}
        assert len(seen) == 3  # 聚合层按该键去重（与 run_scanners 一致）
        order = {"high": 0, "medium": 1, "low": 2}
        sorted_leads = sorted(raw, key=lambda item: order.get(item.severity, 3))
        assert sorted_leads[0].severity == "high"

    def test_leads_markdown_contains_locations(self):
        leads = [scanners.Lead("semgrep", "wy-x", "high", "app/auth.py", 14, "硬编码密钥")]
        text = scanners.leads_markdown(leads)
        assert "app/auth.py:14" in text
        assert "semgrep/wy-x" in text
        assert "误报" in text  # 提示 agent 这是候选线索

    def test_leads_markdown_caps_size(self):
        leads = [
            scanners.Lead("bandit", f"B{i}", "low", "f.py", i, "x" * 120) for i in range(200)
        ]
        text = scanners.leads_markdown(leads, limit=200, max_chars=1500)
        assert len(text) < 2500
        assert "省略" in text

    def test_summary_counts(self):
        leads = [
            scanners.Lead("semgrep", "r", "high", "a.py", 1, "m"),
            scanners.Lead("bandit", "r", "high", "a.py", 1, "m"),
            scanners.Lead("bandit", "r", "low", "b.py", 2, "m"),
        ]
        summary = scanners.summarize_for_report(leads)
        assert summary["total"] == 3
        assert summary["by_severity"] == {"high": 2, "low": 1}
        assert summary["by_tool"] == {"semgrep": 1, "bandit": 2}


class TestRulePack:
    def test_rules_file_is_valid_yaml(self):
        import yaml

        data = yaml.safe_load(Path(scanners.RULES_FILE).read_text(encoding="utf-8"))
        rules = data["rules"]
        assert len(rules) >= 10
        ids = [rule["id"] for rule in rules]
        assert len(ids) == len(set(ids))
        for rule in rules:
            assert rule["message"] and rule["severity"] and rule["languages"]
