"""P9-4 性能冒烟：为关键路径设宽松阈值，防止出现数量级回退。

阈值刻意宽松（CI 机器差异大），只用于拦住「慢一个数量级」的改动。
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "apps"))

from common import backup, generation, standards, store  # noqa: E402

N_THREATS = 1000


@pytest.fixture()
def big_store(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    for name, value in [
        ("DATA_DIR", data_dir),
        ("CONFIG_FILE", data_dir / "web_config.json"),
        ("KEY_FILE", data_dir / "web_key"),
        ("DB_FILE", data_dir / "web.db"),
    ]:
        monkeypatch.setattr(store, name, value)
    store.init_db()
    report_id = store.save_report(
        kind="threat_model", project="大项目", title="t", content_md="m"
    )
    threats = [
        {
            "Threat Type": "Tampering",
            "Scenario": f"场景 {index}：SQL 拼接",
            "Potential Impact": "数据泄露",
            "subsystem": f"模块{index % 20}",
        }
        for index in range(N_THREATS)
    ]
    started = time.perf_counter()
    store.add_threats("大项目", report_id, threats)
    insert_seconds = time.perf_counter() - started
    # 批量写入的用量与审计也塞一些，模拟真实规模
    for index in range(300):
        store.log_usage(
            actor="admin",
            source="web",
            provider="OpenAI API",
            model="gpt-4o-mini",
            kind="threat_model",
            project="大项目",
            prompt_tokens=100 + index,
            completion_tokens=50,
            cost=0.001,
        )
    store.log_action("admin", "批量准备", f"{N_THREATS} 条")
    return {"insert_seconds": insert_seconds}


def test_bulk_insert_speed(big_store):
    assert big_store["insert_seconds"] < 10, f"{N_THREATS} 条威胁写入耗时 {big_store['insert_seconds']:.2f}s"


def test_list_and_query_speed(big_store):
    started = time.perf_counter()
    threats = store.list_threats(project="大项目")
    list_seconds = time.perf_counter() - started
    assert len(threats) == N_THREATS
    assert list_seconds < 3, f"列表查询 {list_seconds:.2f}s"

    started = time.perf_counter()
    stats = store.threat_stats("大项目")
    stats_seconds = time.perf_counter() - started
    assert stats["total"] == N_THREATS
    assert stats_seconds < 3, f"统计 {stats_seconds:.2f}s"

    started = time.perf_counter()
    summary = store.usage_summary()
    usage_seconds = time.perf_counter() - started
    assert summary["totals"]["calls"] == 300
    assert usage_seconds < 3, f"用量汇总 {usage_seconds:.2f}s"


def test_export_speed(big_store):
    threats = store.list_threats(project="大项目")
    started = time.perf_counter()
    sarif = generation.threat_model_to_sarif(threats, project="大项目")
    stix = standards.threats_to_stix(threats, project="大项目")
    export_seconds = time.perf_counter() - started
    assert len(sarif["runs"][0]["results"]) == N_THREATS
    assert [o["type"] for o in stix["objects"]].count("vulnerability") == N_THREATS
    assert export_seconds < 10, f"导出 {export_seconds:.2f}s"


def test_backup_speed(big_store):
    started = time.perf_counter()
    path = backup.create_backup()
    verify = backup.verify_backup(path)
    seconds = time.perf_counter() - started
    assert verify["db_tables"]["threats"] == N_THREATS
    assert seconds < 15, f"备份+校验 {seconds:.2f}s"


def test_db_stats_speed(big_store):
    started = time.perf_counter()
    stats = store.db_stats()
    seconds = time.perf_counter() - started
    assert stats["tables"]["threats"] == N_THREATS
    assert seconds < 2, f"db_stats {seconds:.2f}s"
