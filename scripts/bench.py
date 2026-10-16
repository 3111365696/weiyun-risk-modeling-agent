#!/usr/bin/env python
"""手工性能基准：打印关键路径耗时（开发对照用，不写入真实数据目录）。

用法：
    PYTHONPATH=apps uv run python scripts/bench.py
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "apps"))

from common import backup, generation, scanners, standards, store  # noqa: E402

ROWS: list[tuple[str, float, str]] = []


def bench(label: str, fn, *, note: str = "") -> None:
    started = time.perf_counter()
    result = fn()
    seconds = time.perf_counter() - started
    ROWS.append((label, seconds, note.format(result=result) if note else ""))
    print(f"  {label:<34} {seconds * 1000:10.1f} ms  {note.format(result=result) if note else ''}")


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        data = Path(tmp) / "data"
        data.mkdir()
        store.DATA_DIR = data
        store.CONFIG_FILE = data / "web_config.json"
        store.KEY_FILE = data / "web_key"
        store.DB_FILE = data / "web.db"
        store.init_db()

        print("== 数据库 ==")
        report_id = store.save_report(kind="threat_model", project="基准", title="t", content_md="m")
        threats = [
            {"Threat Type": "Tampering", "Scenario": f"场景 {i}", "Potential Impact": "泄露"}
            for i in range(2000)
        ]
        bench("写入 2000 条威胁", lambda: store.add_threats("基准", report_id, threats))
        bench("列表查询 2000 条", lambda: len(store.list_threats(project="基准")), note="{result} 条")
        bench("台账统计", lambda: store.threat_stats("基准")["total"], note="{result}")
        bench("db_stats", lambda: store.db_stats()["tables"]["threats"], note="{result} 条")

        print("== 导出 ==")
        rows = store.list_threats(project="基准")
        bench("SARIF", lambda: len(generation.threat_model_to_sarif(rows, project="基准")["runs"][0]["results"]))
        bench("STIX", lambda: len(standards.threats_to_stix(rows, project="基准")["objects"]))
        bench("备份+校验", lambda: backup.verify_backup(backup.create_backup())["files"] and "ok", note="{result}")

        print("== 静态分析（对 current 仓库） ==")
        bench(
            "scanners.probe",
            lambda: sum(1 for item in scanners.probe() if item["available"]),
            note="{result} 个工具可用",
        )
        if (REPO / "apps").exists():
            bench(
                "Semgrep 扫描 apps/",
                lambda: len(scanners.run_semgrep(REPO / "apps", timeout=120)[0]),
                note="{result} 条线索",
            )

    print("\n完成。以上为单机参考值（macOS/SSD）。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
