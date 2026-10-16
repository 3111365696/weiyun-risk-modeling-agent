"""定时分析调度进程。

用法：
    uv run python -m apps.scheduler.main            # 常驻，每 60 秒检查一次到期计划
    uv run python -m apps.scheduler.main --once     # 只跑一轮到期的计划（适合外部 cron）
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

_APPS_DIR = Path(__file__).resolve().parent.parent
_REPO_ROOT = _APPS_DIR.parent
for _p in (_REPO_ROOT, _APPS_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from common import generation, store  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("scheduler")


def run_due() -> int:
    """执行所有到期计划，返回到期数量。"""
    due = store.due_schedules()
    for schedule in due:
        log.info("执行计划：%s（间隔 %s 分钟）", schedule["project"], schedule["interval_minutes"])
        result = generation.run_scheduled_analysis(schedule)
        log.info(
            "计划完成：%s -> %s（新增 %s / 消失 %s，推送 %s）",
            schedule["project"],
            result.get("status"),
            result.get("added"),
            result.get("removed"),
            result.get("pushed"),
        )
    return len(due)


def main() -> None:
    parser = argparse.ArgumentParser(description="威云-风险建模智能体 定时分析调度器")
    parser.add_argument("--once", action="store_true", help="只跑一轮到期计划后退出")
    parser.add_argument("--interval", type=int, default=60, help="检查间隔秒数（默认 60）")
    args = parser.parse_args()

    if args.once:
        count = run_due()
        log.info("本次到期计划：%s 条", count)
        return

    log.info("调度器启动（每 %s 秒检查一次到期计划）", args.interval)
    while True:
        try:
            run_due()
        except Exception:
            log.exception("调度循环异常")
        time.sleep(max(5, args.interval))


if __name__ == "__main__":
    main()
