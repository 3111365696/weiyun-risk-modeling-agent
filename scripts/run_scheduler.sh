#!/usr/bin/env bash
# 启动定时分析调度器（常驻）
# 也可用外部 cron：`uv run python -m apps.scheduler.main --once`
set -euo pipefail
cd "$(dirname "$0")/.."
exec uv run python -m apps.scheduler.main "$@"
