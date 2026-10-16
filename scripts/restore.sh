#!/usr/bin/env bash
# 从备份恢复：scripts/restore.sh <备份包.zip> [--no-pre-restore]
# 注意：恢复前会自动备份当前状态；恢复后必须重启 Web / API / 调度器。
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHONPATH=apps exec uv run python -m common.backup restore "$@"
