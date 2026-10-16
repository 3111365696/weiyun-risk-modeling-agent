#!/usr/bin/env bash
# 创建备份：scripts/backup.sh [--with-workspaces] [--out DIR]
# 备份包位于 ~/.stride-gpt/backups/，包含数据库、加密配置与会话密钥。
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHONPATH=apps exec uv run python -m common.backup create "$@"
