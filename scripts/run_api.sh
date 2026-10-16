#!/usr/bin/env bash
# 启动威云-风险建模智能体 REST API（默认 0.0.0.0:8000）
# 用法：./scripts/run_api.sh  （可用 HOST/PORT 环境变量覆盖）
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8000}"

echo "启动 API: http://${HOST}:${PORT}  （文档 /docs）"
exec uv run python -m uvicorn apps.api.main:app --host "$HOST" --port "$PORT"
