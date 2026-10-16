#!/usr/bin/env bash
# 启动 Web 控制台（Streamlit，默认 http://localhost:8501）
set -euo pipefail
cd "$(dirname "$0")/.."
exec uv run streamlit run apps/web/main.py --server.port "${WEB_PORT:-8501}" --server.headless true
