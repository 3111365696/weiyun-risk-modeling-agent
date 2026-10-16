#!/usr/bin/env bash
# 一键安装：检查环境 → 安装依赖 → 初始化数据目录 → 打印后续步骤
#
# 用法：
#   scripts/install.sh            # 安装到当前仓库（uv 管理）
#   scripts/install.sh --dir /opt/wy --data /var/lib/wy
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DATA_DIR="${STRIDE_GPT_DATA_DIR:-$HOME/.stride-gpt}"
TARGET_DIR=""

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) TARGET_DIR="$2"; shift 2 ;;
    --data) DATA_DIR="$2"; shift 2 ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "未知参数：$1" >&2; exit 1 ;;
  esac
done

echo "==> 检查 Python（需要 3.12+）"
PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "未找到 $PYTHON_BIN，请先安装 Python 3.12+" >&2
  exit 1
fi
"$PYTHON_BIN" - <<'PY'
import sys
if sys.version_info < (3, 12):
    raise SystemExit(f"需要 Python 3.12+，当前 {sys.version.split()[0]}")
PY

if [ -n "$TARGET_DIR" ] && [ "$TARGET_DIR" != "$REPO_DIR" ]; then
  echo "==> 复制代码到 $TARGET_DIR"
  mkdir -p "$TARGET_DIR"
  rsync -a --delete --exclude '.venv' --exclude '.git' "$REPO_DIR/" "$TARGET_DIR/"
fi
WORK_DIR="${TARGET_DIR:-$REPO_DIR}"
cd "$WORK_DIR"

echo "==> 安装 uv（如缺失）"
if ! command -v uv >/dev/null 2>&1; then
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
fi

echo "==> 安装依赖（uv sync）"
uv sync --frozen

echo "==> 初始化数据目录：$DATA_DIR"
mkdir -p "$DATA_DIR"
export STRIDE_GPT_DATA_DIR="$DATA_DIR"
uv run python - <<'PY'
import sys
sys.path.insert(0, "apps")
from common import backup, store, version

store.init_db()
print(f"  数据库结构版本：{store.schema_version()}")
print(f"  产品版本：{version.version_line()}")
print(f"  备份目录：{backup.backup_dir()}")
PY

cat <<NEXT

安装完成。下一步：

1) 配置登录凭据与模型 Key
   cp .env.example .env && vi .env        # 至少设置 STRIDE_GPT_PASSWORD 与模型 API Key

2) 启动服务（三个进程）
   scripts/run_web.sh            # 或：uv run streamlit run apps/web/main.py
   scripts/run_api.sh            # REST API（可选）
   scripts/run_scheduler.sh      # 定时分析（可选）

   生产环境建议用 systemd：见 deploy/systemd/ 与 docs/ops-guide.md
   容器部署：docker compose up -d --build

3) 打开 http://localhost:8501 登录；首次使用请在「系统配置 → 模型服务」填写 API Key
NEXT
