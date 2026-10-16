#!/usr/bin/env bash
# 升级：升级前自动备份 → 安装新依赖 → 执行数据库迁移 → 提示重启
#
# 用法：scripts/upgrade.sh
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

echo "==> 1/4 升级前备份"
if [ "${SKIP_BACKUP:-0}" != "1" ]; then
  PYTHONPATH=apps uv run python -m common.backup create
else
  echo "  （SKIP_BACKUP=1，跳过）"
fi

echo "==> 2/4 更新代码"
if [ -d .git ]; then
  if [ -n "$(git remote)" ]; then
    git pull --ff-only
  else
    echo "  本地仓库无远端，跳过 git pull；请先用新版本覆盖代码目录"
  fi
fi

echo "==> 3/4 安装依赖（uv sync --frozen）"
uv sync --frozen

echo "==> 4/4 数据库迁移与自检"
PYTHONPATH=apps uv run python - <<'PY'
import sys
sys.path.insert(0, "apps")
from common import store, version

store.init_db()
history = store.migration_history()
print(f"  产品版本：{version.version_line()}")
print(f"  数据库结构版本：{store.schema_version()}")
for row in history:
    print(f"    v{row['version']} {row['description']}（{row['applied_at']}）")
check = store.db_check()
print(f"  完整性检查：{check}")
print(f"  各表行数：{store.db_stats()['tables']}")
PY

cat <<'NEXT'

升级完成。请重启 Web / API / 调度器：
  systemctl restart wy-web wy-api wy-scheduler        # systemd 部署
  docker compose up -d --build                        # 容器部署
  scripts/run_web.sh                                   # 手工运行

如出现异常，可用升级前的备份回滚：
  scripts/restore.sh ~/.stride-gpt/backups/backup-<时间>.zip
NEXT
