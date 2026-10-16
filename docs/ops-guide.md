# 运维手册

面向部署与维护本系统的运维/平台工程师。功能使用见[用户手册](user-guide.md)。

---

## 1. 架构与进程

```
┌────────────┐   ┌────────────┐   ┌──────────────┐
│ Web (8501) │   │ API (8000) │   │ Scheduler    │
│ Streamlit  │   │ FastAPI    │   │ 定时分析      │
└─────┬──────┘   └─────┬──────┘   └──────┬───────┘
      └────────────┬───┴─────────────────┘
            共享数据目录（默认 ~/.stride-gpt，可用 STRIDE_GPT_DATA_DIR 覆盖）
            ├── web.db        SQLite(WAL)：报告/威胁/用量/审计/任务
            ├── web_config.json  加密配置（Fernet）
            ├── web_key          配置密钥（0600）
            ├── web_session_secret  会话签名密钥
            ├── logs/*.jsonl     结构化日志（5MB×5 轮转）
            ├── backups/*.zip    备份包
            └── workspaces/      代码审计工作区（临时）
```

- 三个进程读写**同一个数据目录**；SQLite 已启用 WAL + busy_timeout，支持并发。
- Web 与 API 可独立部署；调度器不是必需（也可用外部 cron + `--once`）。

## 2. 安装

### 2.1 裸机（推荐用脚本）

```bash
git clone <内部仓库> wy && cd wy
scripts/install.sh                      # 检查 Python3.12+ → uv sync → 初始化数据目录
cp .env.example .env && vi .env         # 至少 STRIDE_GPT_PASSWORD 与模型 API Key
scripts/run_web.sh                      # http://localhost:8501
```

### 2.2 systemd（生产）

```bash
sudo useradd -r -m -d /opt/wy -s /usr/sbin/nologin wy
sudo mkdir -p /opt/wy /var/lib/wy /etc/wy
sudo rsync -a --exclude .venv --exclude .git ./ /opt/wy/
cd /opt/wy && sudo -u wy uv sync --frozen
sudo cp deploy/systemd/*.service /etc/systemd/system/
sudo cp deploy/systemd/wy.env.example /etc/wy/wy.env
sudo chmod 600 /etc/wy/wy.env && sudo chown wy:wy /etc/wy/wy.env
sudo systemctl daemon-reload
sudo systemctl enable --now wy-web wy-api wy-scheduler
```

### 2.3 容器

```bash
cp .env.example .env      # 设置 STRIDE_GPT_PASSWORD（compose 强制校验）等
docker compose up -d --build
docker compose ps         # 三个服务均应 healthy
```

数据在命名卷 `wy-data`（容器内 `/data`）；升级镜像不会丢数据。

## 3. 配置项（环境变量）

| 变量 | 说明 | 默认 |
|---|---|---|
| `STRIDE_GPT_DATA_DIR` | 数据目录 | `~/.stride-gpt` |
| `STRIDE_GPT_USERNAME` / `STRIDE_GPT_PASSWORD` | 内置管理员 | `admin` / `admin123`（务必修改） |
| `STRIDE_GPT_SESSION_DAYS` | 会话有效期（1-30） | 7（界面可改，存库优先） |
| `STRIDE_GPT_SECURE_COOKIE` | HTTPS 时置 1，Cookie 加 Secure | 空 |
| `STRIDE_GPT_LOG_LEVEL` | DEBUG/INFO/WARNING/ERROR | INFO |
| `STRIDE_GPT_DEBUG` | 置 1 错误卡片对所有人展开堆栈（仅排障） | 空 |
| `STRIDE_GPT_API_URL` | 状态页探测 API 的地址 | `http://127.0.0.1:8000` |
| `STRIDE_GPT_SEMGREP_CONFIG` | 自定义 Semgrep 规则（如 `p/ci`） | 内置规则包 |
| `OPENAI_API_KEY` 等 | 模型厂商 Key（也可在界面填写并加密持久化） | 空 |

## 4. 日常运维

### 4.1 健康检查

- Web：`GET http://<host>:8501/_stcore/health` → `ok`
- API：`GET http://<host>:8000/api/v1/health` → `{"ok":true,"version":…,"commit":…,"database":"ok","uptime_seconds":…}`
- 界面：顶栏「系统状态」——版本与运行时长、组件健康（数据库/模型/API/调度器/静态分析）、
  最近任务与告警、一键备份。

### 4.2 日志排障

```bash
ls <数据目录>/logs/                      # web.jsonl / api.jsonl / scheduler.jsonl
grep '"level":"ERROR"' <数据目录>/logs/*.jsonl | tail
grep 'ERR-' <数据目录>/logs/*.jsonl      # 用户报的编号直接可检索
```

每条日志含 `trace`（请求/页面重跑编号）、`user`、`project`；API 响应头 `X-Request-ID`
与日志中的 `trace` 一致（也可由调用方传入）。页面异常会在界面显示 `ERR-XXXXXX` 编号。

### 4.3 备份与恢复

```bash
scripts/backup.sh
PYTHONPATH=apps python -m common.backup verify <备份.zip>
scripts/restore.sh <备份.zip>     # 自动先备份当前状态，恢复后需重启服务
```

建议 cron：`0 3 * * * cd /opt/wy && scripts/backup.sh >> /var/log/wy-backup.log 2>&1`，
并把备份同步到异地。恢复演练建议每季度做一次。

### 4.4 升级

```bash
scripts/upgrade.sh          # 备份 → 拉代码 → uv sync → 迁移与自检（打印结构版本/行数）
sudo systemctl restart wy-web wy-api wy-scheduler
```

数据库结构版本记录在 `schema_migrations` 表（当前 v4），升级脚本会输出已应用迁移。

### 4.5 数据库维护

SQLite 文件位于 `<数据目录>/web.db`（+ `-wal`/`-shm`）。

- 空闲清理：`sqlite3 web.db "PRAGMA wal_checkpoint(TRUNCATE); PRAGMA optimize;"`
- 体积增长主要来自 `usage_log`、`audit_log`、`jobs.summary`；可在低峰期清理历史：
  ```sql
  DELETE FROM usage_log WHERE ts < date('now','-180 day');
  DELETE FROM audit_log WHERE ts < date('now','-365 day');
  ```
  （清理前先备份；表结构见 `store.py`。）
- 完整性：系统状态页显示 quick_check 结果，也可 `sqlite3 web.db "PRAGMA integrity_check;"`。

## 5. 安全加固

1. **修改默认口令**：`STRIDE_GPT_PASSWORD`；数据库用户用强密码（策略已内置）。
2. **HTTPS 反向代理**（Nginx/Caddy）终结 TLS，并设置 `STRIDE_GPT_SECURE_COOKIE=1`。
   注意 Streamlit 的 WebSocket（`/_stcore/stream`）需要开启 Upgrade 透传。
3. **限制暴露面**：API 端口仅内网可达；对外只放 Web；必要时用防火墙/安全组白名单。
4. **文件权限**：`chmod 600 /etc/wy/wy.env <数据目录>/web_key <数据目录>/web_session_secret`。
5. **容器**：以非 root 运行（镜像内置 `appuser`）；只挂载数据卷。
6. **依赖与镜像扫描**：定期 `uv lock --upgrade` 后跑测试；镜像可用 trivy 扫描
   （本系统也集成了 trivy 作为 SAST 线索来源）。
7. **审计留存**：审计日志与 JSON 日志按合规要求留存；导出的报告注意保密标识。

## 6. 常见故障

| 现象 | 排查与处理 |
|---|---|
| 页面显示错误编号 | 用编号在 `logs/web.jsonl` 搜 `error_id` 拿堆栈；多为配置/依赖问题 |
| 生成失败 502/超时 | 模型服务可达性、API Key、代理；查看日志中 `kind`/`provider` 字段 |
| `database is locked` | 应已由 WAL+busy_timeout 避免；若出现，检查是否多个不同数据目录/网络盘 |
| API 401 | Key 过期/被轮换/被吊销；到系统配置查看列表状态 |
| API 403 | Key 只有 read 作用域，或项目权限不足（成员/viewer） |
| 任务「已中断」 | 服务重启导致；用 `POST /api/v1/code-audit/jobs/{id}/retry` 重跑 |
| 磁盘占满 | 清理 `workspaces/`、旧 `backups/`、截断日志；检查 `jobs/` 上传产物 |
| 登录被锁 | 等待锁定时间或用管理员「强制下线」后重置密码 |

## 7. 规模化路线

单机 SQLite + WAL 可支撑数十并发用户与数万威胁条目。超出后建议：

1. 拆分部署：Web/API 独立主机，调度器单独一台，共享同一数据目录（需块存储，勿用 NFS）。
2. 数据归档：超过 90 天的用量/审计归档到冷存储，控制库体积。
3. 数据库外置：将 `store.py` 的数据访问迁移到 PostgreSQL（表结构基本同构；
   当前代码为 SQLite 专用，迁移需成体系改造，已在路线图中）。
4. 水平扩展：Web/API 无状态部分可多副本（会话在 Cookie，任务在库），
   但 SQLite 写入仍建议单副本，迁移 PG 后再放开。
