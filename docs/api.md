# REST API 使用说明

威云-风险建模智能体提供独立的 REST API 服务（`apps/api`），把六类生成能力开放给 CI、工单系统或其他平台调用。
API 与 Web 界面共用同一份存储（报告库、威胁台账、配置），在 Web 里"系统配置 → API 访问"中创建密钥。

## 启动

```bash
# 仓库根目录
uv sync
uv run python -m uvicorn apps.api.main:app --host 0.0.0.0 --port 8000
# 或使用封装脚本
./scripts/run_api.sh
```

- 交互式文档（Swagger）：http://localhost:8000/docs
- 健康检查（无需鉴权）：`GET /api/v1/health`
- 模型来源：优先使用请求参数，其次"系统配置"中保存的服务端配置，最后环境变量（`OPENAI_API_KEY` 等）

> 注意：部分环境 `uv run uvicorn` 可能找不到可执行文件，使用 `python -m uvicorn` 更稳妥。

## 鉴权

所有接口（除健康检查）需要请求头：

```
X-API-Key: wy_xxxxxxxxxxxxxxxx
```

密钥在 Web「系统配置 → API 访问」创建，只显示一次；吊销后立即失效。

## 端点一览

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/health` | 健康检查（无鉴权） |
| GET | `/api/v1/config` | 当前模型配置状态（不返回密钥） |
| POST | `/api/v1/threat-model` | STRIDE 威胁模型 |
| POST | `/api/v1/dfd` | 数据流图（Mermaid） |
| POST | `/api/v1/attack-tree` | 攻击树（Mermaid） |
| POST | `/api/v1/mitigations` | 缓解措施 |
| POST | `/api/v1/dread` | DREAD 风险评估 |
| POST | `/api/v1/test-cases` | Gherkin 测试用例 |
| POST | `/api/v1/full-pipeline` | 一键生成全套（六类） |
| GET | `/api/v1/reports` | 报告列表（`project` / `kind` / `search` / `limit`） |
| GET | `/api/v1/reports/{id}` | 报告详情 |
| DELETE | `/api/v1/reports/{id}` | 删除报告 |
| GET | `/api/v1/reports/{id}/sarif` | 导出威胁模型的 SARIF（CI 用） |
| GET | `/api/v1/projects` | 项目列表（含统计） |
| GET | `/api/v1/projects/{name}/threats` | 项目威胁台账 |
| PATCH | `/api/v1/threats/{id}` | 更新台账条目（status/owner/note） |
| POST | `/api/v1/projects/{name}/webhooks/push` | 台账推送到 Webhook |
| GET/POST | `/api/v1/webhooks` | Webhook 列表 / 新增 |
| DELETE | `/api/v1/webhooks/{id}` | 删除 Webhook |

## 请求示例

### 生成威胁模型

```bash
curl -sS -X POST http://localhost:8000/api/v1/threat-model \
  -H "X-API-Key: $WY_API_KEY" -H "Content-Type: application/json" \
  -d '{
    "description": "一个订单管理 Web 应用，React + FastAPI + PostgreSQL，OAuth2 登录，互联网可达",
    "project": "订单系统",
    "profile": {
      "app_type": "Web application",
      "authentication": ["OAUTH2"],
      "internet_facing": "Yes",
      "sensitive_data": "Confidential"
    }
  }'
```

响应（节选）：

```json
{
  "ok": true,
  "kind": "threat_model",
  "project": "订单系统",
  "report_id": 12,
  "provider": "OpenAI API",
  "model": "gpt-6-astra",
  "markdown": "## 威胁模型\n\n| 威胁类型 | ...",
  "json": {"threat_model": [{"Threat Type": "Spoofing", "...": "..."}], "improvement_suggestions": []}
}
```

### 一键全流程

```bash
curl -sS -X POST http://localhost:8000/api/v1/full-pipeline \
  -H "X-API-Key: $WY_API_KEY" -H "Content-Type: application/json" \
  -d '{"description": "同上", "project": "订单系统"}'
```

为节省额度，部分步骤失败不会中断：`steps` 中逐项返回 `ok`/`error`；依赖威胁模型的步骤在威胁模型失败时标记 `skipped: true`。
`save=false` 可只取结果不归档。

### 报告与 SARIF

```bash
curl -sS "http://localhost:8000/api/v1/reports?project=订单系统" -H "X-API-Key: $WY_API_KEY"
curl -sS "http://localhost:8000/api/v1/reports/12/sarif" -H "X-API-Key: $WY_API_KEY" -o threat.sarif
```

### 台账与 Webhook

```bash
curl -sS -X PATCH http://localhost:8000/api/v1/threats/9 \
  -H "X-API-Key: $WY_API_KEY" -H "Content-Type: application/json" \
  -d '{"status": "已确认", "owner": "安全组", "note": "本周修复"}'

curl -sS -X POST http://localhost:8000/api/v1/projects/订单系统/webhooks/push -H "X-API-Key: $WY_API_KEY"
```

Webhook 类型：`generic`（原样 JSON）、`feishu`、`wecom`、`dingtalk`（自动适配文本消息格式）。

## CI 集成示例（GitHub Actions）

```yaml
name: Threat Model

on:
  workflow_dispatch:
  schedule:
    - cron: "0 2 * * 1"

jobs:
  threat-model:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # 上传 SARIF 需要
    steps:
      - name: 生成威胁模型并导出 SARIF
        env:
          API: ${{ secrets.WY_API_BASE }}     # 例如 http://risk.example.com:8000
          KEY: ${{ secrets.WY_API_KEY }}
        run: |
          curl -sS -f -X POST "$API/api/v1/threat-model" \
            -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
            -d '{"description":"<应用描述>","project":"'${{ github.repository }}'"}' \
            -o model.json
          REPORT_ID=$(python3 -c "import json;print(json.load(open('model.json'))['report_id'])")
          curl -sS -f "$API/api/v1/reports/$REPORT_ID/sarif" -H "X-API-Key: $KEY" -o threat-model.sarif

      - name: 上传到 GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: threat-model.sarif
          category: stride-threat-model
```

> 说明：SARIF 中的定位是逻辑位置（`threat-model`），用于在 Code Scanning / 看板中查看威胁条目；如需按代码行定位，请改用 CLI 的 agentic 分析（带代码证据）。

## 错误码

| 状态码 | 含义 |
|--------|------|
| 400 | 参数/配置问题（未配置模型或 API Key、依赖的威胁模型不存在等） |
| 401 | API Key 缺失、无效或已吊销 |
| 404 | 报告/条目不存在 |
| 502 | 上游模型调用失败（网络、额度、模型返回异常） |

## 新增端点（P2/P3/P4）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/reports/{id}/docx` | 导出 Word（模板：抬头/页脚可在系统配置中设置） |
| GET | `/api/v1/reports/{id}/pdf` | 导出 PDF（服务端需安装 Chrome/Chromium） |
| GET | `/api/v1/projects/{name}/coverage` | STRIDE 覆盖度（最近一次威胁模型） |
| GET | `/api/v1/projects/{name}/diff` | 最近两次威胁模型差异（drift） |
| GET | `/api/v1/schedules` | 定时分析计划列表 |
| POST | `/api/v1/schedules` | 创建/启用计划（project、interval_minutes、notify_on_change） |
| DELETE | `/api/v1/schedules/{id}` | 删除计划 |
| POST | `/api/v1/schedules/{id}/run` | 立即执行一次 |

示例：

```bash
# 导出 Word / PDF
curl -sS -OJ "http://localhost:8000/api/v1/reports/12/docx" -H "X-API-Key: $WY_API_KEY"
curl -sS -OJ "http://localhost:8000/api/v1/reports/12/pdf"  -H "X-API-Key: $WY_API_KEY"

# 覆盖度与差异
curl -sS "http://localhost:8000/api/v1/projects/订单系统/coverage" -H "X-API-Key: $WY_API_KEY"
curl -sS "http://localhost:8000/api/v1/projects/订单系统/diff"     -H "X-API-Key: $WY_API_KEY"

# 定时计划
curl -sS -X POST "http://localhost:8000/api/v1/schedules" -H "X-API-Key: $WY_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"project":"订单系统","interval_minutes":1440,"notify_on_change":true}'
```
