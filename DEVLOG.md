# 开发记录（威云-风险建模智能体）

> 本仓库是 [mrwadams/stride-gpt](https://github.com/mrwadams/stride-gpt) 的中文本地化定制版，
> 基于上游 v0.20.0，产品名定为「威云-风险建模智能体」。

## 运行方式

```bash
cd /Users/cc/stride-gpt-cn
uv sync                                   # 安装依赖（uv.lock 为唯一依赖来源）
uv run streamlit run apps/web/main.py     # 默认 http://localhost:8501
```

- 登录账号：`admin` / `admin123`
  - 可通过环境变量覆盖：`STRIDE_GPT_USERNAME` / `STRIDE_GPT_PASSWORD`（见 `.env.example`）
- 测试：`uv run pytest`（当前 **806 passed**）
- 生成内容需要模型 API Key：登录后进入「系统配置」填写

## 已完成功能

| # | 功能 | 说明 |
|---|------|------|
| 1 | 中文本地化 | Web UI 全量中文；LLM 提示词注入中文输出指令（威胁模型/攻击树/DFD/缓解/DREAD/测试用例）；模型库说明与提供商接入指引中文 |
| 2 | 紫色专业主题 | `.streamlit/config.toml` 暗色紫主题 + `apps/web/main.py` 注入 CSS（下划线标签、静音提示条、表格、滚动条等），去 emoji、去霓虹感 |
| 3 | 登录页 | 控制台风格分屏：透视网格地坪、扫描线动画、SVG 盾牌描边动画、2×2 能力卡、控制台就绪行、底部状态条；自动聚焦用户名 |
| 4 | 登录态与退出 | 顶栏显示头像/用户名/角色；「退出系统」+「退出登录」双入口；退出确认弹窗（显示登录时间） |
| 5 | 系统配置页 | 独立页面：模型服务（提供商/API Key/默认模型/扩展思考/LM Studio）、GitHub 集成、分析参数（token 上限）、当前配置状态面板 |
| 6 | 页面拆分与导航 | 原 6 个标签拆成独立页面；顶部常驻分段导航（威胁模型为首页）；每页 kicker + 标题页头 |

## 关键文件

| 文件 | 改动 |
|------|------|
| `.streamlit/config.toml` | 主题令牌：紫色主色、暗色面、侧边栏配色、圆角、字体、状态色 |
| `apps/web/main.py` | 绝大部分改动：主题 CSS、登录认证、退出弹窗、系统配置页、页面拆分与导航 |
| `apps/web/attack_tree.py` `dfd.py` `dread.py` `mitigations.py` `test_cases.py` `threat_model.py` | 中文提示词指令、DREAD/威胁模型 Markdown 渲染表头中文化、推理过程展开展开文案 |
| `stride_gpt/models.py` | 提供商接入说明与模型帮助文案中文化 |
| `stride_gpt/core/prompts/builder.py` | 注入中文输出指令；DFD/图像分析/攻击树提示词中文指令 |
| `stride_gpt/core/prompts/threat_model/base.md` `quick_base.md` | CLI 智能体系统提示词追加 Output language 段（生成内容中文） |
| `stride_gpt/core/{mitigations,dread,test_cases,dfd}.py` | 解析模型系统提示词追加中文指令 |
| `.env.example` | 增加登录凭据示例 |

## 技术要点备忘

- **页面拆分实现**：六个 `with tabX:` 块原位改造成 `def _page_*()` 页面函数（缩进天然吻合），文件末尾统一调度；共享画像（app_type/sensitive_data/internet_facing/authentication/app_input）在会话状态中全局初始化，任意页面可独立进入。
- **Streamlit 1.59 注意**：`st.container(border=True)` 的 DOM 为 `[data-testid="stVerticalBlock"]`，用 `key=` + `.st-key-xxx` 定位；`st.components.v1.html` 已废弃，改用 `st.iframe`；`st.segmented_control` 的分段按钮在 `[data-testid="stButtonGroup"] button[data-variant="segmented_control"]`。
- **登录实现**：`st.session_state` 会话级校验 + `hmac.compare_digest`；未登录 `st.stop()`，界面不渲染。

## 待办 / 下一步候选

1. **配置持久化**：目前 API Key/模型等只存在浏览器会话中，重启服务需重填；可做「保存到服务端配置文件」。
2. **CLI 界面汉化**：CLI 生成内容已是中文，但 Typer 帮助、进度提示仍为英文。
3. **Web 暴露高级参数**：`--max-llm-calls`、子系统预算等目前仅 CLI 可用。
4. **按评审的智能体优化项**（详见对话记录）：修上下文压缩阈值（上游 #227）、按子系统分配 LLM 预算（#226）、跨子系统威胁去重与稳定 ID（#209/#212）、全局工具缓存与 prompt 缓存统计（#225）。
5. **登录安全**：生产环境建议密码哈希 + 反向代理/SSO；当前为应用内认证。

## 验收基线

- `uv run pytest`：806 passed
- 登录 → 六个页面切换 → 系统配置读写 → 退出登录：全流程实测通过

## 增量记录（2026-10-16）

### 已完成：第一步（配置持久化 + 报告历史 + 导出中心）

| 功能 | 说明 |
|------|------|
| 配置持久化 | 设置页「保存配置到服务端」；Fernet 加密存 `~/.stride-gpt/web_config.json`（密钥 `web_key`，均 0600）；启动自动载入并覆盖 .env 同名值 |
| 报告历史 | 6 类生成结果自动归档到 SQLite（`~/.stride-gpt/web.db`）；新增「报告历史」页面与路由 `/reports`，支持类型/项目/关键字过滤、查看弹窗、删除、统计 |
| 导出中心 | 单条报告导出 Markdown / HTML（自带紫色主题的独立页面）/ JSON；「导出全部 (ZIP)」批量打包（含 manifest.json） |
| 项目名称 | 威胁模型页新增「项目名称（用于报告归档）」输入，留空按应用描述自动取名 |

### 新增/修改文件

- 新增 `apps/web/store.py`：配置加解密、报告 CRUD、HTML/ZIP 导出
- `apps/web/main.py`：启动载入配置、设置页保存/清除按钮、6 处生成归档钩子、报告历史页与路由、项目名称输入
- 修复：设置页 API Key/端点/GitHub Key 输入由 `value=` 改为原生 `key=` 绑定（避免流式输入状态不同步）

### 验证

- `uv run pytest`：806 passed
- 存储自测：插入/搜索/HTML/ZIP/删除、配置加解密往返全部通过
- 浏览器实测：归档列表、查看弹窗、保存配置、重启后 Key 自动恢复、清除配置
- 预置 2 条「演示项目」数据用于查看报告历史页效果（可在页面上直接删除）

## 增量记录（2026-10-16 下午）：P0 + P1

### 风险管理闭环（P0）

| 功能 | 说明 |
|------|------|
| 项目工作区 | 新页面 `/projects`：项目选择、应用描述编辑（保存后同步为分析输入）、产物列表、指标（产物数/威胁数/待处理/已修复） |
| 威胁台账 | 威胁模型生成时自动提取条目（项目内按"类型+场景"指纹去重）；支持逐条设置状态（待处理/已确认/已修复/已接受/已忽略）、负责人、备注；可按状态筛选与搜索 |
| 风险看板 | STRIDE 分布、台账状态分布（主题紫色图表）、高风险 Top 10（DREAD 评分排序；DREAD 报告生成后自动回填分数） |
| 历史回填 | `backfill_project`：把已有威胁模型/DREAD 报告回填到台账（幂等），打开项目页时自动执行 |

### 体验补强（P1）

| 功能 | 说明 |
|------|------|
| 一键全流程生成 | 项目页一键顺序生成 6 类产物（威胁模型→数据流图→攻击树→缓解措施→DREAD→测试用例），每步完成即归档并显示进度；威胁模型失败时跳过依赖步骤 |
| 会话保持 | 登录后写入 HMAC 签名 cookie（7 天），刷新/重开页面免登录；退出登录清除 |
| 草稿自动保存 | 应用描述与画像（应用类型/敏感级别/是否联网/认证方式）自动存草稿，刷新后恢复 |

### 本次修复的关键问题

1. **SIGSEGV 崩溃（最重要）**：`st.data_editor` / `st.dataframe` 触发 pyarrow 的 mimalloc 段错误，进程数秒内崩溃。已移除全部 Arrow/DataFrame 用法（台账改逐行控件、Top10 改 Markdown 表、图表传原生 dict），并在 `main.py` 顶部写入 `ARROW_DEFAULT_MEMORY_POOL=system` 兜底。
2. **环境变量每轮覆盖会话**：`load_env_variables()` 原本每次 rerun 都无条件写 session_state（端点/Key 被重置），已改为 `setdefault` 语义。
3. **配置只在会话首帧加载**：避免每轮用已保存配置覆盖会话内修改。
4. **LM Studio 空 Key**：模型发现补 `not-needed` 哨兵；核心层已支持（空串→None→占位）。
5. **流程描述兜底**：一键全流程在文本框为空时回退到项目已保存描述。

### 验证

- 806 tests passed
- 用本地 OpenAI 兼容模拟服务（`/tmp/mock_llm.py`，非仓库文件）端到端验证：6 步全流程 6 次 LLM 调用、6 份报告归档、4 条新威胁入库去重、DREAD 分数自动回填
- 浏览器实测：cookie 免登录刷新、台账渲染、看板图表、配置持久化重启恢复
- 测试痕迹（mock 报告/威胁/配置）已全部清理

## 增量记录（2026-10-16 晚）：P2 平台化（REST API + CI + 集成）

### 公共层重构（apps/common）

| 模块 | 内容 |
|------|------|
| `apps/common/store.py` | 由 `apps/web/store.py` 迁移；新增 api_keys / webhooks 表；API Key 哈希校验与吊销、Webhook CRUD 与多平台推送体构造 |
| `apps/common/text.py` | 从 apps/web 抽取的纯函数：6 类提示词构造 + 威胁模型/DREAD 的 Markdown 渲染（Web 与 API 共用，无 Streamlit 依赖） |
| `apps/common/generation.py` | 无 Streamlit 的生成编排：模型配置解析（参数 > 保存配置 > 环境变量）、六类生成、归档（报告/项目/台账/DREAD 回填）、全流程、SARIF 生成、Webhook 推送 |

### REST API（apps/api，FastAPI）

- 启动：`uv run python -m uvicorn apps.api.main:app --host 0.0.0.0 --port 8000`（或 `./scripts/run_api.sh`）
- 鉴权：`X-API-Key`（Web「系统配置 → API 访问」创建，仅显示一次，可吊销）
- 端点：健康检查、配置状态、6 类生成、一键全流程、报告 CRUD、SARIF 导出、项目/台账查询与更新、Webhook 管理/推送（Swagger：`/docs`）
- 依赖：fastapi / uvicorn（pyproject `api` 组，已加入 default-groups）

### 集成能力

- **CI**：`GET /api/v1/reports/{id}/sarif` 产出 SARIF 2.1.0；`docs/api.md` 含 GitHub Actions 完整示例（生成 → 导出 → Code Scanning 上传）
- **工单/通知**：Webhook 支持飞书 / 企业微信 / 钉钉 / 通用 JSON，可在项目台账一键推送
- **部署**：docker-compose 新增 `stridegpt-api` 服务（复用 UI 镜像，暴露 8000）

### Web 界面

- 系统配置新增「API 访问」（创建/列表/吊销，密钥一次性展示）与「工单 / 通知集成」（Webhook 增删）
- 威胁台账新增「推送到 Webhook」按钮
- 报告详情弹窗对威胁模型提供「下载 SARIF」

### 修复

1. `json_to_markdown` 对模型漏字段（缺 Potential Impact 等）会 KeyError → 改为 `.get` 兜底
2. `generation` 按 provider_key 查找 ProviderInfo（`PROVIDERS` 是以显示名为键，原实现拿不到 needs_api_key）
3. 抽离函数后 Web 模块的 re-export 被 ruff 当作未使用删除 → 显式 `# noqa: F401` re-export 并复测
4. 中文本地化触发 RUF001-003 → pyproject 显式忽略（有注释说明）

### 验证

- `uv run pytest`：**835 passed**（新增 29 个公共层/API 相关测试：API Key 生命周期、配置加密、会话令牌、Webhook、归档去重、DREAD 回填、SARIF、提示词、流水线编排）
- `uv run ruff check apps/ tests/`：全绿
- API 端到端（模拟 LLM）：配置解析 → 威胁模型生成归档 → 全流程 6 步 → 报告列表 → SARIF → 台账更新 → Webhook 推送 → 401/400 错误路径；测试数据已清理

## 增量记录（2026-10-16 夜）：P3 质量与企业化

### 分析质量

| 功能 | 说明 |
|------|------|
| STRIDE 覆盖度 | `generation.stride_coverage()`：六类计数与缺失类别；生成威胁模型后即时提示；项目概览与报告详情均有展示；API `/projects/{name}/coverage` |
| 报告差异对比（drift） | `generation.diff_latest_threat_models()`：按（类型+场景）指纹对比最近两次威胁模型，输出新增/消失/未变；项目概览折叠卡片展示；API `/projects/{name}/diff` |
| 敏感信息脱敏 | `common/scrub.py`：OpenAI/Anthropic/GitHub/AWS/Google/Slack/JWT/私钥/凭据赋值等模式，发送前替换为 `[已脱敏:...]`；默认开启，可在设置关闭 |
| 企业安全基线 | 设置页可填写自定义要求（如等保/SSO/审计），保存后作为额外 system 指令注入**所有**模型调用 |

核心支撑：`stride_gpt/core/llm.py` 新增两个可选策略钩子（`set_extra_system_instruction` / `set_prompt_scrubber`），CLI 不设置时行为完全不变。

### 多用户与审计

- **用户体系**：环境变量管理员（内置，不可删）+ 数据库用户（PBKDF2-HMAC-SHA256 加盐 20 万次迭代）；角色 `admin` / `user`
- **权限门控**：非管理员看不到「系统配置」入口、无法访问设置页与「用户与审计」页；页面级二次校验
- **用户管理页**（`/users`）：创建用户（用户名/初始密码/角色）、重置密码、删除、审计日志（按用户筛选）
- **审计日志**：登录/登录失败/退出、保存/清除配置、创建/吊销 API Key、增删 Webhook、删除报告、更新台账、一键全流程、用户增删改
- **会话安全修复**：登出时递增该用户的**会话纪元**（`session_epoch`），旧 cookie 立即失效——修复了"退出后被旧 cookie 立刻登回、清 cookie 代码永不执行"的真实 bug

### 验证

- `uv run pytest`：**850 passed**（新增 15 个 P3 测试：脱敏/覆盖度/差异/用户/审计/策略钩子）
- `uv run ruff check apps/ tests/`：全绿
- 浏览器实测：管理员建/看/删用户、普通用户登录后无配置入口且 `/users` 被拒、覆盖度与差异卡片、审计记录完整
- API 实测：`/coverage`、`/diff`、404 错误路径；测试 Key 已吊销

## 增量记录（2026-10-17）：P4 自动化 / 报告模板 / 多语言

### 定时自动分析
- `schedules` 表 + 计划 CRUD/到期判定（`due_schedules`）
- `generation.run_scheduled_analysis()`：执行全流程 → 对比最近两次威胁模型 → 变化时推送 Webhook → 记录 last_run/status
- 独立调度进程 `apps/scheduler/main.py`（常驻，或 `--once` 供外部 cron）+ `scripts/run_scheduler.sh`
- 项目工作区新增「定时自动分析」卡片（间隔/推送开关/保存/立即执行/暂停/删除/状态）
- API：`/schedules` 列表/创建/删除/立即执行；`/projects/{name}/coverage`、`/diff`

### 报告模板（Word/PDF）
- `apps/common/exporters.py`：Markdown → Word（python-docx；标题页 + 元信息表 + 表格/列表/代码块 + 页脚页码）；HTML → PDF（Chrome 无头打印）
- 模板可配置：报告抬头（品牌）、页脚保密标识（系统配置 → 报告模板）
- Web 报告弹窗：下载 Word / 生成并下载 PDF；API：`/reports/{id}/docx|pdf`（RFC 5987 中文文件名）

### 多语言切换
- `apps/common/i18n.py`：`t(zh, en)` + `set_language()`（默认中文，未知语言回退）
- main.py 345 处 UI 文案改为 `_t(...)`；导航/页面标题、按钮/表单/设置/报告/台账/用户页全覆盖
- 报告类型标签、角色名、下拉显示值（应用类型/敏感级别/是否联网/认证方式）运行时按语言切换
- 侧边栏「界面语言 / Language」切换并持久化到服务端配置

### 修复
- 中文文件名写入 HTTP 头导致 latin-1 编码 500 → RFC 5987（`filename*=UTF-8''...`）
- 会话 cookie 与登出竞态 → 会话纪元机制（P3 已记，本期回归验证）

### 验证
- `uv run pytest`：**859 passed**（新增 9 个 P4 测试：计划 CRUD/到期/执行通知、Word 模板与页脚、i18n 切换、通知体格式）
- `ruff check apps/ tests/`：全绿
- 浏览器实测：切到 English 后导航/页面/侧边栏/子标签/角色/按钮全英文，切回中文正常
- API 实测：Word/PDF 下载（正确 magic 与文件名编码）、覆盖度、差异、调度 CRUD

## 修复（2026-10-17）：项目工作区 UnboundLocalError

**现象**：打开「项目工作区」页面直接报 `UnboundLocalError: cannot access local variable '_t' where it is not associated with a value`，页面无法渲染。

**原因**：变更对比卡片的循环变量命名为 `_t`（`for _t in _diff["added"]`），而该函数内还有大量 i18n 调用 `_t(...)`。
Python 看到函数内存在对 `_t` 的赋值就把它当作局部变量，于是前面的 `_t(...)` 调用在赋值前触发 UnboundLocalError。

**修复**：循环变量改名为 `_threat`；并新增静态回归测试 `tests/test_web_static.py`，
用 AST 扫描 `apps/web/main.py`，禁止任何函数内局部变量/循环变量遮蔽模块级助手
（`_t` / `_i18n` / `_generation` / `_exporters` / `_kind_label` 等）。

**验证**：859 → **861 passed**；浏览器逐页检查 9 个页面均无异常，差异卡片可展开显示新增/消失明细。

## 增量记录（2026-10-17）：P5 系统化（概览仪表盘 / 用量与配额 / 对抗式验证 / demo 清理）

### 概览仪表盘（新首页 `/overview`）
- KPI：项目数、报告数、威胁条目、待处理、已修复
- 风险态势：STRIDE 分布、台账状态分布、高风险 Top 5（DREAD）
- 验证与预算：已确认/存疑/已驳回/未验证统计 + 本月用量与预算进度
- 近期报告、快捷入口（一键跳转生成/项目/报告/配置）
- 导航首项改为「概览」，原「威胁模型」保留为第二项

### 用量与成本
- `usage_log` 表 + 核心 LLM 层**用量记录钩子**（线程内上下文：actor/source/project），覆盖 Web、API、调度器、验证全部调用路径
- 价格表与成本估算（`common/usage.py`，未知模型只统计 token 不猜价格）
- 设置页「用量与成本」卡片：月度预算、按模型用量表；仪表盘显示月度进度
- API Key 支持**日 token 配额 / 月费用配额**，超限 429；创建密钥时可设置
- API：`GET /api/v1/usage`

### 对抗式验证（Critic）
- `generation.verify_threats()`：以红队视角逐条复核（已确认 / 存疑 / 已驳回 + 置信度 + 理由），输出严格 JSON，兼容中英文枚举
- 结果写回台账（`verdict` / `confidence` / `verification_note` / `verified_at`），Web 台账新增验证列、验证筛选与「重新验证」按钮；生成后自动复核（可关闭）
- API：生成响应附带 `verification`；`POST /api/v1/projects/{name}/verify`

### 去 demo 化
- 侧边栏移除捐赠按钮、GitHub 加星徽章、示例应用描述区块（保留关于/使用说明/FAQ）

### 修复（重要）
- **测试污染用量统计**：核心用量钩子是全局状态，某个用例安装后未复位，导致 `test_llm_response.py` 等使用 mock 响应的用例把「用量行」写进**真实数据库**（共 119 行，均为 mock 数据，无真实花费）。
  修复：① 新增 autouse 夹具在每个用例前后复位 LLM 策略钩子与调用上下文；② `record_from_response` 在 `PYTEST_CURRENT_TEST` 环境直接跳过；③ 清理 119 行污染数据。
- 数据库增量迁移（`_ensure_column`）从建表前移到建表之后（否则老库 ALTER 报 no such table）

### 验证
- `uv run pytest`：**875 passed**（新增 14 个 P5 测试：价格/用量分组/配额/预算/验证归一化与写回/开关）
- 全量测试后真实库用量行数保持 **0**（不再污染）
- 浏览器实测：概览仪表盘渲染正常（KPI/图表/验证统计/预算/近期报告/快捷入口），导航、去 demo 化侧边栏生效
- API 实测：`/usage`、`/verify`、配额 429 路径

## 增量记录（2026-10-17）：P6 Agentic 代码分析进 Web

### 能力
- 新页面「代码审计」(`/code-audit`)：上传 ZIP 或填写 https 仓库地址，可选 worker/architect 模型与
  LLM/工具调用上限，带确认勾选（成本提示），运行中实时显示阶段、子系统进度与工具调用
- 分析完成后：报告归档为「代码审计」类型（Markdown/JSON/SARIF 可下载），
  威胁写入台账并带 **subsystem / source=agentic / evidence（代码路径+片段+行号）**
- API 异步任务：`POST /code-audit`（仓库）、`POST /code-audit/upload`（ZIP）、任务查询/列表/取消

### 公共层 `apps/common/agentic.py`
- `extract_zip`：zip-slip / 绝对路径 / 符号链接防护，解压总量 300MB、文件数 20000 上限，单根目录自动识别
- `clone_repo`：仅 https + 主机白名单（`STRIDE_GPT_GIT_HOSTS` 可扩展），`--depth 1 --single-branch`、
  禁交互认证、令牌经 `http.extraheader` 注入；克隆超时 300s
- `_EventProgress`：实现完整 ProgressCallback 协议，把 agent 事件转成回调；
  **协作式取消**（回调里抛异常中止运行）
- `archive_report`：渲染 MD/JSON/SARIF 并归档 + 按（类型+场景）去重写入带证据的威胁

### 存储
- `KIND_LABELS` 新增 `code_analysis`（代码审计 / Code Audit），报告类型标签 EN 映射同步
- threats 新增 `subsystem` / `source` / `evidence` 列（含老库迁移）

### 验证
- `uv run pytest`：**892 passed**（新增 17 个 P6 测试：解压安全 6 项、仓库校验 4 项、归档与去重、
  模型对覆盖、进度适配器与取消、API 任务成功/失败路径）
- **端到端（模拟 LLM 走完整 agent 协议）**：ZIP → 规划 1 个子系统 → 分析产出 2 条带证据威胁 →
  归档 `code_analysis` + SARIF 2 条结果；HTTP 上传任务 202 → 轮询 done（report_id/威胁数）
- 浏览器实测：`/code-audit` 页面渲染正常（来源选择/确认/按钮/无异常）

## 增量记录（2026-10-17）：B 阶段 静态分析工具集成（SAST 线索）

### 新增 `apps/common/scanners.py` + `semgrep-rules.yml`
- 统一适配层：探测本机可用工具 → 运行 → 归一化为 `Lead{工具,规则,严重度,文件,行号,说明}`
- 已支持：**semgrep**（15 条内置离线规则：硬编码密钥、JWT 校验关闭、TLS 校验关闭、eval/exec、
  shell 注入、反序列化、yaml 不安全加载、SQL 拼接、CORS 通配、flask debug、弱哈希、JS XSS、Go/Java 命令执行）、
  **bandit**、**detect-secrets**；**gitleaks / trivy** 检测到二进制即启用
- 「可用则用、缺失降级」：工具没装不影响主流程；跨工具去重 + 严重度排序 + 条数上限
- 可用 `STRIDE_GPT_SEMGREP_CONFIG` 指向公司规则（如 `p/ci`）

### 注入 agent
- `run_analysis(seed_context=...)` 新增参数：把线索（`leads_markdown`，上限 40k 字符/60 条）附到
  每个子系统的初始提示词，明确标注「候选线索、可能误报，请核实并引用代码」
- 代码审计流程：扫描 → `scanner_start/scanner_done` 进度事件 → 分析 → 报告末尾附「静态分析线索」表格
- 报告元数据写入 `scanner_leads` 汇总（按工具/严重度）

### 界面与接口
- 代码审计页：扫描器可用性面板（含安装提示）+「启用静态分析线索」开关；运行日志显示线索统计
- API：`enable_scanners` 字段（JSON 与 multipart 均支持）；任务结果带 `scanner_summary`

### 依赖
- 新增 `scanners` 依赖组（bandit / detect-secrets / semgrep）并加入默认组；缺失时自动降级

### 验证
- 新增 10 个扫描器测试（探测/内置规则命中/干净代码零命中/去重排序/提示词截断/规则包校验）
- 端到端：含漏洞的 ZIP → 扫描得 10 条线索（semgrep 5 + bandit 5，高危 5）→ 注入 agent →
  报告含线索附录 + 2 条带证据威胁入库

## 增量记录（2026-10-17）：C/A 阶段 标准映射与开源工具互通

### C：CWE 映射 + STIX 2.1 导出（`apps/common/standards.py`）
- 威胁自动关联 CWE：16 组关键词规则（SQLi→CWE-89、XSS→CWE-79、命令注入→CWE-78、
  反序列化→CWE-502、路径穿越→CWE-22、硬编码凭据→CWE-798、JWT→CWE-347 等），
  未命中则按 STRIDE 类别回退（S→287、T→345、R→778、I→200、D→400、E→269），每条最多 3 个
- 归档路径统一注解：威胁模型归档、agentic 代码审计归档 → 入库 `threats.cwe`（新增列 + 自动迁移）
- SARIF 输出附 `properties.cwe`；威胁台账标签行展示 CWE
- **STIX 2.1 导出**：identity（本系统）+ 每条威胁一个 vulnerability（含 CWE/ATT&CK 外部引用）
  + report 聚合；ID 用 uuid5 确定性生成，便于多次导入去重
- 端点：`GET /api/v1/reports/{id}/stix`；报告弹窗新增「下载 STIX」

### A：Threat Dragon 互通（`apps/common/interop.py`）
- 导出：威胁 → Threat Dragon v2 模型 JSON（severity 由 DREAD 分数 / 验证结论推断，
  threats 挂在模型级），可直接在 Threat Dragon 里继续编辑、分配负责人、画数据流图
- 导入：解析 Threat Dragon 模型（标题/描述/图内组件/信任边界/已有威胁）生成结构化描述，
  作为威胁模型或代码审计的分析输入（已有威胁作为基线，避免重复识别）
- 入口：威胁模型页新增「导入外部模型（Threat Dragon JSON）」；
  报告弹窗新增「下载 Threat Dragon」；端点 `GET /api/v1/reports/{id}/threat-dragon`
- 不做的事（有意为之）：pytm 模型需要执行 Python 代码（RCE 风险，不执行）；
  Threagile 无 findings 导入能力，暂不接入

### 验证
- 新增 35 个测试（CWE 规则/回退/注释不可变性、STIX 结构与确定性 ID、Threat Dragon 往返导入、
  cwe 入库持久化、API 端点与错误码）
- 全量 937 passed，ruff 全绿；API 已重启，新端点在线

## Bugfix（2026-10-16）：系统配置页崩溃

### 现象
打开「系统配置」页，模型服务/安全策略等区块正常，但到「用量与成本」区块时整页抛
`NameError: name '_usage_month_groups' is not defined`（服务端日志有完整堆栈）。

### 原因
`main.py` 是模块级执行脚本：`render_settings()` 在第 2163 行就被调用，而它依赖的
`_usage_month_groups()` 定义在第 4262 行（页面函数区），此时尚未定义。AppTest/单测
此前没有覆盖"配置页生产路径"，所以没暴露。

### 修复
- 把 `_usage_month_groups()` 上移到配置页之前（第 1743 行附近），并加注释说明共用
- 顺带补齐配置页残留的硬编码中文（英文模式下仍显示中文）：当前配置摘要、token 上限
  滑块与帮助、保存状态说明、API Key 列表的「创建/最近使用」、API Key 帮助链接

### 回归防护
- 新增 `tests/test_web_settings.py`（5 个用例）：用 Streamlit AppTest 走与浏览器完全
  相同的执行路径，断言配置页八个区块齐全、中英文渲染、保存按钮真实落库、本月有调用
  记录时用量表格正常渲染
- 已验证该测试在修复前必然失败（NameError）、修复后通过
- 942 passed，ruff 全绿

## P7 工程化底座

### P7-1 结构化日志 + 全局错误边界
- `common/logging_setup.py`：JSON 行日志（ts/level/logger/msg/pid/thread + 上下文字段 +
  异常堆栈），单文件 5MB×5 轮转，写入 `~/.stride-gpt/logs/<组件>.jsonl`
- 上下文用 contextvars（trace/user/source/project…）：每个请求/页面重跑/任务线程独立，
  线程之间不串号；`recent_errors()` / `log_files()` 供状态页使用
- `web/error_boundary.py`：页面异常 → 友好错误卡片 + `ERR-XXXXXX` 编号 + 结构化日志 +
  审计日志；管理员可展开堆栈，普通用户只看编号；RerunException/StopException 原样透传
- API：请求追踪中间件（X-Request-ID、访问日志含耗时/状态码）+ 未处理异常返回 error_id
- scheduler：结构化日志 + 每计划 trace + 单计划失败不中断循环

### P7-2 SQLite 硬化
- `_conn()` 改为上下文管理器（原先连接从不关闭）：提交/回滚/必关闭
- WAL + busy_timeout=30s + synchronous=NORMAL + temp_store=MEMORY：Web/API/调度器并发写不再锁库
- 12 个索引（报告/威胁/审计/用量/计划/任务）
- `store.db_stats()`：文件与 WAL 大小、journal 模式、各表行数

### P7-3 关键链路日志
- 生成：开始/结束/失败（kind/provider/model/prompt 长度/耗时毫秒）
- 静态分析：开始/完成/失败（线索数、按工具统计）

### P7-4 任务持久化（jobs 表）
- `jobs` 表：状态机 queued→running→done/failed/cancelled/interrupted，参数/结果/进度持久化
- 重启恢复：启动时把 running/queued 标记为 `interrupted`（附「可重跑」提示）
- 重跑：`POST /api/v1/code-audit/jobs/{id}/retry`（复用参数与 ZIP 产物；令牌不落库）
- 取消：协作式取消标志落库；已完成任务 DELETE 改为删除记录并清理上传产物
- 安全：仓库令牌只驻内存；上传 ZIP ≤200MB；任务历史自动裁剪（保留 200 条）

### 验证
- 新增 52 个测试（日志 13、错误边界 6、API 追踪 4、SQLite 硬化 9、任务持久化 14 等）
- 988 passed，ruff 全绿

### P7-5 备份/恢复 + 系统状态页
- `common/backup.py`：备份包 = 数据库在线快照（WAL 一致性）+ 加密配置 + 密钥 +
  `manifest.json`（版本/时间/各文件 SHA-256/各表行数）；ZIP 存储、0600 权限
- 校验：manifest 格式 + 逐文件哈希 + `PRAGMA integrity_check`
- 恢复：先自动备份当前状态为 `pre-restore-*.zip`（保留 5 份）→ 临时文件 + 原子替换 →
  清理过期 WAL；返回「需重启」提示；`--no-pre-restore` 可关闭
- CLI：`python -m common.backup create|list|verify|restore`，配套 `scripts/backup.sh` /
  `scripts/restore.sh`
- 系统状态页（顶栏「系统状态」，仅管理员）：版本与运行时长、数据概况、最近任务
  （含「已中断」提示）、组件健康（数据库/模型服务/REST API/调度器/静态分析）、
  最近告警（结构化日志 WARNING+）、一键生成并下载备份 + 最近备份 + CLI 提示
- `/api/v1/health` 增强：返回数据库自检结果与运行时长（探针可用）
- 新增 24 个测试（备份 16 + 状态页 8）；全量 1012 passed，ruff 全绿

### P7-6 拆分 main.py（5027 行 → 434 行）
- 结构：`main.py`（启动装配：环境准备 → 配置加载 → set_page_config → 主题 → 登录门 →
  侧边栏/顶栏 → 页面路由）+ `shared.py`（公共导入/常量/会话读取）+ `widgets.py`
  （引导式描述、GitHub 仓库、架构图、Mermaid 等交互组件）+ `services.py`（报告归档与生成流程）
  + `auth.py`（登录/会话 Cookie/退出/模型回调）+ `theme.py`（CSS）+ `pages/*.py`（13 个页面）
- 会话快照改为动态读取：原先页面函数读模块级快照（`model_provider = st.session_state...`），
  拆分后会读到旧值；改为 `shared._state("model_provider")`，跨 rerun 不过期
- 拆分由 AST 脚本完成：函数体逐字搬运（含装饰器）、自动计算 import、避免页面反向依赖 main
- 防回归：`test_web_static.py` 增加「main.py < 700 行」「页面不得 import main」
  「名字遮蔽检查覆盖 apps/web 全部模块」
- 验证：13/13 页面逐页渲染通过（AppTest 探针）、1014 passed、ruff 全绿
