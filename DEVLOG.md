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
