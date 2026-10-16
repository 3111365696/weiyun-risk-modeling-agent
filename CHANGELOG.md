# 更新日志

本项目是开源项目 [stride-gpt](https://github.com/msoedov/stride-gpt) 的中文本地化发行版
「威云-风险建模智能体」。以下按功能阶段记录变更。

版本规则：主版本 = 交付形态变化，次版本 = 功能阶段（P 编号），修订号 = 缺陷修复。
数据库结构版本见 `schema_migrations` 表（`store.schema_version()`）。

---

## 1.0.0（本地化发行版首次整合发布）

把 stride-gpt 从原型打磨为可交付的内部系统：中文化 + 紫色专业界面 + 登录/多用户 +
全流程威胁建模与代码审计 + 工程化底座 + 安全与权限 + 交付物料。

### 特性总览

- **STRIDE 威胁建模**：威胁模型、数据流图、攻击树、缓解措施、DREAD 风险评估、Gherkin 测试用例
- **Agentic 代码审计**：ZIP / Git 仓库 → 自动探索代码 → 带证据（文件:行）的威胁入库 + SARIF
- **静态分析线索**：Semgrep（内置离线规则包）/ Bandit / detect-secrets，gitleaks / trivy 探测式启用
- **威胁台账与看板**：状态流转、负责人、备注、证据、验证结论（已确认/存疑/已驳回）、风险分排序
- **报告体系**：Markdown / JSON / HTML / SARIF / Word / PDF / ZIP；STIX 2.1；Threat Dragon 互通
- **自动化**：一键全流程、定时分析（scheduler + cron）、Webhook 推送（飞书/企微/钉钉/通用）
- **多模型**：OpenAI / Anthropic / Gemini / DeepSeek / Mistral / Groq / LM Studio（本地）
- **REST API**：全套端点、API Key（作用域/有效期/轮换）、任务持久化与重跑
- **多用户**：admin/user 角色、项目级成员（owner/editor/viewer）、审计日志、会话 Cookie
- **企业策略**：企业安全基线注入、敏感信息脱敏、月度预算与配额
- **中英双语**：全界面切换，i18n 覆盖率门禁防回归

### 工程化（P7）

- 结构化日志：JSON 行、5MB×5 轮转、trace/user/project 上下文、`recent_errors()`
- 全局错误边界：页面异常 → 友好错误卡片 + `ERR-XXXXXX` 编号 + 日志 + 审计
- SQLite 硬化：WAL、busy_timeout、连接必关闭、12+ 索引、`db_stats()/db_check()`
- 任务持久化：`jobs` 表、重启恢复（interrupted）、`retry` 重跑、令牌不落库
- 备份/恢复：数据库在线快照 + 加密配置 + manifest（SHA-256/行数）+ 校验 + 原子恢复
- 系统状态页：版本/运行时长、组件健康、最近任务与告警、一键备份下载
- 模块化：`main.py` 5027 → 442 行，拆为 `shared/widgets/services/auth/theme/pages/*`

### 安全与账号（P8）

- 密码策略、修改/重置密码（旧会话立即失效）、登录失败锁定（5 次/5 分钟、10 次/30 分钟）
- 会话：有效期可配（1-30 天）、退出所有设备、强制下线、Secure Cookie 开关
- API Key：read/write 作用域、有效期、一键轮换、创建人归属
- 项目级 RBAC：成员角色、只读项目禁用写操作、API 侧按密钥 owner 判定
- i18n 覆盖率门禁：AST 扫描未包裹的中文字面量

### 交付与运维（P9）

- 版本与迁移：`common/version.py`（版本/git 提交/Python）、`schema_migrations` 表
- 部署物料：docker-compose（web+api+scheduler）、systemd 单元、安装/升级脚本
- 文档三本：用户手册、管理员手册、运维手册
- 质量门：1047+ 测试、端到端流程测试、性能冒烟基准、ruff

### 相对上游 stride-gpt 的变化

- 全量中文化 + 中英双语切换；紫色专业主题；登录页与访问控制
- 本地数据落地（`~/.stride-gpt`）：SQLite + 加密配置 + 备份；不依赖外部数据库
- 新增：威胁台账、项目工作区、DREAD 页面、测试用例页面、报告历史、用户与审计、
  系统配置、系统状态；REST API 与调度器；Webhook；配额与用量
- 移除：与本地化无关的上游遥测与外部依赖（pyarrow 等）

---

## 缺陷修复记录（节选）

- 系统配置页 `NameError`：`_usage_month_groups` 定义晚于调用（P7-5 前）
- i18n 数据/文案混用导致英文模式统计恒为 0（P8-3a）
- 报告详情弹窗标题在导入时固定，语言切换不生效（P8-3a）
- 模块级会话快照导致拆分后页面读到旧值（P7-6，改为 `_state()` 动态读取）
