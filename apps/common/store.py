"""服务端存储：配置持久化（加密）+ 报告历史（SQLite）+ 导出。

数据目录固定在 ~/.stride-gpt/，与仓库分离：
  - web_config.json  加密后的配置（Fernet）
  - web_key          Fernet 密钥（0600）
  - web.db           报告历史数据库
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import io
import json
import os
import sqlite3
import time
import zipfile
from datetime import datetime
from pathlib import Path

DATA_DIR = Path.home() / ".stride-gpt"
CONFIG_FILE = DATA_DIR / "web_config.json"
KEY_FILE = DATA_DIR / "web_key"
DB_FILE = DATA_DIR / "web.db"

# 需要持久化的字段：模型服务、分析参数、归档项目名、各家 API Key
SENSITIVE_KEYS = {
    "openai_api_key",
    "anthropic_api_key",
    "google_api_key",
    "mistral_api_key",
    "groq_api_key",
    "deepseek_api_key",
    "github_api_key",
    "lm_studio_api_key",
}
PERSIST_KEYS = [
    "model_provider",
    "selected_model",
    "token_limit",
    "use_thinking",
    "lm_studio_endpoint",
    "project_name",
    "security_baseline",
    "scrub_enabled",
    "report_brand",
    "report_footer",
    "ui_language",
    "verify_threats",
    "monthly_budget",
    "enable_scanners",
    *sorted(SENSITIVE_KEYS),
]

KIND_LABELS = {
    "code_analysis": "代码审计",
    "threat_model": "威胁模型",
    "attack_tree": "攻击树",
    "dfd": "数据流图",
    "mitigations": "缓解措施",
    "dread": "DREAD 风险评估",
    "test_cases": "测试用例",
}


# ---------------------------------------------------------------------------
# 配置持久化
# ---------------------------------------------------------------------------


def _ensure_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def _fernet():
    from cryptography.fernet import Fernet

    _ensure_dir()
    if KEY_FILE.exists():
        key = KEY_FILE.read_bytes().strip()
    else:
        key = Fernet.generate_key()
        KEY_FILE.write_bytes(key)
        with contextlib.suppress(OSError):
            KEY_FILE.chmod(0o600)
    return Fernet(key)


def save_config(values: dict) -> str:
    """把配置加密写入磁盘，返回保存时间。"""
    data = {k: values.get(k) for k in PERSIST_KEYS if values.get(k) not in (None, "")}
    saved_at = datetime.now().strftime("%Y-%m-%d %H:%M")
    payload = json.dumps(
        {"saved_at": saved_at, "values": data}, ensure_ascii=False
    ).encode("utf-8")
    _ensure_dir()
    CONFIG_FILE.write_bytes(_fernet().encrypt(payload))
    with contextlib.suppress(OSError):
        CONFIG_FILE.chmod(0o600)
    return saved_at


def load_config() -> dict:
    """读取已保存的配置；损坏或密钥丢失时返回空 dict。"""
    if not CONFIG_FILE.exists():
        return {}
    try:
        raw = _fernet().decrypt(CONFIG_FILE.read_bytes())
        return dict(json.loads(raw).get("values") or {})
    except Exception:
        return {}


def config_saved_at() -> str | None:
    if not CONFIG_FILE.exists():
        return None
    try:
        raw = _fernet().decrypt(CONFIG_FILE.read_bytes())
        return json.loads(raw).get("saved_at")
    except Exception:
        return None


def clear_config() -> None:
    for f in (CONFIG_FILE, KEY_FILE):
        with contextlib.suppress(OSError):
            f.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# 报告历史
# ---------------------------------------------------------------------------


def _conn() -> sqlite3.Connection:
    _ensure_dir()
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _conn() as c:
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                project TEXT NOT NULL DEFAULT '',
                kind TEXT NOT NULL,
                title TEXT NOT NULL DEFAULT '',
                provider TEXT NOT NULL DEFAULT '',
                model TEXT NOT NULL DEFAULT '',
                content_md TEXT NOT NULL DEFAULT '',
                content_json TEXT,
                meta TEXT
            )
            """
        )
        c.execute("CREATE INDEX IF NOT EXISTS idx_reports_kind ON reports(kind)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_reports_project ON reports(project)")
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS projects (
                name TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL DEFAULT ''
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project TEXT NOT NULL DEFAULT '',
                report_id INTEGER,
                threat_type TEXT NOT NULL DEFAULT '',
                scenario TEXT NOT NULL DEFAULT '',
                impact TEXT NOT NULL DEFAULT '',
                owasp_llm TEXT NOT NULL DEFAULT '',
                owasp_asi TEXT NOT NULL DEFAULT '',
                mitre TEXT NOT NULL DEFAULT '',
                insider TEXT NOT NULL DEFAULT '',
                risk_score REAL,
                status TEXT NOT NULL DEFAULT '待处理',
                owner TEXT NOT NULL DEFAULT '',
                note TEXT NOT NULL DEFAULT '',
                fingerprint TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL DEFAULT ''
            )
            """
        )
        c.execute("CREATE INDEX IF NOT EXISTS idx_threats_project ON threats(project)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_threats_fp ON threats(project, fingerprint)")
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS drafts (
                key TEXT PRIMARY KEY,
                payload TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL DEFAULT ''
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL DEFAULT '',
                key_hash TEXT NOT NULL UNIQUE,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT '',
                last_used_at TEXT NOT NULL DEFAULT ''
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS usage_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL DEFAULT '',
                actor TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT 'web',
                provider TEXT NOT NULL DEFAULT '',
                model TEXT NOT NULL DEFAULT '',
                kind TEXT NOT NULL DEFAULT '',
                project TEXT NOT NULL DEFAULT '',
                prompt_tokens INTEGER,
                completion_tokens INTEGER,
                total_tokens INTEGER,
                cost REAL
            )
            """
        )
        c.execute("CREATE INDEX IF NOT EXISTS idx_usage_ts ON usage_log(ts)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_usage_actor ON usage_log(actor)")
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS schedules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                interval_minutes INTEGER NOT NULL DEFAULT 1440,
                notify_on_change INTEGER NOT NULL DEFAULT 1,
                last_run TEXT NOT NULL DEFAULT '',
                last_status TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT ''
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL DEFAULT ''
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                created_at TEXT NOT NULL DEFAULT '',
                last_login TEXT NOT NULL DEFAULT ''
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL DEFAULT '',
                username TEXT NOT NULL DEFAULT '',
                action TEXT NOT NULL DEFAULT '',
                detail TEXT NOT NULL DEFAULT ''
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS webhooks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL DEFAULT '',
                kind TEXT NOT NULL DEFAULT 'generic',
                url TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT ''
            )
            """
        )
        # 增量迁移（老库补列）——必须放在所有建表之后
        _ensure_column(c, "api_keys", "daily_token_limit", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(c, "api_keys", "monthly_cost_limit", "REAL NOT NULL DEFAULT 0")
        _ensure_column(c, "threats", "verdict", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(c, "threats", "confidence", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(c, "threats", "verification_note", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(c, "threats", "verified_at", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(c, "threats", "subsystem", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(c, "threats", "source", "TEXT NOT NULL DEFAULT ''")
        _ensure_column(c, "threats", "evidence", "TEXT NOT NULL DEFAULT ''")


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
    """老库增量迁移：列不存在时补上。"""
    cols = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


def save_report(
    *,
    kind: str,
    content_md: str,
    title: str = "",
    project: str = "",
    content_json: str | None = None,
    provider: str = "",
    model: str = "",
    meta: dict | None = None,
) -> int:
    init_db()
    with _conn() as c:
        cur = c.execute(
            """
            INSERT INTO reports
                (created_at, project, kind, title, provider, model, content_md, content_json, meta)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                project or "",
                kind,
                title or "",
                provider or "",
                model or "",
                content_md or "",
                content_json,
                json.dumps(meta, ensure_ascii=False) if meta else None,
            ),
        )
        return int(cur.lastrowid or 0)


def list_reports(
    *,
    kind: str | None = None,
    project: str | None = None,
    search: str | None = None,
    limit: int = 300,
) -> list[dict]:
    init_db()
    with _conn() as c:
        rows = [dict(r) for r in c.execute("SELECT * FROM reports ORDER BY id DESC").fetchall()]
    if kind:
        rows = [r for r in rows if r["kind"] == kind]
    if project:
        rows = [r for r in rows if (r["project"] or "") == project]
    if search:
        kw = search.strip().lower()
        rows = [
            r
            for r in rows
            if kw in (r["title"] or "").lower()
            or kw in (r["project"] or "").lower()
            or kw in (r["content_md"] or "").lower()
        ]
    return rows[: max(1, limit)]


def get_report(report_id: int) -> dict | None:
    init_db()
    with _conn() as c:
        row = c.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    return dict(row) if row else None


def delete_report(report_id: int) -> None:
    init_db()
    with _conn() as c:
        c.execute("DELETE FROM reports WHERE id = ?", (report_id,))


def report_count() -> int:
    init_db()
    with _conn() as c:
        return int(c.execute("SELECT COUNT(*) FROM reports").fetchone()[0])


# ---------------------------------------------------------------------------
# 导出
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
  :root { color-scheme: dark; }
  body {
    margin: 0; padding: 48px 24px; background: #14121B; color: #DAD7E4;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC",
                 "Hiragino Sans GB", "Microsoft YaHei", "Noto Sans CJK SC", sans-serif;
    font-size: 15px; line-height: 1.75;
  }
  .wrap { max-width: 960px; margin: 0 auto; }
  .kicker { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
            font-size: 12px; letter-spacing: .28em; color: #8E82C8; }
  h1.title { font-size: 28px; margin: 10px 0 6px; letter-spacing: -0.01em; }
  .meta { color: #948EA8; font-size: 13px; border-bottom: 1px solid #2C2839;
          padding-bottom: 16px; margin-bottom: 26px; }
  h2 { font-size: 20px; margin-top: 34px; border-left: 3px solid #7C6BD6; padding-left: 10px; }
  h3 { font-size: 16px; margin-top: 24px; color: #E7E4F0; }
  a { color: #A99AF0; }
  table { border-collapse: collapse; width: 100%; font-size: 13.5px; margin: 14px 0; }
  th { background: #221D31; color: #C9C3DB; text-align: left; }
  th, td { border: 1px solid #2C2839; padding: 8px 10px; vertical-align: top; }
  tr:nth-child(even) td { background: rgba(255,255,255,.015); }
  code { background: #0F0D16; border: 1px solid #2C2839; border-radius: 4px;
         padding: 1px 5px; font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 13px; }
  pre { background: #0F0D16; border: 1px solid #2C2839; border-radius: 8px;
        padding: 14px 16px; overflow-x: auto; }
  blockquote { border-left: 3px solid #453C68; margin: 12px 0; padding: 6px 14px; color: #A29BB8; }
  .foot { margin-top: 42px; padding-top: 14px; border-top: 1px solid #2C2839;
          color: #6E6883; font-size: 12px; font-family: ui-monospace, Menlo, monospace; }
</style>
</head>
<body>
<div class="wrap">
  <div class="kicker">WEIYUN · RISK MODELING AGENT</div>
  <h1 class="title">__TITLE__</h1>
  <div class="meta">__META__</div>
  __BODY__
  <div class="foot">威云-风险建模智能体 · 导出时间 __EXPORTED__</div>
</div>
</body>
</html>
"""


def report_to_html(report: dict) -> str:
    """把一条报告渲染成自带紫色主题的独立 HTML。"""
    from markdown_it import MarkdownIt

    md = MarkdownIt("commonmark").enable("table")
    body = md.render(report.get("content_md") or "")
    kind_label = KIND_LABELS.get(report.get("kind", ""), report.get("kind", ""))
    meta_bits = [
        f"项目：{report.get('project') or '未命名'}",
        f"类型：{kind_label}",
        f"生成时间：{report.get('created_at') or ''}",
    ]
    if report.get("provider") or report.get("model"):
        meta_bits.append(f"模型：{report.get('provider') or ''} / {report.get('model') or ''}")
    title = f"{kind_label} · {report.get('project') or '未命名'}"
    return (
        _HTML_TEMPLATE.replace("__TITLE__", _esc(title))
        .replace("__META__", _esc(" · ".join(meta_bits)))
        .replace("__BODY__", body)
        .replace("__EXPORTED__", datetime.now().strftime("%Y-%m-%d %H:%M"))
    )


def _esc(text: str) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def export_zip(reports: list[dict]) -> bytes:
    """把报告打包成 ZIP（每篇含 md + html，附 manifest.json）。"""
    buf = io.BytesIO()
    manifest = []
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for r in reports:
            tag = KIND_LABELS.get(r["kind"], r["kind"])
            base = f"{r['id']:04d}_{r['kind']}"
            zf.writestr(f"{base}.md", r.get("content_md") or "")
            zf.writestr(f"{base}.html", report_to_html(r))
            manifest.append(
                {
                    "id": r["id"],
                    "kind": r["kind"],
                    "kind_label": tag,
                    "project": r.get("project") or "",
                    "created_at": r.get("created_at") or "",
                    "model": r.get("model") or "",
                }
            )
        zf.writestr(
            "manifest.json",
            json.dumps(manifest, ensure_ascii=False, indent=2),
        )
    return buf.getvalue()


# ---------------------------------------------------------------------------
# 项目工作区
# ---------------------------------------------------------------------------

THREAT_STATUSES = ["待处理", "已确认", "已修复", "已接受", "已忽略"]


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def upsert_project(name: str, description: str = "") -> None:
    """新建项目或刷新更新时间；description 非空时覆盖。"""
    if not name:
        return
    init_db()
    now = _now()
    with _conn() as c:
        c.execute(
            """
            INSERT INTO projects(name, description, created_at, updated_at)
            VALUES(?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                description = CASE WHEN excluded.description != ''
                                   THEN excluded.description ELSE projects.description END,
                updated_at = excluded.updated_at
            """,
            (name, description or "", now, now),
        )


def update_project_description(name: str, description: str) -> None:
    init_db()
    with _conn() as c:
        c.execute(
            "UPDATE projects SET description = ?, updated_at = ? WHERE name = ?",
            (description or "", _now(), name),
        )


def get_project(name: str) -> dict | None:
    init_db()
    with _conn() as c:
        row = c.execute("SELECT * FROM projects WHERE name = ?", (name,)).fetchone()
    return dict(row) if row else None


def sync_projects_from_reports() -> None:
    """把历史报告里出现过的项目补登记为正式项目。"""
    init_db()
    with _conn() as c:
        rows = c.execute(
            "SELECT DISTINCT project FROM reports WHERE project != ''"
        ).fetchall()
        for r in rows:
            c.execute(
                """
                INSERT INTO projects(name, description, created_at, updated_at)
                VALUES(?, '', ?, ?)
                ON CONFLICT(name) DO NOTHING
                """,
                (r["project"], _now(), _now()),
            )


def list_projects() -> list[dict]:
    """项目列表（含报告数 / 威胁数 / 待处理数）。"""
    init_db()
    with _conn() as c:
        rows = c.execute(
            """
            SELECT p.name, p.description, p.created_at, p.updated_at,
                (SELECT COUNT(*) FROM reports r WHERE r.project = p.name) AS report_count,
                (SELECT COUNT(*) FROM threats t WHERE t.project = p.name) AS threat_count,
                (SELECT COUNT(*) FROM threats t WHERE t.project = p.name
                   AND t.status = '待处理') AS open_count,
                (SELECT MAX(created_at) FROM reports r WHERE r.project = p.name) AS last_report
            FROM projects p
            ORDER BY p.updated_at DESC, p.name
            """
        ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# 威胁台账
# ---------------------------------------------------------------------------


def _threat_fingerprint(threat_type: str, scenario: str) -> str:
    raw = f"{(threat_type or '').strip().lower()}|{(scenario or '').strip().lower()}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


def add_threats(
    project: str, report_id: int | None, threats: list[dict], *, source: str = ""
) -> int:
    """写入威胁条目，按（类型+场景）指纹在项目内去重。返回新增数量。

    ``source`` 标记来源（如 "agentic" 表示代码审计、带代码证据）。
    """
    if not project or not threats:
        return 0
    init_db()
    inserted = 0
    now = _now()
    with _conn() as c:
        for t in threats:
            ttype = str(t.get("Threat Type") or t.get("threat_type") or "").strip()
            scenario = str(t.get("Scenario") or t.get("scenario") or "").strip()
            if not scenario:
                continue
            fp = _threat_fingerprint(ttype, scenario)
            exists = c.execute(
                "SELECT 1 FROM threats WHERE project = ? AND fingerprint = ?",
                (project, fp),
            ).fetchone()
            if exists:
                continue
            evidence = t.get("evidence") or []
            c.execute(
                """
                INSERT INTO threats
                    (project, report_id, threat_type, scenario, impact, owasp_llm, owasp_asi,
                     mitre, insider, status, created_at, updated_at, fingerprint,
                     subsystem, source, evidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '待处理', ?, ?, ?, ?, ?, ?)
                """,
                (
                    project,
                    report_id,
                    ttype,
                    scenario,
                    str(t.get("Potential Impact") or t.get("impact") or "").strip(),
                    str(t.get("OWASP_LLM") or "").strip(),
                    str(t.get("OWASP_ASI") or "").strip(),
                    str(t.get("MITRE_ATTACK") or t.get("MITRE") or "").strip(),
                    str(t.get("INSIDER_CATEGORY") or "").strip(),
                    now,
                    now,
                    fp,
                    str(t.get("subsystem") or "").strip(),
                    str(t.get("source") or source or "").strip(),
                    json.dumps(evidence, ensure_ascii=False)[:20000] if evidence else "",
                ),
            )
            inserted += 1
    return inserted


def list_threats(
    *, project: str | None = None, status: str | None = None, search: str | None = None
) -> list[dict]:
    init_db()
    with _conn() as c:
        rows = [dict(r) for r in c.execute("SELECT * FROM threats ORDER BY id").fetchall()]
    if project:
        rows = [r for r in rows if r["project"] == project]
    if status:
        rows = [r for r in rows if r["status"] == status]
    if search:
        kw = search.strip().lower()
        rows = [
            r
            for r in rows
            if kw in (r["scenario"] or "").lower()
            or kw in (r["threat_type"] or "").lower()
            or kw in (r["owner"] or "").lower()
        ]
    return rows


def update_threats(edits: list[dict]) -> int:
    """批量更新台账（status / owner / note）。"""
    if not edits:
        return 0
    init_db()
    now = _now()
    n = 0
    with _conn() as c:
        for e in edits:
            rid = int(e.get("id"))
            c.execute(
                """
                UPDATE threats SET status = ?, owner = ?, note = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    str(e.get("status") or "待处理"),
                    str(e.get("owner") or ""),
                    str(e.get("note") or ""),
                    now,
                    rid,
                ),
            )
            n += 1
    return n


def threat_stats(project: str) -> dict:
    rows = list_threats(project=project)
    by_status = dict.fromkeys(THREAT_STATUSES, 0)
    by_type: dict[str, int] = {}
    for r in rows:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
        by_type[r["threat_type"]] = by_type.get(r["threat_type"], 0) + 1
    return {"total": len(rows), "by_status": by_status, "by_type": by_type}


def apply_dread_scores(project: str, assessment: dict) -> int:
    """把 DREAD 报告中的风险分回填到对应威胁（按场景文本匹配）。"""
    items = (assessment or {}).get("Risk Assessment") or []
    if not project or not isinstance(items, list):
        return 0
    init_db()
    n = 0
    with _conn() as c:
        for item in items:
            if not isinstance(item, dict):
                continue
            scenario = str(item.get("Scenario") or "").strip()
            if not scenario:
                continue
            try:
                score = sum(
                    float(item.get(k) or 0)
                    for k in (
                        "Damage Potential",
                        "Reproducibility",
                        "Exploitability",
                        "Affected Users",
                        "Discoverability",
                    )
                ) / 5.0
            except (TypeError, ValueError):
                continue
            cur = c.execute(
                "UPDATE threats SET risk_score = ?, updated_at = ? WHERE project = ? AND scenario = ?",
                (round(score, 2), _now(), project, scenario),
            )
            n += cur.rowcount or 0
    return n


# ---------------------------------------------------------------------------
# 草稿
# ---------------------------------------------------------------------------


def save_draft(key: str, payload: dict) -> None:
    init_db()
    with _conn() as c:
        c.execute(
            """
            INSERT INTO drafts(key, payload, updated_at) VALUES(?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET payload = excluded.payload, updated_at = excluded.updated_at
            """,
            (key, json.dumps(payload, ensure_ascii=False), _now()),
        )


def load_draft(key: str) -> dict | None:
    if not key:
        return None
    init_db()
    with _conn() as c:
        row = c.execute("SELECT payload FROM drafts WHERE key = ?", (key,)).fetchone()
    if not row:
        return None
    try:
        return dict(json.loads(row["payload"]))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# 会话令牌（cookie 记忆登录）
# ---------------------------------------------------------------------------

SESSION_COOKIE = "wy_session"


def _session_secret() -> bytes:
    f = DATA_DIR / "web_session_secret"
    if f.exists():
        return f.read_bytes().strip()
    _ensure_dir()
    secret = os.urandom(32).hex().encode("utf-8")
    f.write_bytes(secret)
    with contextlib.suppress(OSError):
        f.chmod(0o600)
    return secret


def get_meta(key: str, default: str = "") -> str:
    init_db()
    with _conn() as c:
        row = c.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return str(row["value"]) if row else default


def set_meta(key: str, value: str) -> None:
    init_db()
    with _conn() as c:
        c.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )


def session_epoch(username: str) -> str:
    """会话纪元：登出时递增，使该用户此前签发的所有 cookie 立即失效。"""
    return get_meta(f"session_epoch:{username}", "0")


def bump_session_epoch(username: str) -> str:
    epoch = str(int(session_epoch(username) or "0") + 1)
    set_meta(f"session_epoch:{username}", epoch)
    return epoch


def make_session_token(username: str, days: int = 7) -> str:
    payload = json.dumps(
        {"u": username, "exp": int(time.time()) + days * 86400, "e": session_epoch(username)},
        separators=(",", ":"),
    ).encode("utf-8")
    sig = hmac.new(_session_secret(), payload, hashlib.sha256).hexdigest()
    b64 = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    return f"{b64}.{sig}"


def verify_session_token(token: str | None) -> str | None:
    if not token:
        return None
    try:
        b64, sig = token.split(".", 1)
        payload = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
        expected = hmac.new(_session_secret(), payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        data = json.loads(payload)
        if int(data.get("exp", 0)) < int(time.time()):
            return None
        username = str(data.get("u") or "")
        if not username:
            return None
        # 会话纪元不匹配 = 用户已登出（或凭据已变更）
        if str(data.get("e", "0")) != session_epoch(username):
            return None
        return username
    except Exception:
        return None


def backfill_project(project: str) -> int:
    """把已有的威胁模型 / DREAD 报告回填到台账（幂等，重复调用不会重复写入）。

    分两段处理：先补威胁条目，再用 DREAD 回填风险分（否则会匹配不到威胁）。
    """
    if not project:
        return 0
    added = 0
    _reports = [r for r in list_reports(project=project, limit=1000) if r.get("content_json")]
    _parsed = []
    for r in _reports:
        try:
            _parsed.append((r, json.loads(r["content_json"])))
        except Exception:
            continue
    for r, data in _parsed:
        if r["kind"] == "threat_model":
            added += add_threats(project, r["id"], list((data or {}).get("threat_model") or []))
    for r, data in _parsed:
        if r["kind"] == "dread":
            apply_dread_scores(project, data or {})
    return added


# ---------------------------------------------------------------------------
# API Key 管理
# ---------------------------------------------------------------------------

API_KEY_PREFIX = "wy_"


def _hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def create_api_key(name: str) -> str:
    """创建 API Key，返回明文（仅此一次可见）。"""
    init_db()
    plain = API_KEY_PREFIX + base64.urlsafe_b64encode(os.urandom(24)).decode("ascii").rstrip("=")
    with _conn() as c:
        c.execute(
            "INSERT INTO api_keys(name, key_hash, enabled, created_at, last_used_at)"
            " VALUES(?, ?, 1, ?, '')",
            (name or "未命名", _hash_api_key(plain), _now()),
        )
    return plain


def verify_api_key(key: str | None) -> str | None:
    """校验 API Key；有效则返回名称并刷新 last_used_at。"""
    if not key:
        return None
    init_db()
    with _conn() as c:
        row = c.execute(
            "SELECT id, name, enabled FROM api_keys WHERE key_hash = ?",
            (_hash_api_key(key),),
        ).fetchone()
        if not row or not row["enabled"]:
            return None
        c.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (_now(), row["id"]))
    return str(row["name"])


def list_api_keys() -> list[dict]:
    init_db()
    with _conn() as c:
        rows = c.execute(
            "SELECT id, name, enabled, created_at, last_used_at FROM api_keys ORDER BY id DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def revoke_api_key(key_id: int) -> None:
    init_db()
    with _conn() as c:
        c.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))


# ---------------------------------------------------------------------------
# Webhook（工单/通知集成）
# ---------------------------------------------------------------------------

WEBHOOK_KINDS = ["generic", "feishu", "wecom", "dingtalk"]


def add_webhook(name: str, url: str, kind: str = "generic") -> int:
    init_db()
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO webhooks(name, kind, url, enabled, created_at) VALUES(?, ?, ?, 1, ?)",
            (name or "未命名", kind or "generic", url, _now()),
        )
        return int(cur.lastrowid or 0)


def list_webhooks() -> list[dict]:
    init_db()
    with _conn() as c:
        rows = c.execute(
            "SELECT id, name, kind, url, enabled, created_at FROM webhooks ORDER BY id DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def delete_webhook(webhook_id: int) -> None:
    init_db()
    with _conn() as c:
        c.execute("DELETE FROM webhooks WHERE id = ?", (webhook_id,))


def threat_webhook_payload(kind: str, project: str, threats: list[dict]) -> dict:
    """按 webhook 类型构造推送体。"""
    lines = [f"【{project}】威胁台账推送（{len(threats)} 条）"]
    for t in threats[:20]:
        score = f"{float(t['risk_score']):.1f}" if t.get("risk_score") is not None else "-"
        lines.append(
            f"· [{t.get('threat_type')}] {t.get('scenario')} | 风险 {score} | {t.get('status')}"
        )
        if t.get("owner"):
            lines[-1] += f" | 负责 {t['owner']}"
    text = "\n".join(lines)
    if kind == "feishu":
        return {"msg_type": "text", "content": {"text": text}}
    if kind in ("wecom", "dingtalk"):
        return {"msgtype": "text", "text": {"content": text}}
    return {
        "event": "threat_register.push",
        "project": project,
        "threats": [
            {
                "threat_type": t.get("threat_type"),
                "scenario": t.get("scenario"),
                "impact": t.get("impact"),
                "risk_score": t.get("risk_score"),
                "status": t.get("status"),
                "owner": t.get("owner"),
                "note": t.get("note"),
            }
            for t in threats
        ],
    }


# ---------------------------------------------------------------------------
# 用户与审计
# ---------------------------------------------------------------------------

ROLES = ["admin", "user"]
_PBKDF2_ITERATIONS = 200_000


def _hash_password(password: str, salt_hex: str | None = None) -> tuple[str, str]:
    salt = bytes.fromhex(salt_hex) if salt_hex else os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS)
    return digest.hex(), salt.hex()


def create_user(username: str, password: str, role: str = "user") -> None:
    """创建用户；用户名已存在抛 ValueError。"""
    username = (username or "").strip()
    if not username:
        raise ValueError("用户名不能为空")
    if len(password or "") < 6:
        raise ValueError("密码至少 6 位")
    if role not in ROLES:
        raise ValueError(f"角色必须是 {ROLES}")
    init_db()
    pw_hash, salt = _hash_password(password)
    with _conn() as c:
        exists = c.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        if exists:
            raise ValueError(f"用户「{username}」已存在")
        c.execute(
            "INSERT INTO users(username, password_hash, salt, role, created_at, last_login)"
            " VALUES(?, ?, ?, ?, ?, '')",
            (username, pw_hash, salt, role, _now()),
        )


def verify_user(username: str, password: str) -> dict | None:
    """校验用户名密码；成功返回 {username, role} 并刷新 last_login。"""
    if not username or not password:
        return None
    init_db()
    with _conn() as c:
        row = c.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if not row:
            return None
        digest, _salt = _hash_password(password, row["salt"])
        if not hmac.compare_digest(digest, row["password_hash"]):
            return None
        c.execute("UPDATE users SET last_login = ? WHERE username = ?", (_now(), username))
    return {"username": username, "role": str(row["role"])}


def get_user(username: str) -> dict | None:
    init_db()
    with _conn() as c:
        row = c.execute(
            "SELECT username, role, created_at, last_login FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    return dict(row) if row else None


def list_users() -> list[dict]:
    init_db()
    with _conn() as c:
        rows = c.execute(
            "SELECT username, role, created_at, last_login FROM users ORDER BY username"
        ).fetchall()
    return [dict(r) for r in rows]


def delete_user(username: str) -> None:
    init_db()
    with _conn() as c:
        c.execute("DELETE FROM users WHERE username = ?", (username,))


def set_user_password(username: str, password: str) -> None:
    if len(password or "") < 6:
        raise ValueError("密码至少 6 位")
    pw_hash, salt = _hash_password(password)
    init_db()
    with _conn() as c:
        c.execute(
            "UPDATE users SET password_hash = ?, salt = ? WHERE username = ?",
            (pw_hash, salt, username),
        )


def log_action(username: str, action: str, detail: str = "") -> None:
    """写入审计日志（失败静默，不影响业务）。"""
    try:
        init_db()
        with _conn() as c:
            c.execute(
                "INSERT INTO audit_log(ts, username, action, detail) VALUES(?, ?, ?, ?)",
                (_now(), username or "匿名", action, detail or ""),
            )
    except Exception:
        pass


def list_audit(limit: int = 200, username: str | None = None) -> list[dict]:
    init_db()
    with _conn() as c:
        rows = c.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    result = [dict(r) for r in rows]
    if username:
        result = [r for r in result if r["username"] == username]
    return result


# ---------------------------------------------------------------------------
# 定时分析计划
# ---------------------------------------------------------------------------


def add_schedule(project: str, interval_minutes: int = 1440, notify_on_change: bool = True) -> int:
    init_db()
    with _conn() as c:
        existing = c.execute("SELECT id FROM schedules WHERE project = ?", (project,)).fetchone()
        if existing:
            c.execute(
                "UPDATE schedules SET enabled = 1, interval_minutes = ?, notify_on_change = ?"
                " WHERE id = ?",
                (int(interval_minutes), int(bool(notify_on_change)), existing["id"]),
            )
            return int(existing["id"])
        cur = c.execute(
            "INSERT INTO schedules(project, enabled, interval_minutes, notify_on_change, created_at)"
            " VALUES(?, 1, ?, ?, ?)",
            (project, int(interval_minutes), int(bool(notify_on_change)), _now()),
        )
        return int(cur.lastrowid or 0)


def list_schedules() -> list[dict]:
    init_db()
    with _conn() as c:
        rows = c.execute("SELECT * FROM schedules ORDER BY id").fetchall()
    return [dict(r) for r in rows]


def get_schedule(schedule_id: int) -> dict | None:
    init_db()
    with _conn() as c:
        row = c.execute("SELECT * FROM schedules WHERE id = ?", (schedule_id,)).fetchone()
    return dict(row) if row else None


def update_schedule(schedule_id: int, **fields) -> None:
    allowed = {"enabled", "interval_minutes", "notify_on_change", "last_run", "last_status"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return
    init_db()
    with _conn() as c:
        sets = ", ".join(f"{k} = ?" for k in updates)
        c.execute(f"UPDATE schedules SET {sets} WHERE id = ?", (*updates.values(), schedule_id))


def delete_schedule(schedule_id: int) -> None:
    init_db()
    with _conn() as c:
        c.execute("DELETE FROM schedules WHERE id = ?", (schedule_id,))


def _parse_ts(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return None


def due_schedules(now: datetime | None = None) -> list[dict]:
    """返回到期的启用计划（从未运行过的立即到期）。"""
    now = now or datetime.now()
    due = []
    for row in list_schedules():
        if not row["enabled"]:
            continue
        last = _parse_ts(row["last_run"])
        if last is None or (now - last).total_seconds() >= max(1, int(row["interval_minutes"])) * 60:
            due.append(row)
    return due


def text_webhook_payload(kind: str, title: str, text: str) -> dict:
    """纯文本类 Webhook 推送体（飞书/企微/钉钉/通用）。"""
    body = f"【{title}】\n{text}"
    if kind == "feishu":
        return {"msg_type": "text", "content": {"text": body}}
    if kind in ("wecom", "dingtalk"):
        return {"msgtype": "text", "text": {"content": body}}
    return {"event": "notification", "title": title, "text": text}


# ---------------------------------------------------------------------------
# 用量与成本
# ---------------------------------------------------------------------------


def log_usage(
    *,
    actor: str = "",
    source: str = "web",
    provider: str = "",
    model: str = "",
    kind: str = "",
    project: str = "",
    prompt_tokens: int | None = None,
    completion_tokens: int | None = None,
    cost: float | None = None,
) -> int:
    """记录一次模型调用的用量与估算成本。"""
    init_db()
    total = None
    if prompt_tokens is not None or completion_tokens is not None:
        total = int(prompt_tokens or 0) + int(completion_tokens or 0)
    with _conn() as c:
        cur = c.execute(
            """
            INSERT INTO usage_log
                (ts, actor, source, provider, model, kind, project,
                 prompt_tokens, completion_tokens, total_tokens, cost)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _now(),
                actor or "",
                source or "web",
                provider or "",
                model or "",
                kind or "",
                project or "",
                prompt_tokens,
                completion_tokens,
                total,
                cost,
            ),
        )
        return int(cur.lastrowid or 0)


def usage_rows(since: str | None = None, until: str | None = None) -> list[dict]:
    """按时间范围取用量明细（ts 为 'YYYY-mm-dd HH:MM:SS'，字符串比较即可）。"""
    init_db()
    sql = "SELECT * FROM usage_log"
    params: list = []
    if since or until:
        clauses = []
        if since:
            clauses.append("ts >= ?")
            params.append(since)
        if until:
            clauses.append("ts <= ?")
            params.append(until)
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY id DESC"
    with _conn() as c:
        return [dict(r) for r in c.execute(sql, params).fetchall()]


def usage_summary(since: str | None = None, until: str | None = None) -> dict:
    """汇总：总量 + 按模型/项目/用户/来源分组。"""
    rows = usage_rows(since, until)
    totals = {"calls": len(rows), "prompt_tokens": 0, "completion_tokens": 0, "cost": 0.0, "cost_known": False}
    groups: dict[str, dict[str, dict]] = {"model": {}, "project": {}, "actor": {}, "source": {}}
    for row in rows:
        totals["prompt_tokens"] += int(row.get("prompt_tokens") or 0)
        totals["completion_tokens"] += int(row.get("completion_tokens") or 0)
        if row.get("cost") is not None:
            totals["cost"] += float(row["cost"])
            totals["cost_known"] = True
        for field, key in (
            ("model", row.get("model") or "未知"),
            ("project", row.get("project") or "未命名"),
            ("actor", row.get("actor") or "匿名"),
            ("source", row.get("source") or "web"),
        ):
            bucket = groups[field].setdefault(
                key, {"calls": 0, "tokens": 0, "cost": 0.0, "cost_known": False}
            )
            bucket["calls"] += 1
            bucket["tokens"] += int(row.get("prompt_tokens") or 0) + int(
                row.get("completion_tokens") or 0
            )
            if row.get("cost") is not None:
                bucket["cost"] += float(row["cost"])
                bucket["cost_known"] = True
    totals["total_tokens"] = totals["prompt_tokens"] + totals["completion_tokens"]
    return {"totals": totals, "groups": groups}


def usage_for_actor_today(actor: str) -> dict:
    day = datetime.now().strftime("%Y-%m-%d")
    rows = [r for r in usage_rows(since=f"{day} 00:00:00") if (r.get("actor") or "") == actor]
    tokens = sum(
        int(r.get("prompt_tokens") or 0) + int(r.get("completion_tokens") or 0) for r in rows
    )
    cost = sum(float(r.get("cost") or 0) for r in rows)
    return {"calls": len(rows), "tokens": tokens, "cost": cost}


def usage_for_actor_month(actor: str) -> dict:
    month = datetime.now().strftime("%Y-%m")
    rows = [r for r in usage_rows(since=f"{month}-01 00:00:00") if (r.get("actor") or "") == actor]
    cost = sum(float(r.get("cost") or 0) for r in rows)
    tokens = sum(
        int(r.get("prompt_tokens") or 0) + int(r.get("completion_tokens") or 0) for r in rows
    )
    return {"calls": len(rows), "tokens": tokens, "cost": cost}


def set_api_key_quota(key_id: int, daily_token_limit: int = 0, monthly_cost_limit: float = 0) -> None:
    init_db()
    with _conn() as c:
        c.execute(
            "UPDATE api_keys SET daily_token_limit = ?, monthly_cost_limit = ? WHERE id = ?",
            (int(daily_token_limit or 0), float(monthly_cost_limit or 0), key_id),
        )


def get_api_key_by_name(name: str) -> dict | None:
    init_db()
    with _conn() as c:
        row = c.execute("SELECT * FROM api_keys WHERE name = ?", (name,)).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# 威胁验证（对抗式复核）
# ---------------------------------------------------------------------------

VERDICTS = ["已确认", "存疑", "已驳回"]
CONFIDENCES = ["高", "中", "低"]


def apply_verification(project: str, results: list[dict]) -> int:
    """按（类型+场景）指纹把验证结果写回台账。"""
    if not project or not results:
        return 0
    init_db()
    updated = 0
    now = _now()
    with _conn() as c:
        for item in results:
            ttype = str(item.get("threat_type") or "").strip()
            scenario = str(item.get("scenario") or "").strip()
            if not scenario:
                continue
            fingerprint = _threat_fingerprint(ttype, scenario)
            cur = c.execute(
                """
                UPDATE threats
                SET verdict = ?, confidence = ?, verification_note = ?, verified_at = ?
                WHERE project = ? AND fingerprint = ?
                """,
                (
                    str(item.get("verdict") or ""),
                    str(item.get("confidence") or ""),
                    str(item.get("reason") or ""),
                    now,
                    project,
                    fingerprint,
                ),
            )
            updated += cur.rowcount or 0
    return updated


def threat_verdict_stats(project: str | None = None) -> dict:
    rows = list_threats(project=project)
    stats = dict.fromkeys(VERDICTS, 0)
    unverified = 0
    for row in rows:
        if row.get("verdict") in stats and row["verdict"]:
            stats[row["verdict"]] += 1
        else:
            unverified += 1
    return {**stats, "未验证": unverified, "total": len(rows)}
