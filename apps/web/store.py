"""服务端存储：配置持久化（加密）+ 报告历史（SQLite）+ 导出。

数据目录固定在 ~/.stride-gpt/，与仓库分离：
  - web_config.json  加密后的配置（Fernet）
  - web_key          Fernet 密钥（0600）
  - web.db           报告历史数据库
"""

from __future__ import annotations

import base64
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

DATA_DIR = Path(os.path.expanduser("~/.stride-gpt"))
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
    *sorted(SENSITIVE_KEYS),
]

KIND_LABELS = {
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
        try:
            KEY_FILE.chmod(0o600)
        except OSError:
            pass
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
    try:
        CONFIG_FILE.chmod(0o600)
    except OSError:
        pass
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
        try:
            f.unlink(missing_ok=True)
        except OSError:
            pass


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


def list_projects() -> list[str]:
    init_db()
    with _conn() as c:
        rows = c.execute(
            "SELECT DISTINCT project FROM reports WHERE project != '' ORDER BY project"
        ).fetchall()
    return [r["project"] for r in rows]


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


def add_threats(project: str, report_id: int | None, threats: list[dict]) -> int:
    """写入威胁条目，按（类型+场景）指纹在项目内去重。返回新增数量。"""
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
            c.execute(
                """
                INSERT INTO threats
                    (project, report_id, threat_type, scenario, impact, owasp_llm, owasp_asi,
                     mitre, insider, status, created_at, updated_at, fingerprint)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '待处理', ?, ?, ?)
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
    by_status = {s: 0 for s in THREAT_STATUSES}
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
    try:
        f.chmod(0o600)
    except OSError:
        pass
    return secret


def make_session_token(username: str, days: int = 7) -> str:
    payload = json.dumps(
        {"u": username, "exp": int(time.time()) + days * 86400},
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
        return str(data.get("u") or "") or None
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
