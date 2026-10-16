"""服务端存储：配置持久化（加密）+ 报告历史（SQLite）+ 导出。

数据目录固定在 ~/.stride-gpt/，与仓库分离：
  - web_config.json  加密后的配置（Fernet）
  - web_key          Fernet 密钥（0600）
  - web.db           报告历史数据库
"""

from __future__ import annotations

import io
import json
import os
import sqlite3
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
