"""Phase 1: log every interaction and alert to SQLite."""
import json
import os
import sqlite3
from datetime import datetime, timezone

from app.config import DB_PATH


def _conn():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _conn() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS interactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, session_id TEXT, prompt TEXT, response TEXT,
            tool_calls TEXT, blocked INTEGER)""")
        c.execute("""CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, interaction_id INTEGER, detector TEXT,
            severity TEXT, rule TEXT, evidence TEXT)""")


def now():
    return datetime.now(timezone.utc).isoformat()


def log_interaction(session_id, prompt, response, tool_calls, blocked):
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO interactions (ts, session_id, prompt, response, tool_calls, blocked) "
            "VALUES (?,?,?,?,?,?)",
            (now(), session_id, prompt, response, json.dumps(tool_calls), int(blocked)),
        )
        return cur.lastrowid


def log_alert(interaction_id, alert):
    with _conn() as c:
        c.execute(
            "INSERT INTO alerts (ts, interaction_id, detector, severity, rule, evidence) "
            "VALUES (?,?,?,?,?,?)",
            (now(), interaction_id, alert["detector"], alert["severity"],
             alert["rule"], alert["evidence"][:500]),
        )
    # Also append as JSON lines -> easy to ingest into Splunk later (Phase 5).
    with open(os.path.join(os.path.dirname(DB_PATH) or ".", "alerts.jsonl"), "a") as f:
        f.write(json.dumps({"ts": now(), "interaction_id": interaction_id, **alert}) + "\n")


def recent_alerts(limit=50):
    with _conn() as c:
        rows = c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]
