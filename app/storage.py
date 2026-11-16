"""Log every interaction and alert to SQLite, plus a JSONL alert file for SIEM ingestion."""
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone

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
            ts TEXT, session_id TEXT, source_ip TEXT, prompt TEXT, response TEXT,
            tool_calls TEXT, blocked INTEGER)""")
        c.execute("""CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, interaction_id INTEGER, source_ip TEXT, session_id TEXT,
            detector TEXT, severity TEXT, rule TEXT, evidence TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS outbox (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, session_id TEXT, source_ip TEXT, recipient TEXT, subject TEXT,
            body TEXT, status TEXT, external INTEGER, file TEXT)""")
        # Upgrade databases created by older versions (no source_ip/session_id columns yet)
        for table, column in [("interactions", "source_ip"), ("alerts", "source_ip"),
                              ("alerts", "session_id")]:
            cols = [r["name"] for r in c.execute(f"PRAGMA table_info({table})")]
            if column not in cols:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {column} TEXT")


def now():
    return datetime.now(timezone.utc).isoformat()


def log_interaction(session_id, source_ip, prompt, response, tool_calls, blocked):
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO interactions (ts, session_id, source_ip, prompt, response, tool_calls, blocked) "
            "VALUES (?,?,?,?,?,?,?)",
            (now(), session_id, source_ip, prompt, response, json.dumps(tool_calls), int(blocked)),
        )
        return cur.lastrowid


def log_alert(interaction_id, session_id, source_ip, alert):
    with _conn() as c:
        c.execute(
            "INSERT INTO alerts (ts, interaction_id, source_ip, session_id, detector, severity, rule, evidence) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (now(), interaction_id, source_ip, session_id, alert["detector"], alert["severity"],
             alert["rule"], alert["evidence"][:500]),
        )
    # JSON lines -> easy to ingest into Splunk / any SIEM
    path = os.path.join(os.path.dirname(DB_PATH) or ".", "alerts.jsonl")
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": now(), "interaction_id": interaction_id, "src_ip": source_ip,
                            "session_id": session_id, **alert}) + "\n")


def recent_alerts(limit=50):
    with _conn() as c:
        rows = c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]


def _cutoff(minutes):
    if not minutes or minutes <= 0:
        return ""  # every ISO timestamp is >= ""
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()


def alerts_since(minutes, limit=2000):
    with _conn() as c:
        rows = c.execute("SELECT * FROM alerts WHERE ts >= ? ORDER BY ts DESC, id DESC LIMIT ?",
                         (_cutoff(minutes), limit)).fetchall()
        return [dict(r) for r in rows]


def request_stats(minutes):
    with _conn() as c:
        r = c.execute("""SELECT COUNT(*) AS total,
                                COALESCE(SUM(blocked), 0) AS blocked,
                                COUNT(DISTINCT source_ip) AS unique_ips
                         FROM interactions WHERE ts >= ?""", (_cutoff(minutes),)).fetchone()
        flagged = c.execute("""SELECT COUNT(DISTINCT interaction_id) FROM alerts
                               WHERE ts >= ?""", (_cutoff(minutes),)).fetchone()[0]
        return {**dict(r), "flagged": flagged}


def get_interaction(interaction_id):
    with _conn() as c:
        r = c.execute("SELECT * FROM interactions WHERE id = ?", (interaction_id,)).fetchone()
        if not r:
            return None
        d = dict(r)
        d["tool_calls"] = json.loads(d["tool_calls"] or "[]")
        return d


def log_email(session_id, source_ip, args, status, external, file=None):
    with _conn() as c:
        c.execute("INSERT INTO outbox (ts, session_id, source_ip, recipient, subject, body, status, external, file) "
                  "VALUES (?,?,?,?,?,?,?,?,?)",
                  (now(), session_id, source_ip, str(args.get("to", "")), str(args.get("subject", "") or "(no subject)"),
                   str(args.get("body", "")), status, int(external), file))


def emails_since(minutes, limit=200):
    with _conn() as c:
        rows = c.execute("SELECT * FROM outbox WHERE ts >= ? ORDER BY ts DESC, id DESC LIMIT ?",
                         (_cutoff(minutes), limit)).fetchall()
        return [dict(r) for r in rows]
