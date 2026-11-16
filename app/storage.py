"""Storage: SQLite tables, a JSONL alert file for SIEM ingestion, and a
tamper-evident audit log.

Audit log (EU AI Act Art. 12 "record-keeping", tamper-evidence):
every record written to `interactions`, `alerts` or `outbox` is also appended to
`audit_log` as a canonical JSON copy plus a SHA-256 hash that includes the
previous entry's hash (a hash chain, like a mini blockchain without the hype).

  hash_n = SHA256(hash_{n-1} | ts | table | record_id | payload)

verify_audit() recomputes the chain and compares every audited record with the
live table, so it detects:
  - an edited record (in the table or in the audit log)
  - a deleted record
  - a re-ordered / inserted / removed audit entry (chain breaks)
Limitation: someone who can rewrite the whole database could rebuild the chain.
Real deployments anchor the latest hash somewhere the attacker can't reach
(WORM storage, a SIEM, a signed report). The report prints it for that reason.
"""
import hashlib
import json
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

from app.config import DB_PATH

GENESIS_HASH = "0" * 64
AUDITED_TABLES = ("interactions", "alerts", "outbox")
_write_lock = threading.Lock()  # appends must be sequential or the chain forks


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
        c.execute("""CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, record_table TEXT, record_id INTEGER, payload TEXT,
            prev_hash TEXT, hash TEXT)""")
        # Upgrade databases created by older versions (no source_ip/session_id columns yet)
        for table, column in [("interactions", "source_ip"), ("alerts", "source_ip"),
                              ("alerts", "session_id")]:
            cols = [r["name"] for r in c.execute(f"PRAGMA table_info({table})")]
            if column not in cols:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {column} TEXT")


def now():
    return datetime.now(timezone.utc).isoformat()


# ---------------- audit chain ----------------
def _canonical(record: dict) -> str:
    return json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _chain_hash(prev_hash, ts, table, record_id, payload):
    data = f"{prev_hash}|{ts}|{table}|{record_id}|{payload}".encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _insert_audited(table: str, record: dict) -> int:
    """Insert a record and its audit entry in ONE transaction, under a lock."""
    cols = ", ".join(record)
    marks = ", ".join("?" for _ in record)
    with _write_lock, _conn() as c:
        rid = c.execute(f"INSERT INTO {table} ({cols}) VALUES ({marks})", tuple(record.values())).lastrowid
        stored = dict(c.execute(f"SELECT * FROM {table} WHERE id = ?", (rid,)).fetchone())
        last = c.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        prev = last["hash"] if last else GENESIS_HASH
        ts, payload = now(), _canonical(stored)
        c.execute("INSERT INTO audit_log (ts, record_table, record_id, payload, prev_hash, hash) "
                  "VALUES (?,?,?,?,?,?)",
                  (ts, table, rid, payload, prev, _chain_hash(prev, ts, table, rid, payload)))
        return rid


def verify_audit(max_problems=50):
    """Recompute the hash chain and compare it with the live tables."""
    problems, prev, count, last_hash = [], GENESIS_HASH, 0, GENESIS_HASH
    seen = {t: set() for t in AUDITED_TABLES}

    def problem(entry_id, kind, detail):
        if len(problems) < max_problems:
            problems.append({"audit_id": entry_id, "type": kind, "detail": detail})

    with _conn() as c:
        for e in c.execute("SELECT * FROM audit_log ORDER BY id"):
            count += 1
            if e["prev_hash"] != prev:
                problem(e["id"], "chain_broken",
                        "Previous-hash link does not match: an audit entry was removed, inserted or reordered")
            expected = _chain_hash(e["prev_hash"], e["ts"], e["record_table"], e["record_id"], e["payload"])
            if e["hash"] != expected:
                problem(e["id"], "audit_entry_modified", "Audit entry content does not match its hash")
            table = e["record_table"]
            if table in seen:
                seen[table].add(e["record_id"])
                row = c.execute(f"SELECT * FROM {table} WHERE id = ?", (e["record_id"],)).fetchone()
                if row is None:
                    problem(e["id"], "record_deleted", f"{table} #{e['record_id']} was deleted")
                elif _canonical(dict(row)) != e["payload"]:
                    problem(e["id"], "record_modified", f"{table} #{e['record_id']} was changed after it was logged")
            prev = last_hash = e["hash"]

        # Records with no audit entry: created before the audit log existed, or inserted directly
        unaudited = {}
        for t in AUDITED_TABLES:
            ids = {r[0] for r in c.execute(f"SELECT id FROM {t}")}
            missing = ids - seen[t]
            if missing:
                unaudited[t] = len(missing)

    return {"ok": not problems, "entries": count, "last_hash": last_hash,
            "problems": problems, "unaudited": unaudited, "checked_at": now()}


# ---------------- writers ----------------
def log_interaction(session_id, source_ip, prompt, response, tool_calls, blocked):
    return _insert_audited("interactions", {
        "ts": now(), "session_id": session_id, "source_ip": source_ip, "prompt": prompt,
        "response": response, "tool_calls": json.dumps(tool_calls), "blocked": int(blocked)})


def log_alert(interaction_id, session_id, source_ip, alert):
    ts = now()
    _insert_audited("alerts", {
        "ts": ts, "interaction_id": interaction_id, "source_ip": source_ip, "session_id": session_id,
        "detector": alert["detector"], "severity": alert["severity"], "rule": alert["rule"],
        "evidence": alert["evidence"][:500]})
    # JSON lines -> easy to ingest into Splunk / any SIEM
    path = os.path.join(os.path.dirname(DB_PATH) or ".", "alerts.jsonl")
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": ts, "interaction_id": interaction_id, "src_ip": source_ip,
                            "session_id": session_id, **alert}) + "\n")


def log_email(session_id, source_ip, args, status, external, file=None):
    _insert_audited("outbox", {
        "ts": now(), "session_id": session_id, "source_ip": source_ip,
        "recipient": str(args.get("to", "")), "subject": str(args.get("subject", "") or "(no subject)"),
        "body": str(args.get("body", "")), "status": status, "external": int(external), "file": file})


# ---------------- readers ----------------
def _cutoff(minutes):
    if not minutes or minutes <= 0:
        return ""  # every ISO timestamp is >= ""
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()


def recent_alerts(limit=50):
    with _conn() as c:
        rows = c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]


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


def emails_since(minutes, limit=200):
    with _conn() as c:
        rows = c.execute("SELECT * FROM outbox WHERE ts >= ? ORDER BY ts DESC, id DESC LIMIT ?",
                         (_cutoff(minutes), limit)).fetchall()
        return [dict(r) for r in rows]
