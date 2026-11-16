"""Demo: play an attacker who tries to cover their tracks, and watch the audit log catch it.

What it does (on YOUR local lab database only):
  1. Backs up logs/proxy.db to logs/proxy.backup.db
  2. Takes the newest HIGH alert and silently downgrades it to LOW with harmless-looking evidence,
     the way an insider would hide an incident
  3. Runs the integrity check, which reports exactly which record was changed

Restore afterwards (stop the server first):
  Windows:  Copy-Item logs\\proxy.backup.db logs\\proxy.db -Force
  Linux:    cp logs/proxy.backup.db logs/proxy.db
"""
import os
import shutil
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import storage  # noqa: E402
from app.config import DB_PATH  # noqa: E402

if not os.path.exists(DB_PATH):
    sys.exit("No database yet - run some attacks first (python scripts/run_attacks.py).")

backup = os.path.join(os.path.dirname(DB_PATH), "proxy.backup.db")
shutil.copyfile(DB_PATH, backup)
print(f"[1] Backup written to {backup}")

before = storage.verify_audit()
print(f"[2] Integrity before tampering: {'INTACT' if before['ok'] else 'ALREADY BROKEN'} "
      f"({before['entries']} entries)")

conn = sqlite3.connect(DB_PATH)
row = conn.execute("SELECT id, rule, evidence FROM alerts WHERE severity = 'HIGH' ORDER BY id DESC LIMIT 1").fetchone()
if not row:
    sys.exit("No HIGH alert found - run some attacks first.")
conn.execute("UPDATE alerts SET severity = 'LOW', evidence = 'routine check, no issue' WHERE id = ?", (row[0],))
conn.commit()
conn.close()
print(f"[3] Attacker edited alert #{row[0]} ({row[1]}): severity HIGH -> LOW, evidence rewritten")

after = storage.verify_audit()
print(f"[4] Integrity after tampering:  {'INTACT' if after['ok'] else 'TAMPERING DETECTED'}")
for p in after["problems"]:
    print(f"      audit entry #{p['audit_id']}: {p['type']} - {p['detail']}")
print("\nThe dashboard header now shows the audit log as TAMPERED. Restore with the command above.")
