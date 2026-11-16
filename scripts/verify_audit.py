"""Verify the tamper-evident audit log.

Usage:  python scripts/verify_audit.py
Exit code 0 = intact, 1 = tampering detected (usable in scripts / CI).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import storage  # noqa: E402

storage.init_db()
r = storage.verify_audit()

print(f"Audit entries checked : {r['entries']}")
print(f"Latest chain hash     : {r['last_hash']}")
if r["unaudited"]:
    print(f"Records without audit entry (created before audit logging existed): {r['unaudited']}")

if r["ok"]:
    print("\nRESULT: INTACT - no record was modified, deleted or reordered.")
    sys.exit(0)

print(f"\nRESULT: TAMPERING DETECTED - {len(r['problems'])} problem(s):")
for p in r["problems"]:
    print(f"  audit entry #{p['audit_id']:<5} {p['type']:<22} {p['detail']}")
sys.exit(1)
