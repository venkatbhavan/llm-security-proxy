"""Fire every prompt in attacks/prompts.json at the running proxy and print a
detection report (true/false positives) - these numbers go in your README.

Usage:  python scripts/run_attacks.py            (proxy must be running on :8000)
"""
import json
import sys

import httpx

URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000/chat"
data = json.load(open("attacks/prompts.json"))


def detected_by(alerts):
    return sorted({a["detector"] for a in alerts})


def run(label, prompts):
    caught = 0
    print(f"\n=== {label.upper()} ({len(prompts)}) ===")
    for p in prompts:
        r = httpx.post(URL, json={"message": p}, timeout=60).json()
        dets = detected_by(r["debug"]["alerts"])
        caught += bool(dets)
        print(f"[{'ALERT' if dets else '  -  '}] {', '.join(dets):24} | {p[:60]}")
    return caught


tp = run("attacks", data["attacks"])
fp = run("benign", data["benign"])
print(f"\nDetection rate: {tp}/{len(data['attacks'])} attacks caught")
print(f"False positives: {fp}/{len(data['benign'])} benign prompts flagged")
