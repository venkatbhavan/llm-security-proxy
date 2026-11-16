"""Indirect prompt injection: scan TOOL OUTPUT (reviews, documents, web pages)
before it is handed back to the model.

The user's own message can be completely innocent ("what do reviews say?").
The attack is planted in third-party content the model reads.

scan_tool_result() walks every string in a tool result, scores it, and returns
(alerts, sanitized_result). Flagged strings are replaced with a placeholder
("quarantine") so the model never sees the hidden instructions.
"""
import re

from app.config import TOOL_ALLOWLIST
from app.detectors.rules import check_prompt

ALLOWED_EMAIL_DOMAINS = TOOL_ALLOWLIST["send_email"]["allowed_domains"]
QUARANTINE_TEXT = "[removed by security proxy: suspected prompt injection]"

# (rule_id, regex, score, description) - patterns typical for text that is
# talking TO the AI rather than being normal content.
INDIRECT_RULES = [
    ("addressed_to_ai",
     r"\b(ai|assistant|chatbot|llm|language model|bot)\b.{0,40}\b(must|should|need to|are required|now)\b",
     35, "Text gives orders to the AI"),
    ("fake_boundary",
     r"(-{3,}|={3,}|#{3,})\s*(end|begin|start)\b|\b(end of (reviews?|document|data|context))\b",
     30, "Fake end-of-data marker (breaking out of the content)"),
    ("fake_authority",
     r"\b(system (note|message|instruction|override)|important instruction|admin notice|new instructions?)\b",
     30, "Pretends to be a system/admin message"),
    ("json_breakout",
     r"[\"']\s*[}\]]{1,3}\s*[}\]]",
     20, "Tries to close the JSON/data structure early"),
    ("secrecy_request",
     r"\b(do not|don't|never) (tell|mention|inform|reveal (this )?to) (the )?(user|customer)\b",
     25, "Asks the AI to hide its actions from the user"),
    ("hidden_characters",
     r"[​-‏⁠﻿]|<!--",
     20, "Invisible characters / hidden HTML comment"),
]

EXFIL_ACTION = re.compile(
    r"\b(send|email|forward|mail|transfer|export)\b.{0,80}?([\w.+-]+@([\w-]+\.)+\w+)",
    re.IGNORECASE | re.DOTALL)

SEVERITY_BANDS = [(70, "HIGH"), (40, "MEDIUM"), (25, "LOW")]


def scan_text(text: str):
    hits, score = [], 0
    for rule_id, pattern, pts, desc in INDIRECT_RULES:
        if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
            hits.append((rule_id, desc))
            score += pts

    for m in EXFIL_ACTION.finditer(text):
        domain = m.group(2).split("@")[-1].lower()
        if domain not in ALLOWED_EMAIL_DOMAINS:
            hits.append(("exfil_instruction", f"Instruction to send data to external address {m.group(2)}"))
            score += 40
            break

    # Reuse the direct-injection rules too ("ignore previous instructions" inside a document)
    _, direct_score = check_prompt(text)
    if direct_score >= 40:
        hits.append(("direct_injection_phrasing", "Direct-injection phrasing inside content"))
        score += direct_score

    severity = next((s for limit, s in SEVERITY_BANDS if score >= limit), None)
    return hits, score, severity


def scan_tool_result(tool_name, result, quarantine=True):
    alerts = []

    def walk(obj, path):
        if isinstance(obj, str):
            hits, score, severity = scan_text(obj)
            if severity:
                alerts.append({
                    "detector": "indirect",
                    "severity": severity,
                    "rule": ",".join(h[0] for h in hits),
                    "evidence": f"{tool_name} output at {path}: score={score}; "
                                + "; ".join(h[1] for h in hits) + f" | text: {obj[:160]!r}",
                })
                # Only quarantine MEDIUM+ to limit damage from false positives
                if quarantine and severity in ("MEDIUM", "HIGH"):
                    return QUARANTINE_TEXT
            return obj
        if isinstance(obj, dict):
            return {k: walk(v, f"{path}.{k}") for k, v in obj.items()}
        if isinstance(obj, list):
            return [walk(v, f"{path}[{i}]") for i, v in enumerate(obj)]
        return obj

    sanitized = walk(result, "$")
    return alerts, sanitized
