"""Phase 3: rule-based prompt-injection detection on the INPUT.

Each rule has a regex, a score and a MITRE ATLAS-style label for the write-up.
Total score -> severity. Tune the rules after running attacks/ and benign prompts.
"""
import base64
import re

RULES = [
    # (rule_id, regex, score, description)
    ("override_instructions",
     r"\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|all|earlier)\b.{0,20}\b(instructions?|rules?|prompts?|directions?)",
     40, "Instruction override attempt"),
    ("system_prompt_extraction",
     r"\b(reveal|show|print|repeat|output|what (is|are))\b.{0,30}\b(system prompt|your instructions|initial prompt|hidden (prompt|instructions)|confidential)",
     40, "System prompt extraction attempt"),
    ("role_hijack",
     r"\b(you are now|act as|pretend (to be|you are)|roleplay as|from now on you)\b",
     20, "Role / persona hijack"),
    ("jailbreak_persona",
     r"\b(DAN|do anything now|developer mode|jailbreak|unfiltered|no restrictions)\b",
     35, "Known jailbreak persona"),
    ("delimiter_injection",
     r"(</?system>|\[/?INST\]|###\s*(system|instruction)|<\|im_start\|>)",
     30, "Fake chat-template / delimiter injection"),
    ("encoding_evasion",
     r"\b(base64|rot13|hex|reverse(d)?|spell (it )?backwards|encode)\b",
     15, "Asks for encoded output (evasion)"),
    ("tool_abuse",
     r"\b(send_email|call the tool|use the .{0,15}tool|execute|run the function)\b",
     15, "Direct tool invocation request"),
]

SEVERITY_BANDS = [(70, "HIGH"), (40, "MEDIUM"), (20, "LOW")]


def _decoded_base64_chunks(text):
    """Find base64-looking blobs and decode them, so hidden instructions get scanned too."""
    out = []
    for blob in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", text):
        try:
            decoded = base64.b64decode(blob, validate=True).decode("utf-8")
            if decoded.isprintable():
                out.append(decoded)
        except Exception:
            pass
    return out


def check_prompt(prompt: str):
    texts = [prompt] + _decoded_base64_chunks(prompt)
    hits, score = [], 0
    for rule_id, pattern, pts, desc in RULES:
        for t in texts:
            if re.search(pattern, t, re.IGNORECASE):
                hidden = t is not prompt
                hits.append(f"{rule_id}{' (inside base64)' if hidden else ''}: {desc}")
                score += pts + (15 if hidden else 0)
                break

    severity = next((s for limit, s in SEVERITY_BANDS if score >= limit), None)
    if not severity:
        return [], score
    return [{
        "detector": "rules",
        "severity": severity,
        "rule": ",".join(h.split(":")[0] for h in hits),
        "evidence": f"score={score}; " + "; ".join(hits),
    }], score
