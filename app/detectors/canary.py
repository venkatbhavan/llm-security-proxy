"""Phase 2: canary-token leak detection.

Checks the response for the canary in plain form AND in common encodings,
because attackers often ask the model to "spell it backwards" or "base64 it".
"""
import base64
import codecs

from app.config import CANARY_TOKEN


def _variants(token):
    return {
        "plain": token,
        "reversed": token[::-1],
        "base64": base64.b64encode(token.encode()).decode(),
        "rot13": codecs.encode(token, "rot13"),
        "no_dashes": token.replace("-", ""),
    }


def check_canary(response: str, token: str = CANARY_TOKEN):
    alerts = []
    text = response.lower()
    for name, v in _variants(token).items():
        if v.lower() in text:
            alerts.append({
                "detector": "canary",
                "severity": "HIGH",
                "rule": f"canary_leak_{name}",
                "evidence": f"Canary token found in response ({name} form)",
            })
    # Partial leak: the unique middle part of the token appears.
    core = token.split("-")[1] if "-" in token else token
    if not alerts and core.lower() in text:
        alerts.append({"detector": "canary", "severity": "MEDIUM",
                       "rule": "canary_partial_leak",
                       "evidence": "Part of canary token found in response"})
    return alerts
