"""Framework mapping: every detection rule -> OWASP LLM Top 10 (2025), MITRE ATLAS,
EU AI Act articles and BSI publications, plus a control matrix describing how this
proxy addresses each requirement (with honest status: Implemented / Partial / Gap).

Scope note: the EU AI Act's Art. 9-15 obligations apply to HIGH-RISK AI systems.
A shop support chatbot is usually not high-risk; the Act is used here as a reference
control framework, which is how many organisations apply it voluntarily.
IDs checked against public ATLAS / OWASP references, Nov 2026 - re-check before
relying on them in a real audit.
"""

OWASP = {
    "LLM01": "LLM01:2025 Prompt Injection",
    "LLM02": "LLM02:2025 Sensitive Information Disclosure",
    "LLM06": "LLM06:2025 Excessive Agency",
    "LLM07": "LLM07:2025 System Prompt Leakage",
}
ATLAS = {
    "T0051.000": "AML.T0051.000 LLM Prompt Injection: Direct",
    "T0051.001": "AML.T0051.001 LLM Prompt Injection: Indirect",
    "T0054": "AML.T0054 LLM Jailbreak",
    "T0056": "AML.T0056 LLM Meta Prompt Extraction",
    "T0057": "AML.T0057 LLM Data Leakage",
    "T0068": "AML.T0068 LLM Prompt Obfuscation",
    "T0053": "AML.T0053 AI Agent Tool Invocation",
    "T0055": "AML.T0055 Unsecured Credentials",
}
EU_AI_ACT = {
    "Art9": "EU AI Act Art. 9 Risk management system",
    "Art12": "EU AI Act Art. 12 Record-keeping",
    "Art14": "EU AI Act Art. 14 Human oversight",
    "Art15": "EU AI Act Art. 15 Accuracy, robustness and cybersecurity",
}
BSI = {
    "GenAI": "BSI: Generative AI Models - Opportunities and Risks for Industry and Authorities (2024)",
    "IPI": "BSI: Indirect Prompt Injections - Intrinsic Vulnerability in Application-Integrated AI Language Models (2023)",
}

# rule -> (owasp, atlas, eu_ai_act, bsi)
_RULES = {
    # direct injection (input rules)
    "override_instructions":     (["LLM01"], ["T0051.000"], ["Art15"], ["GenAI"]),
    "system_prompt_extraction":  (["LLM01", "LLM07"], ["T0051.000", "T0056"], ["Art15"], ["GenAI"]),
    "role_hijack":               (["LLM01"], ["T0051.000", "T0054"], ["Art15"], ["GenAI"]),
    "jailbreak_persona":         (["LLM01"], ["T0054"], ["Art15"], ["GenAI"]),
    "delimiter_injection":       (["LLM01"], ["T0051.000"], ["Art15"], ["GenAI"]),
    "encoding_evasion":          (["LLM01"], ["T0068"], ["Art15"], ["GenAI"]),
    "tool_abuse":                (["LLM01", "LLM06"], ["T0051.000", "T0053"], ["Art15"], ["GenAI"]),
    # canary
    "canary_leak":               (["LLM07", "LLM02"], ["T0056", "T0057"], ["Art15"], ["GenAI"]),
    "canary_partial_leak":       (["LLM07", "LLM02"], ["T0056", "T0057"], ["Art15"], ["GenAI"]),
    # tool monitor
    "tool_not_allowlisted":      (["LLM06"], ["T0053"], ["Art15", "Art14"], ["GenAI"]),
    "email_external_domain":     (["LLM06", "LLM02"], ["T0053", "T0057"], ["Art15"], ["GenAI", "IPI"]),
    "canary_in_tool_args":       (["LLM06", "LLM07", "LLM02"], ["T0053", "T0057"], ["Art15"], ["GenAI"]),
    "bulk_data_request":         (["LLM06", "LLM02"], ["T0053", "T0057"], ["Art15"], ["GenAI"]),
    "sqli_in_tool_args":         (["LLM06"], ["T0053"], ["Art15"], ["GenAI"]),
    "honey_tool_triggered":      (["LLM06", "LLM01"], ["T0053", "T0055"], ["Art15"], ["GenAI"]),
    "honey_credential_reused":   (["LLM06", "LLM02"], ["T0055"], ["Art15"], ["GenAI"]),
}
_INDIRECT = (["LLM01", "LLM06"], ["T0051.001"], ["Art15"], ["IPI", "GenAI"])

DESCRIPTIONS = {
    "override_instructions": "User tried to override the system instructions",
    "system_prompt_extraction": "User tried to extract the hidden system prompt",
    "role_hijack": "User tried to give the model a new role or persona",
    "jailbreak_persona": "Known jailbreak persona (e.g. DAN, developer mode)",
    "delimiter_injection": "Fake chat-template / system delimiters in user input",
    "encoding_evasion": "Request for encoded output to evade filters",
    "tool_abuse": "User tried to invoke tools directly",
    "canary_leak": "Confidential canary token appeared in model output (system prompt leaked)",
    "canary_partial_leak": "Part of the canary token appeared in model output",
    "tool_not_allowlisted": "Model requested a tool outside the allowlist",
    "email_external_domain": "Model tried to email an address outside the organisation",
    "canary_in_tool_args": "Confidential data placed into a tool call (exfiltration)",
    "bulk_data_request": "Unusually large data request through a tool",
    "sqli_in_tool_args": "SQL-injection pattern passed to a tool",
    "honey_tool_triggered": "Model called a decoy tool: confirmed manipulation",
    "honey_credential_reused": "Stolen decoy credential reused",
    "indirect_injection": "Hidden instructions found in third-party content the model read",
}


def _base_rule(rule: str) -> str:
    rule = rule.replace(" (inside base64)", "").strip()
    return "canary_leak" if rule.startswith("canary_leak_") else rule


def map_rule(rule: str, detector: str = ""):
    key = _base_rule(rule)
    if key == "indirect_injection":
        detector = "indirect"
    o, a, e, b = _RULES.get(key) or (_INDIRECT if detector == "indirect" else ([], [], [], []))
    return {"owasp": [OWASP[x] for x in o], "atlas": [ATLAS[x] for x in a],
            "eu_ai_act": [EU_AI_ACT[x] for x in e], "bsi": [BSI[x] for x in b]}


def map_alert(alert: dict):
    """Union of mappings for every rule in an alert (rules are comma-separated)."""
    out = {"owasp": [], "atlas": [], "eu_ai_act": [], "bsi": []}
    for r in alert["rule"].split(","):
        m = map_rule(r, alert.get("detector", ""))
        for k in out:
            out[k] += [x for x in m[k] if x not in out[k]]
    return out


def describe(rule: str, detector: str = "") -> str:
    key = _base_rule(rule)
    if key in DESCRIPTIONS:
        return DESCRIPTIONS[key]
    return DESCRIPTIONS["indirect_injection"] if detector == "indirect" else key


# Control matrix: requirement -> how this project implements it (honest status)
CONTROLS = [
    {"framework": "EU AI Act", "ref": "Art. 12 Record-keeping",
     "requirement": "Automatic logging of events over the system's lifetime, enabling traceability",
     "implementation": "Proxy logs every request, response, tool call, alert and email automatically, outside the model. "
                       "SHA-256 hash chain makes edits, deletions and reordering detectable.",
     "evidence": "audit_log table, /api/audit, scripts/verify_audit.py",
     "status": "Partial",
     "gap": "No retention policy (Art. 19 / Art. 26 expect at least 6 months) and no external anchoring of the latest hash."},
    {"framework": "EU AI Act", "ref": "Art. 15 Cybersecurity",
     "requirement": "Resilience against attempts by unauthorised third parties to alter use, outputs or performance by exploiting vulnerabilities",
     "implementation": "Five detection layers: input rules, canary token, tool-call monitor, honey tools, indirect-injection scan with quarantine. BLOCK mode prevents HIGH-risk actions.",
     "evidence": "Attack suite results (scripts/run_attacks.py), alert feed",
     "status": "Implemented",
     "gap": "Rule-based detection can be paraphrased around; no ML classifier yet."},
    {"framework": "EU AI Act", "ref": "Art. 14 Human oversight",
     "requirement": "Humans can monitor operation, interpret outputs and intervene",
     "implementation": "SOC dashboard with alert investigation, outbox review, and MONITOR / BLOCK switch.",
     "evidence": "Dashboard (/), investigation drawer, PROXY_MODE setting",
     "status": "Implemented", "gap": "No per-alert approve/deny workflow yet."},
    {"framework": "EU AI Act", "ref": "Art. 9 Risk management",
     "requirement": "Identify, test and mitigate foreseeable risks, including through testing",
     "implementation": "Repeatable attack suite with benign control set; detection and false-positive rates measured.",
     "evidence": "attacks/prompts.json, scripts/run_attacks.py, this report",
     "status": "Partial", "gap": "Not yet tested against a production LLM; no formal risk register."},
    {"framework": "OWASP LLM Top 10", "ref": "LLM01:2025 Prompt Injection",
     "requirement": "Detect and constrain direct and indirect prompt injection",
     "implementation": "Input rules (direct), tool-output scanning with quarantine (indirect), canary for impact detection.",
     "evidence": "app/detectors/rules.py, app/detectors/indirect.py", "status": "Implemented", "gap": ""},
    {"framework": "OWASP LLM Top 10", "ref": "LLM02:2025 Sensitive Information Disclosure",
     "requirement": "Prevent leakage of confidential data through outputs or actions",
     "implementation": "Canary detection in outputs and tool arguments; external-email detection; outbox evidence.",
     "evidence": "app/detectors/canary.py, outbox table", "status": "Implemented",
     "gap": "No general PII/DLP scanning beyond the canary."},
    {"framework": "OWASP LLM Top 10", "ref": "LLM06:2025 Excessive Agency",
     "requirement": "Limit and monitor what tools the model can invoke",
     "implementation": "Tool allowlist, parameter policies (email domains, result limits), honey tools as tripwires.",
     "evidence": "app/tools.py check_tool_call()", "status": "Implemented", "gap": ""},
    {"framework": "OWASP LLM Top 10", "ref": "LLM07:2025 System Prompt Leakage",
     "requirement": "Detect disclosure of system instructions",
     "implementation": "Canary token in the system prompt, detected in plain and encoded forms.",
     "evidence": "app/detectors/canary.py", "status": "Implemented", "gap": ""},
    {"framework": "BSI", "ref": "Indirect Prompt Injections (2023)",
     "requirement": "Treat third-party data processed by the LLM as untrusted",
     "implementation": "All tool output is scanned before the model reads it; poisoned content is quarantined in BLOCK mode.",
     "evidence": "app/detectors/indirect.py", "status": "Implemented", "gap": ""},
]
