"""Security assessment report: a print-ready HTML page (browser -> Save as PDF).

Everything that came from users/attackers is passed through html.escape().
"""
import html
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone

from app import compliance, storage

AUTHOR = os.getenv("REPORT_AUTHOR", "LLM Security Proxy (automated)")
SYSTEM_NAME = os.getenv("REPORT_SYSTEM", "ExampleShop HelpBot (LLM customer-support assistant)")
SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

RECOMMENDATIONS = {
    "canary_leak": "Treat the system prompt as public: never place real secrets or credentials in it. Rotate anything that was in it.",
    "email_external_domain": "Restrict the email tool to an allowlist of internal domains and require human approval for external recipients.",
    "canary_in_tool_args": "Add data-loss-prevention checks on all outbound tool arguments, not only on chat responses.",
    "honey_tool_triggered": "Keep honey tools deployed and route their alerts to on-call: they have a near-zero false-positive rate.",
    "honey_credential_reused": "Investigate every session that touched decoy data and block the source.",
    "indirect_injection": "Treat all third-party content (reviews, documents, web pages) as untrusted. Sanitise or quarantine it before the model reads it, and moderate user-generated content at the source.",
    "sqli_in_tool_args": "Confirm that all tool back-ends use parameterised queries.",
    "jailbreak_persona": "Add an ML-based guard model; regex rules alone are easy to paraphrase around.",
    "system_prompt_extraction": "Expect system-prompt extraction attempts; monitor with canaries rather than relying on 'do not reveal' instructions.",
}
BASELINE = [
    "Run the proxy in BLOCK mode in production once false-positive rates are acceptable.",
    "Retain logs for at least 6 months and forward them to a SIEM; anchor the latest audit hash in write-once storage.",
    "Apply least privilege to every tool the model can call (EU AI Act Art. 15 / OWASP LLM06).",
    "Re-run the attack suite after every model, prompt or tool change (regression testing).",
    "Evaluate detection against the production LLM, not only the test model.",
]


def _e(x):
    return html.escape("" if x is None else str(x))


def _fmt_ts(iso):
    try:
        return datetime.fromisoformat(iso).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return iso or "-"


def _overall_risk(alerts, emails, mode):
    leaked_ext = [m for m in emails if m["external"] and m["status"] == "SENT"]
    leaked_canary = any(a["detector"] == "canary" for a in alerts)
    if leaked_ext or (leaked_canary and mode != "BLOCK"):
        return "CRITICAL", "Confidential data left the system (exfiltration observed)."
    if any(a["severity"] == "HIGH" for a in alerts):
        return "HIGH", "High-severity attacks were detected; none confirmed as successful exfiltration."
    if alerts:
        return "MEDIUM", "Attack attempts detected at medium/low severity."
    return "LOW", "No attacks detected in the reporting period."


def build_report(minutes: int, mode: str) -> str:
    alerts = storage.alerts_since(minutes, limit=100000)
    emails = storage.emails_since(minutes, limit=100000)
    req = storage.request_stats(minutes)
    audit = storage.verify_audit()
    generated = datetime.now(timezone.utc).astimezone()
    period = "All recorded activity" if not minutes else f"Last {minutes // 60} hour(s)" if minutes >= 60 else f"Last {minutes} minutes"
    risk, risk_text = _overall_risk(alerts, emails, mode)

    sev = Counter(a["severity"] for a in alerts)
    by_det = Counter(a["detector"] for a in alerts)
    ips = Counter(a["source_ip"] or "unknown" for a in alerts)
    ext_sent = [m for m in emails if m["external"] and m["status"] == "SENT"]
    ext_blocked = [m for m in emails if m["external"] and m["status"] == "BLOCKED"]

    # Findings grouped by individual rule
    groups = defaultdict(lambda: {"count": 0, "sev": "LOW", "ips": set(), "first": None, "last": None,
                                  "detector": "", "techniques": set()})
    for a in alerts:
        rules = [r.replace(" (inside base64)", "").strip() for r in a["rule"].split(",")]
        if a["detector"] == "indirect":
            # one indirect-injection finding; the individual rules are the techniques it used
            groups["indirect_injection"]["techniques"].update(rules)
            rules = ["indirect_injection"]
        for key in rules:
            key = "canary_leak" if key.startswith("canary_leak_") else key
            g = groups[key]
            g["count"] += 1
            g["detector"] = a["detector"]
            g["ips"].add(a["source_ip"] or "unknown")
            if SEV_ORDER[a["severity"]] < SEV_ORDER[g["sev"]]:
                g["sev"] = a["severity"]
            g["first"] = min(filter(None, [g["first"], a["ts"]]))
            g["last"] = max(filter(None, [g["last"], a["ts"]]))
    findings = sorted(groups.items(), key=lambda kv: (SEV_ORDER[kv[1]["sev"]], -kv[1]["count"]))

    rec_keys = set()
    for k, g in findings:
        rec_keys.add(k)
    recs = [RECOMMENDATIONS[k] for k in RECOMMENDATIONS if k in rec_keys] + BASELINE

    def chips(items):
        return "".join(f'<span class="chip">{_e(i)}</span>' for i in items) or "-"

    finding_rows = ""
    for i, (rule, g) in enumerate(findings, 1):
        m = compliance.map_rule(rule, g["detector"])
        finding_rows += f"""<tr><td class="mono" style="white-space:nowrap">F-{i:02d}</td><td><span class="sev {g['sev']}">{_e(g['sev'])}</span></td>
          <td><b>{_e(compliance.describe(rule, g['detector']))}</b><div class="mono small">{_e(rule)} · {_e(g['detector'])}</div>
          {f'<div class="small muted">Techniques: {_e(", ".join(sorted(g["techniques"])))}</div>' if g["techniques"] else ''}</td>
          <td class="num">{g['count']}</td><td class="mono small">{_e(', '.join(sorted(g['ips'])))}</td>
          <td class="small">{chips(m['owasp'])}{chips(m['atlas'])}</td>
          <td class="small">{chips(m['eu_ai_act'])}</td></tr>"""

    email_rows = "".join(
        f"""<tr><td class="mono small">{_e(_fmt_ts(m['ts']))}</td><td><span class="sev {'HIGH' if m['status']=='SENT' else 'OK'}">{_e(m['status'])}</span></td>
        <td class="mono small">{_e(m['recipient'])}</td><td>{_e(m['subject'])}</td><td class="mono small">{_e(m['source_ip'])}</td>
        <td class="small">{_e(m['body'][:160])}{'…' if len(m['body']) > 160 else ''}</td></tr>"""
        for m in [x for x in emails if x["external"]][:30])

    control_rows = "".join(
        f"""<tr><td><b>{_e(c['framework'])}</b><div class="small">{_e(c['ref'])}</div></td><td class="small">{_e(c['requirement'])}</td>
        <td class="small">{_e(c['implementation'])}<div class="mono small muted">{_e(c['evidence'])}</div></td>
        <td><span class="status {c['status']}">{_e(c['status'])}</span></td><td class="small">{_e(c['gap']) or '-'}</td></tr>"""
        for c in compliance.CONTROLS)

    det_rows = "".join(f"<tr><td>{_e(d)}</td><td class='num'>{n}</td></tr>" for d, n in by_det.most_common())
    ip_rows = "".join(f"<tr><td class='mono'>{_e(i)}</td><td class='num'>{n}</td></tr>" for i, n in ips.most_common(10))
    problems = "".join(f"<li><b>{_e(p['type'])}</b>: {_e(p['detail'])} (audit entry #{p['audit_id']})</li>"
                       for p in audit["problems"])
    unaudited = ", ".join(f"{_e(k)}: {v}" for k, v in audit["unaudited"].items())
    rec_html = "".join(f"<li>{_e(r)}</li>" for r in recs)
    pct = round(100 * req["flagged"] / req["total"]) if req["total"] else 0
    report_id = f"LLMSEC-{generated:%Y%m%d-%H%M}-{audit['last_hash'][:8]}"

    summary = (f"During the reporting period the assistant handled <b>{req['total']}</b> requests, of which "
               f"<b>{req['flagged']}</b> ({pct}%) triggered at least one detection, producing <b>{len(alerts)}</b> alerts "
               f"(<b>{sev.get('HIGH', 0)}</b> high severity) from <b>{len(ips)}</b> source IP(s). ")
    if ext_sent:
        summary += (f"<b>{len(ext_sent)}</b> email(s) containing data were sent to external recipients while the proxy "
                    f"ran in MONITOR mode: these represent successful data exfiltration in the test environment. ")
    if ext_blocked:
        summary += f"<b>{len(ext_blocked)}</b> external email attempt(s) were blocked. "
    summary += "The audit log integrity check " + ("<b>passed</b>." if audit["ok"] else "<b>FAILED</b>: see section 6.")

    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>{_e(report_id)} · LLM Security Assessment Report</title>
<style>
  @page {{ size: A4; margin: 16mm 14mm; }}
  body {{ font-family: "Segoe UI", system-ui, Roboto, sans-serif; color: #1b1b1a; font-size: 12.5px; line-height: 1.45; margin: 0; background: #fff; }}
  .page {{ max-width: 980px; margin: 0 auto; padding: 28px 32px; }}
  h1 {{ font-size: 24px; margin: 0 0 4px; }} h2 {{ font-size: 16px; margin: 26px 0 8px; padding-bottom: 4px; border-bottom: 2px solid #1b1b1a; }}
  .meta {{ display: grid; grid-template-columns: 150px 1fr 150px 1fr; gap: 3px 10px; margin: 14px 0; font-size: 12px; }}
  .meta dt {{ color: #6b6a64; }} .meta dd {{ margin: 0; }}
  .risk {{ display: flex; gap: 14px; align-items: center; border: 1px solid #ddd; border-left: 6px solid; border-radius: 6px; padding: 12px 14px; margin: 10px 0; }}
  .risk.CRITICAL, .risk.HIGH {{ border-left-color: #d03b3b; }} .risk.MEDIUM {{ border-left-color: #e8a000; }} .risk.LOW {{ border-left-color: #0ca30c; }}
  .risk .lvl {{ font-size: 18px; font-weight: 750; }}
  .kpis {{ display: grid; grid-template-columns: repeat(6, 1fr); gap: 8px; margin: 12px 0; }}
  .kpi {{ border: 1px solid #ddd; border-radius: 6px; padding: 8px 10px; }} .kpi b {{ font-size: 20px; display: block; }} .kpi span {{ color: #6b6a64; font-size: 11px; }}
  table {{ width: 100%; border-collapse: collapse; margin: 6px 0; }}
  th {{ text-align: left; font-size: 11px; color: #6b6a64; border-bottom: 1px solid #bbb; padding: 5px 6px; }}
  td {{ border-bottom: 1px solid #e6e6e3; padding: 6px; vertical-align: top; }}
  tr {{ page-break-inside: avoid; }}
  .num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  .mono {{ font-family: Consolas, "Cascadia Mono", monospace; }} .small {{ font-size: 11px; }} .muted {{ color: #6b6a64; }}
  .chip {{ display: inline-block; border: 1px solid #ccc; border-radius: 4px; padding: 0 5px; margin: 1px 3px 1px 0; font-size: 10.5px; white-space: nowrap; }}
  .sev, .status {{ display: inline-block; font-weight: 700; font-size: 10.5px; padding: 1px 7px; border-radius: 99px; border: 1px solid; white-space: nowrap; }}
  .sev.HIGH {{ color: #b02a2a; border-color: #d03b3b; background: #fdecec; }} .sev.MEDIUM {{ color: #8a5d00; border-color: #e8a000; background: #fff6e0; }}
  .sev.LOW {{ color: #1c5cab; border-color: #6da7ec; background: #eef5fd; }} .sev.OK {{ color: #076b07; border-color: #0ca30c; background: #eaf7ea; }}
  .status.Implemented {{ color: #076b07; border-color: #0ca30c; }} .status.Partial {{ color: #8a5d00; border-color: #e8a000; }} .status.Gap {{ color: #b02a2a; border-color: #d03b3b; }}
  .two {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
  .integrity {{ border: 1px solid #ddd; border-radius: 6px; padding: 10px 12px; }}
  .integrity.ok {{ border-left: 6px solid #0ca30c; }} .integrity.bad {{ border-left: 6px solid #d03b3b; }}
  .hash {{ font-family: Consolas, monospace; font-size: 11px; word-break: break-all; background: #f4f4f2; padding: 4px 6px; border-radius: 4px; }}
  .toolbar {{ position: sticky; top: 0; background: #1b1b1a; color: #fff; padding: 10px 32px; display: flex; gap: 12px; align-items: center; }}
  .toolbar button {{ font: inherit; font-weight: 650; background: #fff; color: #1b1b1a; border: 0; border-radius: 6px; padding: 6px 14px; cursor: pointer; }}
  .note {{ font-size: 11px; color: #6b6a64; }}
  @media print {{ .toolbar {{ display: none; }} .page {{ padding: 0; }} h2 {{ page-break-after: avoid; }} }}
</style></head><body>
<div class="toolbar"><span>Security assessment report · {_e(report_id)}</span><span style="flex:1"></span>
  <button onclick="window.print()">Print / Save as PDF</button></div>
<div class="page">
  <div class="note">CONFIDENTIAL · Test environment</div>
  <h1>LLM Application Security Assessment</h1>
  <div class="muted">Prompt injection, data leakage and tool-abuse monitoring report</div>
  <dl class="meta">
    <dt>Report ID</dt><dd class="mono">{_e(report_id)}</dd><dt>Generated</dt><dd>{generated:%Y-%m-%d %H:%M %Z}</dd>
    <dt>System assessed</dt><dd>{_e(SYSTEM_NAME)}</dd><dt>Reporting period</dt><dd>{_e(period)}</dd>
    <dt>Prepared by</dt><dd>{_e(AUTHOR)}</dd><dt>Proxy mode</dt><dd>{_e(mode)}</dd>
  </dl>

  <h2>1. Executive summary</h2>
  <div class="risk {risk}"><div><div class="muted small">Overall risk</div><div class="lvl">{risk}</div></div><div>{_e(risk_text)}</div></div>
  <p>{summary}</p>
  <div class="kpis">
    <div class="kpi"><b>{req['total']}</b><span>Requests</span></div>
    <div class="kpi"><b>{req['flagged']}</b><span>Flagged ({pct}%)</span></div>
    <div class="kpi"><b>{len(alerts)}</b><span>Alerts</span></div>
    <div class="kpi"><b>{sev.get('HIGH', 0)}</b><span>High severity</span></div>
    <div class="kpi"><b>{len(ext_sent)}</b><span>External emails sent</span></div>
    <div class="kpi"><b>{req['blocked']}</b><span>Blocked responses</span></div>
  </div>

  <h2>2. Findings</h2>
  {'<table><tr><th>ID</th><th>Severity</th><th>Finding</th><th class="num">Count</th><th>Sources</th><th>OWASP / MITRE ATLAS</th><th>EU AI Act</th></tr>' + finding_rows + '</table>' if findings else '<p>No findings in this period.</p>'}

  <h2>3. Data exfiltration attempts (external recipients)</h2>
  {'<table><tr><th>Time</th><th>Status</th><th>Recipient</th><th>Subject</th><th>Source IP</th><th>Content (excerpt)</th></tr>' + email_rows + '</table>' if email_rows else '<p>No emails to external recipients were attempted.</p>'}

  <h2>4. Detection coverage and attack sources</h2>
  <div class="two">
    <div><table><tr><th>Detection layer</th><th class="num">Alerts</th></tr>{det_rows or '<tr><td colspan=2>-</td></tr>'}</table></div>
    <div><table><tr><th>Source IP</th><th class="num">Alerts</th></tr>{ip_rows or '<tr><td colspan=2>-</td></tr>'}</table></div>
  </div>

  <h2>5. Control mapping</h2>
  <p class="note">The EU AI Act's Art. 9-15 obligations apply to high-risk AI systems. This assessment uses them as a reference
  control framework; the assessed chatbot is not necessarily high-risk. Statuses are self-assessed.</p>
  <table><tr><th>Framework / reference</th><th>Requirement</th><th>Implementation and evidence</th><th>Status</th><th>Gap</th></tr>{control_rows}</table>

  <h2>6. Log integrity (tamper evidence)</h2>
  <div class="integrity {'ok' if audit['ok'] else 'bad'}">
    <b>{'INTACT: ' + str(audit['entries']) + ' audit entries verified, no modification, deletion or reordering detected.' if audit['ok'] else 'TAMPERING DETECTED: the records below no longer match the audit log.'}</b>
    {'<ul>' + problems + '</ul>' if problems else ''}
    <div style="margin-top:8px" class="small">Latest chain hash (store this value outside the system to anchor the log):</div>
    <div class="hash">{_e(audit['last_hash'])}</div>
    {f'<div class="small muted" style="margin-top:6px">Records created before audit logging was enabled (not covered): {unaudited}</div>' if unaudited else ''}
  </div>

  <h2>7. Recommendations</h2>
  <ol>{rec_html}</ol>

  <h2>8. Methodology and limitations</h2>
  <p class="small">Traffic to the assistant passes through a monitoring proxy that applies five detection layers: rule-based input
  analysis, a canary token in the system prompt, tool-call policy monitoring, decoy (honey) tools, and scanning of third-party
  content returned by tools. Attacks were generated with a repeatable attack suite plus manual testing from a separate host.
  Limitations: rule-based detection can be evaded by paraphrasing; results from the test model may differ from a production
  LLM; the audit chain is tamper-evident, not tamper-proof, unless its latest hash is anchored externally; email "sending" is
  simulated (messages are written to a local outbox and never leave the machine).</p>
  <p class="note">Framework references: OWASP Top 10 for LLM Applications 2025 · MITRE ATLAS · Regulation (EU) 2024/1689 (AI Act) ·
  BSI "Generative AI Models - Opportunities and Risks for Industry and Authorities" · BSI "Indirect Prompt Injections".</p>
</div></body></html>"""
