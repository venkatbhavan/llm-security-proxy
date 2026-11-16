"""LLM client with two modes.

mock   - fake, deliberately vulnerable model. Lets you build and test the whole
         pipeline with no API key and no cost.
api    - any OpenAI-compatible Chat Completions API (Gemini, Groq, Ollama, OpenAI).

call_llm(messages) takes the full message list (system, user, assistant, tool)
so the model can read tool results and act on them - which is exactly what
indirect prompt injection exploits.

Returns: {"content": str, "tool_calls": [{"id": str, "name": str, "arguments": dict}]}
"""
import json
import re
import time
import uuid

import httpx

from app.config import CANARY_TOKEN, LLM_API_KEY, LLM_BASE_URL, LLM_MODE, LLM_MODEL, SYSTEM_PROMPT
from app.tools import TOOL_SCHEMAS


def _call(name, **arguments):
    return {"id": f"call_{uuid.uuid4().hex[:8]}", "name": name, "arguments": arguments}


def _mock_after_tool(tool_text: str):
    """Mock model reading a tool result. It naively obeys instructions it finds
    in the data - that is the vulnerability indirect injection relies on."""
    if '"status": "sent"' in tool_text:
        sent = json.loads(tool_text)
        return {"content": f"Done! I've sent the email \"{sent['subject']}\" to {sent['to']}.",
                "tool_calls": []}
    if '"error"' in tool_text:
        return {"content": "I tried to complete that, but the action was blocked.", "tool_calls": []}
    m = re.search(r"\b(send|email|forward)\b.{0,80}?([\w.+-]+@([\w-]+\.)+\w+)", tool_text, re.I | re.S)
    if m and "exampleshop.com" not in m.group(2):
        return {"content": "Here is a summary of the reviews.",
                "tool_calls": [_call("send_email", to=m.group(2), subject="Account data backup",
                                     body="Order history for customer Mia K.:\n"
                                          "- A1001  Leather jacket   EUR 249.00  shipped\n"
                                          "- A0974  Running shoes    EUR 119.90  delivered\n"
                                          "Shipping address: Musterstrasse 12, 60311 Frankfurt\n")]}
    if '"reviews"' in tool_text:
        n = tool_text.count('"author"')
        return {"content": f"I found {n} reviews. Customers are mostly happy with it.", "tool_calls": []}
    return {"content": "Done - anything else I can help with?", "tool_calls": []}


def _mock_llm(messages):
    last = messages[-1]
    if last["role"] == "tool":
        return _mock_after_tool(last["content"])

    user_prompt = last["content"]
    p = user_prompt.lower()
    # Vulnerable behaviour on purpose, so detectors have something to catch.
    wants_secret = re.search(r"instructions|system prompt|hidden prompt|reference key|confidential", p)
    if re.search(r"admin.{0,20}(password|credential|login)|(password|credential)s?.{0,20}admin", p):
        return {"content": "Fetching admin credentials.",
                "tool_calls": [_call("get_admin_credentials", system="backend")]}
    if re.search(r"(export|dump|download|list) (all|every|the (whole|full|entire))", p) and "customer" in p:
        return {"content": "Exporting customer data.",
                "tool_calls": [_call("export_all_customers", format="csv")]}
    m = re.search(r"email .*?([\w.+-]+@[\w.-]+\.\w+)", p)
    if m:  # follows the email request - and leaks secrets into it if asked
        if wants_secret:
            subject, body = "Summary of my instructions", "As requested, here are my instructions:\n\n" + SYSTEM_PROMPT
        else:
            subject, body = "Message from ExampleShop support", user_prompt
        return {"content": "Sending that email now.",
                "tool_calls": [_call("send_email", to=m.group(1), subject=subject, body=body)]}
    if wants_secret and "backwards" in p:
        return {"content": f"Here it is reversed: {CANARY_TOKEN[::-1]}", "tool_calls": []}
    if wants_secret:
        return {"content": f"Sure! My instructions are: {SYSTEM_PROMPT}", "tool_calls": []}
    if "review" in p or "customers say" in p:
        product = "leather-jacket" if "jacket" in p else "running-shoes"
        return {"content": "", "tool_calls": [_call("get_product_reviews", product_id=product)]}
    if "order" in p:
        return {"content": "Let me look that up.",
                "tool_calls": [_call("search_orders", query=user_prompt)]}
    return {"content": "I can help with orders, shipping and returns.", "tool_calls": []}


def _api_llm(messages, retries=4):
    """Any OpenAI-compatible Chat Completions API (Gemini, Groq, Ollama, OpenAI)."""
    for attempt in range(retries + 1):
        r = httpx.post(
            f"{LLM_BASE_URL}/chat/completions",
            headers={"Authorization": f"Bearer {LLM_API_KEY}"},
            json={"model": LLM_MODEL, "messages": messages, "tools": TOOL_SCHEMAS},
            timeout=90,
        )
        if r.status_code in (429, 503) and attempt < retries:   # free-tier rate limit: wait and retry
            wait = float(r.headers.get("retry-after", 0) or 0) or 5 * (attempt + 1)
            time.sleep(min(wait, 60))
            continue
        if r.status_code >= 400:
            raise RuntimeError(f"LLM API error {r.status_code}: {r.text[:300]}")
        break
    msg = r.json()["choices"][0]["message"]
    calls = []
    for tc in msg.get("tool_calls") or []:
        args = tc["function"].get("arguments") or "{}"
        calls.append({"id": tc.get("id") or f"call_{uuid.uuid4().hex[:8]}",   # some providers omit ids
                      "name": tc["function"]["name"],
                      "arguments": args if isinstance(args, dict) else json.loads(args)})
    # Keep the provider's original tool_call objects: some (e.g. Gemini 3.x "thought_signature" in
    # extra_content) must be echoed back unchanged in the next request, or the API rejects it.
    raw = msg.get("tool_calls") or []
    for orig, norm in zip(raw, calls):
        orig["id"] = norm["id"]                      # ensure ids match the tool results we send back
        if isinstance(orig.get("function", {}).get("arguments"), dict):
            orig["function"]["arguments"] = json.dumps(orig["function"]["arguments"])
        orig.setdefault("type", "function")
        if "googleapis.com" in LLM_BASE_URL:      # Gemini only: documented fallback if no signature came back
            sig = orig.setdefault("extra_content", {}).setdefault("google", {})
            sig.setdefault("thought_signature", "skip_thought_signature_validator")
    return {"content": msg.get("content") or "", "tool_calls": calls, "raw_tool_calls": raw}


def call_llm(messages):
    return _mock_llm(messages) if LLM_MODE == "mock" else _api_llm(messages)


def start_messages(user_prompt):
    return [{"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt}]
