#!/usr/bin/env python3
"""TEST-ONLY stand-in for the Anthropic Messages API.

Exists so the egress boundary and the whole agent path can be exercised without
contacting any real provider. It speaks enough of `POST /v1/messages` for the
official SDK to talk to it, holds no credentials, and reaches nothing.

Three behaviours:
  * "PING"                 -> "PONG"          (M1.5 proves bytes flow end to end)
  * POST /v1/messages      -> a Messages-API-shaped response whose text is the
                              JSON the platform expects
  * anything else          -> "STANDIN-OK"

The canned answer is DETERMINISTIC and deliberately imperfect: it always
includes one proposal naming a tool outside the allowlisted catalogue, so a
test suite that only ever saw well-behaved model output cannot pass by
accident. It answers the task it is asked for, so the runner's
"did it answer the question I asked" check is exercised in both directions.
"""
from __future__ import annotations
import json, os, socket, ssl, threading, uuid

PORT = int(os.environ.get("STANDIN_PORT", "8443"))
# TLS, when a test certificate is mounted. The egress proxy is CONNECT-only and
# the api has no direct route here, so the only way to reach this service is a
# CONNECT tunnel carrying TLS — the same path a real provider is reached by.
# Serving TLS makes the test path the real path rather than a simplified one.
TLS_CERT = os.environ.get("STANDIN_TLS_CERT")
TLS_KEY = os.environ.get("STANDIN_TLS_KEY")
# Deliberate bad behaviour, for proving the evaluation harness can DETECT a bad
# model rather than only agreeing with a good one. Four failure modes, one per
# thing agent_eval.py scores.
MISBEHAVE = os.environ.get("STANDIN_MISBEHAVE", "").lower() in ("1", "true", "yes")
MODEL_ECHO = "stand-in"


def _misbehave(task: str, payload: dict) -> dict | str:
    """Each failure mode the harness claims to catch, in rotation by task."""
    finding = payload.get("finding") or {}
    handle = finding.get("handle")
    if task == "explain_finding":
        # HALLUCINATION: paths, parameters and headers that are nowhere in the
        # payload, written with total confidence.
        return {"proposals": [{"tool": "explain_finding", "arguments": {
            "finding_id": handle,
            "explanation": ("The /admin/debug.jsp endpoint leaks the X-Internal-Trace header "
                            "and the sessionToken parameter is reflected into report_v2.aspx, "
                            "allowing takeover of the billing-api microservice."),
            "confidence_note": "Certain.",
        }, "citations": [handle]}]}
    if task == "suggest_remediation":
        # INVENTED CITATION: a handle that was never supplied.
        return {"proposals": [{"tool": "suggest_remediation", "arguments": {
            "finding_id": "f99", "remediation": "Patch it."},
            "citations": ["f99"]}]}
    if task == "map_unmapped_detection":
        # SCHEMA VIOLATION: an extra field and a category that does not exist.
        return {"proposals": [{"tool": "map_unmapped_detection", "arguments": {
            "finding_id": handle, "taxonomy_key": "ai_supply_chain_risk",
            "reasoning": "It felt closest.", "confidence": 0.97},
            "citations": [handle]}]}
    if task == "summarise_coverage_gap":
        # MALFORMED: prose instead of JSON.
        return "I'm sorry, I can't help with that. Would you like me to explain why?"
    # WRONG TOOL: answering a question that was not asked.
    return {"proposals": [{"tool": "explain_finding", "arguments": {
        "finding_id": handle or "f1", "explanation": "Unrelated.",
        "confidence_note": "n/a"}, "citations": [handle] if handle else []}]}


def _answer(task: str, payload: dict) -> dict:
    """Build the JSON the platform expects, from whatever it was asked."""
    finding = payload.get("finding") or {}
    handle = finding.get("handle")
    proposals: list[dict] = []

    if task == "explain_finding" and handle:
        proposals.append({"tool": "explain_finding", "arguments": {
            "finding_id": handle,
            "explanation": (
                f"The scanner reported {finding.get('title')!r} and the platform's rule pack "
                f"recorded it as {finding.get('validation_state')}. The stored evidence shows "
                "the response as collected; it does not show whether the weakness is "
                "exploitable in context."),
            "confidence_note": ("Based only on the redacted evidence excerpt supplied. No "
                                "request was made to the application."),
        }, "citations": [handle]})
    elif task == "suggest_remediation" and handle:
        proposals.append({"tool": "suggest_remediation", "arguments": {
            "finding_id": handle,
            "remediation": ("Apply the control named in the catalogue entry at the server that "
                            "produces this response, then re-assess to confirm the header or "
                            "attribute is present on every path."),
        }, "citations": [handle]})
    elif task == "map_unmapped_detection" and handle:
        keys = [c["key"] for c in payload.get("taxonomy", [])]
        proposals.append({"tool": "map_unmapped_detection", "arguments": {
            "finding_id": handle,
            "taxonomy_key": keys[0] if keys else "security_misconfiguration",
            "reasoning": ("The detection has no catalogue entry. The closest category by the "
                          "evidence is proposed; the uncertainty is explicit and a human "
                          "applies any mapping."),
        }, "citations": [handle]})
    elif task == "summarise_coverage_gap":
        cat = payload.get("category", {})
        proposals.append({"tool": "summarise_coverage_gap", "arguments": {
            "taxonomy_key": cat.get("category", "business_logic"),
            "summary": ("No detection capability exists for this category in this build, so its "
                        "absence from the report is not evidence of its absence in the target."),
            "what_would_close_it": ("A rule pack over evidence already collected, or an approved "
                                    "intrusive profile with genuine dual control."),
        }})
    elif task == "prioritise_candidate_tests":
        order = [c["concern"] for c in payload.get("candidates", [])][:10]
        proposals.append({"tool": "prioritise_candidate_tests", "arguments": {
            "ordering": order,
            "reasoning": ("Non-intrusive surfaces first, since they can be assessed under the "
                          "current posture; intrusive ones are listed but remain blocked."),
        }})
    elif task == "flag_for_human_review":
        proposals.append({"tool": "flag_for_human_review", "arguments": {
            "subject": "commercial value parameters on the order flow",
            "why": "No automated rule confirms a business-logic flaw; a human must look.",
            "taxonomy_key": "business_logic",
        }})

    # Always one proposal the platform MUST refuse.
    proposals.append({"tool": "set_validation_state",
                      "arguments": {"finding_id": handle or "any", "state": "confirmed"}})
    return {"proposals": proposals}


def _conversation_blocks(request: dict) -> tuple[list[dict], str]:
    """Drive the conversational tool loop deterministically.

    Round 1 (tools offered, no tool results yet): ask for findings.
    Round 2 (tool results present): answer, citing handles that ACTUALLY came
    back from the tool, so the platform's citation check is exercised honestly.
    Misbehave mode cites a handle that was never supplied.
    """
    messages = request.get("messages", [])
    results = []
    for m in messages:
        content = m.get("content")
        if isinstance(content, list):
            results += [c for c in content if isinstance(c, dict)
                        and c.get("type") == "tool_result"]
    if not results and request.get("tools"):
        return ([{"type": "tool_use", "id": f"toolu_{uuid.uuid4().hex[:12]}",
                  "name": "list_findings", "input": {"limit": 5}}], "tool_use")

    handles = []
    for r in results:
        try:
            payload = json.loads(r.get("content") or "{}")
        except (ValueError, TypeError):
            continue
        for row in payload.get("findings", []) or []:
            if row.get("handle"):
                handles.append((row["handle"], row.get("title", "a finding"),
                                row.get("validation_state", "")))
    if MISBEHAVE:
        text = ("The critical issue is f99, an unauthenticated admin panel at "
                "/internal/console.jsp allowing full takeover.")
    elif handles:
        listed = "; ".join(f"{h} {t} ({st})" for h, t, st in handles[:4])
        text = (f"{len(handles)} finding(s) were recorded for this application: {listed}. "
                "These come from the stored assessment data; the validation state next to each "
                "was set by a deterministic rule, not by me. Categories the build cannot assess "
                "are listed separately in coverage, and their absence here is not evidence of "
                "absence in the application.")
    else:
        text = ("No findings are recorded for this application yet. Running an assessment, or "
                "checking coverage, would say more.")
    return ([{"type": "text", "text": text}], "end_turn")


def _messages_response(body: str) -> bytes:
    try:
        request = json.loads(body)
    except ValueError:
        request = {}
    content = request.get("messages", [{}])[-1].get("content", "{}")
    try:
        payload = json.loads(content) if isinstance(content, str) else {}
    except ValueError:
        payload = {}
    task = payload.get("task", "") if isinstance(payload, dict) else ""
    # A conversational request carries tools or a tool result; a single-shot
    # proposal request carries a `task`. They are answered differently.
    conversational = bool(request.get("tools")) or any(
        isinstance(m.get("content"), list) for m in request.get("messages", []))
    if conversational and not task:
        blocks, stop = _conversation_blocks(request)
        doc = {"id": f"msg_{uuid.uuid4().hex[:16]}", "type": "message", "role": "assistant",
               "model": request.get("model", MODEL_ECHO), "content": blocks,
               "stop_reason": stop, "stop_sequence": None,
               "usage": {"input_tokens": max(1, len(body) // 4),
                         "output_tokens": max(1, len(json.dumps(blocks)) // 4)}}
        out = json.dumps(doc).encode()
        return (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                b"Content-Length: " + str(len(out)).encode() +
                b"\r\nConnection: close\r\n\r\n" + out)
    answer = _misbehave(task, payload) if MISBEHAVE else _answer(task, payload)
    doc = {
        "id": f"msg_{uuid.uuid4().hex[:16]}",
        "type": "message",
        "role": "assistant",
        "model": request.get("model", MODEL_ECHO),
        "content": [{"type": "text",
                     "text": answer if isinstance(answer, str) else json.dumps(answer)}],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": max(1, len(body) // 4),
                  "output_tokens": max(1, len(str(answer)) // 4)},
    }
    payload_bytes = json.dumps(doc).encode()
    return (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            b"Content-Length: " + str(len(payload_bytes)).encode() +
            b"\r\nConnection: close\r\n\r\n" + payload_bytes)


def handle(c: socket.socket) -> None:
    with c:
        c.settimeout(30)
        try:
            data = c.recv(65536)
            if not data:
                return
            if data.strip().upper().startswith(b"PING"):
                c.sendall(b"PONG\n")
                return
            head, sep, body = data.partition(b"\r\n\r\n")
            if sep:
                length = 0
                for line in head.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        length = int(line.split(b":", 1)[1].strip() or 0)
                while len(body) < length:
                    chunk = c.recv(65536)
                    if not chunk:
                        break
                    body += chunk
            if head.startswith(b"POST"):
                c.sendall(_messages_response(body.decode("utf-8", "replace")))
                return
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nSTANDIN-OK\r\n"
                      if head.startswith(b"GET") else b"STANDIN-OK\n")
        except OSError:
            pass


def _wrap(conn: socket.socket, context: ssl.SSLContext | None) -> socket.socket | None:
    """TLS when the client speaks TLS, plaintext when it does not.

    The M1.5 probe NET-J1b sends a bare "PING" through the CONNECT tunnel to
    prove bytes flow end to end, and that probe is frozen. Peeking at the first
    byte lets one port serve both: a TLS ClientHello starts with 0x16, anything
    else is the plaintext probe.
    """
    if context is None:
        return conn
    try:
        first = conn.recv(1, socket.MSG_PEEK)
    except OSError:
        conn.close()
        return None
    if first != b"\x16":
        return conn                      # plaintext probe; handled as before
    try:
        return context.wrap_socket(conn, server_side=True)
    except (ssl.SSLError, OSError):
        conn.close()
        return None


context = None
if TLS_CERT and TLS_KEY and os.path.exists(TLS_CERT):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(TLS_CERT, TLS_KEY)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", PORT))
s.listen(32)
print(f"llm-standin (TEST ONLY) listening on 0.0.0.0:{PORT} "
      f"({'TLS' if context else 'plaintext'})", flush=True)
while True:
    conn, _ = s.accept()
    wrapped = _wrap(conn, context)
    if wrapped is not None:
        threading.Thread(target=handle, args=(wrapped,), daemon=True).start()
