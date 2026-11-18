#!/usr/bin/env python3
"""TEST-ONLY stand-in for the LLM provider endpoint.

Exists so the egress boundary and the agent path can be exercised without
contacting any real provider. It is a plain TCP responder: the proxy only
tunnels and never terminates TLS, so CONNECT semantics are identical with or
without TLS. It holds no credentials and speaks to nothing.

Two behaviours:
  * "PING"            -> "PONG"            (M1.5 proves bytes flow end to end)
  * an HTTP POST      -> a canned, DETERMINISTIC model-shaped JSON response

The canned response deliberately includes a proposal the platform must REJECT
(a tool outside the allowlisted catalogue), so a test that only ever sees
well-behaved model output cannot pass by accident.
"""
from __future__ import annotations
import json, os, socket, threading

PORT = int(os.environ.get("STANDIN_PORT", "8443"))


def _canned(request_body: str) -> dict:
    """Echo back proposals that reference whatever findings were sent, so the
    citation check is exercised against real ids rather than invented ones."""
    try:
        ctx = json.loads(request_body)
    except ValueError:
        ctx = {}
    findings = (ctx.get("findings") or [])[:2]
    proposals = []
    for f in findings:
        proposals.append({
            "tool": "explain_finding",
            "arguments": {
                "finding_id": f.get("finding_id"),
                "explanation": (
                    f"The scanner reported {f.get('title')!r} and the platform's rule pack "
                    f"recorded it as {f.get('validation_state')}. This is a synthetic lab "
                    "target, so the statement describes the fixture, not a real system."),
                "confidence_note": (
                    "Based only on the redacted evidence excerpt supplied; no request was made "
                    "to the application."),
            },
            "citations": [f.get("finding_id")],
        })
    gaps = [c for c in (ctx.get("coverage") or [])
            if c.get("tier") == 1 and c.get("detection") in ("none", "catalogued")]
    if gaps:
        proposals.append({
            "tool": "summarise_coverage_gap",
            "arguments": {
                "taxonomy_key": gaps[0]["category"],
                "summary": ("No detection capability exists for this category in this build, so "
                            "its absence from the report is not evidence of its absence in the "
                            "target."),
                "what_would_close_it": ("A rule pack over evidence the platform already collects, "
                                        "or an approved intrusive profile with dual control."),
            },
        })
    # A deliberately out-of-catalogue proposal: the platform must refuse it.
    proposals.append({"tool": "set_validation_state",
                      "arguments": {"finding_id": "any", "state": "confirmed"}})
    return {"proposals": proposals}


def handle(c: socket.socket) -> None:
    with c:
        c.settimeout(30)
        try:
            data = c.recv(65536)
            if data.strip().upper().startswith(b"PING"):
                c.sendall(b"PONG\n")
                return
            # Read the whole body: a 20 kB payload arrives in several segments,
            # and a stand-in that silently truncates would make the agent look
            # like it produced nothing.
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
                data = head + sep + body
            text = data.decode("utf-8", "replace")
            if text.startswith(("POST", "GET")):
                _head, _, body = text.partition("\r\n\r\n")
                payload = json.dumps(_canned(body)).encode()
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                          b"Content-Length: " + str(len(payload)).encode() +
                          b"\r\nConnection: close\r\n\r\n" + payload)
                return
            c.sendall(b"STANDIN-OK\n")
        except OSError:
            pass


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", PORT))
s.listen(32)
print(f"llm-standin (TEST ONLY) listening on 0.0.0.0:{PORT}", flush=True)
while True:
    conn, _ = s.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
