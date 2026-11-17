#!/usr/bin/env python3
"""TEST-ONLY stand-in for the LLM provider endpoint.

Exists so M1.5 can prove the egress boundary without contacting any real
provider. It is a plain TCP responder: the proxy only tunnels and never
terminates TLS, so CONNECT semantics are identical with or without TLS.
Answers "PING" with "PONG", which proves bytes flow end to end through the
tunnel. It speaks no model API and holds no credentials.
"""
from __future__ import annotations
import os, socket, threading

PORT = int(os.environ.get("STANDIN_PORT", "8443"))


def handle(c: socket.socket) -> None:
    with c:
        c.settimeout(30)
        try:
            data = c.recv(4096)
            if data.strip().upper().startswith(b"PING"):
                c.sendall(b"PONG\n")
            else:
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
