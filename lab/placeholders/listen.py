#!/usr/bin/env python3
"""M1.5 placeholder service.

Holds a container open and listens on EXACTLY the addresses given in BIND_SPEC
("ip:port[,ip:port...]"), so network topology can be measured before any
application code exists. It serves no application function: one line of text
naming the service, then close. No endpoints, no database, no auth.

The api placeholder uses this to bind ONLY its vapt_edge address, which is how
`NET-G5` can prove from the worker's perspective that the api is not reachable
from vapt_core.
"""
from __future__ import annotations
import os, socket, threading

NAME = os.environ.get("SERVICE_NAME", "placeholder")
SPEC = os.environ["BIND_SPEC"]


def serve(ip: str, port: int) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, port))
    s.listen(32)
    print(f"{NAME}: listening on {ip}:{port}", flush=True)
    while True:
        c, _ = s.accept()
        with c:
            try:
                c.sendall(f"{NAME} placeholder (M1.5)\n".encode())
            except OSError:
                pass


threads = []
for entry in SPEC.split(","):
    ip, _, port = entry.strip().rpartition(":")
    t = threading.Thread(target=serve, args=(ip, int(port)), daemon=False)
    t.start()
    threads.append(t)
for t in threads:
    t.join()
