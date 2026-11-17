#!/usr/bin/env python3
"""Allowlisting CONNECT-only egress proxy — the API's single egress boundary.

Design constraints (ADR-0012, NETWORK_ARCHITECTURE.md §4):
  * CONNECT is the ONLY accepted method. Any other request line is refused 403.
  * The destination must match EGRESS_ALLOWLIST exactly ("host:port", case-
    insensitive). No wildcards, no suffix matching, no port ranges.
  * The resolved address must not fall inside an internal VAPT subnet, so an
    allowlisted name cannot be pointed at an internal component.
  * It listens on ONE address (PROXY_BIND_IP) — the egress-network interface —
    so nothing on the WAN side can use it as a proxy.
  * No caching, no request-body handling, no credential passthrough.
  * Every decision is one JSON line on stdout (collected by `docker logs`, and
    in M2 shipped into the audit trail).

This component has no notion of prompts, models or providers. Destination
allowlisting happens below the application, so an application bug cannot open a
destination this proxy does not permit.
"""
from __future__ import annotations
import ipaddress, json, os, selectors, socket, sys, threading, time

BIND_IP = os.environ["PROXY_BIND_IP"]
BIND_PORT = int(os.environ.get("PROXY_PORT", "3128"))
ALLOWLIST = {e.strip().lower() for e in os.environ.get("EGRESS_ALLOWLIST", "").split(",") if e.strip()}
DENY_CIDRS = [ipaddress.ip_network(c.strip()) for c in
              os.environ.get("INTERNAL_DENY_CIDRS", "172.30.20.0/24,172.30.21.0/24,172.30.22.0/24,172.30.10.0/24").split(",")
              if c.strip()]
MAX_HEADER = 8192
IDLE_TIMEOUT = 60


def log(**kw) -> None:
    print(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **kw}), flush=True)


def deny(conn: socket.socket, code: int, reason: str, **ctx) -> None:
    log(verdict="deny", code=code, reason=reason, **ctx)
    try:
        conn.sendall(f"HTTP/1.1 {code} Forbidden\r\nContent-Length: 0\r\n"
                     f"X-Egress-Deny-Reason: {reason}\r\nConnection: close\r\n\r\n".encode())
    except OSError:
        pass
    conn.close()


def relay(a: socket.socket, b: socket.socket) -> tuple[int, int]:
    sel = selectors.DefaultSelector()
    sel.register(a, selectors.EVENT_READ, b)
    sel.register(b, selectors.EVENT_READ, a)
    sent = {id(a): 0, id(b): 0}
    try:
        while True:
            events = sel.select(timeout=IDLE_TIMEOUT)
            if not events:
                break
            for key, _ in events:
                src, dst = key.fileobj, key.data
                data = src.recv(65536)
                if not data:
                    return sent[id(a)], sent[id(b)]
                dst.sendall(data)
                sent[id(src)] += len(data)
    except OSError:
        pass
    finally:
        sel.close()
    return sent[id(a)], sent[id(b)]


def handle(conn: socket.socket, peer: tuple[str, int]) -> None:
    conn.settimeout(20)
    ctx = {"peer": peer[0]}
    try:
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(1024)
            if not chunk:
                return conn.close()
            buf += chunk
            if len(buf) > MAX_HEADER:
                return deny(conn, 431, "header_too_large", **ctx)
        head = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1")
        lines = head.split("\r\n")
        parts = lines[0].split()
        ctx["request_line"] = lines[0][:120]
        for h in lines[1:]:
            if h.lower().startswith("x-vapt-trace:"):
                ctx["trace_id"] = h.split(":", 1)[1].strip()[:64]
        if len(parts) != 3:
            return deny(conn, 400, "malformed_request_line", **ctx)
        method, target, _ = parts
        ctx["method"] = method
        if method.upper() != "CONNECT":
            return deny(conn, 403, "method_not_connect", **ctx)
        if ":" not in target:
            return deny(conn, 403, "no_port_in_target", **ctx)
        host, _, port_s = target.rpartition(":")
        ctx["destination"] = f"{host}:{port_s}"
        if not port_s.isdigit():
            return deny(conn, 403, "non_numeric_port", **ctx)
        if f"{host.lower()}:{port_s}" not in ALLOWLIST:
            return deny(conn, 403, "destination_not_allowlisted", **ctx)
        try:
            infos = socket.getaddrinfo(host, int(port_s), socket.AF_INET, socket.SOCK_STREAM)
        except OSError as e:
            return deny(conn, 502, f"resolution_failed:{e.__class__.__name__}", **ctx)
        addrs = {i[4][0] for i in infos}
        ctx["resolved"] = sorted(addrs)
        for a in addrs:
            if any(ipaddress.ip_address(a) in n for n in DENY_CIDRS):
                return deny(conn, 403, "resolves_into_internal_network", **ctx)
        up = socket.create_connection((sorted(addrs)[0], int(port_s)), timeout=10)
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        log(verdict="allow", **ctx)
        conn.settimeout(None); up.settimeout(None)
        tx, rx = relay(conn, up)
        log(verdict="closed", bytes_client_to_dest=tx, bytes_dest_to_client=rx, **ctx)
        up.close()
    except (OSError, UnicodeDecodeError) as e:
        log(verdict="error", error=e.__class__.__name__, **ctx)
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main() -> None:
    if not ALLOWLIST:
        sys.exit("refused to start: EGRESS_ALLOWLIST is empty (fail closed)")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((BIND_IP, BIND_PORT))          # single interface, never 0.0.0.0
    srv.listen(64)
    log(event="listening", bind=f"{BIND_IP}:{BIND_PORT}", allowlist=sorted(ALLOWLIST),
        internal_deny=[str(c) for c in DENY_CIDRS])
    while True:
        conn, peer = srv.accept()
        threading.Thread(target=handle, args=(conn, peer), daemon=True).start()


if __name__ == "__main__":
    main()
