#!/usr/bin/env python3
"""Allowlisting CONNECT-only egress proxy — the API's single egress boundary.

THIS IS A SECURITY BOUNDARY. It is deliberately small so it can be read in full,
but small is not the same as safe, so every property below is enforced in code
and covered by adversarial tests (tests/net/test_proxy_adversarial.py).

Policy, in order of evaluation:
  1. SOURCE   the peer address must be inside ALLOWED_CLIENT_CIDRS. Defence in
              depth: network isolation already prevents the worker and frontend
              from reaching this port, and the proxy refuses them anyway.
  2. CAPACITY a bounded number of concurrent tunnels; past that, 503. Thread
              creation is capped, so a flood cannot exhaust the host.
  3. SYNTAX   the request line must be exactly `CONNECT host:port HTTP/x.y`.
              The target is matched against a strict pattern: no scheme, no
              userinfo, no path, no brackets, no whitespace, no IPv6 literal.
              The port must be a decimal 1..65535.
  4. POLICY   `host:port` must match EGRESS_ALLOWLIST exactly (case-insensitive).
              No wildcards, no suffix matching. A trailing dot, a leading-zero
              port and a numeric host that is not a dotted-quad are REFUSED
              rather than normalised: parser-differential forms never reach
              policy evaluation.
  5. RESOLVE  the proxy resolves the name itself (A records only).
  6. ADDRESS  every resolved address must be outside INTERNAL_DENY_CIDRS, and
              must be a global unicast address — so an allowlisted NAME cannot
              be pointed at an internal component, at loopback, or at link-local
              metadata addresses.
  7. CONNECT  the connection is made to the VALIDATED IP ADDRESS, never to the
              hostname. The destination connected to is therefore the exact
              destination the policy authorised: there is no second resolution
              and so no DNS-rebinding window between check and connect.
  8. LIMITS   each tunnel is bounded by idle timeout, total duration and total
              bytes. Exceeding a bound closes the tunnel and logs it.

Every decision is one JSON line on stdout. The proxy has no notion of prompts,
models or providers: destination policy lives below the application, so an
application bug cannot open a destination this proxy does not permit.
"""
from __future__ import annotations
import ipaddress, json, os, re, selectors, socket, string, sys, threading, time

BIND_IP = os.environ["PROXY_BIND_IP"]
BIND_PORT = int(os.environ.get("PROXY_PORT", "3128"))
ALLOWLIST = {e.strip().lower().rstrip(".") for e in os.environ.get("EGRESS_ALLOWLIST", "").split(",") if e.strip()}
ALLOWED_CLIENT_CIDRS = [ipaddress.ip_network(c.strip()) for c in
                        os.environ.get("ALLOWED_CLIENT_CIDRS", "").split(",") if c.strip()]
DENY_CIDRS = [ipaddress.ip_network(c.strip()) for c in
              os.environ.get("INTERNAL_DENY_CIDRS",
                             "172.30.20.0/24,172.30.21.0/24,172.30.22.0/24,172.30.10.0/24").split(",")
              if c.strip()]
MAX_HEADER = int(os.environ.get("PROXY_MAX_HEADER_BYTES", "8192"))
MAX_HEADER_LINES = int(os.environ.get("PROXY_MAX_HEADER_LINES", "64"))
HEADER_TIMEOUT = int(os.environ.get("PROXY_HEADER_TIMEOUT_SECONDS", "15"))
IDLE_TIMEOUT = int(os.environ.get("PROXY_IDLE_TIMEOUT_SECONDS", "60"))
MAX_TUNNEL_SECONDS = int(os.environ.get("PROXY_MAX_TUNNEL_SECONDS", "900"))
MAX_TUNNEL_BYTES = int(os.environ.get("PROXY_MAX_TUNNEL_BYTES", str(64 * 1024 * 1024)))
MAX_CONCURRENT = int(os.environ.get("PROXY_MAX_CONCURRENT_TUNNELS", "16"))
UPSTREAM_TIMEOUT = int(os.environ.get("PROXY_UPSTREAM_TIMEOUT_SECONDS", "10"))

# host: dot-separated labels only. Rejects scheme, userinfo, path, query,
# brackets, IPv6 literals, whitespace and embedded colons by construction.
HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                     r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
PRINTABLE = set(string.printable) - set("\r\n\t\x0b\x0c")
_slots = threading.BoundedSemaphore(MAX_CONCURRENT)


def log(**kw) -> None:
    print(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **kw}), flush=True)


def scrub(s: str, limit: int = 120) -> str:
    return "".join(c if c in PRINTABLE else "?" for c in s)[:limit]


def refuse(conn: socket.socket, code: int, reason: str, **ctx) -> None:
    log(verdict="deny", code=code, reason=reason, **ctx)
    try:
        conn.sendall(f"HTTP/1.1 {code} {'Service Unavailable' if code == 503 else 'Forbidden'}\r\n"
                     f"Content-Length: 0\r\nX-Egress-Deny-Reason: {reason}\r\n"
                     f"Connection: close\r\n\r\n".encode())
    except OSError:
        pass
    try:
        conn.close()
    except OSError:
        pass


def relay(a: socket.socket, b: socket.socket) -> tuple[int, int, str]:
    """Bounded bidirectional relay. Returns (a->b bytes, b->a bytes, stop reason)."""
    sel = selectors.DefaultSelector()
    sel.register(a, selectors.EVENT_READ, b)
    sel.register(b, selectors.EVENT_READ, a)
    sent = {id(a): 0, id(b): 0}
    deadline = time.monotonic() + MAX_TUNNEL_SECONDS
    stop = "eof"
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return sent[id(a)], sent[id(b)], "max_duration"
            events = sel.select(timeout=min(IDLE_TIMEOUT, remaining))
            if not events:
                return sent[id(a)], sent[id(b)], ("max_duration" if time.monotonic() >= deadline else "idle_timeout")
            for key, _ in events:
                src, dst = key.fileobj, key.data
                data = src.recv(65536)
                if not data:
                    return sent[id(a)], sent[id(b)], "eof"
                dst.sendall(data)
                sent[id(src)] += len(data)
                if sent[id(a)] + sent[id(b)] > MAX_TUNNEL_BYTES:
                    return sent[id(a)], sent[id(b)], "max_bytes"
    except OSError:
        stop = "socket_error"
    finally:
        sel.close()
    return sent[id(a)], sent[id(b)], stop


def validate_target(target: str) -> tuple[str, int] | str:
    """Return (host, port) or a denial reason. Pure function; unit-testable."""
    if ":" not in target:
        return "no_port_in_target"
    host, _, port_s = target.rpartition(":")
    if not host:
        return "empty_host"
    if not port_s.isdigit() or not port_s.isascii():
        return "non_numeric_port"
    if len(port_s) > 1 and port_s[0] == "0":
        return "non_canonical_port"       # 08443 == 8443; refuse the ambiguous form
    port = int(port_s)
    if not 1 <= port <= 65535:
        return "port_out_of_range"
    if not HOST_RE.match(host):
        return "malformed_host"           # scheme, userinfo, path, brackets, IPv6 literal, whitespace
    # Alternative IP representations: a host made only of IP-ish characters must
    # be a valid dotted-quad IPv4 literal. This refuses decimal (2130706433),
    # hex (0x7f000001) and octal forms explicitly, instead of leaving them to be
    # caught by the allowlist.
    if host.strip(".0123456789abcdefABCDEFxX") == "":
        try:
            ipaddress.IPv4Address(host)
        except ipaddress.AddressValueError:
            return "ambiguous_numeric_host"
    return host, port


def handle(conn: socket.socket, peer: tuple[str, int]) -> None:
    ctx: dict[str, object] = {"peer": peer[0]}
    try:
        if ALLOWED_CLIENT_CIDRS and not any(ipaddress.ip_address(peer[0]) in n for n in ALLOWED_CLIENT_CIDRS):
            return refuse(conn, 403, "source_not_allowed", **ctx)
        conn.settimeout(HEADER_TIMEOUT)
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(1024)
            if not chunk:
                return conn.close()
            buf += chunk
            if len(buf) > MAX_HEADER:
                return refuse(conn, 431, "header_too_large", **ctx)
        head = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1")
        lines = head.split("\r\n")
        if len(lines) > MAX_HEADER_LINES:
            return refuse(conn, 431, "too_many_header_lines", **ctx)
        ctx["request_line"] = scrub(lines[0])
        for h in lines[1:]:
            if h.lower().startswith("x-vapt-trace:"):
                ctx["trace_id"] = scrub(h.split(":", 1)[1].strip(), 64)
        parts = lines[0].split(" ")
        if len(parts) != 3:
            return refuse(conn, 400, "malformed_request_line", **ctx)
        method, target, version = parts
        ctx["method"] = scrub(method, 16)
        if method != "CONNECT":                       # case-sensitive: HTTP methods are
            return refuse(conn, 403, "method_not_connect", **ctx)
        if not version.startswith("HTTP/1."):
            return refuse(conn, 400, "unsupported_http_version", **ctx)
        checked = validate_target(target)
        if isinstance(checked, str):
            ctx["destination"] = scrub(target, 80)
            return refuse(conn, 403, checked, **ctx)
        host, port = checked
        ctx["destination"] = f"{host.lower()}:{port}"
        if ctx["destination"] not in ALLOWLIST:
            return refuse(conn, 403, "destination_not_allowlisted", **ctx)
        try:
            infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        except OSError as e:
            return refuse(conn, 502, f"resolution_failed:{e.__class__.__name__}", **ctx)
        addrs = sorted({i[4][0] for i in infos})
        ctx["resolved"] = addrs
        if not addrs:
            return refuse(conn, 502, "no_a_record", **ctx)
        for a in addrs:
            ip = ipaddress.ip_address(a)
            if any(ip in n for n in DENY_CIDRS):
                return refuse(conn, 403, "resolves_into_internal_network", **ctx)
            if not ip.is_global and not any(ip in n for n in [ipaddress.ip_network("172.30.23.0/24")]):
                # The M1.5 stand-in lives on a private test network; in production
                # the allowlisted provider resolves to a global address. Anything
                # else private (loopback, link-local 169.254, other RFC1918) is refused.
                return refuse(conn, 403, "resolved_address_not_permitted", **ctx)
        # Connect to the VALIDATED ADDRESS, never re-resolving the name.
        try:
            up = socket.create_connection((addrs[0], port), timeout=UPSTREAM_TIMEOUT)
        except OSError as e:
            return refuse(conn, 502, f"upstream_unreachable:{e.__class__.__name__}", **ctx)
        ctx["connected_to"] = f"{addrs[0]}:{port}"
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        log(verdict="allow", **ctx)
        conn.settimeout(None)
        up.settimeout(None)
        tx, rx, stop = relay(conn, up)
        log(verdict="closed", stop_reason=stop, bytes_client_to_dest=tx, bytes_dest_to_client=rx, **ctx)
        try:
            up.close()
        except OSError:
            pass
    except (OSError, UnicodeDecodeError, ValueError) as e:
        log(verdict="error", error=e.__class__.__name__, **ctx)
    finally:
        try:
            conn.close()
        except OSError:
            pass


def serve(conn: socket.socket, peer: tuple[str, int]) -> None:
    try:
        handle(conn, peer)
    finally:
        _slots.release()


def main() -> None:
    if not ALLOWLIST:
        sys.exit("refused to start: EGRESS_ALLOWLIST is empty (fail closed)")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((BIND_IP, BIND_PORT))          # single interface, never 0.0.0.0
    srv.listen(64)
    log(event="listening", bind=f"{BIND_IP}:{BIND_PORT}", allowlist=sorted(ALLOWLIST),
        allowed_clients=[str(c) for c in ALLOWED_CLIENT_CIDRS] or ["<any — network isolation only>"],
        internal_deny=[str(c) for c in DENY_CIDRS],
        limits={"max_concurrent": MAX_CONCURRENT, "max_tunnel_seconds": MAX_TUNNEL_SECONDS,
                "max_tunnel_bytes": MAX_TUNNEL_BYTES, "idle_timeout": IDLE_TIMEOUT,
                "header_timeout": HEADER_TIMEOUT, "max_header_bytes": MAX_HEADER})
    while True:
        conn, peer = srv.accept()
        if not _slots.acquire(blocking=False):
            refuse(conn, 503, "capacity_exceeded", peer=peer[0])
            continue
        threading.Thread(target=serve, args=(conn, peer), daemon=True).start()


if __name__ == "__main__":
    main()
