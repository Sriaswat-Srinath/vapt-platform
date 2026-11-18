#!/usr/bin/env python3
"""Loopback-only TCP forwarder for the application plane.

Why it exists: the api and frontend are attached to internal networks only, and
Docker silently ignores `ports:` for such containers (M1.5 deviation D19). The
host can already reach those container addresses directly, so a host-local,
inbound-only relay grants no container any capability it lacked, and gives the
application plane no egress.

Same guarantees as scripts/lab_publish.py:
  * FIXED destinations from a closed table below. Nothing else can be named.
  * LOOPBACK-ONLY bind (literal "127.0.0.1"); never 0.0.0.0.
  * No proxying: an L4 relay to one address. It parses no protocol.
  * Explicit shutdown; never started automatically.
"""
from __future__ import annotations
import argparse, asyncio, contextlib, ipaddress, os, pathlib, signal, sys

STATE = pathlib.Path(os.environ.get("LAB_STATE_DIR", ".lab-state"))
APP_SUBNETS = [ipaddress.ip_network("172.30.20.0/24"), ipaddress.ip_network("172.30.21.0/24")]

# service -> (destination ip, destination port, loopback listen port)
TARGETS: dict[str, tuple[str, int, int]] = {
    "api": ("172.30.20.20", 8000, 8000),
    "frontend": ("172.30.20.10", 8080, 5173),
}
LISTEN_HOST = "127.0.0.1"          # literal; never configurable


async def pipe(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
    try:
        while data := await r.read(65536):
            w.write(data)
            await w.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
        pass
    finally:
        with contextlib.suppress(Exception):
            w.close()


async def serve(service: str) -> None:
    dest_host, dest_port, listen_port = TARGETS[service]
    addr = ipaddress.ip_address(dest_host)
    if not any(addr in n for n in APP_SUBNETS):
        sys.exit(f"refused: {dest_host} is outside the application subnets")

    async def handle(cr: asyncio.StreamReader, cw: asyncio.StreamWriter) -> None:
        try:
            tr, tw = await asyncio.wait_for(
                asyncio.open_connection(dest_host, dest_port), timeout=10)
        except Exception:
            with contextlib.suppress(Exception):
                cw.close()
            return
        await asyncio.gather(pipe(cr, tw), pipe(tr, cw))

    server = await asyncio.start_server(handle, host=LISTEN_HOST, port=listen_port)
    bound = [s.getsockname() for s in server.sockets]
    assert all(b[0] == LISTEN_HOST for b in bound), bound
    print(f"{service}: forwarding {bound} -> {dest_host}:{dest_port}", flush=True)
    loop = asyncio.get_running_loop()
    stop = loop.create_future()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: stop.done() or stop.set_result(None))
    async with server:
        await stop
    print("forwarder stopped", flush=True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("service", choices=sorted(TARGETS))
    a = ap.parse_args()
    STATE.mkdir(exist_ok=True)
    (STATE / f"publish-{a.service}.pid").write_text(str(os.getpid()))
    try:
        asyncio.run(serve(a.service))
    finally:
        with contextlib.suppress(FileNotFoundError):
            (STATE / f"publish-{a.service}.pid").unlink()
