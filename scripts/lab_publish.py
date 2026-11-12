#!/usr/bin/env python3
"""Loopback-only TCP forwarder: 127.0.0.1:<port> -> THE registered lab target.

Ratified as deviation D19 with conditions (all enforced here, not by convention):
  * FIXED destination: the registered target only (JUICESHOP_IP:3000 from the
    lab configuration). There is no CLI/env override of the destination; a
    destination outside the lab subnet, or not equal to the registered target,
    is refused before any socket is opened.
  * LOOPBACK-ONLY binding: host is the literal "127.0.0.1"; not parameterised.
  * NO arbitrary proxying: this is an L4 relay to one address. It does not parse
    HTTP, honour CONNECT, or follow any destination named by the client.
  * EXPLICIT shutdown: SIGTERM/SIGINT or `make lab-unpublish`; also stopped by
    `make lab-down`.
  * NO automatic startup: never started by `lab-up`, `lab-reset` or any test
    fixture; only by an operator running `make lab-publish`.

Why it is safe: the host already reaches the lab bridge directly, so an
inbound-only, host-local relay grants no container any new capability and gives
the lab no egress. No container is dual-homed.
"""
from __future__ import annotations
import asyncio, contextlib, ipaddress, os, pathlib, signal, sys

STATE = pathlib.Path(os.environ.get("LAB_STATE_DIR", ".lab-state"))
LAB_SUBNET = ipaddress.ip_network(os.environ.get("LAB_SUBNET", "172.30.10.0/24"))
REGISTERED_TARGET_IP = os.environ.get("JUICESHOP_IP", "172.30.10.20")
REGISTERED_TARGET_PORT = 3000                 # MOCK-WEB-001 container port; fixed
LISTEN_HOST = "127.0.0.1"                     # literal; never configurable
LISTEN_PORT = int(os.environ.get("MOCK_TARGET_PUBLISH_PORT", "3000"))


def resolve_destination(argv: list[str]) -> tuple[str, int]:
    """The only destination is the registered target. Anything else is refused."""
    if len(argv) > 1:
        # No override surface: any attempt to name a destination is an error.
        sys.exit(f"refused: lab_publish.py takes no arguments (got {argv[1:]}); "
                 f"the destination is fixed to the registered target")
    host, port = REGISTERED_TARGET_IP, REGISTERED_TARGET_PORT
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        sys.exit(f"refused: destination {host!r} is not an IP address (hostnames are not accepted)")
    if addr not in LAB_SUBNET:
        sys.exit(f"refused: destination {host} is outside the lab subnet {LAB_SUBNET}")
    if addr == LAB_SUBNET.network_address + 1:
        sys.exit("refused: destination is the lab gateway (the host), not the target")
    return host, port


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


async def serve(dest_host: str, dest_port: int) -> None:
    async def handle(cr: asyncio.StreamReader, cw: asyncio.StreamWriter) -> None:
        try:
            tr, tw = await asyncio.wait_for(asyncio.open_connection(dest_host, dest_port), timeout=10)
        except Exception:
            with contextlib.suppress(Exception):
                cw.close()
            return
        await asyncio.gather(pipe(cr, tw), pipe(tr, cw))

    server = await asyncio.start_server(handle, host=LISTEN_HOST, port=LISTEN_PORT)
    bound = [s.getsockname() for s in server.sockets]
    assert all(b[0] == LISTEN_HOST for b in bound), bound     # belt and braces
    print(f"forwarding {bound} -> {dest_host}:{dest_port} (fixed destination)", flush=True)
    loop = asyncio.get_running_loop()
    stop = loop.create_future()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: stop.done() or stop.set_result(None))
    async with server:
        await stop
    print("forwarder stopped (explicit shutdown)", flush=True)


if __name__ == "__main__":
    dest = resolve_destination(sys.argv)
    STATE.mkdir(exist_ok=True)
    (STATE / "publish.pid").write_text(str(os.getpid()))
    try:
        asyncio.run(serve(*dest))
    finally:
        with contextlib.suppress(FileNotFoundError):
            (STATE / "publish.pid").unlink()
