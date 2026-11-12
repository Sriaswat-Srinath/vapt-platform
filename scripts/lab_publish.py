#!/usr/bin/env python3
"""Loopback-only TCP forwarder: 127.0.0.1:<port> -> <lab target>:3000.

WHY THIS EXISTS: Docker silently ignores `ports:` for a container attached only
to an `internal: true` network, so the documented direct publish is infeasible
without weakening isolation (see docs/M1_REPORT.md, deviation D19).

WHY IT IS SAFE: the host can already reach the lab bridge directly, so a
host-local, inbound-only forwarder grants no container any capability it did not
already have. It does NOT give the lab egress: traffic flows host -> lab only,
to one fixed destination. No container is dual-homed, so no container bridges
the lab to a network with egress.

Binds 127.0.0.1 exclusively. Never 0.0.0.0.
"""
from __future__ import annotations
import argparse, asyncio, contextlib, os, pathlib, signal, sys

STATE = pathlib.Path(os.environ.get("LAB_STATE_DIR", ".lab-state"))


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


async def main(listen_port: int, target_host: str, target_port: int) -> None:
    async def handle(cr: asyncio.StreamReader, cw: asyncio.StreamWriter) -> None:
        try:
            tr, tw = await asyncio.wait_for(
                asyncio.open_connection(target_host, target_port), timeout=10)
        except Exception:
            with contextlib.suppress(Exception):
                cw.close()
            return
        await asyncio.gather(pipe(cr, tw), pipe(tr, cw))

    # host="127.0.0.1" is deliberate and must not be parameterised.
    server = await asyncio.start_server(handle, host="127.0.0.1", port=listen_port)
    for s in server.sockets:
        print(f"forwarding {s.getsockname()} -> {target_host}:{target_port}", flush=True)
    loop = asyncio.get_running_loop()
    stop = loop.create_future()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: stop.done() or stop.set_result(None))
    async with server:
        await stop
    print("forwarder stopped", flush=True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen-port", type=int, default=int(os.environ.get("MOCK_TARGET_PUBLISH_PORT", 3000)))
    ap.add_argument("--target-host", default=os.environ.get("JUICESHOP_IP", "172.30.10.20"))
    ap.add_argument("--target-port", type=int, default=3000)
    a = ap.parse_args()
    STATE.mkdir(exist_ok=True)
    (STATE / "publish.pid").write_text(str(os.getpid()))
    try:
        asyncio.run(main(a.listen_port, a.target_host, a.target_port))
    except KeyboardInterrupt:
        pass
    finally:
        with contextlib.suppress(FileNotFoundError):
            (STATE / "publish.pid").unlink()
