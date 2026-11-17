#!/usr/bin/env python3
"""
境外探针（wall 外侧）。部署在墙外 VPS 上，供墙内机器人询问“这个 IP 从外面看通不通”。

为什么需要它：只有“墙内不通 + 墙外通”才能确认是被墙，而不是实例宕机。
纯用公共 API（check-host）也行，但限流且节点随机，建议自建。

运行（只需要 aiohttp，无其它依赖）：
    pip install aiohttp
    PROBE_TOKEN=长随机串 python3 server.py --port 8787

systemd 见 deploy/probe-agent.service
"""
from __future__ import annotations

import argparse
import asyncio
import hmac
import os
import socket
import ssl
import time
from typing import Any

from aiohttp import web

MAX_ATTEMPTS = 5
MAX_CONCURRENCY = 64
_sem: asyncio.Semaphore


def classify(exc: BaseException) -> str:
    if isinstance(exc, asyncio.TimeoutError):
        return "timeout"
    if isinstance(exc, ConnectionResetError):
        return "reset"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if isinstance(exc, socket.gaierror):
        return "dns"
    if isinstance(exc, ssl.SSLError):
        return "tls"
    if isinstance(exc, OSError):
        return "reset" if getattr(exc, "errno", None) in (104, 54) else "other"
    return "other"


async def one_probe(ip: str, port: int, timeout: float, sni: str, tls: bool) -> dict[str, Any]:
    started = time.monotonic()
    writer: asyncio.StreamWriter | None = None
    try:
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx, server_hostname=sni or None), timeout
            )
            del reader
            return {"ok": True, "connect_ms": round((time.monotonic() - started) * 1000, 1), "tls_ok": True}
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        del reader
        return {"ok": True, "connect_ms": round((time.monotonic() - started) * 1000, 1), "tls_ok": None}
    except BaseException as exc:  # noqa: BLE001
        return {
            "ok": False,
            "connect_ms": None,
            "tls_ok": False,
            "error": f"{type(exc).__name__}: {exc}"[:200],
            "kind": classify(exc),
        }
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


def make_app(token: str) -> web.Application:
    app = web.Application()

    async def health(_: web.Request) -> web.Response:
        return web.json_response({"ok": True, "zone": "overseas", "time": int(time.time())})

    async def probe(request: web.Request) -> web.Response:
        if token and request.headers.get("X-Probe-Token") != token:
            # 用 compare_digest 防时序攻击
            supplied = request.headers.get("X-Probe-Token", "")
            if not hmac.compare_digest(supplied, token):
                return web.json_response({"error": "unauthorized"}, status=401)
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "invalid json"}, status=400)
        if not isinstance(body, dict):
            return web.json_response({"error": "body must be object"}, status=400)

        ip = str(body.get("ip") or "").strip()
        if not ip or len(ip) > 64:
            return web.json_response({"error": "ip required"}, status=400)
        try:
            port = int(body.get("port") or 443)
            attempts = max(1, min(MAX_ATTEMPTS, int(body.get("attempts") or 3)))
            timeout = float(body.get("timeout") or 6.0)
        except (TypeError, ValueError):
            return web.json_response({"error": "bad port/attempts/timeout"}, status=400)
        if not (1 <= port <= 65535):
            return web.json_response({"error": "port out of range"}, status=400)

        sni = str(body.get("sni") or "")[:253]
        tls = bool(body.get("tls"))

        async with _sem:
            results = [await one_probe(ip, port, timeout, sni, tls) for _ in range(attempts)]
        return web.json_response(
            {
                "ok": True,
                "ip": ip,
                "port": port,
                "zone": "overseas",
                "attempts": results,
                "ts": int(time.time()),
            }
        )

    app.router.add_get("/health", health)
    app.router.add_post("/probe", probe)
    return app


def main() -> None:
    ap = argparse.ArgumentParser(description="EIP Guard 境外探针")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=int(os.getenv("PROBE_PORT", "8787")))
    ap.add_argument("--token", default=os.getenv("PROBE_TOKEN", ""))
    args = ap.parse_args()

    global _sem
    _sem = asyncio.Semaphore(MAX_CONCURRENCY)
    if not args.token:
        print("警告：未设置 PROBE_TOKEN，任何人可调用探针接口")
    web.run_app(make_app(args.token), host=args.host, port=args.port, print=None, access_log=None)


if __name__ == "__main__":
    main()
