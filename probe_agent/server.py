#!/usr/bin/env python3
"""
墙内/墙外探针（服务端模式）。供主程序主动来问"这个 IP 端口通不通"。

如果你的探针在家宽后面（没有公网 IP），**不要用这个模式**，
用 client.py 的反向模式：探针主动连主程序，主程序下发任务。

部署（只需要 aiohttp）：
    pip install aiohttp
    PROBE_TOKEN=长随机串 ZONE=cn python3 server.py --port 8787

systemd 见 deploy/probe-agent.service
"""
from __future__ import annotations

import argparse
import asyncio
import hmac
import os
import shutil
import socket
import ssl
import time
from typing import Any

from aiohttp import web

MAX_ATTEMPTS = 5
MAX_PORTS = 8
MAX_CONCURRENCY = 64
VALID_LAYERS = {"icmp", "tcp", "tls", "http"}
# 这台探针在墙的哪一侧：cn=国内，overseas=国外。决定判定可信度，装的时候必须填对。
SELF_ZONE = os.getenv("ZONE", "overseas")
_sem: asyncio.Semaphore | None = None


def sem() -> asyncio.Semaphore:
    global _sem
    if _sem is None:
        _sem = asyncio.Semaphore(MAX_CONCURRENCY)
    return _sem


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


async def ping(ip: str, count: int, timeout: float) -> dict[str, Any]:
    exe = shutil.which("ping")
    if not exe:
        return {"ok": None, "error": "探针没有 ping 命令"}
    try:
        proc = await asyncio.create_subprocess_exec(
            exe, "-c", str(count), "-W", str(max(1, int(timeout))), "-n", ip,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        rc = await asyncio.wait_for(proc.wait(), timeout=count * timeout + 3)
    except asyncio.TimeoutError:
        return {"ok": False, "kind": "timeout", "error": "ping 超时"}
    except (OSError, PermissionError) as exc:
        return {"ok": None, "error": f"无法执行 ping: {exc}"}
    return {"ok": True} if rc == 0 else {"ok": False, "kind": "icmp-loss", "error": "100% 丢包"}


async def tcp(ip: str, port: int, timeout: float) -> dict[str, Any]:
    started = time.monotonic()
    writer: asyncio.StreamWriter | None = None
    try:
        _r, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        return {"ok": True, "ms": round((time.monotonic() - started) * 1000, 1)}
    except BaseException as exc:  # noqa: BLE001
        return {"ok": False, "kind": classify(exc), "error": f"{type(exc).__name__}: {exc}"[:160]}
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def tls(ip: str, port: int, sni: str, timeout: float) -> dict[str, Any]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    started = time.monotonic()
    writer: asyncio.StreamWriter | None = None
    try:
        _r, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=sni or None), timeout
        )
        ms = round((time.monotonic() - started) * 1000, 1)
        proto = ""
        try:
            ssl_obj = writer.get_extra_info("ssl_object")
            proto = ssl_obj.version() if ssl_obj else ""
        except Exception:
            proto = ""
        return {"ok": True, "ms": ms, "detail": proto}
    except BaseException as exc:  # noqa: BLE001
        return {"ok": False, "kind": classify(exc), "error": f"{type(exc).__name__}: {exc}"[:160]}
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def http_check(ip: str, port: int, sni: str, path: str, timeout: float) -> dict[str, Any]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    writer: asyncio.StreamWriter | None = None
    started = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=sni or None), timeout
        )
        assert writer is not None
        host = sni or ip
        request = (
            f"GET {path or '/'} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: eipguard\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n"
        )
        writer.write(request.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(64), timeout)
        ms = round((time.monotonic() - started) * 1000, 1)
        if data.startswith(b"HTTP/"):
            return {"ok": True, "ms": ms, "detail": data.split(b"\r\n")[0].decode("latin1", "ignore")}
        return {"ok": False, "kind": "http", "error": f"非 HTTP 响应: {data[:40]!r}", "ms": ms}
    except BaseException as exc:  # noqa: BLE001
        return {"ok": False, "kind": classify(exc), "error": f"{type(exc).__name__}: {exc}"[:160]}
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def probe_port(
    ip: str,
    port: int,
    sni: str,
    timeout: float,
    layers: list[str],
    attempts: int,
    http_path: str,
) -> dict[str, Any]:
    """测一个端口：tcp 必测；tls/http 只在 tcp 通时才测。"""

    async def repeatedly(fn, *args) -> dict[str, Any]:
        best: dict[str, Any] | None = None
        for _ in range(attempts):
            item = await fn(*args)
            if item.get("ok"):
                return item
            best = best or item
        return best or {"ok": False, "kind": "other", "error": "没有结果"}

    tcp_result = await repeatedly(tcp, ip, port, timeout)
    out: dict[str, Any] = {"tcp": tcp_result}
    if "tls" in layers:
        out["tls"] = (
            await repeatedly(tls, ip, port, sni, timeout)
            if tcp_result.get("ok")
            else {"ok": None, "error": "TCP 不通，跳过 TLS"}
        )
    if "http" in layers:
        out["http"] = (
            await repeatedly(http_check, ip, port, sni, http_path, timeout)
            if out.get("tls", {}).get("ok")
            else {"ok": None, "error": "TLS 不通，跳过 HTTP"}
        )
    return out


async def run_job(body: dict[str, Any], default_timeout: float = 6.0) -> dict[str, Any]:
    """执行一次探测任务。服务端模式和反向 agent 模式共用。

    body: {ip, ports|port, sni, attempts, layers, http_path, timeout}
    返回: {ok, ip, ports: {port: {...}}, icmp, zone, ts}
    """
    ip = str(body.get("ip") or "").strip()
    if not ip or len(ip) > 64:
        raise ValueError("ip required")

    raw_ports = body.get("ports")
    if raw_ports is None:
        raw_ports = [body.get("port") or 443]
    ports: list[int] = []
    for item in raw_ports if isinstance(raw_ports, list) else [raw_ports]:
        try:
            port = int(item)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535 and port not in ports and len(ports) < MAX_PORTS:
            ports.append(port)
    if not ports:
        raise ValueError("ports required")

    try:
        attempts = max(1, min(MAX_ATTEMPTS, int(body.get("attempts") or 2)))
        timeout = float(body.get("timeout") or default_timeout)
    except (TypeError, ValueError) as exc:
        raise ValueError("bad attempts/timeout") from exc

    sni = str(body.get("sni") or "")[:253]
    http_path = str(body.get("http_path") or "/")[:200]
    raw_layers = body.get("layers") or ["icmp", "tls"]
    layers = [str(x).lower() for x in raw_layers if str(x).lower() in VALID_LAYERS]
    if not layers:
        layers = ["tcp"]

    async with sem():
        icmp_result = await ping(ip, min(attempts + 1, 3), timeout) if "icmp" in layers else None
        port_results: dict[str, Any] = {}
        for index, port in enumerate(ports):
            # 只对第一个端口做 TLS/HTTP（业务端口），其余端口只测 TCP，省时间
            port_layers = layers if index == 0 else ["tcp"]
            port_results[str(port)] = await probe_port(
                ip, port, sni, timeout, port_layers, attempts, http_path
            )

    return {
        "ok": True,
        "ip": ip,
        "ports": port_results,
        "icmp": icmp_result,
        "zone": SELF_ZONE,
        "ts": int(time.time()),
    }


def make_app(token: str) -> web.Application:
    app = web.Application()

    async def health(_: web.Request) -> web.Response:
        return web.json_response(
            {"ok": True, "zone": SELF_ZONE, "time": int(time.time()), "ping": bool(shutil.which("ping"))}
        )

    async def probe(request: web.Request) -> web.Response:
        if token:
            supplied = request.headers.get("X-Probe-Token", "")
            if not hmac.compare_digest(supplied, token):
                return web.json_response({"error": "unauthorized"}, status=401)
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "invalid json"}, status=400)
        if not isinstance(body, dict):
            return web.json_response({"error": "body must be object"}, status=400)
        try:
            return web.json_response(await run_job(body))
        except ValueError as exc:
            return web.json_response({"error": str(exc)}, status=400)

    app.router.add_get("/health", health)
    app.router.add_post("/probe", probe)
    return app


def main() -> None:
    ap = argparse.ArgumentParser(description="EIP Guard 探针（服务端模式，需要公网可达）")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=int(os.getenv("PROBE_PORT", "8787")))
    ap.add_argument("--token", default=os.getenv("PROBE_TOKEN", ""))
    args = ap.parse_args()

    global _sem
    _sem = asyncio.Semaphore(MAX_CONCURRENCY)
    if not args.token:
        print("警告：未设置 PROBE_TOKEN，任何人可调用探针接口")
    if not shutil.which("ping"):
        print("提示：没有 ping 命令，ICMP 层会被跳过（apt install iputils-ping）")
    print(f"探针启动：zone={SELF_ZONE} 监听 {args.host}:{args.port}")
    web.run_app(make_app(args.token), host=args.host, port=args.port, print=None, access_log=None)


if __name__ == "__main__":
    main()
