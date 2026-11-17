#!/usr/bin/env python3
"""
境外探针（墙外侧）。部署在墙外 VPS 上，供墙内机器人询问“这个 IP 从外面看通不通”。

为什么要分层：GFW 可以让 ping 通、TCP 也能建连，然后在 TLS 或数据阶段才断。
只测 TCP 会把“IP 已废”误判成“正常”，或者把“只是封了端口”误判成“整台 IP 被封”。

部署（只需要 aiohttp）：
    pip install aiohttp
    PROBE_TOKEN=长随机串 python3 server.py --port 8787

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
MAX_CONCURRENCY = 64
VALID_LAYERS = {"icmp", "tcp", "tls", "http", "aux"}
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
    if rc == 0:
        return {"ok": True}
    return {"ok": False, "kind": "icmp-loss", "error": "100% 丢包"}


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


async def probe_layers(
    ip: str,
    port: int,
    sni: str,
    timeout: float,
    layers: list[str],
    attempts: int,
    aux_ports: list[int],
    http_path: str,
) -> dict[str, Any]:
    """按层探测。每层做 attempts 次，任一次成功即算该层通。"""
    result: dict[str, Any] = {}

    async def repeatedly(fn, *args) -> dict[str, Any]:
        best: dict[str, Any] | None = None
        for _ in range(attempts):
            item = await fn(*args)
            if item.get("ok"):
                return item
            best = best or item
        return best or {"ok": False, "kind": "other", "error": "没有结果"}

    if "icmp" in layers:
        result["icmp"] = await ping(ip, min(attempts + 1, 3), timeout)
    if "tcp" in layers:
        result["tcp"] = await repeatedly(tcp, ip, port, timeout)
    if "tls" in layers:
        if result.get("tcp", {}).get("ok"):
            result["tls"] = await repeatedly(tls, ip, port, sni, timeout)
        else:
            result["tls"] = {"ok": None, "error": "TCP 不通，跳过 TLS"}
    if "http" in layers:
        if result.get("tls", {}).get("ok"):
            result["http"] = await repeatedly(http_check, ip, port, sni, http_path, timeout)
        else:
            result["http"] = {"ok": None, "error": "TLS 不通，跳过 HTTP"}
    if "aux" in layers:
        ports: dict[str, Any] = {}
        for aux_port in aux_ports:
            ports[str(aux_port)] = await tcp(ip, aux_port, timeout)
        any_ok = any(v.get("ok") for v in ports.values())
        result["aux"] = {
            "ok": any_ok if ports else None,
            "detail": " ".join(f"{p}{'✓' if v.get('ok') else '✗'}" for p, v in ports.items()),
            "ports": ports,
            "kind": "" if any_ok else "timeout",
        }
    return result


def make_app(token: str) -> web.Application:
    app = web.Application()

    async def health(_: web.Request) -> web.Response:
        return web.json_response({"ok": True, "zone": "overseas", "time": int(time.time()),
                                  "ping": bool(shutil.which("ping"))})

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

        ip = str(body.get("ip") or "").strip()
        if not ip or len(ip) > 64:
            return web.json_response({"error": "ip required"}, status=400)
        try:
            port = int(body.get("port") or 443)
            attempts = max(1, min(MAX_ATTEMPTS, int(body.get("attempts") or 2)))
            timeout = float(body.get("timeout") or 6.0)
        except (TypeError, ValueError):
            return web.json_response({"error": "bad port/attempts/timeout"}, status=400)
        if not (1 <= port <= 65535):
            return web.json_response({"error": "port out of range"}, status=400)

        sni = str(body.get("sni") or "")[:253]
        http_path = str(body.get("http_path") or "/")[:200]
        raw_layers = body.get("layers") or ["icmp", "tcp", "tls"]
        layers = [str(x).lower() for x in raw_layers if str(x).lower() in VALID_LAYERS] or ["tcp"]
        raw_aux = body.get("aux_ports") or []
        aux_ports: list[int] = []
        for item in raw_aux if isinstance(raw_aux, list) else []:
            try:
                aux_port = int(item)
            except (TypeError, ValueError):
                continue
            if 1 <= aux_port <= 65535 and aux_port != port and len(aux_ports) < 8:
                aux_ports.append(aux_port)
        # 给了其它端口就必须测 aux 层，否则客户端会以为"全部端口不通"
        if aux_ports and "aux" not in layers:
            layers.append("aux")

        async with _sem:
            layers_result = await probe_layers(
                ip, port, sni, timeout, layers, attempts, aux_ports, http_path
            )
        return web.json_response(
            {
                "ok": True,
                "ip": ip,
                "port": port,
                "zone": "overseas",
                "layers": layers_result,
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
    if not shutil.which("ping"):
        print("提示：没有 ping 命令，ICMP 层会被跳过（apt install iputils-ping）")
    web.run_app(make_app(args.token), host=args.host, port=args.port, print=None, access_log=None)


if __name__ == "__main__":
    main()
