#!/usr/bin/env python3
"""
反向模式探针（agent）。给**没有公网 IP** 的机器用 —— 家宽、NAT、PVE 后面的机器。

原理：探针主动连主程序并注册，主程序把探测任务下发给它，它在本机执行后回传结果。
所以主程序不需要能访问探针，探针也不需要公网 IP / 端口转发。

启动：
    PROBE_TOKEN=同一个token ZONE=cn \
    python3 client.py --hub wss://主程序地址:8790 --name home-cn

主程序侧需要开启 hub（config.yaml 里 hub.enabled: true）并开放 8790 端口。
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import socket
import sys
from typing import Any

import aiohttp

# 复用服务端的探测实现，保证两种模式行为完全一致
try:
    from server import SELF_ZONE, run_job  # type: ignore
except ImportError:  # 单独拷走 client.py 时
    run_job = None  # type: ignore


def log(msg: str) -> None:
    print(msg, flush=True)


async def handle_task(payload: dict[str, Any]) -> dict[str, Any]:
    if run_job is None:
        return {"ok": False, "error": "缺少 server.py（client.py 需要与它放在同一目录）"}
    try:
        return await run_job(payload)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


async def run_agent(hub: str, token: str, zone: str, name: str) -> None:
    """连上 hub，收任务、跑任务、回结果。断线自动重连。"""
    url = hub.rstrip("/") + "/agent"
    backoff = 2.0
    while True:
        try:
            log(f"连接主程序 {url} …")
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=None, sock_connect=15, sock_read=None)
            ) as session:
                async with session.ws_connect(
                    url,
                    headers={
                        "X-Probe-Token": token,
                        "X-Probe-Zone": zone,
                        "X-Probe-Name": name,
                    },
                    heartbeat=30,
                    max_msg_size=4 * 1024 * 1024,
                ) as ws:
                    log(f"已连接，zone={zone} name={name}，等待任务")
                    backoff = 2.0
                    async for msg in ws:
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            try:
                                task = json.loads(msg.data)
                            except json.JSONDecodeError:
                                continue
                            task_id = task.get("id")
                            payload = task.get("payload") or {}
                            log(
                                f"任务 {task_id}: {payload.get('ip')} "
                                f"{payload.get('ports') or payload.get('port')}"
                            )
                            result = await handle_task(payload)
                            result["id"] = task_id
                            await ws.send_str(json.dumps(result, ensure_ascii=False))
                        elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                            break
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            log(f"连接断开：{type(exc).__name__}: {exc}")
        log(f"{backoff:.0f}s 后重连")
        await asyncio.sleep(backoff)
        backoff = min(backoff * 1.6, 60.0)


def main() -> None:
    ap = argparse.ArgumentParser(description="EIP Guard 反向探针（适合家宽/NAT）")
    ap.add_argument("--hub", default=os.getenv("PROBE_HUB", ""), help="主程序地址，如 wss://1.2.3.4:8790")
    ap.add_argument("--token", default=os.getenv("PROBE_TOKEN", ""))
    ap.add_argument("--zone", default=os.getenv("ZONE", "cn"), choices=["cn", "overseas"])
    ap.add_argument("--name", default=os.getenv("PROBE_NAME", socket.gethostname()))
    args = ap.parse_args()

    if not args.hub:
        sys.exit("需要 --hub（主程序的 ws 地址，如 wss://1.2.3.4:8790）")
    if not args.token:
        sys.exit("需要 PROBE_TOKEN（与主程序一致）")

    global SELF_ZONE
    SELF_ZONE = args.zone
    if run_job is not None:
        try:
            import server as _server

            _server.SELF_ZONE = args.zone
        except Exception:
            pass

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    task = loop.create_task(run_agent(args.hub, args.token, args.zone, args.name))
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, task.cancel)
        except NotImplementedError:
            pass
    try:
        loop.run_until_complete(task)
    except asyncio.CancelledError:
        log("已停止")
    finally:
        loop.close()


if __name__ == "__main__":
    main()
