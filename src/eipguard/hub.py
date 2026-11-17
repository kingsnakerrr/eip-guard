from __future__ import annotations

import asyncio
import hmac
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from aiohttp import WSMsgType, web

log = logging.getLogger(__name__)


@dataclass
class AgentConn:
    name: str
    zone: str
    ws: web.WebSocketResponse
    connected_at: float = field(default_factory=time.time)
    tasks: int = 0

    def brief(self) -> str:
        age = int(time.time() - self.connected_at)
        return f"{self.name}({self.zone}) 已连 {age}s 完成 {self.tasks} 次"


class ProbeHub:
    """反向探针的中心节点。

    家宽探针（没有公网 IP）主动连上来；主程序通过这条长连接下发探测任务。
    这样主程序不需要能访问探针，探针也不需要开端口。
    """

    def __init__(self, token: str, port: int = 8790, host: str = "0.0.0.0") -> None:
        self.token = token
        self.port = port
        self.host = host
        self.agents: dict[str, AgentConn] = {}
        self._pending: dict[str, asyncio.Future[dict[str, Any]]] = {}
        self._runner: web.AppRunner | None = None
        self._app: web.Application | None = None

    # ------------------------------------------------------------ 生命周期
    def build(self) -> web.Application:
        app = web.Application()
        app.router.add_get("/agent", self._handle_agent)
        app.router.add_get("/hub/status", self._handle_status)
        self._app = app
        return app

    async def start(self) -> None:
        if self._runner is not None:
            return
        self._runner = web.AppRunner(self.build())
        await self._runner.setup()
        site = web.TCPSite(self._runner, self.host, self.port)
        await site.start()
        log.info("反向探针 hub 已启动：ws://%s:%d/agent", self.host, self.port)

    async def close(self) -> None:
        for future in self._pending.values():
            if not future.done():
                future.set_exception(RuntimeError("hub 关闭"))
        self._pending.clear()
        for agent in list(self.agents.values()):
            try:
                await agent.ws.close()
            except Exception:
                pass
        self.agents.clear()
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None

    # ------------------------------------------------------------ HTTP 处理
    async def _handle_status(self, _: web.Request) -> web.Response:
        return web.json_response(
            {
                "ok": True,
                "agents": [{"name": a.name, "zone": a.zone, "tasks": a.tasks} for a in self.agents.values()],
            }
        )

    async def _handle_agent(self, request: web.Request) -> web.WebSocketResponse:
        supplied = request.headers.get("X-Probe-Token", "")
        if self.token and not hmac.compare_digest(supplied, self.token):
            raise web.HTTPUnauthorized(text="probe token mismatch")
        zone = str(request.headers.get("X-Probe-Zone") or "cn").lower()
        if zone not in {"cn", "overseas"}:
            zone = "cn"
        name = str(request.headers.get("X-Probe-Name") or f"agent-{zone}")

        ws = web.WebSocketResponse(heartbeat=30, max_msg_size=4 * 1024 * 1024)
        await ws.prepare(request)

        agent = AgentConn(name=name, zone=zone, ws=ws)
        # 同名重连时替换旧的
        old = self.agents.get(f"{name}:{zone}")
        if old is not None:
            try:
                await old.ws.close()
            except Exception:
                pass
        self.agents[f"{name}:{zone}"] = agent
        log.info("探针已连接：%s", agent.brief())

        try:
            async for msg in ws:
                if msg.type != WSMsgType.TEXT:
                    if msg.type in (WSMsgType.CLOSED, WSMsgType.ERROR):
                        break
                    continue
                try:
                    data = json.loads(msg.data)
                except json.JSONDecodeError:
                    continue
                task_id = str(data.get("id") or "")
                future = self._pending.pop(task_id, None)
                if future is not None and not future.done():
                    agent.tasks += 1
                    future.set_result(data)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            log.warning("探针连接异常 %s：%s", agent.name, exc)
        finally:
            self.agents.pop(f"{name}:{zone}", None)
            log.info("探针断开：%s(%s)", name, zone)

        return ws

    # ------------------------------------------------------------ 下发任务
    def has_zone(self, zone: str) -> bool:
        return any(a.zone == zone for a in self.agents.values())

    def zones(self) -> list[str]:
        return sorted({a.zone for a in self.agents.values()})

    async def probe(
        self,
        zone: str,
        ip: str,
        ports: list[int],
        *,
        sni: str = "",
        attempts: int = 2,
        layers: list[str] | None = None,
        timeout: float = 6.0,
        http_path: str = "/",
        overall_timeout: float = 90.0,
    ) -> dict[str, Any]:
        """向指定 zone 的探针下发任务并等待结果。"""
        targets = [a for a in self.agents.values() if a.zone == zone]
        if not targets:
            raise RuntimeError(f"没有 zone={zone} 的在线探针")
        agent = targets[0]

        task_id = uuid.uuid4().hex
        future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self._pending[task_id] = future
        payload = {
            "id": task_id,
            "payload": {
                "ip": ip,
                "ports": ports,
                "sni": sni,
                "attempts": attempts,
                "layers": layers or ["icmp", "tls"],
                "timeout": timeout,
                "http_path": http_path,
            },
        }
        try:
            await agent.ws.send_str(json.dumps(payload, ensure_ascii=False))
            return await asyncio.wait_for(future, timeout=overall_timeout)
        finally:
            self._pending.pop(task_id, None)

    def status_text(self) -> str:
        if not self.agents:
            return "无在线探针"
        return " | ".join(a.brief() for a in self.agents.values())
