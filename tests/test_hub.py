from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path

import aiohttp
import pytest

from eipguard.hub import ProbeHub

PROBE_DIR = Path(__file__).resolve().parents[1] / "probe_agent"


def load_server_module():
    spec = importlib.util.spec_from_file_location("probe_server_hub", PROBE_DIR / "server.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def load_client_module(server_module):
    spec = importlib.util.spec_from_file_location("probe_client_hub", PROBE_DIR / "client.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    module.run_job = server_module.run_job  # 复用探测实现
    spec.loader.exec_module(module)
    return module


@pytest.fixture
async def hub():
    node = ProbeHub("hub-token", port=0)
    node.port = 0
    # 用随机端口启动
    from aiohttp import web

    runner = web.AppRunner(node.build())
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    node._runner = runner
    port = site._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
    node.port = port
    yield node
    await node.close()


@pytest.mark.asyncio
async def test_no_agent_means_no_zone(hub):
    assert hub.has_zone("cn") is False
    assert hub.zones() == []
    with pytest.raises(RuntimeError, match="没有 zone=cn"):
        await hub.probe("cn", "1.1.1.1", [443])


@pytest.mark.asyncio
async def test_agent_registers_and_reports_zone(hub):
    """家宽那台主动连上来后，hub 应该知道它在 cn 侧。"""
    async with aiohttp.ClientSession() as session:
        ws = await session.ws_connect(
            f"http://127.0.0.1:{hub.port}/agent",
            headers={"X-Probe-Token": "hub-token", "X-Probe-Zone": "cn", "X-Probe-Name": "home"},
        )
        await asyncio.sleep(0.2)
        assert hub.has_zone("cn") is True
        assert hub.zones() == ["cn"]
        assert "home(cn)" in hub.status_text()
        await ws.close()


@pytest.mark.asyncio
async def test_wrong_token_rejected(hub):
    async with aiohttp.ClientSession() as session:
        with pytest.raises(aiohttp.WSServerHandshakeError):
            await session.ws_connect(
                f"http://127.0.0.1:{hub.port}/agent",
                headers={"X-Probe-Token": "wrong", "X-Probe-Zone": "cn"},
            )
    assert hub.zones() == []


@pytest.mark.asyncio
async def test_probe_task_roundtrip(hub):
    """核心：hub 下发任务 -> agent 执行 -> 结果回传。"""
    server = load_server_module()
    server._sem = None
    server.SELF_ZONE = "cn"

    async with aiohttp.ClientSession() as session:
        ws = await session.ws_connect(
            f"http://127.0.0.1:{hub.port}/agent",
            headers={"X-Probe-Token": "hub-token", "X-Probe-Zone": "cn", "X-Probe-Name": "home"},
        )
        await asyncio.sleep(0.2)

        async def agent_worker() -> None:
            async for msg in ws:
                if msg.type != aiohttp.WSMsgType.TEXT:
                    break
                task = json.loads(msg.data)
                result = await server.run_job(task["payload"])
                result["id"] = task["id"]
                await ws.send_str(json.dumps(result))

        worker = asyncio.create_task(agent_worker())
        # 用一个关闭的端口，确保确定性
        data = await hub.probe("cn", "127.0.0.1", [9], attempts=1, layers=["tcp"], timeout=2)
        worker.cancel()
        await ws.close()

    assert data["ok"] is True
    assert data["zone"] == "cn"
    assert data["ports"]["9"]["tcp"]["ok"] is False


@pytest.mark.asyncio
async def test_probe_timeout_when_agent_silent(hub):
    async with aiohttp.ClientSession() as session:
        ws = await session.ws_connect(
            f"http://127.0.0.1:{hub.port}/agent",
            headers={"X-Probe-Token": "hub-token", "X-Probe-Zone": "cn"},
        )
        await asyncio.sleep(0.2)
        with pytest.raises(asyncio.TimeoutError):
            await hub.probe("cn", "1.1.1.1", [443], overall_timeout=0.5)
        await ws.close()


@pytest.mark.asyncio
async def test_agent_reconnect_replaces_old(hub):
    async with aiohttp.ClientSession() as session:
        ws1 = await session.ws_connect(
            f"http://127.0.0.1:{hub.port}/agent",
            headers={"X-Probe-Token": "hub-token", "X-Probe-Zone": "cn", "X-Probe-Name": "home"},
        )
        await asyncio.sleep(0.2)
        ws2 = await session.ws_connect(
            f"http://127.0.0.1:{hub.port}/agent",
            headers={"X-Probe-Token": "hub-token", "X-Probe-Zone": "cn", "X-Probe-Name": "home"},
        )
        await asyncio.sleep(0.3)
        # 同名重连后只有一个在册
        assert len([a for a in hub.agents.values() if a.name == "home"]) == 1
        await ws2.close()
        await ws1.close()


@pytest.mark.asyncio
async def test_hub_status_endpoint(hub):
    async with aiohttp.ClientSession() as session:
        async with session.get(f"http://127.0.0.1:{hub.port}/hub/status") as resp:
            data = await resp.json()
    assert data["ok"] is True
    assert data["agents"] == []
