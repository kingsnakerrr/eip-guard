from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path

import pytest
from aiohttp import web

from eipguard.detect.probe import ProbeAgentClient, judge

PROBE_SERVER = Path(__file__).resolve().parents[1] / "probe_agent" / "server.py"


def load_probe_module():
    spec = importlib.util.spec_from_file_location("probe_server", PROBE_SERVER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture
async def probe_server():
    module = load_probe_module()
    # 探针模块用模块级信号量，需要重置到当前事件循环
    module._sem = asyncio.Semaphore(8)
    app = module.make_app("secret-token")
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
    yield f"http://127.0.0.1:{port}"
    await runner.cleanup()


@pytest.mark.asyncio
async def test_probe_agent_reports_closed_port(probe_server):
    client = ProbeAgentClient(
        [{"url": probe_server, "token": "secret-token", "zone": "overseas", "name": "us"}], timeout=2
    )
    nodes = await client.check("127.0.0.1", 9, attempts=2)
    assert len(nodes) == 1
    node = nodes[0]
    assert node.zone == "overseas"
    assert node.ok is False
    assert len(node.attempts) == 2
    assert all(a.kind in {"refused", "reset", "timeout"} for a in node.attempts)


@pytest.mark.asyncio
async def test_probe_agent_rejects_bad_token(probe_server):
    client = ProbeAgentClient(
        [{"url": probe_server, "token": "wrong", "zone": "overseas", "name": "us"}], timeout=2
    )
    nodes = await client.check("127.0.0.1", 9, attempts=1)
    assert nodes[0].error and "401" in nodes[0].error


@pytest.mark.asyncio
async def test_probe_agent_reports_open_port(probe_server):
    # 起一个本地监听端口，探针应判定可达
    reader = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = reader.sockets[0].getsockname()[1]
    client = ProbeAgentClient([{"url": probe_server, "token": "secret-token", "zone": "overseas"}], timeout=2)
    nodes = await client.check("127.0.0.1", port, attempts=2)
    reader.close()
    await reader.wait_closed()
    assert nodes[0].ok is True


@pytest.mark.asyncio
async def test_judge_with_overseas_only_is_not_blocked(probe_server):
    client = ProbeAgentClient([{"url": probe_server, "token": "secret-token", "zone": "overseas"}], timeout=2)
    nodes = await client.check("127.0.0.1", 9, attempts=2)
    outcome = judge(nodes, min_samples=1)
    assert outcome.blocked is False
