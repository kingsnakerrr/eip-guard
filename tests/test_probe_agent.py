from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path

import pytest
from aiohttp import web

from eipguard.detect.probe import (
    LAYER_AUX,
    LAYER_ICMP,
    LAYER_TCP,
    LAYER_TLS,
    LayerResult,
    NodeResult,
    ProbeAgentClient,
    Verdict,
    judge,
)

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
    tcp = node.layers[LAYER_TCP]
    assert tcp.ok is False
    assert tcp.kind in {"refused", "reset", "timeout"}
    # 端口关闭时，探针会跳过 TLS 层
    assert node.layers[LAYER_TLS].ok is None


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
    assert nodes[0].layers[LAYER_TCP].ok is True


@pytest.mark.asyncio
async def test_judge_with_overseas_only_is_not_blocked(probe_server):
    client = ProbeAgentClient([{"url": probe_server, "token": "secret-token", "zone": "overseas"}], timeout=2)
    nodes = await client.check("127.0.0.1", 9, attempts=2)
    outcome = judge(nodes, min_samples=1)
    assert outcome.blocked is False


@pytest.mark.asyncio
async def test_probe_agent_ping_ok_but_port_dead(probe_server):
    """关键场景：探针能 ping 通 127.0.0.1，但端口 9 关闭 → 应报告 TCP 不通而 ICMP 通。"""
    client = ProbeAgentClient(
        [{"url": probe_server, "token": "secret-token", "zone": "cn"}], timeout=3, layers=["icmp", "tcp", "tls"]
    )
    nodes = await client.check("127.0.0.1", 9, attempts=1)
    node = nodes[0]
    assert node.layers[LAYER_ICMP].ok is True, "本机 loopback 应该能 ping 通"
    assert node.layers[LAYER_TCP].ok is False
    outcome = judge(nodes, port=9)
    assert outcome.verdict is Verdict.UNKNOWN or outcome.verdict is Verdict.IP_BLOCKED


@pytest.mark.asyncio
async def test_probe_agent_aux_ports(probe_server):
    """aux 端口探测：一个开一个关，aux 层应为通。"""
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    open_port = server.sockets[0].getsockname()[1]
    client = ProbeAgentClient(
        [{"url": probe_server, "token": "secret-token", "zone": "cn"}], timeout=3, layers=["tcp", "aux"]
    )
    client.aux_ports = [open_port, 9]
    nodes = await client.check("127.0.0.1", 9, attempts=1)
    server.close()
    await server.wait_closed()
    aux = nodes[0].layers[LAYER_AUX]
    assert aux.ok is True
    assert f"{open_port}✓" in aux.detail


@pytest.mark.asyncio
async def test_aux_ports_are_actually_probed_even_if_not_in_layers(probe_server):
    """回归：配了 aux_ports 但 layers 没写 aux 时，必须自动补上 aux 层，
    否则会把"只封了一个端口"误判成"整台 IP 被封"。"""
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    open_port = server.sockets[0].getsockname()[1]
    client = ProbeAgentClient(
        [{"url": probe_server, "token": "secret-token", "zone": "cn"}],
        timeout=3,
        layers=["icmp", "tcp"],       # 故意不写 aux
        aux_ports=[open_port],
    )
    nodes = await client.check("127.0.0.1", 9, attempts=1)
    server.close()
    await server.wait_closed()
    assert LAYER_AUX in nodes[0].layers, "aux 层必须被探测"
    assert nodes[0].layers[LAYER_AUX].ok is True

    outcome = judge(nodes, port=9, aux_ports=[open_port])
    assert outcome.verdict is Verdict.PORT_BLOCKED, "其它端口通时不能判成 IP 被墙"


@pytest.mark.asyncio
async def test_all_ports_dead_with_ping_is_ip_blocked_end_to_end(probe_server):
    """用户场景回归：ping 通、所有端口不通、墙外正常 → IP 被墙。"""
    client = ProbeAgentClient(
        [{"url": probe_server, "token": "secret-token", "zone": "cn", "name": "cn"}],
        timeout=3,
        layers=["icmp", "tcp", "tls"],
        aux_ports=[9, 8],
    )
    nodes = await client.check("127.0.0.1", 9, attempts=1)
    assert nodes[0].layers[LAYER_ICMP].ok is True
    assert nodes[0].layers[LAYER_TCP].ok is False

    outside = NodeResult(
        "us",
        "overseas",
        {
            LAYER_ICMP: LayerResult(LAYER_ICMP, True),
            LAYER_TCP: LayerResult(LAYER_TCP, True),
            LAYER_TLS: LayerResult(LAYER_TLS, True),
        },
    )
    outcome = judge(nodes + [outside], port=9, aux_ports=[9, 8])
    assert outcome.verdict is Verdict.IP_BLOCKED
    assert outcome.blocked is True
