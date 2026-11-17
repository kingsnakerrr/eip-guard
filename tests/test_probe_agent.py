from __future__ import annotations

import asyncio
import importlib.util
from pathlib import Path

import pytest
from aiohttp import web

from eipguard.detect.probe import LayerResult, NodeResult, PortProbe, ProbeAgentClient, Verdict, judge

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
        [{"url": probe_server, "token": "secret-token", "zone": "overseas", "name": "us"}],
        timeout=2,
        layers=["icmp", "tls"],
    )
    nodes = await client.check("127.0.0.1", [9], attempts=2)
    assert len(nodes) == 1
    node = nodes[0]
    assert node.zone == "overseas"
    probe = node.port(9)
    assert probe is not None
    assert probe.tcp.ok is False
    assert probe.tcp.kind in {"refused", "reset", "timeout"}
    # 端口关闭时探针会跳过 TLS
    assert probe.tls is not None and probe.tls.ok is None


@pytest.mark.asyncio
async def test_probe_agent_rejects_bad_token(probe_server):
    client = ProbeAgentClient(
        [{"url": probe_server, "token": "wrong", "zone": "overseas", "name": "us"}], timeout=2
    )
    nodes = await client.check("127.0.0.1", [9], attempts=1)
    assert nodes[0].error and "401" in nodes[0].error


@pytest.mark.asyncio
async def test_probe_agent_reports_open_port(probe_server):
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    client = ProbeAgentClient(
        [{"url": probe_server, "token": "secret-token", "zone": "overseas"}], timeout=2, layers=["tcp"]
    )
    nodes = await client.check("127.0.0.1", [port], attempts=2)
    server.close()
    await server.wait_closed()
    probe = nodes[0].port(port)
    assert probe is not None and probe.tcp.ok is True


@pytest.mark.asyncio
async def test_probe_agent_multiple_ports(probe_server):
    """一次请求测多个端口：节点端口开、另一个关。"""
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    open_port = server.sockets[0].getsockname()[1]
    client = ProbeAgentClient(
        [{"url": probe_server, "token": "secret-token", "zone": "cn"}], timeout=2, layers=["tcp"]
    )
    nodes = await client.check("127.0.0.1", [open_port, 9], attempts=1)
    server.close()
    await server.wait_closed()
    node = nodes[0]
    assert node.tcp_ok(open_port) is True
    assert node.tcp_ok(9) is False


@pytest.mark.asyncio
async def test_probe_agent_icmp_reported(probe_server):
    client = ProbeAgentClient(
        [{"url": probe_server, "token": "secret-token", "zone": "cn"}], timeout=2, layers=["icmp", "tcp"]
    )
    nodes = await client.check("127.0.0.1", [9], attempts=1)
    icmp = nodes[0].icmp
    # loopback 应该能 ping 通；若探针机没 ping 命令则为 None
    assert icmp is not None
    assert icmp.ok in (True, None)


@pytest.mark.asyncio
async def test_overseas_only_cannot_decide(probe_server):
    client = ProbeAgentClient(
        [{"url": probe_server, "token": "secret-token", "zone": "overseas"}], timeout=2
    )
    nodes = await client.check("127.0.0.1", [9], attempts=2)
    outcome = judge(nodes, ports=[9])
    assert outcome.blocked is False
    assert outcome.verdict is Verdict.UNKNOWN


@pytest.mark.asyncio
async def test_end_to_end_ip_blocked(probe_server):
    """用户场景：国内节点能 ping 通，但端口全不通；国外一切正常 → IP 被墙。"""
    client = ProbeAgentClient(
        [{"url": probe_server, "token": "secret-token", "zone": "cn", "name": "cn"}],
        timeout=2,
        layers=["icmp", "tcp"],
    )
    cn_nodes = await client.check("127.0.0.1", [9, 8], attempts=1)
    assert cn_nodes[0].icmp is not None and cn_nodes[0].icmp.ok is True
    assert cn_nodes[0].tcp_ok(9) is False

    outside = NodeResult(
        "us",
        "overseas",
        LayerResult(True),
        {
            9: PortProbe(9, LayerResult(True)),
            8: PortProbe(8, LayerResult(True)),
        },
    )
    outcome = judge(cn_nodes + [outside], ports=[9, 8])
    assert outcome.verdict is Verdict.IP_BLOCKED
    assert outcome.blocked is True
    assert "整台 IP 被墙" in outcome.reason


@pytest.mark.asyncio
async def test_end_to_end_port_blocked(probe_server):
    """22 端口国内能连、443 国内不通，国外两个都通 → 只封了 443。"""
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    open_port = server.sockets[0].getsockname()[1]
    client = ProbeAgentClient(
        [{"url": probe_server, "token": "secret-token", "zone": "cn"}], timeout=2, layers=["tcp"]
    )
    cn_nodes = await client.check("127.0.0.1", [9, open_port], attempts=1)
    server.close()
    await server.wait_closed()
    assert cn_nodes[0].tcp_ok(open_port) is True
    assert cn_nodes[0].tcp_ok(9) is False

    outside = NodeResult(
        "us",
        "overseas",
        None,
        {9: PortProbe(9, LayerResult(True)), open_port: PortProbe(open_port, LayerResult(True))},
    )
    outcome = judge(cn_nodes + [outside], ports=[9, open_port])
    assert outcome.verdict is Verdict.PORT_BLOCKED
    assert str(open_port) in outcome.reason
