from __future__ import annotations

import asyncio

import pytest

from eipguard.detect.probe import (
    LayerResult,
    NodeResult,
    PortProbe,
    Verdict,
    classify_exception,
    icmp_probe,
    judge,
    tcp_probe,
    tls_probe,
)


def tcp(ok: bool | None, kind: str = "") -> LayerResult:
    return LayerResult(ok, 20.0 if ok else None, kind, "" if ok else kind)


def node(
    name: str,
    zone: str,
    *ports: tuple[int, bool | None, str],
    icmp: bool | None = True,
    tls: bool | None = None,
    http: bool | None = None,
) -> NodeResult:
    probes = {}
    for port, ok, kind in ports:
        probes[port] = PortProbe(
            port,
            tcp(ok, kind),
            LayerResult(tls) if tls is not None else None,
            LayerResult(http) if http is not None else None,
        )
    return NodeResult(name, zone, LayerResult(icmp) if icmp is not None else None, probes)


def cn(*ports, **kw) -> NodeResult:
    return node("cn", "cn", *ports, **kw)


def us(*ports, **kw) -> NodeResult:
    return node("us", "overseas", *ports, **kw)


# ------------------------------------------------------- 用户的核心疑问
def test_ssh_open_but_web_dead_is_port_blocked_not_ip_blocked():
    """22 能连、443 连不上：说明 22 服务活着，但不能证明 IP 没被封。
    正确结论要看 443 本身：国内不通 + 国外通 → 只有 443 被墙 → 换端口，
    因为 22 能连恰恰证明这台 IP 还能用（如果整台 IP 被封，22 也连不上）。"""
    nodes = [cn((443, False, "timeout"), (22, True, "")), us((443, True, ""), (22, True, ""))]
    out = judge(nodes, ports=[443, 22])
    assert out.verdict is Verdict.PORT_BLOCKED
    assert out.blocked is True
    assert "只封了这一个端口" in out.reason


def test_ssh_dead_and_web_dead_but_overseas_ok_is_ip_blocked():
    """22 和 443 国内都连不上、国外都通 → 整台 IP 被墙。"""
    nodes = [cn((443, False, "timeout"), (22, False, "timeout")), us((443, True, ""), (22, True, ""))]
    out = judge(nodes, ports=[443, 22])
    assert out.verdict is Verdict.IP_BLOCKED
    assert "整台 IP 被墙" in out.reason


def test_ping_ok_but_all_ports_dead_overseas_ok_is_ip_blocked():
    """能 ping 通、端口全废、国外通 → IP 被墙（ping 通毫无意义）。"""
    nodes = [cn((443, False, "timeout"), (22, False, "timeout"), icmp=True), us((443, True, ""))]
    out = judge(nodes, ports=[443, 22])
    assert out.verdict is Verdict.IP_BLOCKED
    assert out.ok is False


def test_service_dead_both_sides_is_not_wall():
    """国内外都不通 → 服务/安全组问题，换 IP 没用。这才是「全坏了」的正解。"""
    nodes = [cn((443, False, "refused"), (22, False, "refused")), us((443, False, "refused"), (22, False, "refused"))]
    out = judge(nodes, ports=[443, 22])
    assert out.verdict is Verdict.SERVICE_DOWN
    assert out.blocked is False
    assert "换 IP" in out.advice and "无效" in out.advice


def test_service_dead_even_if_ssh_alive():
    """443 服务挂了、22 正常：国内外都连不上 443 → 不是墙。"""
    nodes = [cn((443, False, "refused"), (22, True, "")), us((443, False, "refused"), (22, True, ""))]
    out = judge(nodes, ports=[443, 22])
    assert out.verdict is Verdict.SERVICE_DOWN
    assert out.blocked is False


def test_normal_when_cn_can_connect():
    nodes = [cn((443, True, ""), (22, True, ""), tls=True), us((443, True, ""))]
    out = judge(nodes, ports=[443, 22])
    assert out.verdict is Verdict.OK


def test_tls_blocked_when_tcp_ok_but_handshake_reset():
    nodes = [
        cn((443, True, ""), tls=False),
        us((443, True, ""), tls=True),
    ]
    out = judge(nodes, ports=[443])
    assert out.verdict is Verdict.TLS_BLOCKED


def test_tls_failure_without_overseas_ok_is_not_tls_block():
    """国内外 TLS 都失败 → 是证书/协议配置问题，不是墙。"""
    nodes = [cn((443, True, ""), tls=False), us((443, True, ""), tls=False)]
    out = judge(nodes, ports=[443])
    assert out.verdict is Verdict.SERVICE_DOWN
    assert "证书" in out.reason


def test_data_blocked_when_http_broken_but_handshake_ok():
    nodes = [cn((443, True, ""), tls=True, http=False), us((443, True, ""), tls=True, http=True)]
    out = judge(nodes, ports=[443])
    assert out.verdict is Verdict.DATA_BLOCKED


def test_missing_cn_probe_is_unknown():
    out = judge([us((443, True, ""))], ports=[443])
    assert out.verdict is Verdict.UNKNOWN
    assert out.blocked is False


def test_missing_overseas_probe_is_unknown():
    out = judge([cn((443, False, "timeout"))], ports=[443])
    assert out.verdict is Verdict.UNKNOWN
    assert "国外" in out.reason


def test_unmeasured_overseas_port_is_unknown_not_blocked():
    nodes = [cn((443, False, "timeout")), us()]
    out = judge(nodes, ports=[443])
    assert out.verdict is Verdict.UNKNOWN


def test_empty_nodes_unknown():
    assert judge([]).verdict is Verdict.UNKNOWN


def test_blocked_other_port_plus_failing_other_is_still_ip_blocked():
    """443 被墙，22 国内外都不通（服务问题）→ 不能靠 22 说"IP 没被封"。"""
    nodes = [cn((443, False, "timeout"), (22, False, "refused")), us((443, True, ""), (22, False, "refused"))]
    out = judge(nodes, ports=[443, 22])
    assert out.verdict is Verdict.IP_BLOCKED
    assert "服务本身问题" in out.reason


def test_untested_aux_port_mentions_aux_ports_hint():
    nodes = [cn((443, False, "timeout")), us((443, True, ""))]
    out = judge(nodes, ports=[443, 22])
    assert out.verdict is Verdict.IP_BLOCKED
    assert "aux_ports" in out.reason


def test_majority_vote_across_cn_nodes():
    nodes = [
        node("bj", "cn", (443, False, "timeout")),
        node("sh", "cn", (443, False, "timeout")),
        node("gz", "cn", (443, True, "")),
        us((443, True, "")),
    ]
    out = judge(nodes, ports=[443], fail_ratio=0.6)
    assert out.verdict is Verdict.IP_BLOCKED


def test_minority_failure_is_ok():
    nodes = [
        node("bj", "cn", (443, True, "")),
        node("sh", "cn", (443, True, "")),
        node("gz", "cn", (443, False, "timeout")),
        us((443, True, "")),
    ]
    out = judge(nodes, ports=[443], fail_ratio=0.6)
    assert out.verdict is Verdict.OK


def test_port_states_recorded_for_reporting():
    nodes = [cn((443, False, "timeout"), (22, True, "")), us((443, True, ""), (22, True, ""))]
    out = judge(nodes, ports=[443, 22])
    assert [(p.port, p.cn, p.os) for p in out.ports] == [(443, "fail", "ok"), (22, "ok", "ok")]
    assert out.node_port == 443


def test_to_dict_is_serialisable():
    import json

    out = judge([cn((443, False, "timeout")), us((443, True, ""))], ports=[443])
    json.dumps(out.to_dict(), ensure_ascii=False)


# ------------------------------------------------------- 本机原语
@pytest.mark.asyncio
async def test_tcp_probe_closed_port():
    layer = await tcp_probe("127.0.0.1", 9, 0.5)
    assert layer.ok is False
    assert layer.kind in {"refused", "reset", "timeout"}


@pytest.mark.asyncio
async def test_tls_probe_against_plain_tcp_port_fails():
    async def handler(_r, w):
        w.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        layer = await tls_probe("127.0.0.1", port, "example.com", 3)
        assert layer.ok is False
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_icmp_probe_loopback():
    layer = await icmp_probe("127.0.0.1", count=1, timeout=2)
    assert layer.ok in (True, None)


def test_classify_variants():
    assert classify_exception(asyncio.TimeoutError()) == "timeout"
    assert classify_exception(ConnectionResetError()) == "reset"
    assert classify_exception(ConnectionRefusedError()) == "refused"


def test_verdict_tables_complete():
    from eipguard.detect.probe import VERDICT_ADVICE, VERDICT_ICONS, VERDICT_LABELS

    for verdict in Verdict:
        assert verdict in VERDICT_LABELS
        assert verdict in VERDICT_ICONS
        assert verdict in VERDICT_ADVICE
