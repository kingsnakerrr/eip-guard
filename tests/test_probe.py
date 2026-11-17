from __future__ import annotations

import asyncio

import pytest

from eipguard.detect.probe import (
    LAYER_AUX,
    LAYER_HTTP,
    LAYER_ICMP,
    LAYER_TCP,
    LAYER_TLS,
    LayerResult,
    NodeResult,
    Verdict,
    classify_exception,
    icmp_probe,
    judge,
    tcp_probe,
    tls_probe,
)


def L(layer: str, ok: bool | None, kind: str = "", detail: str = "") -> LayerResult:
    return LayerResult(layer, ok, 20.0 if ok else None, kind, "" if ok else kind, detail)


def node(name: str, zone: str, **layers: LayerResult) -> NodeResult:
    return NodeResult(name, zone, dict(layers))


def cn_node(**layers: LayerResult) -> NodeResult:
    return node("cn", "cn", **layers)


def os_node(**layers: LayerResult) -> NodeResult:
    # 墙外节点通常各层都通
    defaults = {
        LAYER_ICMP: L(LAYER_ICMP, True),
        LAYER_TCP: L(LAYER_TCP, True),
        LAYER_TLS: L(LAYER_TLS, True),
    }
    defaults.update(layers)
    return node("us", "overseas", **defaults)


# ------------------------------------------------------------ 用户遇到的场景
def test_ping_ok_but_all_ports_dead_is_ip_blocked():
    """能 ping 通，但节点端口和其它端口全都不通 → IP 被墙（不是正常！）。"""
    nodes = [
        cn_node(
            **{
                LAYER_ICMP: L(LAYER_ICMP, True),
                LAYER_TCP: L(LAYER_TCP, False, "timeout"),
                LAYER_AUX: L(LAYER_AUX, False, "timeout", ),
                LAYER_TLS: L(LAYER_TLS, None),
            }
        ),
        os_node(),
    ]
    out = judge(nodes, port=443, aux_ports=[80, 22])
    assert out.verdict is Verdict.IP_BLOCKED
    assert out.blocked is True
    assert "ICMP" in out.reason
    assert "不代表 IP 可用" in out.reason


def test_ping_ok_tcp_ok_tls_ok_is_normal():
    nodes = [cn_node(**{LAYER_ICMP: L(LAYER_ICMP, True), LAYER_TCP: L(LAYER_TCP, True), LAYER_TLS: L(LAYER_TLS, True)}), os_node()]
    out = judge(nodes)
    assert out.verdict is Verdict.OK
    assert out.ok is True


def test_ping_ok_tcp_dead_but_other_port_open_is_port_blocked():
    """只封了一个端口：换 IP 没用，应提示换端口。"""
    nodes = [
        cn_node(
            **{
                LAYER_ICMP: L(LAYER_ICMP, True),
                LAYER_TCP: L(LAYER_TCP, False, "timeout"),
                LAYER_AUX: L(LAYER_AUX, True, detail="80✓ 22✗"),
            }
        ),
        os_node(),
    ]
    out = judge(nodes, port=443, aux_ports=[80, 22])
    assert out.verdict is Verdict.PORT_BLOCKED
    assert out.blocked is True
    assert "仅端口被封" in out.reason
    assert "换端口" in out.advice


def test_tcp_ok_tls_reset_is_tls_blocked():
    nodes = [
        cn_node(**{LAYER_TCP: L(LAYER_TCP, True), LAYER_TLS: L(LAYER_TLS, False, "reset")}),
        os_node(),
    ]
    out = judge(nodes)
    assert out.verdict is Verdict.TLS_BLOCKED
    assert "SNI" in out.reason or "SNI" in out.advice


def test_tcp_tls_ok_but_http_broken_is_data_blocked():
    nodes = [
        cn_node(
            **{
                LAYER_TCP: L(LAYER_TCP, True),
                LAYER_TLS: L(LAYER_TLS, True),
                LAYER_HTTP: L(LAYER_HTTP, False, "reset"),
            }
        ),
        os_node(**{LAYER_HTTP: L(LAYER_HTTP, True)}),
    ]
    out = judge(nodes)
    assert out.verdict is Verdict.DATA_BLOCKED


def test_both_sides_dead_is_down_not_blocked():
    nodes = [
        cn_node(**{LAYER_TCP: L(LAYER_TCP, False, "refused")}),
        os_node(**{LAYER_TCP: L(LAYER_TCP, False, "refused")}),
    ]
    out = judge(nodes)
    assert out.verdict is Verdict.DOWN
    assert out.blocked is False


def test_overseas_only_never_claims_blocked():
    out = judge([os_node(**{LAYER_TCP: L(LAYER_TCP, True)})])
    assert out.verdict is Verdict.UNKNOWN
    assert out.blocked is False


def test_empty_nodes_unknown():
    out = judge([])
    assert out.verdict is Verdict.UNKNOWN


def test_cn_majority_failure_counts_as_blocked():
    nodes = [
        node("bj", "cn", **{LAYER_TCP: L(LAYER_TCP, False, "timeout")}),
        node("sh", "cn", **{LAYER_TCP: L(LAYER_TCP, False, "timeout")}),
        node("gz", "cn", **{LAYER_TCP: L(LAYER_TCP, True)}),
        os_node(),
    ]
    out = judge(nodes, fail_ratio=0.6)
    assert out.blocked is True


def test_cn_partial_failure_below_ratio_is_ok():
    nodes = [
        node("bj", "cn", **{LAYER_TCP: L(LAYER_TCP, True)}),
        node("sh", "cn", **{LAYER_TCP: L(LAYER_TCP, True)}),
        node("gz", "cn", **{LAYER_TCP: L(LAYER_TCP, False, "timeout")}),
        os_node(),
    ]
    out = judge(nodes, fail_ratio=0.6)
    assert out.verdict is Verdict.OK


def test_icmp_untested_still_detects_ip_block():
    nodes = [
        cn_node(**{LAYER_TCP: L(LAYER_TCP, False, "timeout"), LAYER_AUX: L(LAYER_AUX, False, "timeout")}),
        os_node(),
    ]
    out = judge(nodes, aux_ports=[80])
    assert out.verdict is Verdict.IP_BLOCKED


# ------------------------------------------------------------ 探针原语
@pytest.mark.asyncio
async def test_tcp_probe_closed_port():
    layer = await tcp_probe("127.0.0.1", 9, 0.5)
    assert layer.ok is False
    assert layer.kind in {"refused", "reset", "timeout"}


@pytest.mark.asyncio
async def test_tls_probe_against_plain_tcp_port_fails():
    # 一个只接受连接但不做 TLS 的端口 → TLS 层应失败
    async def handler(_r, w):
        w.close()

    server = await asyncio_start(handler)
    port = server.sockets[0].getsockname()[1]
    try:
        layer = await tls_probe("127.0.0.1", port, "example.com", 3)
        assert layer.ok is False
    finally:
        server.close()
        await server.wait_closed()


async def asyncio_start(handler):
    return await asyncio.start_server(handler, "127.0.0.1", 0)


@pytest.mark.asyncio
async def test_icmp_probe_loopback():
    layer = await icmp_probe("127.0.0.1", count=1, timeout=2)
    # 没有 ping 命令时 ok=None，有的话应为通
    assert layer.ok in (True, None)


def test_classify_variants():
    assert classify_exception(asyncio.TimeoutError()) == "timeout"
    assert classify_exception(ConnectionResetError()) == "reset"
    assert classify_exception(ConnectionRefusedError()) == "refused"


def test_verdict_labels_and_advice_complete():
    from eipguard.detect.probe import VERDICT_ADVICE, VERDICT_ICONS, VERDICT_LABELS

    for verdict in Verdict:
        assert verdict in VERDICT_LABELS
        assert verdict in VERDICT_ICONS
        assert verdict in VERDICT_ADVICE
