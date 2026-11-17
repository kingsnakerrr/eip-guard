from __future__ import annotations

import pytest

from eipguard.detect.probe import (
    Attempt,
    NodeResult,
    classify_exception,
    judge,
    tcp_probe,
)


def node(name: str, zone: str, oks: list[bool]) -> NodeResult:
    attempts = [
        Attempt(ok, 20.0 if ok else None, None, "" if ok else "timeout", "" if ok else "timeout")
        for ok in oks
    ]
    return NodeResult(name, zone, attempts)


def test_blocked_when_cn_fails_and_overseas_ok():
    nodes = [node("bj", "cn", [False, False]), node("sh", "cn", [False]), node("us", "overseas", [True])]
    out = judge(nodes, fail_ratio=0.6, min_samples=2)
    assert out.blocked is True
    assert out.ok is False


def test_not_blocked_when_wall_side_ok():
    nodes = [node("bj", "cn", [True, True]), node("us", "overseas", [True])]
    out = judge(nodes, fail_ratio=0.6, min_samples=2)
    assert out.ok is True
    assert out.blocked is False


def test_down_not_blocked_when_both_sides_fail():
    nodes = [node("bj", "cn", [False, False]), node("us", "overseas", [False])]
    out = judge(nodes, fail_ratio=0.6, min_samples=2)
    assert out.ok is False
    assert out.blocked is False
    assert "故障" in out.reason


def test_no_cn_nodes_cannot_confirm_block():
    nodes = [node("us", "overseas", [False, False])]
    out = judge(nodes, min_samples=2)
    assert out.blocked is False


def test_partial_cn_failure_below_ratio_is_ok():
    nodes = [node("a", "cn", [True, True, True]), node("b", "cn", [False])]
    out = judge(nodes, fail_ratio=0.6, min_samples=2)
    assert out.ok is True


def test_empty_nodes_is_safe():
    out = judge([])
    assert out.ok is True and out.blocked is False


@pytest.mark.asyncio
async def test_tcp_probe_against_closed_port():
    # 127.0.0.1 上没有监听端口，应为失败且被分类
    attempt = await tcp_probe("127.0.0.1", 9, 0.5)
    assert attempt.ok is False
    assert attempt.kind in {"refused", "reset", "timeout"}


def test_classify_timeout():
    import asyncio

    assert classify_exception(asyncio.TimeoutError()) == "timeout"
    assert classify_exception(ConnectionResetError()) == "reset"
    assert classify_exception(ConnectionRefusedError()) == "refused"
