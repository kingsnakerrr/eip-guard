from __future__ import annotations

import time
from typing import Any

import pytest

from eipguard.cloud.aliyun import EipInfo
from eipguard.cloud.cloudflare import DnsRecord
from eipguard.config import Config, TargetConfig
from eipguard.detect.probe import (
    LAYER_AUX,
    LAYER_ICMP,
    LAYER_TCP,
    LAYER_TLS,
    LayerResult,
    NodeResult,
    ProbeOutcome,
    Verdict,
)
from eipguard.engine import Engine
from eipguard.state import Settings, StateStore


class FakeAliyun:
    def __init__(self) -> None:
        self.eips: dict[str, EipInfo] = {}
        self.calls: list[str] = []
        self.fail_on: set[str] = set()
        self.alloc_queue: list[str] = []
        self._seq = 0

    def seed(self, allocation_id: str, ip: str, instance_id: str = "", status: str = "Available") -> EipInfo:
        info = EipInfo(allocation_id=allocation_id, ip=ip, status=status, instance_id=instance_id)
        self.eips[allocation_id] = info
        return info

    async def describe_eips(self, **kw: Any) -> list[EipInfo]:
        out = list(self.eips.values())
        if kw.get("allocation_id"):
            out = [e for e in out if e.allocation_id == kw["allocation_id"]]
        if kw.get("instance_id"):
            out = [e for e in out if e.instance_id == kw["instance_id"]]
        return out

    async def get_eip(self, allocation_id: str, region_id: str | None = None) -> EipInfo | None:
        return self.eips.get(allocation_id)

    async def find_instance_eip(self, instance_id: str, region_id: str | None = None) -> EipInfo | None:
        for e in self.eips.values():
            if e.instance_id == instance_id:
                return e
        return None

    async def allocate_eip(self, **kw: Any) -> EipInfo:
        if "AllocateEipAddress" in self.fail_on:
            raise RuntimeError("allocate failed")
        self._seq += 1
        ip = self.alloc_queue.pop(0) if self.alloc_queue else f"10.0.0.{self._seq}"
        return self.seed(f"eip-new{self._seq}", ip)

    async def associate(self, allocation_id: str, instance_id: str, region_id: str | None = None) -> None:
        self.calls.append(f"associate:{allocation_id}")
        if "AssociateEipAddress" in self.fail_on:
            raise RuntimeError("associate failed")
        e = self.eips[allocation_id]
        e.instance_id = instance_id
        e.status = "InUse"

    async def unassociate(self, allocation_id: str, instance_id: str = "", region_id: str | None = None) -> None:
        self.calls.append(f"unassociate:{allocation_id}")
        e = self.eips[allocation_id]
        e.instance_id = ""
        e.status = "Available"

    async def release(self, allocation_id: str, region_id: str | None = None) -> None:
        self.calls.append(f"release:{allocation_id}")
        self.eips.pop(allocation_id, None)

    async def wait_status(self, allocation_id: str, wanted: set[str], **kw: Any) -> EipInfo:
        e = self.eips[allocation_id]
        e.status = wanted.pop() if len(wanted) == 1 else e.status
        return e


class FakeCloudflare:
    def __init__(self) -> None:
        self.points: dict[str, str] = {}
        self.fail = False

    async def point_many(self, names: list[str], ip: str) -> list[dict[str, str]]:
        if self.fail:
            return [{"name": n, "action": "error", "detail": "cf down", "ok": "0"} for n in names]
        out = []
        for n in names:
            self.points[n] = ip
            out.append({"name": n, "action": "updated", "detail": f"{n} → {ip}", "ok": "1"})
        return out

    async def point_to(self, name: str, ip: str) -> tuple[str, str]:
        self.points[name] = ip
        return "updated", f"{name} → {ip}"

    async def close(self) -> None:
        return None


class FakeDetector:
    """按顺序返回预设结论；list 用尽后重复最后一个。"""

    def __init__(self, results: list[ProbeOutcome]) -> None:
        self.results = results
        self.calls = 0
        self.by_ip: dict[str, ProbeOutcome] = {}

    async def check(self, ip: str, port: int, *, sni: str = "") -> ProbeOutcome:
        self.calls += 1
        if ip in self.by_ip:
            return self.by_ip[ip]
        if not self.results:
            return ok_outcome()
        idx = min(self.calls - 1, len(self.results) - 1)
        return self.results[idx]

    async def close(self) -> None:
        return None


class WallDetector(FakeDetector):
    """旧 IP 被墙、其余 IP 正常 —— 更贴近真实换 IP 场景。"""

    def __init__(self, walled: set[str]) -> None:
        super().__init__([])
        self.walled = walled

    async def check(self, ip: str, port: int, *, sni: str = "") -> ProbeOutcome:
        self.calls += 1
        return blocked_outcome() if ip in self.walled else ok_outcome()


def _layer(name: str, ok: bool | None, kind: str = "") -> LayerResult:
    return LayerResult(name, ok, 10.0 if ok else None, kind, "" if ok else kind)


def _cn(**layers: LayerResult) -> NodeResult:
    return NodeResult("cn", "cn", dict(layers))


def _us(**layers: LayerResult) -> NodeResult:
    base = {
        LAYER_ICMP: _layer(LAYER_ICMP, True),
        LAYER_TCP: _layer(LAYER_TCP, True),
        LAYER_TLS: _layer(LAYER_TLS, True),
    }
    base.update(layers)
    return NodeResult("us", "overseas", base)


def ok_outcome() -> ProbeOutcome:
    return ProbeOutcome(
        Verdict.OK,
        "探测正常",
        [
            _cn(**{LAYER_TCP: _layer(LAYER_TCP, True), LAYER_TLS: _layer(LAYER_TLS, True)}),
            _us(),
        ],
    )


def blocked_outcome() -> ProbeOutcome:
    """能 ping 通但端口全不通 → IP 被墙（用户遇到的真实场景）。"""
    return ProbeOutcome(
        Verdict.IP_BLOCKED,
        "ICMP 能通但端口全部不通，墙外正常 → IP 被墙",
        [
            _cn(
                **{
                    LAYER_ICMP: _layer(LAYER_ICMP, True),
                    LAYER_TCP: _layer(LAYER_TCP, False, "timeout"),
                    LAYER_AUX: _layer(LAYER_AUX, False, "timeout"),
                }
            ),
            _us(),
        ],
        "换 IP 有效。",
    )


def port_blocked_outcome() -> ProbeOutcome:
    return ProbeOutcome(
        Verdict.PORT_BLOCKED,
        "节点端口不通但其它端口可连 → 仅端口被封",
        [
            _cn(
                **{
                    LAYER_TCP: _layer(LAYER_TCP, False, "timeout"),
                    LAYER_AUX: _layer(LAYER_AUX, True),
                }
            ),
            _us(),
        ],
        "换 IP 通常无效且浪费钱。",
    )


def down_outcome() -> ProbeOutcome:
    return ProbeOutcome(
        Verdict.DOWN,
        "墙外也连不上 → 服务故障",
        [
            _cn(**{LAYER_TCP: _layer(LAYER_TCP, False, "refused")}),
            _us(**{LAYER_TCP: _layer(LAYER_TCP, False, "refused")}),
        ],
    )


def make_cfg(tmp_path: Any, **over: Any) -> Config:
    config_text = f"""
telegram:
  token: "1:abc"
  admin_chat_ids: "42"
aliyun:
  access_key_id: ak
  access_key_secret: sk
cloudflare:
  api_token: cf
  zone_name: example.com
detect:
  provider: tcp_self
switch:
  auto: true
  cooldown: 0
  max_attempts: 2
  release_old: true
  restore_old_on_failure: true
targets:
  - name: hk
    instance_id: i-1
    dns_records: ["hk.example.com"]
"""
    p = tmp_path / "config.yaml"
    p.write_text(config_text, "utf-8")
    cfg = Config.load(p)
    for k, v in over.items():
        setattr(cfg, k, v)
    return cfg


def make_engine(tmp_path: Any, detector: FakeDetector, aliyun: FakeAliyun, cf: FakeCloudflare) -> tuple[Engine, StateStore, list]:
    cfg = make_cfg(tmp_path)
    store = StateStore.load(cfg.data_dir / "state.json", ["hk"], {"auto": True})
    settings = Settings.from_values({"auto": True, "interval": 1, "failure_threshold": 1, "cooldown": 0}, {})
    events: list[dict[str, Any]] = []

    async def notify(ev: dict[str, Any]) -> None:
        events.append(ev)

    engine = Engine(
        cfg,
        store,
        settings,
        notifier=notify,
        aliyun=aliyun,  # type: ignore[arg-type]
        cloudflare=cf,  # type: ignore[arg-type]
        detector=detector,  # type: ignore[arg-type]
    )
    engine.cfg.detect.verify_delay = 0
    engine.cfg.detect.verify_attempts = 1
    return engine, store, events


@pytest.mark.asyncio
async def test_switch_happy_path(tmp_path):
    aliyun = FakeAliyun()
    aliyun.seed("eip-old", "1.1.1.1", instance_id="i-1", status="InUse")
    cf = FakeCloudflare()
    detector = FakeDetector([blocked_outcome(), ok_outcome()])
    engine, store, events = make_engine(tmp_path, detector, aliyun, cf)

    result = await engine.switch("hk", reason="test", manual=True)
    assert result.ok is True
    assert result.old_ip == "1.1.1.1"
    assert result.new_ip
    assert cf.points["hk.example.com"] == result.new_ip
    assert "release:eip-old" in aliyun.calls
    assert store.get("hk").current_ip == result.new_ip
    types = [e["type"] for e in events]
    assert types[0] == "switch_started"
    assert "switch_success" in types
    await engine.close()


@pytest.mark.asyncio
async def test_switch_rolls_back_when_dns_fails(tmp_path):
    aliyun = FakeAliyun()
    aliyun.seed("eip-old", "1.1.1.1", instance_id="i-1", status="InUse")
    cf = FakeCloudflare()
    cf.fail = True
    detector = FakeDetector([blocked_outcome()])
    engine, store, events = make_engine(tmp_path, detector, aliyun, cf)

    result = await engine.switch("hk", reason="test")
    assert result.ok is False
    # 新 EIP 被释放，旧 EIP 回绑，业务仍可用
    assert "eip-old" in aliyun.eips
    assert aliyun.eips["eip-old"].instance_id == "i-1"
    assert any(e["type"] == "switch_failed" for e in events)
    await engine.close()


@pytest.mark.asyncio
async def test_new_ip_also_blocked_tries_next(tmp_path):
    aliyun = FakeAliyun()
    aliyun.seed("eip-old", "1.1.1.1", instance_id="i-1", status="InUse")
    aliyun.alloc_queue = ["2.2.2.2", "3.3.3.3"]
    cf = FakeCloudflare()
    # 第一次 verify 失败（新 IP 也被墙），第二次成功
    detector = FakeDetector([blocked_outcome(), blocked_outcome(), ok_outcome()])
    engine, store, _ = make_engine(tmp_path, detector, aliyun, cf)

    result = await engine.switch("hk", reason="test")
    assert result.ok is True
    assert result.new_ip == "3.3.3.3"
    assert "2.2.2.2" not in [e.ip for e in aliyun.eips.values()]
    await engine.close()


@pytest.mark.asyncio
async def test_dns_not_pointed_at_failed_new_ip(tmp_path):
    """新 IP 验证失败时，解析绝不能指过去（否则线上直接断）。"""
    aliyun = FakeAliyun()
    aliyun.seed("eip-old", "1.1.1.1", instance_id="i-1", status="InUse")
    cf = FakeCloudflare()
    detector = WallDetector({"1.1.1.1", "10.0.0.1"})  # 旧 IP 和新 IP 都被墙
    engine, store, events = make_engine(tmp_path, detector, aliyun, cf)
    engine.cfg.switch.max_attempts = 1

    result = await engine.switch("hk", reason="test")
    assert result.ok is False
    assert cf.points == {}, f"不应改动任何解析，实际 {cf.points}"
    assert any(e["type"] == "switch_failed" for e in events)
    assert aliyun.eips["eip-old"].instance_id == "i-1"
    await engine.close()


@pytest.mark.asyncio
async def test_dns_rollback_when_update_partially_fails(tmp_path):
    """只有部分解析失败时：IP 换成功、不回滚到被墙的旧 IP，但要给出警告。"""
    aliyun = FakeAliyun()
    aliyun.seed("eip-old", "1.1.1.1", instance_id="i-1", status="InUse")
    cf = FakeCloudflare()

    class HalfFailCF(FakeCloudflare):
        async def point_many(self, names, ip):
            self.points[names[0]] = ip
            return [
                {"name": names[0], "action": "updated", "detail": "ok", "ok": "1"},
                {"name": names[1], "action": "error", "detail": "boom", "ok": "0"},
            ]

    cf = HalfFailCF()
    detector = WallDetector({"1.1.1.1"})
    engine, store, events = make_engine(tmp_path, detector, aliyun, cf)
    engine.cfg.switch.max_attempts = 1
    engine.cfg.targets[0].dns_records = ["a.example.com", "b.example.com"]

    result = await engine.switch("hk", reason="test")
    assert result.ok is True, "IP 已换成功，不应因部分域名失败而回滚"
    assert result.warnings and "b.example.com" in result.warnings[0]
    success = next(e for e in events if e["type"] == "switch_success")
    assert success["warnings"]

    aliyun = FakeAliyun()
    cf = FakeCloudflare()
    engine, _, events = make_engine(tmp_path, FakeDetector([]), aliyun, cf)
    result = await engine.switch("hk")
    assert result.ok is False
    assert "EIP" in result.error
    assert any(e["type"] == "switch_failed" for e in events)
    await engine.close()


@pytest.mark.asyncio
async def test_monitor_triggers_after_threshold(tmp_path):
    aliyun = FakeAliyun()
    aliyun.seed("eip-old", "1.1.1.1", instance_id="i-1", status="InUse")
    cf = FakeCloudflare()
    detector = WallDetector({"1.1.1.1"})
    engine, store, events = make_engine(tmp_path, detector, aliyun, cf)
    engine.settings.failure_threshold = 3
    state = store.get("hk")

    await engine._check_one("hk")
    assert state.failures == 1
    assert state.switches == 0, "未达阈值不应换 IP"
    assert any(e["type"] == "blocked_suspect" for e in events)
    assert not any(e["type"] == "blocked_confirmed" for e in events)

    await engine._check_one("hk")
    assert state.failures == 2
    assert state.switches == 0

    await engine._check_one("hk")
    assert any(e["type"] == "blocked_confirmed" for e in events)
    assert state.failures == 0, "换成功后失败计数应清零"
    assert state.switches == 1
    assert state.current_ip != "1.1.1.1"
    assert any(e["type"] == "switch_success" for e in events)

    # 新 IP 正常，不再动作
    await engine._check_one("hk")
    assert state.switches == 1
    assert state.failures == 0
    await engine.close()


@pytest.mark.asyncio
async def test_auto_disabled_prevents_switch(tmp_path):
    aliyun = FakeAliyun()
    aliyun.seed("eip-old", "1.1.1.1", instance_id="i-1", status="InUse")
    cf = FakeCloudflare()
    detector = FakeDetector([blocked_outcome()])
    engine, store, events = make_engine(tmp_path, detector, aliyun, cf)
    engine.settings.auto = False
    engine.settings.failure_threshold = 1
    for _ in range(3):
        await engine._check_one("hk")
    assert store.get("hk").switches == 0
    assert not any(c.startswith("associate:eip-new") for c in aliyun.calls)
    assert any(e["type"] == "auto_disabled" for e in events)
    await engine.close()


@pytest.mark.asyncio
async def test_down_is_not_treated_as_blocked(tmp_path):
    aliyun = FakeAliyun()
    aliyun.seed("eip-old", "1.1.1.1", instance_id="i-1", status="InUse")
    cf = FakeCloudflare()
    engine, store, events = make_engine(tmp_path, FakeDetector([down_outcome()]), aliyun, cf)
    engine.settings.failure_threshold = 1
    for _ in range(3):
        await engine._check_one("hk")
    assert store.get("hk").switches == 0, "实例故障不应触发换 IP"
    assert not any(e["type"] == "blocked_confirmed" for e in events)
    await engine.close()


@pytest.mark.asyncio
async def test_manual_dns_uses_current_ip(tmp_path):
    aliyun = FakeAliyun()
    aliyun.seed("eip-old", "1.1.1.1", instance_id="i-1", status="InUse")
    cf = FakeCloudflare()
    engine, _, events = make_engine(tmp_path, FakeDetector([]), aliyun, cf)
    results = await engine.manual_dns("hk")
    assert results[0]["ok"] == "1"
    assert cf.points["hk.example.com"] == "1.1.1.1"
    assert any(e["type"] == "dns_sync" for e in events)
    await engine.close()


@pytest.mark.asyncio
async def test_state_persists(tmp_path):
    cfg = make_cfg(tmp_path)
    store = StateStore.load(cfg.data_dir / "state.json", ["hk"], {"auto": True})
    store.get("hk").current_ip = "9.9.9.9"
    store.get("hk").switches = 3
    store.channel_id = -100123
    store.save()

    again = StateStore.load(cfg.data_dir / "state.json", ["hk"])
    assert again.get("hk").current_ip == "9.9.9.9"
    assert again.get("hk").switches == 3
    assert again.channel_id == -100123
