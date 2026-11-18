from __future__ import annotations

import pytest

from eipguard.cloud.aliyun import EipInfo
from eipguard.config import Config
from eipguard.engine import Engine

CONFIG = """
telegram:
  token: "1:abc"
  admin_chat_ids: "42"
aliyun:
  accounts:
    - name: main
      access_key_id: ak1
      access_key_secret: sk1
      region: cn-hongkong
    - name: second
      access_key_id: ak2
      access_key_secret: sk2
      region: ap-southeast-1
cloudflare:
  api_token: cf
  zone_name: example.com
switch:
  release_old: true
  max_attempts: 2
targets:
  - name: hk
    account: main
    instance_id: i-1
    dns_records: ["hk.example.com", "api.example.com"]
  - name: sg
    account: second
    instance_id: i-2
    dns_records: ["sg.example.com"]
"""


class FakeAliyun:
    def __init__(self, tag: str = "") -> None:
        self.tag = tag
        self.eips: dict[str, EipInfo] = {}
        self.calls: list[str] = []
        self._seq = 0
        self.alloc_ips: list[str] = []
        self.alloc_fail = 0

    def seed(self, allocation_id: str, ip: str, instance_id: str = "", status: str = "Available") -> None:
        self.eips[allocation_id] = EipInfo(
            allocation_id=allocation_id, ip=ip, status=status, instance_id=instance_id
        )

    async def describe_eips(self, **kw):
        return list(self.eips.values())

    async def get_eip(self, allocation_id, region_id=None):
        return self.eips.get(allocation_id)

    async def find_instance_eip(self, instance_id, region_id=None):
        for e in self.eips.values():
            if e.instance_id == instance_id:
                return e
        return None

    async def allocate_eip(self, **kw):
        if self.alloc_fail > 0:
            self.alloc_fail -= 1
            from eipguard.cloud.aliyun import AliyunError

            raise AliyunError("AllocateEipAddress", "Throttling", "限流")
        self._seq += 1
        ip = self.alloc_ips.pop(0) if self.alloc_ips else f"10.0.{self.tag or '0'}.{self._seq}"
        self.seed(f"{self.tag}eip-new{self._seq}", ip)
        return self.eips[f"{self.tag}eip-new{self._seq}"]

    async def associate(self, allocation_id, instance_id, region_id=None):
        self.calls.append(f"associate:{allocation_id}")
        e = self.eips[allocation_id]
        e.instance_id = instance_id
        e.status = "InUse"

    async def unassociate(self, allocation_id, instance_id="", region_id=None):
        self.calls.append(f"unassociate:{allocation_id}")
        e = self.eips[allocation_id]
        e.instance_id = ""
        e.status = "Available"

    async def release(self, allocation_id, region_id=None):
        self.calls.append(f"release:{allocation_id}")
        self.eips.pop(allocation_id, None)

    async def wait_status(self, allocation_id, wanted, **kw):
        e = self.eips[allocation_id]
        e.status = sorted(wanted)[0]
        return e


class FakeCloudflare:
    def __init__(self) -> None:
        self.points: dict[str, str] = {}
        self.fail_names: set[str] = set()
        self.raise_all = False
        self.by_ip: dict[str, list[str]] = {}

    async def point_many(self, names, ip):
        if self.raise_all:
            return [{"name": n, "action": "error", "detail": "cf down", "ok": "0"} for n in names]
        out = []
        for n in names:
            if n in self.fail_names:
                out.append({"name": n, "action": "error", "detail": "record not found", "ok": "0"})
            else:
                self.points[n] = ip
                out.append({"name": n, "action": "updated", "detail": f"{n} → {ip}", "ok": "1"})
        return out

    async def list_records(self, name, record_type="A"):
        return []

    async def find_records_by_ip(self, ip, record_type="A"):
        from eipguard.cloud.cloudflare import DnsRecord

        return [
            DnsRecord(id=f"rec-{n}", name=n, type="A", content=ip)
            for n in self.by_ip.get(ip, [])
        ]

    async def close(self):
        return None


def make(tmp_path, *, cf: FakeCloudflare | None = None) -> tuple[Config, dict[str, FakeAliyun], Engine, list]:
    path = tmp_path / "config.yaml"
    path.write_text(CONFIG, "utf-8")
    cfg = Config.load(path)
    aliyuns = {"main": FakeAliyun("a"), "second": FakeAliyun("b")}
    aliyuns["main"].seed("eip-a1", "1.1.1.1", instance_id="i-1", status="InUse")
    aliyuns["second"].seed("eip-b1", "2.2.2.2", instance_id="i-2", status="InUse")
    events: list = []

    async def notify(ev):
        events.append(ev)

    engine = Engine(
        cfg,
        notifier=notify,
        aliyuns=aliyuns,  # type: ignore[arg-type]
        cloudflare=(cf or FakeCloudflare()),  # type: ignore[arg-type]
    )
    return cfg, aliyuns, engine, events


@pytest.mark.asyncio
async def test_switch_releases_old_then_binds_new(tmp_path):
    cfg, aliyuns, engine, events = make(tmp_path)
    result = await engine.switch("hk", reason="手动")
    assert result.ok is True
    assert result.old_ip == "1.1.1.1"
    assert result.new_ip
    assert result.old_released is True

    main = aliyuns["main"]
    # 旧 EIP 被解绑并释放
    assert "unassociate:eip-a1" in main.calls
    assert "release:eip-a1" in main.calls
    assert "eip-a1" not in main.eips, "旧 EIP 必须被释放以停止计费"
    # 新 EIP 绑定到实例
    new = next(e for e in main.eips.values() if e.instance_id == "i-1")
    assert new.ip == result.new_ip
    # 域名指向新 IP
    assert cfg.target("hk").dns_records
    await engine.close()


@pytest.mark.asyncio
async def test_switch_pushes_every_step(tmp_path):
    """释放成功、拿到新 IP、解析成功都要推送。"""
    cfg, _, engine, events = make(tmp_path)
    await engine.switch("hk")
    kinds = [e["type"] for e in events]
    assert "switch_started" in kinds
    assert "ip_allocated" in kinds
    assert "old_ip_released" in kinds
    assert "ip_bound" in kinds
    assert "dns_updated" in kinds
    assert kinds[-1] == "switch_success"

    released = next(e for e in events if e["type"] == "old_ip_released")
    assert released["old_ip"] == "1.1.1.1"
    assert released["allocation_id"] == "eip-a1"

    allocated = next(e for e in events if e["type"] == "ip_allocated")
    assert allocated["new_ip"]

    dns = next(e for e in events if e["type"] == "dns_updated")
    assert len(dns["dns"]) == 2
    await engine.close()


@pytest.mark.asyncio
async def test_multi_account_uses_right_client(tmp_path):
    cfg, aliyuns, engine, _ = make(tmp_path)
    r1 = await engine.switch("hk")
    r2 = await engine.switch("sg")
    assert r1.ok and r2.ok
    assert "release:eip-a1" in aliyuns["main"].calls
    assert not any("eip-a1" in c for c in aliyuns["second"].calls)
    assert "release:eip-b1" in aliyuns["second"].calls
    assert aliyuns["main"].calls != aliyuns["second"].calls
    await engine.close()


@pytest.mark.asyncio
async def test_release_off_keeps_old_eip(tmp_path):
    cfg, aliyuns, engine, events = make(tmp_path)
    cfg.switch.release_old = False
    result = await engine.switch("hk")
    assert result.ok
    assert result.old_released is False
    assert "eip-a1" in aliyuns["main"].eips, "关闭释放时应保留旧 EIP"
    assert "release:eip-a1" not in aliyuns["main"].calls
    assert not any(e["type"] == "old_ip_released" for e in events)
    await engine.close()


@pytest.mark.asyncio
async def test_allocate_retries_then_succeeds(tmp_path):
    cfg, aliyuns, engine, _ = make(tmp_path)
    aliyuns["main"].alloc_fail = 1  # 第一次失败
    result = await engine.switch("hk")
    assert result.ok is True, "重试后应成功"
    await engine.close()


@pytest.mark.asyncio
async def test_allocate_fails_all_attempts_keeps_old_ip(tmp_path):
    cfg, aliyuns, engine, events = make(tmp_path)
    aliyuns["main"].alloc_fail = 10
    result = await engine.switch("hk")
    assert result.ok is False
    assert "分配新 EIP 失败" in result.error
    # 分配失败时绝不能动旧 IP
    assert "eip-a1" in aliyuns["main"].eips
    assert aliyuns["main"].eips["eip-a1"].instance_id == "i-1"
    assert "release:eip-a1" not in aliyuns["main"].calls
    assert any(e["type"] == "switch_failed" for e in events)
    await engine.close()


@pytest.mark.asyncio
async def test_no_eip_is_clear_error(tmp_path):
    cfg, aliyuns, engine, events = make(tmp_path)
    aliyuns["main"].eips.clear()
    result = await engine.switch("hk")
    assert result.ok is False
    assert "没有绑定 EIP" in result.error
    assert any(e["type"] == "switch_failed" for e in events)
    await engine.close()


@pytest.mark.asyncio
async def test_partial_dns_failure_still_succeeds_with_warning(tmp_path):
    cf = FakeCloudflare()
    cf.fail_names = {"api.example.com"}
    cfg, _, engine, events = make(tmp_path, cf=cf)
    result = await engine.switch("hk")
    assert result.ok is True, "IP 已换好，部分域名失败不该整体失败"
    assert cf.points.get("hk.example.com") == result.new_ip
    assert "api.example.com" not in cf.points
    dns_event = next(e for e in events if e["type"] == "dns_updated")
    assert [d["ok"] for d in dns_event["dns"]] == ["1", "0"]
    await engine.close()


@pytest.mark.asyncio
async def test_all_dns_failure_is_error(tmp_path):
    cf = FakeCloudflare()
    cf.raise_all = True
    cfg, _, engine, events = make(tmp_path, cf=cf)
    result = await engine.switch("hk")
    assert result.ok is False
    assert "解析" in result.error
    assert any(e["type"] == "switch_failed" for e in events)
    await engine.close()


@pytest.mark.asyncio
async def test_target_without_dns_only_switches_ip(tmp_path):
    cfg, aliyuns, engine, events = make(tmp_path)
    cfg.target("hk").dns_records = []
    result = await engine.switch("hk")
    assert result.ok is True
    assert result.dns == []
    assert not any(e["type"] == "dns_updated" for e in events)
    await engine.close()


@pytest.mark.asyncio
async def test_describe_reports_current_ip(tmp_path):
    cfg, _, engine, _ = make(tmp_path)
    detail = await engine.describe(cfg.target("hk"))
    assert detail["eip"].ip == "1.1.1.1"
    assert detail["error"] == ""
    await engine.close()


@pytest.mark.asyncio
async def test_describe_error_when_no_eip(tmp_path):
    cfg, aliyuns, engine, _ = make(tmp_path)
    aliyuns["main"].eips.clear()
    detail = await engine.describe(cfg.target("hk"))
    assert detail["eip"] is None
    assert "EIP" in detail["error"]
    await engine.close()


@pytest.mark.asyncio
async def test_lock_prevents_concurrent_switch(tmp_path):
    import asyncio

    cfg, _, engine, events = make(tmp_path)
    async with engine.lock("hk"):
        result = await engine.switch("hk")
    assert result.ok is False
    assert "正在处理" in result.error
    await engine.close()


@pytest.mark.asyncio
async def test_manual_dns_uses_current_ip(tmp_path):
    cfg, _, engine, events = make(tmp_path)
    results = await engine.manual_dns("hk")
    assert all(r["ok"] == "1" for r in results)
    assert any(e["type"] == "dns_sync" for e in events)
    await engine.close()


@pytest.mark.asyncio
async def test_no_cloudflare_configured_only_switches_ip(tmp_path):
    """没配 CF 时：换 IP 照做，但必须明确告警说域名没改。"""
    cf = FakeCloudflare()
    cfg, aliyuns, engine, events = make(tmp_path, cf=cf)
    cfg.cloudflare.api_token = ""
    cfg.cloudflare.zone_name = ""
    cfg.cloudflare.zone_id = ""

    result = await engine.switch("hk")
    assert result.ok is True, "换 IP 本身应该成功"
    assert result.old_released is True, "旧 IP 仍然要释放，停止计费"
    assert cf.points == {}, "没配 CF 就不该动解析"
    assert result.warnings, "必须告诉用户域名没改"
    assert "没有配置 Cloudflare" in result.warnings[0]
    assert "域名不会更新" in result.warnings[0]
    # 推送里也要带警告
    started = next(e for e in events if e["type"] == "switch_started")
    assert started["warnings"]
    assert started["dns"] == []
    await engine.close()


@pytest.mark.asyncio
async def test_auto_discover_domains_by_old_ip(tmp_path):
    """没配域名但配了 CF：按旧 IP 反查出哪些域名指向它，自动更新。"""
    cf = FakeCloudflare()
    cf.by_ip = {"1.1.1.1": ["hk.example.com", "api.example.com"]}
    cfg, _, engine, events = make(tmp_path, cf=cf)
    cfg.target("hk").dns_records = []  # 显式清空，走自动发现

    result = await engine.switch("hk")
    assert result.ok is True
    assert set(cf.points) == {"hk.example.com", "api.example.com"}
    assert all(v == result.new_ip for v in cf.points.values())
    started = next(e for e in events if e["type"] == "switch_started")
    assert started["discovered"] is True
    assert len(started["dns"]) == 2
    # 发现的域名写回配置，下次不用再查
    assert set(cfg.target("hk").dns_records) == {"hk.example.com", "api.example.com"}
    await engine.close()


@pytest.mark.asyncio
async def test_cf_ok_but_nothing_points_to_old_ip(tmp_path):
    """CF 正常但这个 IP 没被任何记录指向：不能假装成功改了解析。"""
    cf = FakeCloudflare()
    cf.by_ip = {}
    cfg, _, engine, events = make(tmp_path, cf=cf)
    cfg.target("hk").dns_records = []

    result = await engine.switch("hk")
    assert result.ok is True
    assert cf.points == {}
    assert result.warnings
    assert "没有指向" in result.warnings[0]
    assert "/target dns" in result.warnings[0]
    await engine.close()


@pytest.mark.asyncio
async def test_dns_exception_is_reported_as_failure(tmp_path):
    """解析过程中抛任何异常，都必须整体判失败，不能报成功。"""
    class BoomCF(FakeCloudflare):
        async def point_many(self, names, ip):
            raise RuntimeError("网络断了")

    cfg, aliyuns, engine, events = make(tmp_path, cf=BoomCF())
    result = await engine.switch("hk")
    assert result.ok is False
    assert "网络断了" in result.error
    assert any(e["type"] == "switch_failed" for e in events)
    # 旧 IP 已经释放、新 IP 已经绑定，要在告警里说清楚当前状态
    assert result.old_released is True
    assert result.new_ip
    await engine.close()
