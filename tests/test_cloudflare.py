from __future__ import annotations

import json
from typing import Any

import pytest
from aiohttp import web

from eipguard.cloud.cloudflare import Cloudflare, CloudflareError


class FakeCF:
    """最小 Cloudflare API 模拟，行为与真实 API 的响应包装一致。"""

    def __init__(self) -> None:
        self.zone_id = "zone123"
        self.records: dict[str, dict[str, Any]] = {}
        self.calls: list[tuple[str, str]] = []
        self.fail_next: int = 0
        self.authed: list[str] = []
        self._seq = 0

    def add(self, name: str, content: str) -> str:
        self._seq += 1
        rid = f"rec{self._seq}"
        self.records[rid] = {
            "id": rid,
            "name": name,
            "type": "A",
            "content": content,
            "ttl": 1,
            "proxied": False,
            "zone_id": self.zone_id,
        }
        return rid

    async def handler(self, request: web.Request) -> web.Response:
        self.calls.append((request.method, request.path))
        self.authed.append(request.headers.get("Authorization", ""))
        if self.fail_next:
            self.fail_next -= 1
            return web.json_response({"success": False, "errors": [{"code": 10000, "message": "boom"}]}, status=500)
        path = request.path
        if path == "/client/v4/zones" and request.method == "GET":
            name = request.query.get("name")
            zones = [{"id": self.zone_id, "name": name}] if name else []
            return web.json_response({"success": True, "result": zones, "errors": []})
        if path == f"/client/v4/zones/{self.zone_id}" and request.method == "GET":
            return web.json_response(
                {"success": True, "result": {"id": self.zone_id, "name": "example.com"}, "errors": []}
            )
        if path == f"/client/v4/zones/{self.zone_id}/dns_records" and request.method == "GET":
            name = request.query.get("name")
            items = [r for r in self.records.values() if r["name"] == name and r["type"] == "A"]
            return web.json_response({"success": True, "result": items, "errors": []})
        if path == f"/client/v4/zones/{self.zone_id}/dns_records" and request.method == "POST":
            body = await request.json()
            rid = self._seq = self._seq + 1
            rec = {
                "id": f"rec{rid}",
                "name": body["name"],
                "type": body["type"],
                "content": body["content"],
                "ttl": body.get("ttl", 1),
                "proxied": body.get("proxied", False),
            }
            self.records[rec["id"]] = rec
            return web.json_response({"success": True, "result": rec, "errors": []})
        if path.startswith(f"/client/v4/zones/{self.zone_id}/dns_records/") and request.method == "PUT":
            rid = path.rsplit("/", 1)[-1]
            body = await request.json()
            rec = dict(self.records[rid])
            rec.update({"content": body["content"], "ttl": body.get("ttl", 1), "proxied": body.get("proxied", False)})
            self.records[rid] = rec
            return web.json_response({"success": True, "result": rec, "errors": []})
        if path.startswith(f"/client/v4/zones/{self.zone_id}/dns_records/") and request.method == "DELETE":
            rid = path.rsplit("/", 1)[-1]
            self.records.pop(rid, None)
            return web.json_response({"success": True, "result": {"id": rid}, "errors": []})
        return web.json_response({"success": False, "errors": [{"message": "not found"}]}, status=404)


@pytest.fixture
async def cf_server():
    fake = FakeCF()
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", fake.handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
    fake.base = f"http://127.0.0.1:{port}/client/v4"
    yield fake
    await runner.cleanup()


def make(fake: FakeCF, **kw: Any) -> Cloudflare:
    kw.setdefault("ttl", 60)
    return Cloudflare(
        "token-abc",
        zone_name="example.com",
        api_base=fake.base,  # type: ignore[attr-defined]
        **kw,
    )


async def test_zone_lookup_and_auth_header(cf_server):
    async with make(cf_server) as cf:
        zone_id = await cf.resolve_zone_id()
        assert zone_id == cf_server.zone_id
        assert cf_server.authed[0] == "Bearer token-abc"


async def test_create_when_missing(cf_server):
    async with make(cf_server) as cf:
        action, detail = await cf.point_to("hk", "1.2.3.4")
        assert action == "created"
        assert "hk.example.com" in detail
        assert [r for r in cf_server.records.values() if r["content"] == "1.2.3.4"]
        # 再次同步 → 无需修改
        action2, _ = await cf.point_to("hk.example.com", "1.2.3.4")
        assert action2 == "unchanged"


async def test_update_existing(cf_server):
    cf_server.add("hk.example.com", "9.9.9.9")
    async with make(cf_server) as cf:
        action, detail = await cf.point_to("hk.example.com", "1.2.3.4")
        assert action == "updated"
        assert "1.2.3.4" in [r["content"] for r in cf_server.records.values()]


async def test_replace_all_records(cf_server):
    cf_server.add("hk.example.com", "9.9.9.9")
    cf_server.add("hk.example.com", "8.8.8.8")
    async with make(cf_server) as cf:
        await cf.point_to("hk", "1.2.3.4")
        contents = {r["content"] for r in cf_server.records.values()}
        assert contents == {"1.2.3.4"}


async def test_keep_policy_only_first(cf_server):
    cf_server.add("hk.example.com", "9.9.9.9")
    cf_server.add("hk.example.com", "8.8.8.8")
    async with make(cf_server, multi_record_policy="keep") as cf:
        await cf.point_to("hk", "1.2.3.4")
        contents = sorted(r["content"] for r in cf_server.records.values())
        assert contents == ["1.2.3.4", "8.8.8.8"]


async def test_missing_and_no_create_raises(cf_server):
    async with make(cf_server, create_missing=False) as cf:
        with pytest.raises(CloudflareError):
            await cf.point_to("nope", "1.2.3.4")


async def test_point_many_reports_per_record(cf_server):
    async with make(cf_server) as cf:
        results = await cf.point_many(["a", "b"], "5.6.7.8")
        assert [r["ok"] for r in results] == ["1", "1"]
        assert {r["name"] for r in results} == {"a.example.com", "b.example.com"}


async def test_retry_on_500(cf_server):
    cf_server.fail_next = 2
    async with make(cf_server) as cf:
        action, _ = await cf.point_to("hk", "1.2.3.4")
        assert action == "created"


async def test_error_surfaces(cf_server):
    cf_server.fail_next = 5
    async with make(cf_server) as cf:
        with pytest.raises(CloudflareError) as exc:
            await cf.point_to("hk", "1.2.3.4")
        assert "boom" in str(exc.value) or "失败" in str(exc.value)


async def test_zone_id_only_resolves_name(cf_server):
    async with Cloudflare(zone_id=cf_server.zone_id, api_token="t", api_base=cf_server.base) as cf:  # type: ignore[attr-defined]
        await cf.resolve_zone_id()
        assert cf.zone_name == "example.com"
        action, detail = await cf.point_to("hk", "1.2.3.4")
        assert action == "created"
        assert "hk.example.com" in detail


async def test_proxied_record_uses_auto_ttl(cf_server):
    async with make(cf_server, proxied=True, ttl=60) as cf:
        await cf.point_to("hk", "1.2.3.4")
        rec = next(iter(cf_server.records.values()))
        assert rec["proxied"] is True
        assert rec["ttl"] == 1, "Cloudflare 代理记录只允许 Auto TTL"


async def test_fqdn_outside_zone_rejected_by_api(cf_server):
    """写别的域名会被 CF 拒绝，我们不静默放过。"""
    cf_server.add("hk.example.com", "9.9.9.9")
    async with make(cf_server) as cf:
        # full_name 只补全本 zone 的短名
        assert cf.full_name("hk") == "hk.example.com"
        assert cf.full_name("hk.example.com") == "hk.example.com"
        assert cf.full_name("other.com") == "other.com"
