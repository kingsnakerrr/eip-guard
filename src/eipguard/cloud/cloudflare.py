from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any

import aiohttp

log = logging.getLogger(__name__)

RECORD_TYPE = "A"


class CloudflareError(RuntimeError):
    def __init__(self, action: str, message: str, *, errors: list[Any] | None = None) -> None:
        self.action = action
        self.errors = errors or []
        detail = f"{action} 失败: {message}"
        if self.errors:
            detail += f" | {self.errors}"
        super().__init__(detail)


@dataclass
class DnsRecord:
    id: str
    name: str
    type: str
    content: str
    ttl: int = 1
    proxied: bool = False

    def describe(self) -> str:
        flag = " (代理)" if self.proxied else ""
        return f"{self.name} {self.type} → {self.content}{flag}"


class Cloudflare:
    def __init__(
        self,
        api_token: str,
        *,
        zone_id: str = "",
        zone_name: str = "",
        ttl: int = 60,
        proxied: bool = False,
        create_missing: bool = True,
        multi_record_policy: str = "replace",
        api_base: str = "https://api.cloudflare.com/client/v4",
        timeout: float = 20.0,
    ) -> None:
        self.api_token = api_token
        self.zone_id = zone_id.strip()
        self.zone_name = zone_name.strip().lower().rstrip(".")
        self.ttl = ttl or 1
        self.proxied = proxied
        self.create_missing = create_missing
        self.multi_record_policy = multi_record_policy
        self.api_base = api_base.rstrip("/")
        self.timeout = timeout
        self._session: aiohttp.ClientSession | None = None
        self._zone_lock = asyncio.Lock()

    async def __aenter__(self) -> "Cloudflare":
        await self.start()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def start(self) -> None:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers={
                    "Authorization": f"Bearer {self.api_token}",
                    "Content-Type": "application/json",
                },
            )

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
        self._session = None

    # ---------------- HTTP ----------------
    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        retries: int = 3,
    ) -> dict[str, Any]:
        await self.start()
        assert self._session is not None
        url = f"{self.api_base}{path}"
        last_err = ""
        for attempt in range(1, retries + 1):
            try:
                async with self._session.request(method, url, params=params, json=json) as resp:
                    text = await resp.text()
                    try:
                        data = await resp.json(content_type=None)
                    except Exception:
                        data = {}
                    if resp.status == 429 or resp.status >= 500:
                        last_err = f"HTTP {resp.status}: {text[:200]}"
                        if attempt < retries:
                            await asyncio.sleep(1.5 * attempt)
                            continue
                    if not isinstance(data, dict):
                        raise CloudflareError(path, f"HTTP {resp.status} 非 JSON 响应: {text[:200]}")
                    if not data.get("success", False):
                        errors = data.get("errors") or [{"message": text[:300] or f"HTTP {resp.status}"}]
                        raise CloudflareError(f"{method} {path}", "Cloudflare 返回失败", errors=errors)
                    return data
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                last_err = f"{type(exc).__name__}: {exc}"
                if attempt < retries:
                    await asyncio.sleep(1.5 * attempt)
                    continue
                raise CloudflareError(path, last_err) from exc
        raise CloudflareError(path, last_err)

    # ---------------- zone ----------------
    def _zone_ttl(self) -> int:
        # Cloudflare 对代理记录强制 Auto(1)，传 60 会报错
        return 1 if self.proxied else (self.ttl or 1)

    async def resolve_zone_id(self) -> str:
        if self.zone_id and self.zone_name:
            return self.zone_id
        if self.zone_id and not self.zone_name:
            # 只给了 zone_id 时补查域名，否则短名记录无法拼成完整域名
            async with self._zone_lock:
                if self.zone_id and self.zone_name:
                    return self.zone_id
                data = await self._request("GET", f"/zones/{self.zone_id}")
                result = data.get("result") or {}
                self.zone_name = str(result.get("name") or "").lower()
                if not self.zone_name:
                    raise CloudflareError("resolve_zone_id", f"无法从 zone_id {self.zone_id} 获取域名")
                return self.zone_id
        if not self.zone_name:
            raise CloudflareError("resolve_zone_id", "zone_id 与 zone_name 均为空")
        async with self._zone_lock:
            if self.zone_id:
                return self.zone_id
            data = await self._request("GET", "/zones", params={"name": self.zone_name, "per_page": 1})
            zones = data.get("result") or []
            if not zones:
                raise CloudflareError("resolve_zone_id", f"找不到 zone {self.zone_name}（检查 token 权限）")
            self.zone_id = str(zones[0]["id"])
            self.zone_name = str(zones[0].get("name") or self.zone_name)
            log.info("Cloudflare zone %s → %s", self.zone_name, self.zone_id)
            return self.zone_id

    def full_name(self, name: str) -> str:
        n = name.strip().lower().rstrip(".")
        if self.zone_name and (n == self.zone_name or n.endswith("." + self.zone_name)):
            return n
        if "." not in n:
            base = self.zone_name or self.zone_id
            return f"{n}.{base}" if base else n
        return n

    async def verify_token(self) -> dict[str, Any]:
        data = await self._request("GET", "/user/tokens/verify")
        return data.get("result") or {}

    # ---------------- records ----------------
    async def list_records(self, name: str, record_type: str = RECORD_TYPE) -> list[DnsRecord]:
        zone_id = await self.resolve_zone_id()
        fqdn = self.full_name(name)
        data = await self._request(
            "GET", f"/zones/{zone_id}/dns_records", params={"name": fqdn, "type": record_type, "per_page": 100}
        )
        out: list[DnsRecord] = []
        for item in data.get("result") or []:
            out.append(
                DnsRecord(
                    id=str(item.get("id")),
                    name=str(item.get("name")),
                    type=str(item.get("type")),
                    content=str(item.get("content")),
                    ttl=int(item.get("ttl") or 1),
                    proxied=bool(item.get("proxied")),
                )
            )
        return out

    async def update_record(self, record_id: str, name: str, content: str) -> DnsRecord:
        zone_id = await self.resolve_zone_id()
        body: dict[str, Any] = {"type": RECORD_TYPE, "name": self.full_name(name), "content": content}
        body["ttl"] = self._zone_ttl()
        body["proxied"] = self.proxied
        data = await self._request("PUT", f"/zones/{zone_id}/dns_records/{record_id}", json=body)
        item = data.get("result") or {}
        log.info("CF 更新 %s → %s", item.get("name"), content)
        return DnsRecord(
            id=str(item.get("id") or record_id),
            name=str(item.get("name") or self.full_name(name)),
            type=str(item.get("type") or RECORD_TYPE),
            content=str(item.get("content") or content),
            ttl=int(item.get("ttl") or self._zone_ttl()),
            proxied=bool(item.get("proxied", self.proxied)),
        )

    async def create_record(self, name: str, content: str) -> DnsRecord:
        zone_id = await self.resolve_zone_id()
        body: dict[str, Any] = {
            "type": RECORD_TYPE,
            "name": self.full_name(name),
            "content": content,
            "ttl": self._zone_ttl(),
            "proxied": self.proxied,
        }
        data = await self._request("POST", f"/zones/{zone_id}/dns_records", json=body)
        item = data.get("result") or {}
        log.info("CF 创建 %s → %s", item.get("name"), content)
        return DnsRecord(
            id=str(item.get("id")),
            name=str(item.get("name") or self.full_name(name)),
            type=str(item.get("type") or RECORD_TYPE),
            content=str(item.get("content") or content),
            ttl=int(item.get("ttl") or self._zone_ttl()),
            proxied=bool(item.get("proxied", self.proxied)),
        )

    async def delete_record(self, record_id: str) -> None:
        zone_id = await self.resolve_zone_id()
        await self._request("DELETE", f"/zones/{zone_id}/dns_records/{record_id}")

    async def point_to(self, name: str, ip: str) -> tuple[str, str]:
        """把 name 指向 ip。返回 (action, 详情)，action ∈ updated/created/unchanged/kept。

        replace 策略：所有 A 记录都改成新 IP（多 A 记录都指向同一台机器时保持一致）。
        keep 策略：只改第一条 A 记录，其余保留（用于多机负载的场景）。
        """
        records = await self.list_records(name)
        fqdn = self.full_name(name)
        if not records:
            if not self.create_missing:
                raise CloudflareError("point_to", f"{fqdn} 没有 A 记录，且 create_missing=false")
            rec = await self.create_record(name, ip)
            return "created", rec.describe()

        stale = [r for r in records if r.content != ip]
        if not stale:
            return "unchanged", f"{fqdn} 已是 {ip}"

        if self.multi_record_policy == "keep":
            target = records[0]
            if target.content == ip:
                return "unchanged", f"{fqdn} 首条记录已是 {ip}"
            rec = await self.update_record(target.id, target.name, ip)
            return "updated", rec.describe()

        changed: list[str] = []
        for rec in stale:
            updated = await self.update_record(rec.id, rec.name, ip)
            changed.append(updated.name)
        return "updated", f"{', '.join(changed)} → {ip}"

    async def point_many(self, names: list[str], ip: str) -> list[dict[str, str]]:
        results: list[dict[str, str]] = []
        for name in names:
            try:
                action, detail = await self.point_to(name, ip)
                results.append({"name": self.full_name(name), "action": action, "detail": detail, "ok": "1"})
            except CloudflareError as exc:
                log.error("CF 解析 %s 失败: %s", name, exc)
                results.append({"name": name, "action": "error", "detail": str(exc), "ok": "0"})
        return results
