from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from .cloud.aliyun import AliyunError, AliyunVpc, EipInfo
from .cloud.cloudflare import Cloudflare, CloudflareError
from .config import Config, Target

log = logging.getLogger(__name__)

Notifier = Callable[[dict[str, Any]], Awaitable[None]]


class Phase:
    """换 IP 的阶段标识，用于给用户推送进度。"""

    START = "switch_started"
    OLD_FOUND = "old_ip_found"
    ALLOCATED = "ip_allocated"
    OLD_RELEASED = "old_ip_released"
    BOUND = "ip_bound"
    DNS_DONE = "dns_updated"
    DONE = "switch_success"
    FAILED = "switch_failed"


@dataclass
class SwitchResult:
    ok: bool = False
    target: str = ""
    account: str = ""
    old_ip: str = ""
    new_ip: str = ""
    old_allocation_id: str = ""
    new_allocation_id: str = ""
    old_released: bool = False
    dns: list[dict[str, str]] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    error: str = ""
    elapsed: float = 0.0

    def step(self, text: str) -> None:
        self.steps.append(f"{time.strftime('%H:%M:%S')} {text}")
        log.info("[%s] %s", self.target, text)


class Engine:
    def __init__(
        self,
        cfg: Config,
        *,
        notifier: Notifier | None = None,
        aliyuns: dict[str, AliyunVpc] | None = None,
        cloudflare: Cloudflare | None = None,
    ) -> None:
        self.cfg = cfg
        self.notify = notifier
        self.aliyuns = aliyuns or {name: self.make_client(acc) for name, acc in cfg.accounts.items()}
        self.cloudflare = cloudflare or Cloudflare(
            cfg.cloudflare.api_token,
            zone_id=cfg.cloudflare.zone_id,
            zone_name=cfg.cloudflare.zone_name,
            ttl=cfg.cloudflare.ttl,
            proxied=cfg.cloudflare.proxied,
            create_missing=cfg.cloudflare.create_missing,
            multi_record_policy=cfg.cloudflare.multi_record_policy,
            api_base=cfg.cloudflare.api_base,
        )
        self._locks: dict[str, asyncio.Lock] = {}

    # ------------------------------------------------------------------ 基础
    def lock(self, name: str) -> asyncio.Lock:
        return self._locks.setdefault(name, asyncio.Lock())

    def make_client(self, account: Any) -> AliyunVpc:
        """构造账号客户端。集中在一处，方便替换（测试/未来换 SDK）。"""
        return AliyunVpc(
            account.access_key_id,
            account.access_key_secret,
            account.region,
            getattr(account, "endpoint", "vpc.aliyuncs.com"),
            getattr(account, "api_version", "2016-04-28"),
        )

    def client(self, target: Target) -> AliyunVpc:
        client = self.aliyuns.get(target.account)
        if client is None:
            raise AliyunError(
                "AliyunClient", "NoAccount", f"账号 {target.account} 没有可用客户端（检查 AK/SK）"
            )
        return client

    async def _emit(self, event: dict[str, Any]) -> None:
        if not self.notify:
            return
        try:
            await self.notify(event)
        except Exception:  # noqa: BLE001 - 通知失败不影响主流程
            log.exception("通知发送失败")

    # ------------------------------------------------------------------ 查询
    async def resolve_eip(self, target: Target) -> EipInfo | None:
        client = self.client(target)
        region = self.cfg.region_for(target)
        if target.eip_allocation_id:
            info = await client.get_eip(target.eip_allocation_id, region_id=region)
            if info:
                return info
        return await client.find_instance_eip(target.instance_id, region_id=region)

    async def describe(self, target: Target) -> dict[str, Any]:
        """查当前 EIP（不改动任何东西）。"""
        try:
            eip = await self.resolve_eip(target)
        except AliyunError as exc:
            return {"target": target, "eip": None, "error": str(exc)}
        if not eip:
            return {
                "target": target,
                "eip": None,
                "error": "找不到绑定中的 EIP（检查实例 ID / EIP ID / 地域）",
            }
        return {"target": target, "eip": eip, "error": ""}

    async def list_eips(self, account_name: str) -> list[EipInfo]:
        """列出账号下所有 EIP，方便未绑定实例时填写。"""
        client = self.aliyuns.get(account_name)
        if client is None:
            raise AliyunError("AliyunClient", "NoAccount", f"账号 {account_name} 不存在")
        return await client.describe_eips()

    # ------------------------------------------------------------------ 换 IP
    async def switch(self, name: str, *, reason: str = "手动触发") -> SwitchResult:
        """手动换 IP：释放旧 → 分配新 → 绑定 → 改 CF 解析。

        每一步都推送消息：释放成功、新 IP、解析成功、最终结果。
        """
        started = time.monotonic()
        target = self.cfg.target(name)
        result = SwitchResult(target=name, account=target.account)
        lock = self.lock(name)
        if lock.locked():
            result.error = "这个目标正在处理中，请稍后"
            await self._emit(
                {"type": Phase.FAILED, "target": name, "error": result.error, "steps": result.steps}
            )
            return result

        async with lock:
            try:
                await self._switch_locked(target, result, reason)
            except AliyunError as exc:
                result.error = str(exc)
                result.step(f"失败：{exc}")
            except CloudflareError as exc:
                result.error = str(exc)
                result.step(f"失败：{exc}")
            except Exception as exc:  # noqa: BLE001
                result.error = f"{type(exc).__name__}: {exc}"
                result.step(f"未预期异常：{result.error}")
                log.exception("%s 换 IP 异常", name)
            finally:
                result.elapsed = time.monotonic() - started
                if not result.ok and result.error:
                    await self._emit(
                        {
                            "type": Phase.FAILED,
                            "target": name,
                            "account": target.account,
                            "old_ip": result.old_ip,
                            "new_ip": result.new_ip,
                            "old_released": result.old_released,
                            "error": result.error,
                            "dns": result.dns,
                            "steps": result.steps,
                            "elapsed": result.elapsed,
                        }
                    )
        return result

    async def _switch_locked(self, target: Target, result: SwitchResult, reason: str) -> None:
        client = self.client(target)
        region = self.cfg.region_for(target)
        name = target.name

        # ---------- 1) 记录旧 IP ----------
        old = await self.resolve_eip(target)
        if not old:
            raise AliyunError(
                "DescribeEipAddresses",
                "NoEip",
                "该实例没有绑定 EIP，无法换 IP（先在阿里云控制台绑定一个）",
            )
        result.old_ip = old.ip
        result.old_allocation_id = old.allocation_id
        result.step(f"当前 IP {old.ip}，EIP {old.allocation_id}")

        # ---------- 域名从哪来：显式配置 > CF 里按旧 IP 自动发现 ----------
        cf_conf = self.cfg.cloudflare
        cf_ready = bool(cf_conf.api_token and (cf_conf.zone_name or cf_conf.zone_id))
        # 没配 CF 时即使写了域名也改不了，直接当作「无域名」，并明确告警
        dns_names = list(target.dns_records) if cf_ready else []
        discovered = False
        if not cf_ready and target.dns_records:
            result.step("⚠️ 配了域名但没有 Cloudflare 凭证，跳过解析")
        if not dns_names and old.ip and cf_ready:
            try:
                found = await self.cloudflare.find_records_by_ip(old.ip)
                dns_names = [r.name for r in found]
                discovered = bool(dns_names)
                if discovered:
                    result.step(f"自动发现 {len(dns_names)} 条解析指向旧 IP：{', '.join(dns_names)}")
            except CloudflareError as exc:
                result.step(f"⚠️ 自动发现域名失败：{exc}")

        if not dns_names:
            if not cf_ready:
                extra = (
                    f"（已配置的域名 {', '.join(target.dns_records)} 没能更新）"
                    if target.dns_records
                    else ""
                )
                result.warnings.append(
                    f"没有配置 Cloudflare（缺 API Token 或域名），这次只换 IP，域名不会更新{extra}。"
                    "发 /cf 设置后再 /dns 目标名 可以补上。"
                )
                result.step("⚠️ 未配置 Cloudflare，只换 IP")
            else:
                result.warnings.append(
                    f"这个 zone 下没有指向 {old.ip} 的 A 记录，这次只换 IP。"
                    "请发 /target dns 目标名 你的域名 指定要改哪条。"
                )
                result.step("⚠️ 未找到指向旧 IP 的域名，只换 IP")
        else:
            result.step(f"将更新域名：{', '.join(dns_names)}" + ("（自动发现）" if discovered else ""))

        await self._emit(
            {
                "type": Phase.START,
                "target": name,
                "account": target.account,
                "old_ip": old.ip,
                "allocation_id": old.allocation_id,
                "reason": reason,
                "dns": dns_names,
                "discovered": discovered,
                "warnings": result.warnings,
            }
        )

        # ---------- 2) 分配新 EIP ----------
        # 先分配再释放旧 IP，避免万一分配失败导致机器没 IP
        last_error = ""
        new: EipInfo | None = None
        for attempt in range(1, self.cfg.switch.max_attempts + 1):
            try:
                result.step(f"分配新 EIP（第 {attempt}/{self.cfg.switch.max_attempts} 次）")
                new = await client.allocate_eip(
                    internet_charge_type=self.cfg.switch.internet_charge_type,
                    bandwidth_mbps=self.cfg.switch.bandwidth_mbps,
                    isp=self.cfg.switch.isp,
                    region_id=region,
                )
                break
            except AliyunError as exc:
                last_error = str(exc)
                result.step(f"分配失败：{exc}")
                if attempt < self.cfg.switch.max_attempts:
                    await asyncio.sleep(min(10, 3 * attempt))
        if new is None:
            raise AliyunError("AllocateEipAddress", "AllocateFailed", f"分配新 EIP 失败：{last_error}")

        result.new_ip = new.ip
        result.new_allocation_id = new.allocation_id
        result.step(f"已分配新 IP {new.ip}（{new.allocation_id}）")
        await self._emit(
            {
                "type": Phase.ALLOCATED,
                "target": name,
                "account": target.account,
                "old_ip": old.ip,
                "new_ip": new.ip,
                "new_allocation_id": new.allocation_id,
            }
        )

        # ---------- 3) 解绑并释放旧 EIP（立刻停止计费）----------
        if self.cfg.switch.release_old:
            try:
                live_old = await client.get_eip(old.allocation_id, region_id=region)
                if live_old and live_old.bound:
                    result.step("解绑旧 EIP")
                    await client.unassociate(
                        old.allocation_id,
                        live_old.instance_id or old.instance_id or target.instance_id,
                        region_id=region,
                    )
                    await client.wait_status(old.allocation_id, {"Available"}, timeout=60, region_id=region)
                result.step("释放旧 EIP（停止计费）")
                await client.release(old.allocation_id, region_id=region)
                result.old_released = True
                result.step(f"旧 IP {old.ip} 已释放")
                await self._emit(
                    {
                        "type": Phase.OLD_RELEASED,
                        "target": name,
                        "account": target.account,
                        "old_ip": old.ip,
                        "allocation_id": old.allocation_id,
                    }
                )
            except AliyunError as exc:
                # 释放失败：新 IP 已经分配了，必须继续绑定，否则机器没网
                result.step(f"⚠️ 旧 EIP 释放失败（继续绑定新 IP）：{exc}")
        else:
            try:
                live_old = await client.get_eip(old.allocation_id, region_id=region)
                if live_old and live_old.bound:
                    result.step("解绑旧 EIP（保留不释放，会继续计费）")
                    await client.unassociate(
                        old.allocation_id,
                        live_old.instance_id or old.instance_id or target.instance_id,
                        region_id=region,
                    )
            except AliyunError as exc:
                result.step(f"⚠️ 旧 EIP 解绑失败：{exc}")

        # ---------- 4) 绑定新 EIP ----------
        result.step(f"绑定新 IP 到实例 {target.instance_id}")
        await client.associate(new.allocation_id, target.instance_id, region_id=region)
        await client.wait_status(new.allocation_id, {"InUse"}, timeout=90, region_id=region)
        result.step("绑定完成")
        await self._emit(
            {
                "type": Phase.BOUND,
                "target": name,
                "account": target.account,
                "new_ip": new.ip,
                "instance_id": target.instance_id,
            }
        )

        # ---------- 5) 改 Cloudflare 解析 ----------
        if dns_names:
            result.step(f"更新 Cloudflare 解析（{len(dns_names)} 条）")
            result.dns = await self.cloudflare.point_many(dns_names, new.ip)
            ok_count = sum(1 for d in result.dns if d["ok"] == "1")
            result.step(f"解析完成 {ok_count}/{len(result.dns)}")
            await self._emit(
                {
                    "type": Phase.DNS_DONE,
                    "target": name,
                    "account": target.account,
                    "new_ip": new.ip,
                    "dns": result.dns,
                }
            )
            if ok_count == 0:
                raise CloudflareError("point_many", "所有域名解析都更新失败")

        if discovered and dns_names and not target.dns_records:
            target.dns_records = list(dns_names)
            result.step("已把发现的域名记入配置")

        result.ok = True
        result.step("全部完成")
        await self._emit(
            {
                "type": Phase.DONE,
                "target": name,
                "account": target.account,
                "old_ip": old.ip,
                "new_ip": new.ip,
                "old_released": result.old_released,
                "new_allocation_id": new.allocation_id,
                "dns": result.dns,
                "reason": reason,
                "steps": result.steps,
                "warnings": result.warnings,
                "elapsed": result.elapsed,
            }
        )

    # ------------------------------------------------------------------ 解析
    async def manual_dns(self, name: str, ip: str = "") -> list[dict[str, str]]:
        target = self.cfg.target(name)
        if not target.dns_records:
            return [{"name": name, "action": "error", "detail": "该目标没有配置域名", "ok": "0"}]
        if not ip:
            eip = await self.resolve_eip(target)
            if not eip:
                return [{"name": name, "action": "error", "detail": "查不到当前 EIP", "ok": "0"}]
            ip = eip.ip
        results = await self.cloudflare.point_many(target.dns_records, ip)
        await self._emit(
            {"type": "dns_sync", "target": name, "ip": ip, "dns": results, "manual": True}
        )
        return results

    async def close(self) -> None:
        await self.cloudflare.close()
