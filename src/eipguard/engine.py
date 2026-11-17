from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from . import fmt
from .cloud.aliyun import AliyunError, AliyunVpc, EipInfo
from .cloud.cloudflare import Cloudflare, CloudflareError
from .config import Config, TargetConfig
from .detect.probe import Detector, ProbeOutcome, Verdict, build_detector
from .state import Settings, StateStore, TargetState

log = logging.getLogger(__name__)

Notifier = Callable[[dict[str, Any]], Awaitable[None]]


def pingpe_link(target: TargetConfig, ip: str, default_port: int = 443) -> str:
    """生成 ping.pe 自查链接（人工复核用）。

    ping.pe 的格式：https://ping.pe/1.2.3.4 或 https://ping.pe/1.2.3.4:443
    带上域名（target.dns_records[0]）时用 TCP 检测，能看到国内外逐项结果，
    正好和本项目自动判定的是同一套逻辑。
    """
    if not ip:
        return ""
    port = target.probe_port or default_port
    base = f"https://ping.pe/{ip}" if not port else f"https://ping.pe/{ip}:{port}"
    if target.dns_records:
        return f"{base}?host={target.dns_records[0]}"
    return base


@dataclass
class SwitchResult:
    ok: bool
    target: str
    old_ip: str = ""
    new_ip: str = ""
    old_allocation_id: str = ""
    new_allocation_id: str = ""
    steps: list[str] = field(default_factory=list)
    dns: list[dict[str, str]] = field(default_factory=list)
    verify: ProbeOutcome | None = None
    error: str = ""
    manual: bool = False
    dry_run: bool = False
    elapsed: float = 0.0
    warnings: list[str] = field(default_factory=list)

    def step(self, text: str) -> None:
        self.steps.append(f"{time.strftime('%H:%M:%S')} {text}")
        log.info("[%s] %s", self.target, text)


class Engine:
    def __init__(
        self,
        cfg: Config,
        store: StateStore,
        settings: Settings,
        *,
        notifier: Notifier | None = None,
        aliyun: AliyunVpc | None = None,
        aliyun_accounts: dict[str, AliyunVpc] | None = None,
        cloudflare: Cloudflare | None = None,
        detector: Detector | None = None,
    ) -> None:
        self.cfg = cfg
        self.store = store
        self.settings = settings
        self.notify = notifier
        # 多账号：每个阿里云账号一个客户端
        if aliyun_accounts:
            self.aliyuns = aliyun_accounts
        elif aliyun is not None:
            self.aliyuns = {name: aliyun for name in cfg.aliyun.accounts} or {"default": aliyun}
        else:
            self.aliyuns = {
                name: AliyunVpc(
                    account.access_key_id,
                    account.access_key_secret,
                    account.default_region,
                    account.endpoint,
                    account.api_version,
                )
                for name, account in cfg.aliyun.accounts.items()
            }
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
        self.detector = detector or build_detector(cfg.detect)
        self._locks: dict[str, asyncio.Lock] = {}
        self._running = True

    # ------------------------------------------------------------------ utils
    def lock(self, name: str) -> asyncio.Lock:
        return self._locks.setdefault(name, asyncio.Lock())

    def aliyun_for(self, target: TargetConfig) -> AliyunVpc:
        client = self.aliyuns.get(target.account) or self.aliyuns.get("default")
        if client is None:
            raise AliyunError("AliyunClient", "NoAccount", f"没有可用于账号 {target.account} 的客户端")
        return client

    def region_for(self, target: TargetConfig) -> str:
        if target.region_id:
            return target.region_id
        account = self.cfg.aliyun.accounts.get(target.account)
        return account.default_region if account else self.cfg.aliyun.region_id

    def target_state(self, name: str) -> TargetState:
        return self.store.get(name)

    def switchable_verdicts(self) -> set[Verdict]:
        """哪些结论允许自动换 IP。可在配置里扩展（例如你确认端口封锁也换）。"""
        base = {Verdict.IP_BLOCKED}
        for item in self.cfg.switch.auto_switch_on:
            try:
                base.add(Verdict(item))
            except ValueError:
                log.warning("switch.auto_switch_on 里有未知结论：%s", item)
        return base

    def auto_enabled(self, name: str) -> bool:
        """全局开关与单目标开关都要开，才不会自动换。"""
        return bool(self.settings.auto and self.store.get(name).auto)

    async def _emit(self, event: dict[str, Any]) -> None:
        self.store.add_history(event)
        self.store.save()
        if self.notify:
            try:
                await self.notify(event)
            except Exception:  # noqa: BLE001 - 通知失败不能影响主流程
                log.exception("通知发送失败")

    async def resolve_eip(self, target: TargetConfig) -> EipInfo | None:
        client = self.aliyun_for(target)
        region = self.region_for(target)
        if target.eip_allocation_id:
            info = await client.get_eip(target.eip_allocation_id, region_id=region)
            if info:
                return info
        return await client.find_instance_eip(target.instance_id, region_id=region)

    async def _probe(self, target: TargetConfig, ip: str) -> ProbeOutcome:
        sni = target.dns_records[0] if target.dns_records else ""
        ports = target.all_ports(self.cfg.detect.port)
        return await self.detector.check(ip, ports, sni=sni)

    async def probe_once(self, ip: str, ports: list[int], sni: str = "") -> ProbeOutcome:
        """对外暴露的一次探测（机器人 /health 使用）。"""
        return await self.detector.check(ip, ports, sni=sni)

    # ------------------------------------------------------------------ status
    async def inspect(self, name: str) -> dict[str, Any]:
        """刷新一个目标的实时状态（EIP + 探测）。"""
        target = self.cfg.target(name)
        state = self.target_state(name)
        try:
            eip = await self.resolve_eip(target)
        except AliyunError as exc:
            return {"target": target, "state": state, "error": str(exc), "eip": None, "probe": None}
        if not eip:
            return {
                "target": target,
                "state": state,
                "error": "找不到绑定中的 EIP（检查 instance_id / eip_allocation_id 与地域）",
                "eip": None,
                "probe": None,
            }
        state.current_ip = eip.ip
        state.allocation_id = eip.allocation_id
        try:
            probe = await self._probe(target, eip.ip)
        except Exception as exc:  # noqa: BLE001 - 探测服务异常不能当作被墙
            log.warning("%s 探测异常：%s", name, exc)
            return {"target": target, "state": state, "eip": eip, "probe": None, "error": f"探测异常：{exc}"}
        state.last_check = time.time()
        state.last_reason = probe.reason
        state.last_verdict = probe.verdict.value
        state.last_advice = probe.advice
        if probe.ok:
            state.failures = 0
            state.notified_stage = 0
            state.last_ok = time.time()
        return {"target": target, "state": state, "eip": eip, "probe": probe, "error": ""}

    # ------------------------------------------------------------------ 自动轮询
    async def monitor_loop(self) -> None:
        log.info("开始监控 %d 个目标，间隔 %ss", len(self.cfg.targets), self.settings.interval)
        while self._running:
            started = time.monotonic()
            try:
                await asyncio.gather(*(self._check_one(t.name) for t in self.cfg.targets))
            except Exception:  # noqa: BLE001
                log.exception("监控轮次异常")
            elapsed = time.monotonic() - started
            await asyncio.sleep(max(5.0, self.settings.interval - elapsed))

    async def _check_one(self, name: str) -> None:
        try:
            await self._check_one_inner(name)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - 单个目标异常不能影响其它目标
            log.exception("%s 检查异常", name)

    async def _check_one_inner(self, name: str) -> None:
        target = self.cfg.target(name)
        state = self.target_state(name)
        if not target.instance_id:
            return
        info = await self.inspect(name)
        probe: ProbeOutcome | None = info.get("probe")
        if info.get("error") and not probe:
            log.warning("%s 状态检查失败：%s", name, info["error"])
            return

        assert probe is not None
        state.last_verdict = probe.verdict.value
        state.last_reason = probe.reason
        state.last_advice = probe.advice
        if probe.ok:
            if state.failures or state.notified_stage:
                log.info("%s 恢复正常", name)
                was_failing = state.failures > 0
                state.failures = 0
                state.notified_stage = 0
                self.store.save()
                if was_failing:
                    await self._emit(
                        {
                            "type": "recovered",
                            "target": name,
                            "ip": state.current_ip,
                            "detail": probe.reason,
                        }
                    )
            return

        state.failures += 1
        self.store.save()
        log.warning(
            "%s 探测异常 %d/%d [%s]：%s",
            name,
            state.failures,
            self.settings.failure_threshold,
            probe.verdict.value,
            probe.reason,
        )

        # 只有"换 IP 真能解决问题"的结论才继续往下走。
        # 端口/TLS/数据面被阻断换 IP 无效，只告警，避免白花钱。
        switchable = probe.verdict in self.switchable_verdicts()
        confirmed = state.failures >= self.settings.failure_threshold
        if state.notified_stage < (2 if confirmed else 1):
            state.notified_stage = 2 if confirmed else 1
            self.store.save()
            auto_on = self.auto_enabled(name)
            if not switchable:
                kind = "service_down" if probe.verdict is Verdict.SERVICE_DOWN else "block_other"
            elif confirmed and not auto_on:
                kind = "auto_disabled"
            else:
                kind = "blocked_confirmed" if confirmed else "blocked_suspect"
            await self._emit(
                {
                    "type": kind,
                    "target": name,
                    "ip": state.current_ip,
                    "account": target.account,
                    "verdict": probe.verdict.value,
                    "label": probe.label,
                    "advice": probe.advice,
                    "matrix": fmt.matrix_text(probe),
                    "pingpe": pingpe_link(target, state.current_ip),
                    "count": state.failures,
                    "threshold": self.settings.failure_threshold,
                    "detail": probe.reason,
                    "will_switch": confirmed and switchable and auto_on,
                    "auto_off": not auto_on,
                    "switchable": switchable,
                }
            )

        if not switchable:
            return
        if not confirmed:
            return
        if not self.auto_enabled(name):
            return
        remaining = state.paused_until - time.time()
        if remaining > 0:
            log.info("%s 冷却中，还剩 %.0fs", name, remaining)
            return
        if time.time() - state.last_switch < self.settings.cooldown:
            return

        result = await self.switch(name, reason="自动：连续探测判定被墙", probe=probe)
        if not result.ok:
            # 失败后允许冷却结束再次告警，避免静默失败
            state.notified_stage = 1
            self.store.save()

    # ------------------------------------------------------------------ 换 IP
    async def switch(
        self,
        name: str,
        *,
        reason: str = "手动触发",
        probe: ProbeOutcome | None = None,
        dry_run: bool = False,
        manual: bool = True,
        force: bool = False,
    ) -> SwitchResult:
        started = time.monotonic()
        result = SwitchResult(ok=False, target=name, manual=manual, dry_run=dry_run)
        target = self.cfg.target(name)
        state = self.target_state(name)
        region = self.region_for(target)
        lock = self.lock(name)
        if lock.locked() and not force:
            result.error = "该目标正在处理中，请稍后再试"
            return result

        async with lock:
            try:
                return await self._switch_locked(target, state, region, result, probe, dry_run, reason)
            finally:
                result.elapsed = time.monotonic() - started
                if result.steps and not result.dry_run:  # 真正发起过操作才计入统计
                    state.last_switch = time.time()
                    state.switches += 1
                    state.last_switch_ok = result.ok
                self.store.save()

    async def _switch_locked(
        self,
        target: TargetConfig,
        state: TargetState,
        region: str,
        result: SwitchResult,
        probe: ProbeOutcome | None,
        dry_run: bool,
        reason: str,
    ) -> SwitchResult:
        name = target.name
        client = self.aliyun_for(target)
        old: EipInfo | None = None
        try:
            old = await self.resolve_eip(target)
        except AliyunError as exc:
            result.error = f"查询当前 EIP 失败：{exc}"
            await self._emit({"type": "switch_failed", "target": name, "error": result.error, "manual": result.manual})
            return result

        if not old:
            result.error = "该实例没有绑定 EIP，无法更换"
            await self._emit({"type": "switch_failed", "target": name, "error": result.error, "manual": result.manual})
            return result

        result.old_ip = old.ip
        result.old_allocation_id = old.allocation_id
        state.current_ip = old.ip
        state.allocation_id = old.allocation_id
        result.step(f"当前 EIP {old.ip} ({old.allocation_id}) 状态 {old.status}")

        if dry_run:
            result.ok = True
            result.new_ip = "(演练，未改动)"
            result.step("演练模式：跳过分配与解析")
            return result

        probe = probe or await self._probe(target, old.ip)
        result.verify = probe
        result.step(f"探测结论：{probe.reason}")

        await self._emit(
            {
                "type": "switch_started",
                "target": name,
                "old_ip": old.ip,
                "reason": reason,
                "detail": probe.reason,
                "manual": result.manual,
            }
        )

        allocate_kwargs: dict[str, Any] = {
            "internet_charge_type": self.cfg.switch.internet_charge_type or old.charge_type,
            "bandwidth_mbps": self.cfg.switch.bandwidth_mbps
            or (int(old.bandwidth) if old.bandwidth.isdigit() else None),
            # 线路只在显式配置时传，避免小地域不支持指定 ISP
            "isp": self.cfg.switch.isp,
            "region_id": region,
        }

        last_error = ""
        for attempt in range(1, self.cfg.switch.max_attempts + 1):
            new: EipInfo | None = None
            try:
                result.step(f"第 {attempt}/{self.cfg.switch.max_attempts} 次尝试：分配新 EIP")
                new = await client.allocate_eip(**allocate_kwargs)
                result.new_ip = new.ip
                result.new_allocation_id = new.allocation_id
                result.step(f"新 EIP {new.ip} ({new.allocation_id})")

                await self._wait_available(client, new.allocation_id, region)

                live_old = await client.get_eip(old.allocation_id, region_id=region)
                if live_old and live_old.bound:
                    result.step("解绑旧 EIP")
                    await client.unassociate(
                        old.allocation_id,
                        live_old.instance_id or old.instance_id or target.instance_id,
                        region_id=region,
                    )
                    await client.wait_status(old.allocation_id, {"Available"}, timeout=60, region_id=region)

                result.step(f"绑定新 EIP 到 {target.instance_id}")
                await client.associate(new.allocation_id, target.instance_id, region_id=region)
                await client.wait_status(new.allocation_id, {"InUse"}, timeout=90, region_id=region)
                result.step("绑定完成")

                # 先验证再改 DNS：新 IP 万一也被墙，解析不会被带到废 IP 上
                verified = await self._verify(target, new.ip)
                result.verify = verified
                if not verified.ok:
                    result.step(f"新 IP 验证未通过：{verified.reason}")
                    last_error = f"新 IP {new.ip} 验证未通过（可能同样被墙）：{verified.reason}"
                    # 新 IP 也不行：解绑并释放，继续尝试下一个
                    await self._cleanup_failed(
                        client, new, old, target, region, result, keep_old_bound=True
                    )
                    result.new_ip = result.new_allocation_id = ""
                    result.dns = []
                    continue
                result.step(f"新 IP 验证通过：{verified.reason}")

                if target.dns_records:
                    result.step(f"更新 Cloudflare 解析 {len(target.dns_records)} 条")
                    result.dns = await self.cloudflare.point_many(target.dns_records, new.ip)
                    failed = [d["name"] for d in result.dns if d["ok"] != "1"]
                    ok_count = len(result.dns) - len(failed)
                    result.step(f"DNS 完成 {ok_count}/{len(result.dns)}")
                    if ok_count == 0:
                        raise CloudflareError("point_many", "全部域名解析更新失败")
                    if failed:
                        # 只失败一部分时 IP 已经换成功，不该回滚到被墙的 IP；
                        # 但必须显式告警，否则会以为域名都跟上了
                        warning = f"部分解析未更新：{', '.join(failed)}"
                        result.warnings.append(warning)
                        result.step(f"⚠️ {warning}（请检查记录名或 CF 权限）")
                state.current_ip = new.ip
                state.allocation_id = new.allocation_id
                state.failures = 0
                state.last_ok = time.time()
                state.last_reason = verified.reason
                state.paused_until = 0
                state.notified_stage = 0

                if self.settings.release_old and self.cfg.switch.release_old:
                    try:
                        result.step("释放旧 EIP")
                        await client.release(old.allocation_id, region_id=region)
                    except AliyunError as exc:
                        result.step(f"旧 EIP 释放失败（不影响换 IP）：{exc}")
                else:
                    result.step("保留旧 EIP（未释放，会继续计费）")

                result.ok = True
                result.step("全部完成")
                await self._emit(
                    {
                        "type": "switch_success",
                        "target": name,
                        "old_ip": old.ip,
                        "new_ip": new.ip,
                        "dns": result.dns,
                        "detail": verified.reason,
                        "reason": reason,
                        "manual": result.manual,
                        "elapsed": result.elapsed,
                        "warnings": result.warnings,
                    }
                )
                return result

            except (AliyunError, CloudflareError) as exc:
                last_error = str(exc)
                result.step(f"失败：{exc}")
                log.error("%s 换 IP 第 %d 次失败：%s", name, attempt, exc)
                if new:
                    await self._rollback(client, new, old, target, region, result)
                if attempt < self.cfg.switch.max_attempts:
                    backoff = min(15, 3 * attempt)
                    result.step(f"{backoff}s 后重试")
                    await asyncio.sleep(backoff)
            except Exception as exc:  # noqa: BLE001
                last_error = f"{type(exc).__name__}: {exc}"
                log.exception("%s 换 IP 未预期异常", name)
                result.step(f"未预期异常：{last_error}")
                if new:
                    await self._rollback(client, new, old, target, region, result)
                break

        # 全部失败
        state.paused_until = time.time() + max(60, self.cfg.switch.cooldown)
        result.error = last_error or "未知错误"
        if self.cfg.switch.restore_old_on_failure and old and not old.bound:
            try:
                result.step("尝试把旧 EIP 绑回实例")
                await client.associate(old.allocation_id, target.instance_id, region_id=region)
                result.step("旧 EIP 已绑回（旧 IP 仍可能被墙）")
            except AliyunError as exc:
                result.step(f"旧 EIP 绑回失败：{exc}")
        result.step("换 IP 失败，进入冷却")
        await self._emit(
            {
                "type": "switch_failed",
                "target": name,
                "old_ip": old.ip if old else "",
                "error": result.error,
                "dns": result.dns,
                "manual": result.manual,
                "elapsed": result.elapsed,
            }
        )
        return result

    async def _wait_available(self, client: AliyunVpc, allocation_id: str, region: str) -> None:
        try:
            await client.wait_status(allocation_id, {"Available"}, timeout=60, region_id=region)
        except AliyunError as exc:
            # 部分地域分配后直接就是 InUse/状态字段缺失，不阻塞
            log.debug("等待 Available 超时（继续）：%s", exc)

    async def _cleanup_failed(
        self,
        client: AliyunVpc,
        new: EipInfo,
        old: EipInfo,
        target: TargetConfig,
        region: str,
        result: SwitchResult,
        *,
        keep_old_bound: bool,
    ) -> None:
        try:
            result.step("新 IP 不可用，解绑并释放新 EIP")
            await client.unassociate(new.allocation_id, target.instance_id, region_id=region)
            await client.release(new.allocation_id, region_id=region)
        except AliyunError as exc:
            log.warning("清理新 EIP 失败：%s", exc)
            result.step(f"清理新 EIP 失败：{exc}")
        if keep_old_bound:
            try:
                result.step("把旧 EIP 重新绑回，等待下一次尝试")
                await client.associate(old.allocation_id, target.instance_id, region_id=region)
            except AliyunError as exc:
                log.warning("旧 EIP 回绑失败：%s", exc)

    async def _rollback(
        self,
        client: AliyunVpc,
        new: EipInfo,
        old: EipInfo,
        target: TargetConfig,
        region: str,
        result: SwitchResult,
    ) -> None:
        """分配/绑定/解析任一步失败时的回滚：解绑并释放新 EIP，尽量恢复旧 EIP。"""
        # 解析可能已经部分改到新 IP 上，先改回旧 IP，避免解析指向即将释放的地址
        updated = [d for d in result.dns if d.get("ok") == "1"]
        if updated and old.ip:
            try:
                result.step(f"回滚：把 {len(updated)} 条解析改回旧 IP {old.ip}")
                await self.cloudflare.point_many(target.dns_records, old.ip)
            except CloudflareError as exc:
                log.warning("回滚解析失败：%s", exc)
                result.step(f"回滚解析失败，请手动处理：{exc}")
        try:
            info = await client.get_eip(new.allocation_id, region_id=region)
            if info and info.instance_id:
                result.step("回滚：解绑新 EIP")
                await client.unassociate(new.allocation_id, info.instance_id, region_id=region)
        except AliyunError as exc:
            log.warning("回滚解绑失败：%s", exc)
        try:
            await client.release(new.allocation_id, region_id=region)
            result.step("回滚：已释放新 EIP")
        except AliyunError as exc:
            log.warning("回滚释放失败（可能仍在计费）：%s", exc)
            result.step(f"回滚：新 EIP 释放失败，请手动处理 {new.allocation_id}")
        # 旧 EIP 如果没有绑定回去就绑回，保证业务至少还能操作
        try:
            info = await client.get_eip(old.allocation_id, region_id=region)
            if info and not info.bound:
                result.step("回滚：把旧 EIP 绑回实例")
                await client.associate(old.allocation_id, target.instance_id, region_id=region)
        except AliyunError as exc:
            log.warning("回滚旧 EIP 失败：%s", exc)

    async def _verify(self, target: TargetConfig, ip: str) -> ProbeOutcome:
        delay = self.cfg.detect.verify_delay
        if delay:
            await asyncio.sleep(delay)
        best: ProbeOutcome | None = None
        for i in range(1, self.cfg.detect.verify_attempts + 1):
            outcome = await self._probe(target, ip)
            best = outcome
            log.info("%s 验证第 %d 次：%s", target.name, i, outcome.reason)
            if outcome.ok:
                return outcome
            if i < self.cfg.detect.verify_attempts:
                await asyncio.sleep(min(30, 8 * i))
        assert best is not None
        return best

    # ------------------------------------------------------------------ 命令辅助
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
            {
                "type": "dns_sync",
                "target": name,
                "ip": ip,
                "dns": results,
                "manual": True,
            }
        )
        return results

    async def bind_dns_ip(self, record: str, ip: str) -> tuple[str, str]:
        action, detail = await self.cloudflare.point_to(record, ip)
        await self._emit({"type": "dns_sync", "target": record, "ip": ip, "manual": True, "dns": [{"name": record, "action": action, "detail": detail, "ok": "1"}]})
        return action, detail

    async def close(self) -> None:
        self._running = False
        await self.detector.close()
        await self.cloudflare.close()
