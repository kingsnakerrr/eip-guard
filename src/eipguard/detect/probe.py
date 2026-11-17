from __future__ import annotations

import asyncio
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any

import aiohttp

from ..config import DetectConfig


@dataclass
class Attempt:
    ok: bool
    connect_ms: float | None = None
    tls_ok: bool | None = None
    error: str = ""
    kind: str = ""  # timeout / reset / refused / dns / tls / other

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "connect_ms": self.connect_ms,
            "tls_ok": self.tls_ok,
            "error": self.error,
            "kind": self.kind,
        }


@dataclass
class NodeResult:
    """一个探针节点的探测结果。zone: cn=墙内, overseas=墙外。"""

    node: str
    zone: str
    attempts: list[Attempt] = field(default_factory=list)
    error: str = ""

    @property
    def ok(self) -> bool:
        return any(a.ok for a in self.attempts)

    @property
    def ok_ratio(self) -> float:
        if not self.attempts:
            return 0.0
        return sum(1 for a in self.attempts if a.ok) / len(self.attempts)

    def brief(self) -> str:
        if self.error and not self.attempts:
            return f"{self.node}({self.zone}) 探测失败: {self.error}"
        if self.ok:
            best = min((a.connect_ms or 0) for a in self.attempts if a.ok)
            return f"{self.node}({self.zone}) 通 {best:.0f}ms"
        kinds = sorted({a.kind or "fail" for a in self.attempts})
        return f"{self.node}({self.zone}) 不通({','.join(kinds)})"


def classify_exception(exc: BaseException) -> str:
    if isinstance(exc, asyncio.TimeoutError):
        return "timeout"
    if isinstance(exc, ConnectionResetError):
        return "reset"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if isinstance(exc, socket.gaierror):
        return "dns"
    if isinstance(exc, ssl.SSLError):
        return "tls"
    if isinstance(exc, OSError):
        return "reset" if exc.errno in (104, 54) else "other"
    return "other"


async def tcp_probe(ip: str, port: int, timeout: float, sni: str = "", tls: bool = False) -> Attempt:
    started = time.monotonic()
    writer: asyncio.StreamWriter | None = None
    try:
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx, server_hostname=sni or None), timeout
            )
            elapsed = (time.monotonic() - started) * 1000
            del reader
            return Attempt(True, round(elapsed, 1), True)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        elapsed = (time.monotonic() - started) * 1000
        del reader
        return Attempt(True, round(elapsed, 1), None)
    except BaseException as exc:  # noqa: BLE001 - 需要分类所有网络异常
        return Attempt(False, None, False, f"{type(exc).__name__}: {exc}", classify_exception(exc))
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ---------------------------------------------------------------- 探针客户端
class ProbeAgentClient:
    """调用自建探针（probe_agent/server.py）。"""

    def __init__(self, agents: list[dict[str, Any]], timeout: float = 8.0) -> None:
        self.agents = agents
        self.timeout = timeout

    async def check(self, ip: str, port: int, *, sni: str = "", tls: bool = False, attempts: int = 3) -> list[NodeResult]:
        if not self.agents:
            return []
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout + attempts * 3)) as session:
            tasks = [self._one(session, a, ip, port, sni, tls, attempts) for a in self.agents]
            return list(await asyncio.gather(*tasks))

    async def _one(
        self,
        session: aiohttp.ClientSession,
        agent: dict[str, Any],
        ip: str,
        port: int,
        sni: str,
        tls: bool,
        attempts: int,
    ) -> NodeResult:
        url = str(agent["url"]).rstrip("/") + "/probe"
        name = str(agent.get("name") or url.split("//")[-1].split("/")[0])
        zone = str(agent.get("zone") or "cn").lower()
        payload = {"ip": ip, "port": port, "attempts": attempts, "sni": sni, "tls": tls}
        headers = {}
        if agent.get("token"):
            headers["X-Probe-Token"] = str(agent["token"])
        try:
            async with session.post(url, json=payload, headers=headers) as resp:
                data = await resp.json(content_type=None)
                if resp.status != 200:
                    msg = ""
                    if isinstance(data, dict):
                        msg = str(data.get("error") or data.get("detail") or "")
                    return NodeResult(name, zone, error=f"HTTP {resp.status} {msg}".strip())
        except Exception as exc:  # noqa: BLE001
            log_msg = f"{type(exc).__name__}: {exc}"
            return NodeResult(name, zone, error=log_msg)

        items = data.get("attempts") if isinstance(data, dict) else None
        results: list[Attempt] = []
        for item in items or []:
            if not isinstance(item, dict):
                continue
            results.append(
                Attempt(
                    ok=bool(item.get("ok")),
                    connect_ms=item.get("connect_ms"),
                    tls_ok=item.get("tls_ok"),
                    error=str(item.get("error") or ""),
                    kind=str(item.get("kind") or ""),
                )
            )
        if not results:
            return NodeResult(name, zone, error="探针没有返回结果")
        return NodeResult(name, zone, results)


# ---------------------------------------------------------------- check-host.net
CHECKHOST_API = "https://check-host.net"


class CheckHostClient:
    """免费公共探测网络（会带上节点国家）。无需账号，偶发限流。"""

    def __init__(self, port: int = 443, nodes: int = 6, timeout: int = 20) -> None:
        self.port = port
        self.nodes = nodes
        self.timeout = timeout

    async def check(self, ip: str, port: int, *, sni: str = "") -> list[NodeResult]:
        headers = {"Accept": "application/json", "User-Agent": "eipguard/1.0"}
        request_id = ""
        nodes_meta: dict[str, str] = {}
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout + 20),
            headers=headers,
        ) as session:
            # 1) 发起检查
            try:
                async with session.get(
                    f"{CHECKHOST_API}/check-tcp",
                    params={"host": f"{ip}:{port or self.port}", "max_nodes": self.nodes},
                ) as resp:
                    data = await resp.json(content_type=None)
            except Exception as exc:  # noqa: BLE001
                return [NodeResult("check-host", "unknown", error=f"{type(exc).__name__}: {exc}")]
            if not isinstance(data, dict) or not data.get("ok"):
                return [NodeResult("check-host", "unknown", error=f"发起检查失败: {data}")]
            request_id = str(data.get("request_id") or "")
            for name, meta in (data.get("nodes") or {}).items():
                country = ""
                if isinstance(meta, list) and meta:
                    country = str(meta[0] or "").lower()
                nodes_meta[str(name)] = country
            if not request_id:
                return [NodeResult("check-host", "unknown", error="没有 request_id")]

            # 2) 轮询结果
            result: dict[str, Any] = {}
            for _ in range(self.timeout):
                await asyncio.sleep(1.0)
                try:
                    async with session.get(f"{CHECKHOST_API}/check-result/{request_id}") as resp:
                        result = await resp.json(content_type=None) or {}
                except Exception:
                    continue
                if result and all(v is not None for v in result.values()):
                    break

        out: list[NodeResult] = []
        for name, value in result.items():
            country = nodes_meta.get(name, "")
            zone = "cn" if country in {"cn"} else "overseas" if country else "unknown"
            if value is None:
                out.append(NodeResult(name, zone, error="结果超时"))
                continue
            if isinstance(value, dict) and value.get("error"):
                out.append(NodeResult(name, zone, [Attempt(False, error=str(value["error"]), kind="other")]))
                continue
            attempts: list[Attempt] = []
            for entry in value if isinstance(value, list) else [value]:
                if isinstance(entry, dict):
                    attempts.append(Attempt(True, round(float(entry.get("time") or 0) * 1000, 1)))
                elif isinstance(entry, list) and entry:
                    attempts.append(Attempt(True, round(float(entry[0] or 0) * 1000, 1)))
            out.append(NodeResult(name, zone, attempts or [Attempt(False, error="无数据", kind="other")]))
        return out


# ---------------------------------------------------------------- 结论合成
@dataclass
class ProbeOutcome:
    ok: bool
    blocked: bool
    reason: str
    nodes: list[NodeResult] = field(default_factory=list)

    @property
    def summary(self) -> str:
        return " | ".join(n.brief() for n in self.nodes) or "无探测数据"


def judge(
    nodes: list[NodeResult],
    *,
    fail_ratio: float = 0.6,
    min_samples: int = 2,
    require_overseas_confirm: bool = True,
) -> ProbeOutcome:
    """判断“被墙”。

    被墙的典型特征：墙内节点连不上，墙外节点正常。
      - 墙内失败 + 墙外成功 → BLOCKED
      - 墙内失败 + 墙外也失败 → 机器/服务故障，不算墙
      - 墙内成功 → 正常
    没有墙内节点时无法区分“被墙”和“宕机”，只报 DOWN，避免乱换 IP。
    """
    cn = [n for n in nodes if n.zone == "cn"]
    os_ = [n for n in nodes if n.zone in {"overseas", "unknown"}]
    cn_total = sum(len(n.attempts) for n in cn)
    cn_ok = sum(1 for n in cn for a in n.attempts if a.ok)
    os_total = sum(len(n.attempts) for n in os_)
    os_ok = sum(1 for n in os_ for a in n.attempts if a.ok)
    summary = " | ".join(n.brief() for n in nodes) if nodes else "无探测数据"

    if not nodes:
        return ProbeOutcome(True, False, "没有可用的探测节点，跳过", nodes)

    if cn_total == 0:
        if os_total and os_ok / os_total < fail_ratio:
            return ProbeOutcome(False, False, f"境外节点也不通，疑似实例/服务故障而非被墙：{summary}", nodes)
        return ProbeOutcome(True, False, f"仅境外探测正常（缺少墙内节点，无法判定被墙）：{summary}", nodes)

    cn_fail_ratio = 1 - cn_ok / cn_total
    if cn_total < min_samples:
        # 样本太少，只在完全不通时才提示
        if cn_ok == 0:
            return ProbeOutcome(False, False, f"墙内节点样本不足且不通，继续观察：{summary}", nodes)
        return ProbeOutcome(True, False, f"正常（样本少）：{summary}", nodes)

    if cn_fail_ratio < fail_ratio:
        return ProbeOutcome(True, False, f"正常：{summary}", nodes)

    # 墙内大面积不通
    if require_overseas_confirm and os_total:
        if os_ok / os_total >= 0.5:
            return ProbeOutcome(False, True, f"墙内不通、墙外正常 → 判定被墙：{summary}", nodes)
        return ProbeOutcome(False, False, f"墙内外都不通，按故障处理：{summary}", nodes)
    if require_overseas_confirm and os_total == 0:
        return ProbeOutcome(False, False, f"墙内不通但缺少墙外节点确认：{summary}", nodes)
    return ProbeOutcome(False, True, f"墙内不通 → 判定被墙：{summary}", nodes)


def build_detector(cfg: DetectConfig) -> "Detector":
    if cfg.provider == "checkhost":
        return CheckHostDetector(cfg)
    if cfg.provider == "tcp_self":
        return SelfDetector(cfg)
    if cfg.provider == "hybrid":
        return HybridDetector(cfg)
    return ProbeAgentDetector(cfg)


class Detector:
    name = "base"

    def __init__(self, cfg: DetectConfig) -> None:
        self.cfg = cfg

    async def check(self, ip: str, port: int, *, sni: str = "") -> ProbeOutcome:
        raise NotImplementedError

    async def close(self) -> None:
        return None


class ProbeAgentDetector(Detector):
    name = "probe_agent"

    def __init__(self, cfg: DetectConfig) -> None:
        super().__init__(cfg)
        self.client = ProbeAgentClient(cfg.probe_agents, timeout=cfg.timeout)

    async def check(self, ip: str, port: int, *, sni: str = "") -> ProbeOutcome:
        nodes = await self.client.check(ip, port, sni=sni, tls=self.cfg.tls_check and bool(sni), attempts=3)
        return judge(nodes, fail_ratio=self.cfg.fail_ratio, min_samples=self.cfg.min_samples)


class CheckHostDetector(Detector):
    name = "checkhost"

    def __init__(self, cfg: DetectConfig) -> None:
        super().__init__(cfg)
        self.client = CheckHostClient(nodes=cfg.checkhost_max_nodes, timeout=cfg.checkhost_timeout)

    async def check(self, ip: str, port: int, *, sni: str = "") -> ProbeOutcome:
        nodes = await self.client.check(ip, port)
        return judge(nodes, fail_ratio=self.cfg.fail_ratio, min_samples=self.cfg.min_samples)


class SelfDetector(Detector):
    """从本机直接探测（机器人跑在墙内时可用，无需探针）。"""

    name = "tcp_self"

    async def check(self, ip: str, port: int, *, sni: str = "") -> ProbeOutcome:
        attempts = [await tcp_probe(ip, port, self.cfg.timeout, sni=sni, tls=self.cfg.tls_check and bool(sni))]
        node = NodeResult("self", "cn", attempts)
        return judge([node], fail_ratio=1.0, min_samples=1, require_overseas_confirm=False)


class HybridDetector(Detector):
    """自建探针 + check-host 公共网络，任一判定被墙即算（互为补充）。"""

    name = "hybrid"

    def __init__(self, cfg: DetectConfig) -> None:
        super().__init__(cfg)
        self.parts: list[Detector] = []
        if cfg.probe_agents:
            self.parts.append(ProbeAgentDetector(cfg))
        self.parts.append(CheckHostDetector(cfg))

    async def check(self, ip: str, port: int, *, sni: str = "") -> ProbeOutcome:
        results = list(await asyncio.gather(*(p.check(ip, port, sni=sni) for p in self.parts)))
        nodes = [n for r in results for n in r.nodes]
        blocked = any(r.blocked for r in results)
        ok = all(r.ok for r in results)
        reason = " || ".join(f"[{p.name}] {r.reason}" for p, r in zip(self.parts, results))
        return ProbeOutcome(ok, blocked, reason, nodes)
