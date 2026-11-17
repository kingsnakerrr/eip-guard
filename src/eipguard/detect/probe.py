from __future__ import annotations

import asyncio
import shutil
import socket
import ssl
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import aiohttp

from ..config import DetectConfig

# ---------------------------------------------------------------- 分层模型
# 一次探测按"层"分别记录，这样才能区分"封 IP / 封端口 / 封 TLS / 封流量"。
# 只测 TCP 连接是最容易误判的：GFW 可以让 SYN/ACK 正常完成，然后在握手或传输阶段再断。
LAYER_ICMP = "icmp"   # ICMP echo（ping）
LAYER_TCP = "tcp"     # 节点端口 TCP 建连
LAYER_AUX = "aux"     # 其它常见端口的 TCP 建连（判断是"整台 IP"还是"单个端口"）
LAYER_TLS = "tls"     # 节点端口上的 TLS 握手（SNI 阻断会在这里暴露）
LAYER_HTTP = "http"   # TLS 之上真的发一次 HTTP 请求（可选，判断数据面）

ALL_LAYERS = (LAYER_ICMP, LAYER_TCP, LAYER_AUX, LAYER_TLS, LAYER_HTTP)


class Verdict(str, Enum):
    OK = "ok"
    DEGRADED = "degraded"
    IP_BLOCKED = "ip_blocked"          # 整台 IP：ICMP 可能通，但所有端口都不通
    PORT_BLOCKED = "port_blocked"      # 只有节点端口不通，其它端口正常
    TLS_BLOCKED = "tls_blocked"        # TCP 通，TLS 握手被断（SNI / 指纹）
    DATA_BLOCKED = "data_blocked"      # 握手通，但一传数据就断
    DOWN = "down"                       # 墙外也不通：实例/服务故障
    UNKNOWN = "unknown"                 # 没有墙内节点，无法确认


BLOCKING_VERDICTS = {
    Verdict.IP_BLOCKED,
    Verdict.PORT_BLOCKED,
    Verdict.TLS_BLOCKED,
    Verdict.DATA_BLOCKED,
}

VERDICT_LABELS = {
    Verdict.OK: "正常",
    Verdict.DEGRADED: "可用但异常",
    Verdict.IP_BLOCKED: "IP 被墙",
    Verdict.PORT_BLOCKED: "端口被墙",
    Verdict.TLS_BLOCKED: "TLS 被阻断",
    Verdict.DATA_BLOCKED: "数据面被阻断",
    Verdict.DOWN: "服务不可用",
    Verdict.UNKNOWN: "无法判定",
}

VERDICT_ICONS = {
    Verdict.OK: "🟢",
    Verdict.DEGRADED: "🟡",
    Verdict.IP_BLOCKED: "🔴",
    Verdict.PORT_BLOCKED: "🟠",
    Verdict.TLS_BLOCKED: "🟣",
    Verdict.DATA_BLOCKED: "🟣",
    Verdict.DOWN: "⚫",
    Verdict.UNKNOWN: "⚪",
}

# 每种结论建议怎么办。ip_blocked 才默认换 IP，其它先别花钱。
VERDICT_ADVICE = {
    Verdict.IP_BLOCKED: "换 IP 有效。",
    Verdict.PORT_BLOCKED: "换 IP 通常无效且浪费钱：先换节点端口（如 443→8443），或同时给 EIP 换 IP+换端口。",
    Verdict.TLS_BLOCKED: "换 IP 基本无效：这是按 SNI/证书指纹阻断，应换域名、换端口或改用 Reality/无 SNI 方案。",
    Verdict.DATA_BLOCKED: "换 IP 基本无效：TCP 和握手都正常，是按流量特征阻断，应换协议/混淆或换端口。",
    Verdict.DOWN: "墙外也不通，是实例/服务本身挂了，先查进程、安全组和系统防火墙。",
    Verdict.UNKNOWN: "缺少墙内探针，无法区分被墙还是故障。",
    Verdict.OK: "",
    Verdict.DEGRADED: "部分节点异常，继续观察。",
}


@dataclass
class LayerResult:
    layer: str
    ok: bool | None = None          # None = 未测试 / 探针不支持
    ms: float | None = None
    kind: str = ""                  # timeout / reset / refused / tls / icmp-loss / http
    error: str = ""
    detail: str = ""                # 例如各端口结果 "80✓ 22✗"

    def mark(self) -> str:
        if self.ok is None:
            return "–"
        return "✓" if self.ok else "✗"

    def to_dict(self) -> dict[str, Any]:
        return {
            "layer": self.layer,
            "ok": self.ok,
            "ms": self.ms,
            "kind": self.kind,
            "error": self.error,
            "detail": self.detail,
        }


@dataclass
class NodeResult:
    """一个探针节点的结果。zone: cn=墙内, overseas=墙外。"""

    node: str
    zone: str
    layers: dict[str, LayerResult] = field(default_factory=dict)
    error: str = ""

    def layer(self, name: str) -> LayerResult | None:
        return self.layers.get(name)

    def ok_on(self, name: str) -> bool | None:
        item = self.layers.get(name)
        return None if item is None else item.ok

    def summary(self) -> str:
        parts = []
        for name in (LAYER_ICMP, LAYER_TCP, LAYER_TLS, LAYER_AUX, LAYER_HTTP):
            item = self.layers.get(name)
            if item is None:
                continue
            text = f"{name}{item.mark()}"
            if item.ok is False and item.kind:
                text += f"({item.kind})"
            parts.append(text)
        return " ".join(parts)

    def brief(self) -> str:
        if self.error and not self.layers:
            return f"{self.node}({self.zone}) 探测失败: {self.error}"
        return f"{self.node}({self.zone}) {self.summary()}"


# ---------------------------------------------------------------- 本地探测原语
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
        return "reset" if getattr(exc, "errno", None) in (104, 54) else "other"
    return "other"


async def icmp_probe(ip: str, count: int = 2, timeout: float = 2.0) -> LayerResult:
    """系统 ping。没有 ping 命令或没权限时返回 ok=None（未测），不当作失败。"""
    exe = shutil.which("ping")
    if not exe:
        return LayerResult(LAYER_ICMP, None, error="本机没有 ping 命令")
    try:
        proc = await asyncio.create_subprocess_exec(
            exe, "-c", str(count), "-W", str(max(1, int(timeout))), "-n", ip,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        rc = await asyncio.wait_for(proc.wait(), timeout=count * timeout + 3)
    except asyncio.TimeoutError:
        return LayerResult(LAYER_ICMP, False, kind="timeout", error="ping 超时")
    except (NotImplementedError, PermissionError, OSError) as exc:
        return LayerResult(LAYER_ICMP, None, error=f"无法执行 ping: {exc}")
    if rc == 0:
        return LayerResult(LAYER_ICMP, True)
    return LayerResult(LAYER_ICMP, False, kind="icmp-loss", error="100% 丢包")


async def tcp_probe(ip: str, port: int, timeout: float) -> LayerResult:
    started = time.monotonic()
    writer: asyncio.StreamWriter | None = None
    try:
        _reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        return LayerResult(LAYER_TCP, True, round((time.monotonic() - started) * 1000, 1))
    except BaseException as exc:  # noqa: BLE001
        return LayerResult(
            LAYER_TCP, False, None, classify_exception(exc), f"{type(exc).__name__}: {exc}"[:160]
        )
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def tls_probe(ip: str, port: int, sni: str, timeout: float) -> LayerResult:
    """真实 TLS 握手。SNI 阻断在 ClientHello 之后就会回 RST，这一步会失败。"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    started = time.monotonic()
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=sni or None), timeout
        )
        elapsed = round((time.monotonic() - started) * 1000, 1)
        assert writer is not None
        try:
            ssl_obj = writer.get_extra_info("ssl_object")
            version = ssl_obj.version() if ssl_obj else ""
        except Exception:
            version = ""
        del reader
        return LayerResult(LAYER_TLS, True, elapsed, detail=version or "")
    except BaseException as exc:  # noqa: BLE001
        kind = classify_exception(exc)
        # TLS 阶段被重置/超时，常见是 SNI 关键字阻断
        return LayerResult(
            LAYER_TLS, False, None, kind, f"{type(exc).__name__}: {exc}"[:160]
        )
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def http_probe(ip: str, port: int, sni: str, path: str, timeout: float) -> LayerResult:
    """TLS 之上发一个真实的 HTTP 请求，用来发现"握手能过、数据一过就断"。"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    writer: asyncio.StreamWriter | None = None
    started = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=sni or None), timeout
        )
        host = sni or ip
        request = (
            f"GET {path or '/'} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: eipguard\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n"
        )
        assert writer is not None
        writer.write(request.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(64), timeout)
        elapsed = round((time.monotonic() - started) * 1000, 1)
        if data.startswith(b"HTTP/"):
            return LayerResult(LAYER_HTTP, True, elapsed, detail=data.split(b"\r\n")[0].decode("latin1", "ignore"))
        return LayerResult(LAYER_HTTP, False, elapsed, "http", f"非 HTTP 响应: {data[:40]!r}")
    except BaseException as exc:  # noqa: BLE001
        return LayerResult(
            LAYER_HTTP, False, None, classify_exception(exc), f"{type(exc).__name__}: {exc}"[:160]
        )
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ---------------------------------------------------------------- 探针客户端
class ProbeAgentClient:
    """调用自建探针（probe_agent/server.py），拿回分层结果。"""

    def __init__(self, agents: list[dict[str, Any]], timeout: float = 8.0, layers: list[str] | None = None,
                 aux_ports: list[int] | None = None, http_path: str = "") -> None:
        self.agents = agents
        self.timeout = timeout
        self.layers = list(layers or [LAYER_ICMP, LAYER_TCP, LAYER_TLS])
        self.aux_ports = aux_ports or []
        # 配了其它端口就必须真的去测，否则会误判成"整台 IP 被封"
        if self.aux_ports and LAYER_AUX not in self.layers:
            self.layers.append(LAYER_AUX)
        self.http_path = http_path

    async def check(self, ip: str, port: int, *, sni: str = "", attempts: int = 2) -> list[NodeResult]:
        if not self.agents:
            return []
        total = self.timeout * (len(self.layers) + len(self.aux_ports) + 2)
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=total)) as session:
            tasks = [self._one(session, a, ip, port, sni, attempts) for a in self.agents]
            return list(await asyncio.gather(*tasks))

    async def _one(
        self,
        session: aiohttp.ClientSession,
        agent: dict[str, Any],
        ip: str,
        port: int,
        sni: str,
        attempts: int,
    ) -> NodeResult:
        url = str(agent["url"]).rstrip("/") + "/probe"
        name = str(agent.get("name") or url.split("//")[-1].split("/")[0])
        zone = str(agent.get("zone") or "cn").lower()
        payload = {
            "ip": ip,
            "port": port,
            "sni": sni,
            "attempts": attempts,
            "layers": self.layers,
            "aux_ports": self.aux_ports,
            "http_path": self.http_path,
        }
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
            return NodeResult(name, zone, error=f"{type(exc).__name__}: {exc}")

        if not isinstance(data, dict):
            return NodeResult(name, zone, error="探针返回非 JSON")
        layers: dict[str, LayerResult] = {}
        for layer, item in (data.get("layers") or {}).items():
            if not isinstance(item, dict):
                continue
            layers[str(layer)] = LayerResult(
                layer=str(layer),
                ok=item.get("ok"),
                ms=item.get("ms"),
                kind=str(item.get("kind") or ""),
                error=str(item.get("error") or ""),
                detail=str(item.get("detail") or ""),
            )
        if not layers:
            return NodeResult(name, zone, error="探针没有返回分层结果")
        return NodeResult(name, zone, layers)


# ---------------------------------------------------------------- check-host.net
CHECKHOST_API = "https://check-host.net"


class CheckHostClient:
    """免费公共探测网络。只有 TCP 和 ICMP 两层，没有 TLS，判端口/整机够用。"""

    def __init__(self, port: int = 443, nodes: int = 6, timeout: int = 20) -> None:
        self.port = port
        self.nodes = nodes
        self.timeout = timeout

    async def _run(self, session: aiohttp.ClientSession, kind: str, target: str) -> tuple[dict[str, Any], dict[str, str]]:
        nodes_meta: dict[str, str] = {}
        try:
            async with session.get(
                f"{CHECKHOST_API}/check-{kind}",
                params={"host": target, "max_nodes": self.nodes},
            ) as resp:
                data = await resp.json(content_type=None)
        except Exception:
            return {}, {}
        if not isinstance(data, dict) or not data.get("ok"):
            return {}, {}
        request_id = str(data.get("request_id") or "")
        for name, meta in (data.get("nodes") or {}).items():
            country = ""
            if isinstance(meta, list) and meta:
                country = str(meta[0] or "").lower()
            nodes_meta[str(name)] = country
        if not request_id:
            return {}, nodes_meta
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
        return result, nodes_meta

    async def check(self, ip: str, port: int, **_: Any) -> list[NodeResult]:
        headers = {"Accept": "application/json", "User-Agent": "eipguard/1.0"}
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout * 2 + 20), headers=headers
        ) as session:
            tcp_result, nodes_meta = await self._run(session, "tcp", f"{ip}:{port or self.port}")
            icmp_result, icmp_meta = await self._run(session, "ping", ip)
            nodes_meta.update({k: v for k, v in icmp_meta.items() if k not in nodes_meta})

        out: list[NodeResult] = []
        names = set(tcp_result) | set(icmp_result)
        for name in names:
            country = nodes_meta.get(name, "")
            zone = "cn" if country == "cn" else ("overseas" if country else "unknown")
            layers: dict[str, LayerResult] = {}

            tcp_value = tcp_result.get(name)
            if tcp_value is not None:
                layers[LAYER_TCP] = self._layer_from(tcp_value, LAYER_TCP)
            icmp_value = icmp_result.get(name)
            if icmp_value is not None:
                layers[LAYER_ICMP] = self._layer_from(icmp_value, LAYER_ICMP)
            out.append(NodeResult(name, zone, layers))
        if not out:
            out.append(NodeResult("check-host", "unknown", error="check-host 无结果"))
        return out

    @staticmethod
    def _layer_from(value: Any, layer: str) -> LayerResult:
        if isinstance(value, dict) and value.get("error"):
            return LayerResult(layer, False, kind="other", error=str(value["error"]))
        entries = value if isinstance(value, list) else [value]
        ok = False
        ms: float | None = None
        for entry in entries:
            if isinstance(entry, dict):
                ok = True
                ms = round(float(entry.get("time") or 0) * 1000, 1) if entry.get("time") else ms
            elif isinstance(entry, list) and entry:
                ok = True
                try:
                    ms = round(float(entry[0]) * 1000, 1)
                except (TypeError, ValueError):
                    pass
        if not entries:
            return LayerResult(layer, False, kind="other", error="无数据")
        return LayerResult(layer, ok, ms, "" if ok else "timeout")


# ---------------------------------------------------------------- 结论合成
@dataclass
class ProbeOutcome:
    verdict: Verdict
    reason: str
    nodes: list[NodeResult] = field(default_factory=list)
    advice: str = ""

    @property
    def ok(self) -> bool:
        return self.verdict in (Verdict.OK, Verdict.DEGRADED)

    @property
    def blocked(self) -> bool:
        return self.verdict in BLOCKING_VERDICTS

    @property
    def label(self) -> str:
        return VERDICT_LABELS[self.verdict]

    @property
    def icon(self) -> str:
        return VERDICT_ICONS[self.verdict]

    @property
    def summary(self) -> str:
        return " | ".join(n.brief() for n in self.nodes) if self.nodes else "无探测数据"

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "reason": self.reason,
            "advice": self.advice,
            "nodes": [
                {"node": n.node, "zone": n.zone, "summary": n.summary(), "error": n.error}
                for n in self.nodes
            ],
        }


def _side(nodes: list[NodeResult], zone: str) -> list[NodeResult]:
    return [n for n in nodes if (n.zone == "cn") if zone == "cn"] if zone == "cn" else [
        n for n in nodes if n.zone != "cn"
    ]


def _state(nodes: list[NodeResult], layer: str, fail_ratio: float) -> str:
    """返回 ok / fail / untested（同侧多节点按失败比例投票）。"""
    tested = [
        n.layers[layer]
        for n in nodes
        if layer in n.layers and n.layers[layer].ok is not None
    ]
    if not tested:
        return "untested"
    ok_ratio = sum(1 for item in tested if item.ok) / len(tested)
    return "ok" if ok_ratio >= 1 - fail_ratio else "fail"


def _kinds(nodes: list[NodeResult], layer: str) -> str:
    kinds = sorted({n.layers[layer].kind for n in nodes if layer in n.layers and n.layers[layer].kind})
    return "/".join(kinds)


def judge(
    nodes: list[NodeResult],
    *,
    port: int = 443,
    aux_ports: list[int] | None = None,
    fail_ratio: float = 0.6,
    min_samples: int = 1,
) -> ProbeOutcome:
    """把分层结果合成一个明确结论。

    判定表（墙内 vs 墙外）：
      ICMP   TCP(节点端口)  其它端口   TLS       墙外       结论
      ✗/✓    ✗            ✗        -         ✓         IP 被墙（ICMP 可能被放行来迷惑你）
      ✓      ✗            ✓        -         ✓         端口被墙（换 IP 没用，换端口）
      ✓      ✓            -        ✗         ✓         TLS 被阻断（SNI/指纹，换 IP 没用）
      ✓      ✓            -        ✓         ✓         正常
      -      ✗            -        -         ✗         服务故障，不是墙
      -      -            -        -         -         无法判定（缺墙内探针）
    """
    if not nodes:
        return ProbeOutcome(Verdict.UNKNOWN, "没有可用的探测节点", nodes, VERDICT_ADVICE[Verdict.UNKNOWN])

    cn = _side(nodes, "cn")
    outside = _side(nodes, "overseas")
    summary = " | ".join(n.brief() for n in nodes)

    os_tcp = _state(outside, LAYER_TCP, fail_ratio)
    os_tls = _state(outside, LAYER_TLS, fail_ratio)
    os_http = _state(outside, LAYER_HTTP, fail_ratio)

    # 1) 墙外自己都不通 → 实例/服务故障，绝不换 IP
    if outside and os_tcp == "fail":
        return ProbeOutcome(
            Verdict.DOWN,
            f"墙外节点也连不上节点端口，判定为服务/实例故障，不是墙：{summary}",
            nodes,
            VERDICT_ADVICE[Verdict.DOWN],
        )

    if not cn:
        # 只有墙外数据：可以判断"活着"，但无法区分被墙
        if os_tcp == "fail":
            return ProbeOutcome(
                Verdict.DOWN, f"墙外也不通，服务可能挂了：{summary}", nodes, VERDICT_ADVICE[Verdict.DOWN]
            )
        return ProbeOutcome(
            Verdict.UNKNOWN,
            f"缺少墙内探针（zone: cn），只能确认墙外可达，无法判定是否被墙：{summary}",
            nodes,
            VERDICT_ADVICE[Verdict.UNKNOWN],
        )

    cn_tcp = _state(cn, LAYER_TCP, fail_ratio)
    cn_tls = _state(cn, LAYER_TLS, fail_ratio)
    cn_http = _state(cn, LAYER_HTTP, fail_ratio)
    cn_aux = _state(cn, LAYER_AUX, fail_ratio)
    cn_icmp = _state(cn, LAYER_ICMP, fail_ratio)

    # 2) 节点端口能建连
    if cn_tcp == "ok":
        if cn_tls == "fail" and os_tls != "fail":
            kinds = _kinds(cn, LAYER_TLS)
            return ProbeOutcome(
                Verdict.TLS_BLOCKED,
                f"TCP 能连上但 TLS 握手{'被重置' if 'reset' in kinds else '失败'}，墙外 TLS 正常 → "
                f"按 SNI/指纹阻断：{summary}",
                nodes,
                VERDICT_ADVICE[Verdict.TLS_BLOCKED],
            )
        if cn_http == "fail" and os_http == "ok":
            return ProbeOutcome(
                Verdict.DATA_BLOCKED,
                f"TCP 与 TLS 都正常，但 HTTP 数据请求被断，墙外正常 → 数据面被阻断：{summary}",
                nodes,
                VERDICT_ADVICE[Verdict.DATA_BLOCKED],
            )
        if cn_tls == "untested" and cn_http == "untested":
            return ProbeOutcome(Verdict.OK, f"节点端口 TCP 可达（未测 TLS）：{summary}", nodes)
        return ProbeOutcome(Verdict.OK, f"探测正常：{summary}", nodes)

    # 3) 节点端口不通：先看是不是只有这个端口
    if cn_aux == "ok":
        aux_detail = next(
            (n.layers[LAYER_AUX].detail for n in cn if n.layers.get(LAYER_AUX) and n.layers[LAYER_AUX].detail),
            "",
        )
        return ProbeOutcome(
            Verdict.PORT_BLOCKED,
            f"节点端口 {port} 不通，但其它端口（{aux_detail or 'aux'}）可连，墙外节点端口正常 → "
            f"仅端口被封：{summary}",
            nodes,
            VERDICT_ADVICE[Verdict.PORT_BLOCKED],
        )

    # 4) 所有端口都不通
    aux_note = "" if cn_aux != "untested" else "（未配置 aux_ports，没测其它端口）"
    if cn_icmp == "ok":
        return ProbeOutcome(
            Verdict.IP_BLOCKED,
            f"ICMP 能通但 {port} 和其它测试端口全部不通{aux_note}，墙外正常 → IP 被墙"
            f"（ICMP 被放行是常见假象，不代表 IP 可用）：{summary}",
            nodes,
            VERDICT_ADVICE[Verdict.IP_BLOCKED],
        )
    if cn_icmp == "fail":
        return ProbeOutcome(
            Verdict.IP_BLOCKED,
            f"ICMP 和 TCP 全部不通，墙外正常 → IP 被墙：{summary}",
            nodes,
            VERDICT_ADVICE[Verdict.IP_BLOCKED],
        )
    # ICMP 没测（探针没 ping 权限）但 TCP 全不通
    if cn_aux == "untested":
        return ProbeOutcome(
            Verdict.IP_BLOCKED,
            f"节点端口不通、墙外正常，且探针未测其它端口/ICMP（建议开启 aux_ports 提高准确度）→ "
            f"按 IP 被墙处理：{summary}",
            nodes,
            VERDICT_ADVICE[Verdict.IP_BLOCKED],
        )
    return ProbeOutcome(
        Verdict.IP_BLOCKED,
        f"ICMP 未测，TCP 全部不通，墙外正常 → IP 被墙：{summary}",
        nodes,
        VERDICT_ADVICE[Verdict.IP_BLOCKED],
    )


# ---------------------------------------------------------------- 探测器
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
        self.client = ProbeAgentClient(
            cfg.probe_agents,
            timeout=cfg.timeout,
            layers=cfg.layers,
            aux_ports=cfg.aux_ports,
            http_path=cfg.http_path,
        )

    async def check(self, ip: str, port: int, *, sni: str = "") -> ProbeOutcome:
        nodes = await self.client.check(ip, port, sni=sni, attempts=self.cfg.attempts)
        return judge(
            nodes,
            port=port,
            aux_ports=self.cfg.aux_ports,
            fail_ratio=self.cfg.fail_ratio,
            min_samples=self.cfg.min_samples,
        )


class CheckHostDetector(Detector):
    name = "checkhost"

    def __init__(self, cfg: DetectConfig) -> None:
        super().__init__(cfg)
        self.client = CheckHostClient(nodes=cfg.checkhost_max_nodes, timeout=cfg.checkhost_timeout)

    async def check(self, ip: str, port: int, *, sni: str = "") -> ProbeOutcome:
        nodes = await self.client.check(ip, port)
        return judge(nodes, port=port, aux_ports=[], fail_ratio=self.cfg.fail_ratio)


class SelfDetector(Detector):
    """从本机直接探测（机器人跑在墙内时可用）。墙内视角，没有墙外确认。"""

    name = "tcp_self"

    async def check(self, ip: str, port: int, *, sni: str = "") -> ProbeOutcome:
        layers: dict[str, LayerResult] = {}
        if LAYER_ICMP in self.cfg.layers:
            layers[LAYER_ICMP] = await icmp_probe(ip, count=2, timeout=self.cfg.timeout)
        tcp = await tcp_probe(ip, port, self.cfg.timeout)
        tcp.layer = LAYER_TCP
        layers[LAYER_TCP] = tcp
        if tcp.ok and LAYER_TLS in self.cfg.layers and sni:
            tls = await tls_probe(ip, port, sni, self.cfg.timeout)
            layers[LAYER_TLS] = tls
        if tcp.ok and LAYER_HTTP in self.cfg.layers and sni and self.cfg.http_path:
            layers[LAYER_HTTP] = await http_probe(ip, port, sni, self.cfg.http_path, self.cfg.timeout)

        node = NodeResult("self", "cn", layers)
        # 本机就是墙内，墙外不可见：只能对"能通"下结论，否者交给 wall 侧确认
        tcp_state = _state([node], LAYER_TCP, 1.0)
        tls_state = _state([node], LAYER_TLS, 1.0)
        if tcp_state == "ok" and tls_state in ("ok", "untested"):
            return ProbeOutcome(Verdict.OK, f"本机探测正常：{node.brief()}", [node])
        if tcp_state == "ok" and tls_state == "fail":
            return ProbeOutcome(
                Verdict.TLS_BLOCKED,
                f"本机 TCP 通但 TLS 失败（无墙外对照，可能只是服务配置问题）：{node.brief()}",
                [node],
                VERDICT_ADVICE[Verdict.TLS_BLOCKED],
            )
        return ProbeOutcome(
            Verdict.UNKNOWN,
            f"本机连不上，但没有墙外节点确认，无法区分被墙/故障：{node.brief()}",
            [node],
            VERDICT_ADVICE[Verdict.UNKNOWN],
        )


class HybridDetector(Detector):
    """自建探针 + check-host，任一给出阻塞结论即采用。"""

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
        # 自建探针的结论最可信，优先用它
        primary = results[0]
        if primary.verdict in BLOCKING_VERDICTS or primary.verdict == Verdict.OK:
            primary.nodes = nodes
            primary.reason = " || ".join(f"[{p.name}] {r.reason}" for p, r in zip(self.parts, results))
            return primary
        blocked = [r for r in results if r.verdict in BLOCKING_VERDICTS]
        if blocked:
            blocked[0].nodes = nodes
            blocked[0].reason = " || ".join(f"[{p.name}] {r.reason}" for p, r in zip(self.parts, results))
            return blocked[0]
        primary.nodes = nodes
        primary.reason = " || ".join(f"[{p.name}] {r.reason}" for p, r in zip(self.parts, results))
        return primary
