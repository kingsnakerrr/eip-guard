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

# ---------------------------------------------------------------- 判定模型
# 核心思想（和 ping.pe 一样）：同一个端口，分别从「国内」和「国外」测。
#   国内不通 + 国外通   → 这个端口被墙
#   国内不通 + 国外不通 → 服务/端口本身坏了，不是墙（换 IP 没用）
#   国内通             → 正常
# 只看国内、或只看「有没有别的端口通」，都会得出错误结论——那正是上一版的 bug。


class Verdict(str, Enum):
    OK = "ok"
    IP_BLOCKED = "ip_blocked"            # 节点端口被墙，且这台 IP 上没有别的端口能从国内连上
    PORT_BLOCKED = "port_blocked"        # 只有节点端口被墙，同 IP 其它端口国内能连
    TLS_BLOCKED = "tls_blocked"          # TCP 通，TLS 握手被断（SNI/指纹）
    DATA_BLOCKED = "data_blocked"        # 握手通，一传数据就断
    SERVICE_DOWN = "service_down"        # 国外也连不上这个端口 → 服务/安全组/防火墙问题
    UNKNOWN = "unknown"                  # 缺国内或国外节点，无法对比

BLOCKING_VERDICTS = {
    Verdict.IP_BLOCKED,
    Verdict.PORT_BLOCKED,
    Verdict.TLS_BLOCKED,
    Verdict.DATA_BLOCKED,
}

VERDICT_LABELS = {
    Verdict.OK: "正常",
    Verdict.IP_BLOCKED: "IP 被墙",
    Verdict.PORT_BLOCKED: "端口被墙",
    Verdict.TLS_BLOCKED: "TLS 被阻断",
    Verdict.DATA_BLOCKED: "数据面被阻断",
    Verdict.SERVICE_DOWN: "服务不可用",
    Verdict.UNKNOWN: "无法判定",
}

VERDICT_ICONS = {
    Verdict.OK: "🟢",
    Verdict.IP_BLOCKED: "🔴",
    Verdict.PORT_BLOCKED: "🟠",
    Verdict.TLS_BLOCKED: "🟣",
    Verdict.DATA_BLOCKED: "🟣",
    Verdict.SERVICE_DOWN: "⚫",
    Verdict.UNKNOWN: "⚪",
}

VERDICT_ADVICE = {
    Verdict.IP_BLOCKED: "整台 IP 的这个端口从国内不可达、国外正常，且同 IP 没有其它端口能从国内连上 → 换 IP 有效。",
    Verdict.PORT_BLOCKED: "只有这一个端口被墙，同 IP 其它端口国内能连 → 换端口（如 443→8443）最有效；换 IP 也可能有用但更贵。",
    Verdict.TLS_BLOCKED: "换 IP 基本无效：这是按 SNI/证书指纹阻断，应换域名、换端口或改用 Reality/无 SNI 方案。",
    Verdict.DATA_BLOCKED: "换 IP 基本无效：TCP 和握手都正常，是按流量特征阻断，应换协议/混淆或换端口。",
    Verdict.SERVICE_DOWN: "国外也连不上这个端口，是服务没起/安全组没放行/服务器防火墙挡住了，换 IP 完全无效。",
    Verdict.UNKNOWN: "缺少国内或国外探针，无法做「国内不通 + 国外通」的对比。",
    Verdict.OK: "",
}


@dataclass
class LayerResult:
    ok: bool | None = None       # None = 未测试
    ms: float | None = None
    kind: str = ""               # timeout / reset / refused / tls / http / icmp-loss
    error: str = ""
    detail: str = ""

    def mark(self) -> str:
        if self.ok is None:
            return "–"
        text = "✓" if self.ok else "✗"
        if self.ok is False and self.kind:
            text += f"({self.kind})"
        return text

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "ms": self.ms, "kind": self.kind, "error": self.error, "detail": self.detail}


@dataclass
class PortProbe:
    """一个端口在一个探针节点上的结果。"""

    port: int
    tcp: LayerResult
    tls: LayerResult | None = None
    http: LayerResult | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"tcp": self.tcp.to_dict()}
        if self.tls is not None:
            out["tls"] = self.tls.to_dict()
        if self.http is not None:
            out["http"] = self.http.to_dict()
        return out


@dataclass
class NodeResult:
    """一个探针节点的全部结果。zone: cn = 国内, overseas = 国外。"""

    node: str
    zone: str
    icmp: LayerResult | None = None
    ports: dict[int, PortProbe] = field(default_factory=dict)
    error: str = ""

    def port(self, port: int) -> PortProbe | None:
        return self.ports.get(port)

    def tcp_ok(self, port: int) -> bool | None:
        probe = self.ports.get(port)
        return None if probe is None else probe.tcp.ok

    def brief(self) -> str:
        if self.error and not self.ports:
            return f"{self.node}({self.zone}) 探测失败: {self.error}"
        parts = []
        for port in sorted(self.ports):
            probe = self.ports[port]
            text = f"{port}:{probe.tcp.mark()}"
            if probe.tls is not None and probe.tls.ok is False:
                text += f" tls✗({probe.tls.kind})"
            if probe.http is not None and probe.http.ok is False:
                text += " http✗"
            parts.append(text)
        icmp = f" icmp{self.icmp.mark()}" if self.icmp and self.icmp.ok is not None else ""
        return f"{self.node}({self.zone}){' '.join(parts)}{icmp}"

    def summary(self) -> str:
        return self.brief()


@dataclass
class PortState:
    """某端口在国内外两侧的对比结果。"""

    port: int
    cn: str            # ok / fail / untested
    os: str
    cn_kind: str = ""
    os_kind: str = ""

    @property
    def blocked(self) -> bool:
        return self.cn == "fail" and self.os == "ok"

    @property
    def broken(self) -> bool:
        return self.os == "fail"

    @property
    def reachable_from_cn(self) -> bool:
        return self.cn == "ok"

    def line(self) -> str:
        def mark(state: str, kind: str) -> str:
            if state == "ok":
                return "✓"
            if state == "fail":
                return f"✗({kind})" if kind else "✗"
            return "–"

        return f"{self.port}: 国内 {mark(self.cn, self.cn_kind)} / 国外 {mark(self.os, self.os_kind)}"


# ---------------------------------------------------------------- 本机探测原语
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
    exe = shutil.which("ping")
    if not exe:
        return LayerResult(None, error="本机没有 ping 命令")
    try:
        proc = await asyncio.create_subprocess_exec(
            exe, "-c", str(count), "-W", str(max(1, int(timeout))), "-n", ip,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        rc = await asyncio.wait_for(proc.wait(), timeout=count * timeout + 3)
    except asyncio.TimeoutError:
        return LayerResult(False, kind="timeout", error="ping 超时")
    except (NotImplementedError, PermissionError, OSError) as exc:
        return LayerResult(None, error=f"无法执行 ping: {exc}")
    if rc == 0:
        return LayerResult(True)
    return LayerResult(False, kind="icmp-loss", error="100% 丢包")


async def tcp_probe(ip: str, port: int, timeout: float) -> LayerResult:
    started = time.monotonic()
    writer: asyncio.StreamWriter | None = None
    try:
        _reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        return LayerResult(True, round((time.monotonic() - started) * 1000, 1))
    except BaseException as exc:  # noqa: BLE001
        return LayerResult(False, None, classify_exception(exc), f"{type(exc).__name__}: {exc}"[:160])
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def tls_probe(ip: str, port: int, sni: str, timeout: float) -> LayerResult:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    started = time.monotonic()
    writer: asyncio.StreamWriter | None = None
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=sni or None), timeout
        )
        assert writer is not None
        elapsed = round((time.monotonic() - started) * 1000, 1)
        proto = ""
        try:
            ssl_obj = writer.get_extra_info("ssl_object")
            proto = ssl_obj.version() if ssl_obj else ""
        except Exception:
            proto = ""
        return LayerResult(True, elapsed, detail=proto)
    except BaseException as exc:  # noqa: BLE001
        return LayerResult(False, None, classify_exception(exc), f"{type(exc).__name__}: {exc}"[:160])
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def http_probe(ip: str, port: int, sni: str, path: str, timeout: float) -> LayerResult:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    writer: asyncio.StreamWriter | None = None
    started = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=sni or None), timeout
        )
        assert writer is not None
        host = sni or ip
        request = (
            f"GET {path or '/'} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: eipguard\r\n"
            "Accept: */*\r\nConnection: close\r\n\r\n"
        )
        writer.write(request.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(64), timeout)
        elapsed = round((time.monotonic() - started) * 1000, 1)
        if data.startswith(b"HTTP/"):
            return LayerResult(True, elapsed, detail=data.split(b"\r\n")[0].decode("latin1", "ignore"))
        return LayerResult(False, elapsed, "http", f"非 HTTP 响应: {data[:40]!r}")
    except BaseException as exc:  # noqa: BLE001
        return LayerResult(False, None, classify_exception(exc), f"{type(exc).__name__}: {exc}"[:160])
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ---------------------------------------------------------------- 探针客户端
class ProbeAgentClient:
    def __init__(
        self,
        agents: list[dict[str, Any]],
        timeout: float = 8.0,
        layers: list[str] | None = None,
        http_path: str = "/",
    ) -> None:
        self.agents = agents
        self.timeout = timeout
        self.layers = list(layers or ["icmp", "tls"])
        self.http_path = http_path

    async def check(self, ip: str, ports: list[int], *, sni: str = "", attempts: int = 2) -> list[NodeResult]:
        if not self.agents:
            return []
        # 每个端口最坏要等 attempts 次超时
        total = self.timeout * (len(ports) * attempts + 4) + 10
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=total)) as session:
            tasks = [self._one(session, a, ip, ports, sni, attempts) for a in self.agents]
            return list(await asyncio.gather(*tasks))

    async def _one(
        self,
        session: aiohttp.ClientSession,
        agent: dict[str, Any],
        ip: str,
        ports: list[int],
        sni: str,
        attempts: int,
    ) -> NodeResult:
        url = str(agent["url"]).rstrip("/") + "/probe"
        name = str(agent.get("name") or url.split("//")[-1].split("/")[0])
        zone = str(agent.get("zone") or "cn").lower()
        payload = {
            "ip": ip,
            "ports": ports,
            "sni": sni,
            "attempts": attempts,
            "layers": self.layers,
            "http_path": self.http_path,
            "timeout": self.timeout,
        }
        headers = {}
        if agent.get("token"):
            headers["X-Probe-Token"] = str(agent["token"])
        try:
            async with session.post(url, json=payload, headers=headers) as resp:
                data = await resp.json(content_type=None)
                if resp.status != 200:
                    msg = str(data.get("error") or "") if isinstance(data, dict) else ""
                    return NodeResult(name, zone, error=f"HTTP {resp.status} {msg}".strip())
        except Exception as exc:  # noqa: BLE001
            return NodeResult(name, zone, error=f"{type(exc).__name__}: {exc}")

        if not isinstance(data, dict):
            return NodeResult(name, zone, error="探针返回非 JSON")
        # 配置没写 zone 时，用探针自报的位置（安装时 --zone 决定）
        if not agent.get("zone") and data.get("zone") in {"cn", "overseas"}:
            zone = str(data["zone"])

        def layer(raw: Any) -> LayerResult | None:
            if not isinstance(raw, dict):
                return None
            return LayerResult(
                ok=raw.get("ok"),
                ms=raw.get("ms"),
                kind=str(raw.get("kind") or ""),
                error=str(raw.get("error") or ""),
                detail=str(raw.get("detail") or ""),
            )

        icmp = layer(data.get("icmp"))
        result: dict[int, PortProbe] = {}
        raw_ports = data.get("ports") or {}
        for key, item in raw_ports.items():
            if not isinstance(item, dict):
                continue
            try:
                port = int(key)
            except (TypeError, ValueError):
                continue
            tcp = layer(item.get("tcp"))
            if tcp is None:
                continue
            result[port] = PortProbe(port, tcp, layer(item.get("tls")), layer(item.get("http")))
        if not result:
            return NodeResult(name, zone, icmp, error="探针没有返回端口结果")
        return NodeResult(name, zone, icmp, result)


# ---------------------------------------------------------------- check-host.net
CHECKHOST_API = "https://check-host.net"


class CheckHostClient:
    """免费公共探测网。只能测单端口，但节点里常有中国的，适合做交叉验证。"""

    def __init__(self, nodes: int = 6, timeout: int = 20) -> None:
        self.nodes = nodes
        self.timeout = timeout

    async def _run(self, session: aiohttp.ClientSession, kind: str, target: str) -> tuple[dict[str, Any], dict[str, str]]:
        nodes_meta: dict[str, str] = {}
        try:
            async with session.get(
                f"{CHECKHOST_API}/check-{kind}", params={"host": target, "max_nodes": self.nodes}
            ) as resp:
                data = await resp.json(content_type=None)
        except Exception:
            return {}, {}
        if not isinstance(data, dict) or not data.get("ok"):
            return {}, {}
        request_id = str(data.get("request_id") or "")
        for name, meta in (data.get("nodes") or {}).items():
            country = str(meta[0] if isinstance(meta, list) and meta else "").lower()
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

    async def check(self, ip: str, ports: list[int], **_: Any) -> list[NodeResult]:
        port = ports[0] if ports else 443
        headers = {"Accept": "application/json", "User-Agent": "eipguard/1.0"}
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout * 2 + 25), headers=headers
        ) as session:
            tcp_result, nodes_meta = await self._run(session, "tcp", f"{ip}:{port}")
            icmp_result, icmp_meta = await self._run(session, "ping", ip)
            nodes_meta.update({k: v for k, v in icmp_meta.items() if k not in nodes_meta})

        out: list[NodeResult] = []
        for name in set(tcp_result) | set(icmp_result):
            country = nodes_meta.get(name, "")
            zone = "cn" if country == "cn" else ("overseas" if country else "unknown")
            probes: dict[int, PortProbe] = {}
            tcp_value = tcp_result.get(name)
            if tcp_value is not None:
                probes[port] = PortProbe(port, self._layer(tcp_value))
            icmp_value = icmp_result.get(name)
            icmp = self._layer(icmp_value) if icmp_value is not None else None
            out.append(NodeResult(name, zone, icmp, probes))
        if not out:
            out.append(NodeResult("check-host", "unknown", error="check-host 无结果"))
        return out

    @staticmethod
    def _layer(value: Any) -> LayerResult:
        if isinstance(value, dict) and value.get("error"):
            return LayerResult(False, kind="other", error=str(value["error"]))
        entries = value if isinstance(value, list) else [value]
        ok = False
        ms: float | None = None
        for entry in entries:
            if isinstance(entry, dict):
                ok = True
                if entry.get("time"):
                    ms = round(float(entry["time"]) * 1000, 1)
            elif isinstance(entry, list) and entry:
                ok = True
                try:
                    ms = round(float(entry[0]) * 1000, 1)
                except (TypeError, ValueError):
                    pass
        if not entries:
            return LayerResult(False, kind="other", error="无数据")
        return LayerResult(ok, ms, "" if ok else "timeout")


# ---------------------------------------------------------------- 结论合成
@dataclass
class ProbeOutcome:
    verdict: Verdict
    reason: str
    nodes: list[NodeResult] = field(default_factory=list)
    advice: str = ""
    ports: list[PortState] = field(default_factory=list)
    node_port: int = 443
    icmp_cn: str = "untested"
    icmp_os: str = "untested"

    @property
    def ok(self) -> bool:
        return self.verdict is Verdict.OK

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
            "node_port": self.node_port,
            "ports": [{"port": p.port, "cn": p.cn, "os": p.os} for p in self.ports],
            "nodes": [{"node": n.node, "zone": n.zone, "summary": n.brief(), "error": n.error} for n in self.nodes],
        }


def _side(nodes: list[NodeResult], side: str) -> list[NodeResult]:
    if side == "cn":
        return [n for n in nodes if n.zone == "cn"]
    return [n for n in nodes if n.zone != "cn"]


def _port_state(nodes: list[NodeResult], port: int, fail_ratio: float) -> tuple[str, str]:
    """返回 (state, kind)。state ∈ ok / fail / untested。"""
    tested = [n.ports[port].tcp for n in nodes if port in n.ports and n.ports[port].tcp.ok is not None]
    if not tested:
        return "untested", ""
    ok_count = sum(1 for item in tested if item.ok)
    fail_ratio_actual = 1 - ok_count / len(tested)
    kinds = sorted({item.kind for item in tested if item.kind})
    kind = "/".join(kinds)
    if fail_ratio_actual >= fail_ratio:
        return "fail", kind
    return "ok", ""


def _icmp_state(nodes: list[NodeResult], fail_ratio: float) -> str:
    tested = [n.icmp for n in nodes if n.icmp is not None and n.icmp.ok is not None]
    if not tested:
        return "untested"
    ok_ratio = sum(1 for item in tested if item.ok) / len(tested)
    return "ok" if ok_ratio >= 1 - fail_ratio else "fail"


def judge(
    nodes: list[NodeResult],
    *,
    ports: list[int] | None = None,
    fail_ratio: float = 0.6,
) -> ProbeOutcome:
    """同一端口国内外对比，得出结论。

    规则（node_port 指 target 的探测端口，其余为辅助端口）：
      node_port 国内通                        → OK（再看 TLS/HTTP）
      node_port 国内不通 + 国外通              → 被墙
          同 IP 有其它端口国内通              → PORT_BLOCKED（换端口）
          同 IP 其它端口国内都不通/没测        → IP_BLOCKED（换 IP）
      node_port 国内不通 + 国外也不通          → SERVICE_DOWN（不是墙）
      缺国内或国外节点                        → UNKNOWN
    """
    ports = ports or sorted({p for n in nodes for p in n.ports}) or [443]
    node_port = ports[0]

    if not nodes:
        return ProbeOutcome(Verdict.UNKNOWN, "没有可用的探测节点", nodes, VERDICT_ADVICE[Verdict.UNKNOWN], node_port=node_port)

    cn = _side(nodes, "cn")
    outside = _side(nodes, "overseas")
    summary = " | ".join(n.brief() for n in nodes)

    states: list[PortState] = []
    for port in ports:
        cn_state, cn_kind = _port_state(cn, port, fail_ratio) if cn else ("untested", "")
        os_state, os_kind = _port_state(outside, port, fail_ratio) if outside else ("untested", "")
        states.append(PortState(port, cn_state, os_state, cn_kind, os_kind))
    by_port = {item.port: item for item in states}
    main = by_port[node_port]

    icmp_cn = _icmp_state(cn, fail_ratio) if cn else "untested"
    icmp_os = _icmp_state(outside, fail_ratio) if outside else "untested"
    matrix = "；".join(item.line() for item in states)

    def outcome(verdict: Verdict, reason: str) -> ProbeOutcome:
        return ProbeOutcome(
            verdict, reason, nodes, VERDICT_ADVICE[verdict], states, node_port, icmp_cn, icmp_os
        )

    if not cn:
        failed = [n for n in nodes if n.error]
        hint = ""
        if failed:
            hint = (
                "（探针连不上：若探针在家宽后面，需要 Tailscale/frp 打通，"
                "见 docs/家宽探针方案.md）"
            )
        return outcome(
            Verdict.UNKNOWN,
            f"没有国内探针（zone: cn），无法做「国内不通 vs 国外通」的对比{hint}：{summary}",
        )
    if not outside:
        return outcome(
            Verdict.UNKNOWN,
            f"没有国外探针（zone: overseas），无法确认端口在墙外是否正常：{summary}",
        )

    # 1) 国内能连上节点端口
    if main.cn == "ok":
        cn_tls = _aggregate_layer(cn, node_port, "tls", fail_ratio)
        os_tls = _aggregate_layer(outside, node_port, "tls", fail_ratio)
        cn_http = _aggregate_layer(cn, node_port, "http", fail_ratio)
        os_http = _aggregate_layer(outside, node_port, "http", fail_ratio)
        if cn_tls == "fail" and os_tls == "fail":
            # 两边 TLS 都失败：证书/协议配置有问题，不是墙
            return outcome(
                Verdict.SERVICE_DOWN,
                f"TCP 能连上，但国内外 TLS 握手都失败 → 是证书/协议配置问题，不是墙：{summary}",
            )
        if cn_tls == "fail" and os_tls == "ok":
            return outcome(
                Verdict.TLS_BLOCKED,
                f"国内 TCP 能连上，但 TLS 握手被重置/超时，国外 TLS 正常 → 按 SNI/证书指纹阻断：{summary}",
            )
        if cn_http == "fail" and os_http == "ok":
            return outcome(
                Verdict.DATA_BLOCKED,
                f"国内 TCP 与 TLS 都正常，但真实 HTTP 请求被断，国外正常 → 数据面被阻断：{summary}",
            )
        return outcome(Verdict.OK, f"国内可正常连通节点端口 {node_port}：{summary}")

    # 2) 国内连不上，且国外也连不上 → 不是墙
    if main.os == "fail":
        return outcome(
            Verdict.SERVICE_DOWN,
            f"端口 {node_port} 在国内和国外都连不上 → 不是墙，是服务没起/安全组没放行/"
            f"服务器防火墙挡住（{main.os_kind or '连接失败'}）。换 IP 无效：{summary}",
        )

    # 3) 国内连不上，国外能连 → 这个端口被墙
    if main.os == "untested":
        return outcome(
            Verdict.UNKNOWN,
            f"国内连不上端口 {node_port}，但国外节点没有该端口的结果，无法确认是否被墙：{summary}",
        )

    reachable_others = [item.port for item in states if item.port != node_port and item.cn == "ok"]
    blocked_others = [item.port for item in states if item.port != node_port and item.blocked]
    broken_others = [item.port for item in states if item.port != node_port and item.os == "fail"]
    untested = [item.port for item in states if item.port != node_port and item.cn == "untested"]

    if reachable_others:
        return outcome(
            Verdict.PORT_BLOCKED,
            f"端口 {node_port} 国内不通、国外正常，但同 IP 的 {', '.join(map(str, reachable_others))} "
            f"国内能连 → 只封了这一个端口：{matrix}",
        )
    if blocked_others:
        return outcome(
            Verdict.IP_BLOCKED,
            f"端口 {node_port} 与 {', '.join(map(str, blocked_others))} 国内都不通、国外都正常 → "
            f"整台 IP 被墙：{matrix}",
        )
    if untested and not broken_others:
        return outcome(
            Verdict.IP_BLOCKED,
            f"端口 {node_port} 国内不通、国外正常（其它端口 {', '.join(map(str, untested))} 未测到，"
            f"建议在目标上配置 aux_ports 以便区分「整机被封」和「只封端口」）：{matrix}",
        )
    note = f"（{', '.join(map(str, broken_others))} 在国内外都不通，属于服务本身问题，不影响结论）" if broken_others else ""
    return outcome(
        Verdict.IP_BLOCKED,
        f"端口 {node_port} 国内不通、国外正常，同 IP 其它端口也没有国内可达的{note} → 判定 IP 被墙：{matrix}",
    )


def _aggregate_layer(nodes: list[NodeResult], port: int, name: str, fail_ratio: float) -> str:
    tested = []
    for node in nodes:
        probe = node.ports.get(port)
        if not probe:
            continue
        item = getattr(probe, name, None)
        if item is not None and item.ok is not None:
            tested.append(item)
    if not tested:
        return "untested"
    ok_ratio = sum(1 for item in tested if item.ok) / len(tested)
    return "ok" if ok_ratio >= 1 - fail_ratio else "fail"


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

    async def check(self, ip: str, ports: list[int], *, sni: str = "") -> ProbeOutcome:
        raise NotImplementedError

    async def close(self) -> None:
        return None


class ProbeAgentDetector(Detector):
    name = "probe_agent"

    def __init__(self, cfg: DetectConfig) -> None:
        super().__init__(cfg)
        self.client = ProbeAgentClient(cfg.probe_agents, cfg.timeout, cfg.layers, cfg.http_path)

    async def check(self, ip: str, ports: list[int], *, sni: str = "") -> ProbeOutcome:
        nodes = await self.client.check(ip, ports, sni=sni, attempts=self.cfg.attempts)
        return judge(nodes, ports=ports, fail_ratio=self.cfg.fail_ratio)


class CheckHostDetector(Detector):
    name = "checkhost"

    def __init__(self, cfg: DetectConfig) -> None:
        super().__init__(cfg)
        self.client = CheckHostClient(cfg.checkhost_max_nodes, cfg.checkhost_timeout)

    async def check(self, ip: str, ports: list[int], *, sni: str = "") -> ProbeOutcome:
        nodes = await self.client.check(ip, ports)
        return judge(nodes, ports=ports[:1], fail_ratio=self.cfg.fail_ratio)


class SelfDetector(Detector):
    """仅本机视角：能证明"通"，不能证明"被墙"。"""

    name = "tcp_self"

    async def check(self, ip: str, ports: list[int], *, sni: str = "") -> ProbeOutcome:
        probes: dict[int, PortProbe] = {}
        for index, port in enumerate(ports):
            tcp = await tcp_probe(ip, port, self.cfg.timeout)
            probe = PortProbe(port, tcp)
            if index == 0 and tcp.ok:
                if "tls" in self.cfg.layers and sni:
                    probe.tls = await tls_probe(ip, port, sni, self.cfg.timeout)
                if "http" in self.cfg.layers and sni and self.cfg.http_path:
                    probe.http = await http_probe(ip, port, sni, self.cfg.http_path, self.cfg.timeout)
            probes[port] = probe
        icmp = await icmp_probe(ip, 1, self.cfg.timeout) if "icmp" in self.cfg.layers else None
        node = NodeResult("self", "cn", icmp, probes)
        outcome = judge([node], ports=ports, fail_ratio=1.0)
        if outcome.verdict is Verdict.UNKNOWN and node.tcp_ok(ports[0]):
            return ProbeOutcome(Verdict.OK, f"本机可连通端口 {ports[0]}：{node.brief()}", [node], "", node_port=ports[0])
        if outcome.verdict is Verdict.UNKNOWN:
            outcome.reason = f"本机连不上，但没有国外节点对比，无法区分被墙/服务故障：{node.brief()}"
        return outcome


class HybridDetector(Detector):
    """自建探针为主，check-host 交叉验证。"""

    name = "hybrid"

    def __init__(self, cfg: DetectConfig) -> None:
        super().__init__(cfg)
        self.parts: list[Detector] = []
        if cfg.probe_agents:
            self.parts.append(ProbeAgentDetector(cfg))
        self.parts.append(CheckHostDetector(cfg))

    async def check(self, ip: str, ports: list[int], *, sni: str = "") -> ProbeOutcome:
        results = list(await asyncio.gather(*(p.check(ip, ports, sni=sni) for p in self.parts)))
        nodes = [n for r in results for n in r.nodes]
        primary = results[0]
        if primary.verdict in BLOCKING_VERDICTS or primary.verdict in (Verdict.OK, Verdict.SERVICE_DOWN):
            primary.nodes = nodes
            primary.reason = " || ".join(f"[{p.name}] {r.reason}" for p, r in zip(self.parts, results))
            return primary
        for result in results:
            if result.verdict in BLOCKING_VERDICTS:
                result.nodes = nodes
                result.reason = " || ".join(f"[{p.name}] {r.reason}" for p, r in zip(self.parts, results))
                return result
        primary.nodes = nodes
        primary.reason = " || ".join(f"[{p.name}] {r.reason}" for p, r in zip(self.parts, results))
        return primary
