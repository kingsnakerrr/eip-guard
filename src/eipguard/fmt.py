from __future__ import annotations

import html
import time
from typing import Any

from .detect.probe import VERDICT_ADVICE, VERDICT_ICONS, VERDICT_LABELS, ProbeOutcome, Verdict
from .state import TargetState


def esc(text: Any) -> str:
    return html.escape(str(text), quote=False)


def ts(epoch: float | None, fmt: str = "%m-%d %H:%M:%S") -> str:
    if not epoch:
        return "-"
    return time.strftime(fmt, time.localtime(epoch))


def ago(epoch: float | None) -> str:
    if not epoch:
        return "从未"
    delta = int(time.time() - epoch)
    if delta < 0:
        return f"{abs(delta) // 60}m 后"
    if delta < 60:
        return f"{delta}s 前"
    if delta < 3600:
        return f"{delta // 60}m 前"
    if delta < 86400:
        return f"{delta // 3600}h 前"
    return f"{delta // 86400}d 前"


def health_icon(state: TargetState) -> str:
    if state.failures <= 0:
        return "🟢"
    try:
        return VERDICT_ICONS[Verdict(state.last_verdict)]
    except (ValueError, KeyError):
        return "🟠"


def probe_lines(probe: ProbeOutcome | None) -> str:
    if not probe:
        return ""
    lines = [f"{probe.icon} 判定：<b>{esc(probe.label)}</b> — {esc(probe.reason)}"]
    for node in probe.nodes:
        lines.append(f"   • {esc(node.brief())}")
    return "\n".join(lines)


def port_matrix(probe: ProbeOutcome | None) -> str:
    """国内外端口对照表 —— 这就是 ping.pe 给出的那种信息，只是自动跑。"""
    if not probe or not probe.ports:
        return ""
    lines = ["<b>端口对照</b>（国内 / 国外）"]
    for item in probe.ports:
        mark = " ← 节点端口" if item.port == probe.node_port else ""
        if item.cn == "fail" and item.os == "ok":
            hint = "被墙"
        elif item.os == "fail":
            hint = "服务本身不通"
        elif item.cn == "ok":
            hint = "正常"
        elif item.cn == "fail" and item.os == "untested":
            hint = "国外未测"
        else:
            hint = ""
        suffix = f" · {hint}" if hint else ""
        lines.append(f"  {item.line()}{suffix}{mark}")
    icmp = f"ICMP 国内 {probe.icmp_cn} / 国外 {probe.icmp_os}"
    icmp = icmp.replace("ok", "通").replace("fail", "不通").replace("untested", "未测")
    lines.append(f"  {icmp}")
    return "\n".join(lines)


def status_block(name: str, state: TargetState, detail: dict[str, Any], auto: bool, threshold: int) -> str:
    target = detail["target"]
    eip = detail.get("eip")
    probe = detail.get("probe")
    lines = [
        f"{health_icon(state)} <b>{esc(name)}</b>"
        + (f" · {esc(target.notes)}" if target.notes else ""),
        f"  实例 <code>{esc(target.instance_id)}</code> · 账号 {esc(target.account)}",
    ]
    if eip:
        bound = f" → {esc(eip.instance_id)}" if eip.instance_id else " （未绑定）"
        lines.append(f"  IP <code>{esc(eip.ip)}</code>{bound}")
        lines.append(f"  EIP <code>{esc(eip.allocation_id)}</code> · {esc(eip.status or '?')}")
    elif detail.get("error"):
        lines.append(f"  ⚠️ {esc(detail['error'])}")
    if target.dns_records:
        ports = ", ".join(str(p) for p in target.all_ports(detail.get("port") or 443))
        lines.append(f"  域名 {esc(', '.join(target.dns_records))}")
        lines.append(f"  探测端口 {ports}")
    lines.append(
        f"  连续异常 {state.failures}/{threshold} · 自动换IP {'开' if auto else '关'}"
        f" · 累计换 {state.switches} 次"
    )
    lines.append(f"  上次检查 {ago(state.last_check)} · 上次切换 {ago(state.last_switch)}")
    if probe:
        lines.append(probe_lines(probe))
        matrix = port_matrix(probe)
        if matrix:
            lines.append(matrix)
        if probe.advice:
            lines.append(f"  💡 {esc(probe.advice)}")
    elif state.last_reason:
        lines.append(f"  上次结论：{esc(state.last_reason)}")
    if state.paused_until and state.paused_until > time.time():
        lines.append(f"  ⏸ 冷却中，{ago(state.paused_until)}解除")
    return "\n".join(lines)


def switch_success_text(ev: dict[str, Any]) -> str:
    lines = [
        "✅ <b>EIP 更换成功</b>",
        "",
        f"🎯 目标：<code>{esc(ev.get('target'))}</code>"
        + (f" · 账号 {esc(ev['account'])}" if ev.get("account") else ""),
        f"📤 旧 IP：<code>{esc(ev.get('old_ip') or '-')}</code>",
        f"📥 新 IP：<code>{esc(ev.get('new_ip') or '-')}</code>",
        f"🧭 触发：{esc(ev.get('reason') or '自动检测')}",
    ]
    dns = ev.get("dns") or []
    if dns:
        ok = sum(1 for d in dns if d.get("ok") == "1")
        lines.append(f"🌐 Cloudflare：{ok}/{len(dns)} 条已更新")
        for d in dns:
            mark = "✓" if d.get("ok") == "1" else "✗"
            lines.append(f"   {mark} <code>{esc(d.get('name'))}</code> {esc(d.get('detail') or '')}")
    if ev.get("detail"):
        lines.append(f"🔎 验证：{esc(ev['detail'])}")
    for warning in ev.get("warnings") or []:
        lines.append(f"⚠️ {esc(warning)}")
    elapsed = ev.get("elapsed")
    if elapsed:
        lines.append(f"⏱ 耗时 {elapsed:.1f}s")
    lines.append(f"🕒 {ts(ev.get('ts'))}")
    return "\n".join(lines)


def switch_failed_text(ev: dict[str, Any]) -> str:
    lines = [
        "❌ <b>EIP 更换失败</b>",
        "",
        f"🎯 目标：<code>{esc(ev.get('target'))}</code>",
    ]
    if ev.get("old_ip"):
        lines.append(f"📤 旧 IP：<code>{esc(ev['old_ip'])}</code>")
    lines.append(f"💥 原因：{esc(ev.get('error') or '未知')}")
    dns = ev.get("dns") or []
    if dns:
        lines.append(f"🌐 DNS：{sum(1 for d in dns if d.get('ok') == '1')}/{len(dns)} 条成功")
    for warning in ev.get("warnings") or []:
        lines.append(f"⚠️ {esc(warning)}")
    lines.append(f"🕒 {ts(ev.get('ts'))}")
    return "\n".join(lines)


def switch_started_text(ev: dict[str, Any]) -> str:
    tag = "（手动）" if ev.get("manual") else "（自动）"
    return "\n".join(
        [
            f"🔁 <b>开始更换 EIP</b>{tag}",
            "",
            f"🎯 目标：<code>{esc(ev.get('target'))}</code>",
            f"📤 当前 IP：<code>{esc(ev.get('old_ip'))}</code>",
            f"🧭 原因：{esc(ev.get('reason'))}",
            f"🔎 {esc(ev.get('detail') or '')}",
            f"🕒 {ts(ev.get('ts'))}",
        ]
    )


def blocked_text(ev: dict[str, Any]) -> str:
    verdict = str(ev.get("verdict") or "")
    try:
        label = VERDICT_LABELS[Verdict(verdict)]
        icon = VERDICT_ICONS[Verdict(verdict)]
    except (ValueError, KeyError):
        label = str(ev.get("label") or "探测异常")
        icon = "⚠️"

    will = bool(ev.get("will_switch"))
    switchable = bool(ev.get("switchable", True))
    if will:
        title = f"{icon} <b>{esc(label)}，已确认，准备更换 IP</b>"
    elif not switchable:
        title = f"{icon} <b>{esc(label)}</b>（换 IP 无效，不自动更换）"
    else:
        title = f"{icon} <b>{esc(label)}</b>"

    lines = [
        title,
        "",
        f"🎯 目标：<code>{esc(ev.get('target'))}</code>",
        f"📤 IP：<code>{esc(ev.get('ip'))}</code>",
    ]
    if ev.get("count") and ev.get("threshold"):
        lines.append(f"📉 连续异常 {ev['count']}/{ev['threshold']} 次")
    lines.append(f"🔎 {esc(ev.get('detail') or '')}")
    if ev.get("matrix"):
        lines.append(str(ev["matrix"]))
    if ev.get("advice"):
        lines.append(f"💡 建议：{esc(ev['advice'])}")
    if will:
        lines.append("🔄 正在自动更换 IP…")
    elif not switchable:
        lines.append("ℹ️ 这类问题换 IP 解决不了，见上建议。确认仍要换可发 /switch。")
    elif ev.get("auto_off"):
        lines.append("ℹ️ 该目标自动换 IP 已关闭，需要手动 /switch。")
    else:
        lines.append("ℹ️ 尚未达到阈值，暂不动作。")
    if ev.get("pingpe"):
        lines.append(f"🔗 自查：{ev['pingpe']}")
    lines.append(f"🕒 {ts(ev.get('ts'))}")
    return "\n".join(lines)


def verdict_definitions_text() -> str:
    lines = ["<b>判定定义</b>", "", "<b>核心规则</b>：同一个端口，国内测一次、国外测一次。"]
    lines.append("")
    rows = [
        (Verdict.IP_BLOCKED, "国内连不上、国外能连，且这台 IP 没有别的端口能从国内连上", "换 IP 有效"),
        (Verdict.PORT_BLOCKED, "只有这个端口国内不通，同 IP 其它端口国内能连", "换端口最有效，换 IP 也可能有用"),
        (Verdict.TLS_BLOCKED, "TCP 能连，TLS 握手被断，国外 TLS 正常", "换 IP 无效，按 SNI/域名阻断"),
        (Verdict.DATA_BLOCKED, "TCP 与 TLS 都通，一传 HTTP 数据就被断", "换 IP 无效，按流量特征阻断"),
        (Verdict.SERVICE_DOWN, "这个端口国内外都连不上", "服务没起/安全组/防火墙，换 IP 无效"),
        (Verdict.OK, "国内能正常连上", "—"),
        (Verdict.UNKNOWN, "缺国内或国外探针，没法对比", "补探针"),
    ]
    for verdict, desc, action in rows:
        lines.append(f"{VERDICT_ICONS[verdict]} <b>{VERDICT_LABELS[verdict]}</b>：{desc}")
        if action != "—":
            lines.append(f"    → {action}")
    lines.append("")
    lines.append("<b>为什么不能靠 22 端口判断</b>：")
    lines.append("  • 22 通、443 不通 → 可能只是 443 服务挂了，也可能只封了 443")
    lines.append("  • 22 也不通 → 可能 22 被封，也可能 SSH 挂了")
    lines.append("  两种情况都说明不了 IP 是否被墙。只有「同一端口国内不通 + 国外通」才是墙。")
    lines.append("")
    lines.append("自动换 IP 只在判定为「IP 被墙」时触发（可在 switch.auto_switch_on 里加其它类型）。")
    return "\n".join(lines)


def recovered_text(ev: dict[str, Any]) -> str:
    return "\n".join(
        [
            "✅ <b>已恢复正常</b>",
            "",
            f"🎯 目标：<code>{esc(ev.get('target'))}</code>",
            f"📥 IP：<code>{esc(ev.get('ip'))}</code>",
            f"🔎 {esc(ev.get('detail') or '')}",
            f"🕒 {ts(ev.get('ts'))}",
        ]
    )


def service_down_text(ev: dict[str, Any]) -> str:
    """国内外都不通：服务/安全组问题，不是墙。"""
    lines = [
        "⚫ <b>服务不可用（不是被墙）</b>",
        "",
        f"🎯 目标：<code>{esc(ev.get('target'))}</code>",
        f"📤 IP：<code>{esc(ev.get('ip'))}</code>",
        f"🔎 {esc(ev.get('detail') or '')}",
    ]
    if ev.get("matrix"):
        lines.append(str(ev["matrix"]))
    lines.append(
        "💡 这个端口国内外都连不上，换 IP 解决不了。依次检查："
        "① 服务进程在监听吗（ss -lntp）② 阿里云安全组放行了吗 "
        "③ 系统防火墙（firewalld/ufw/iptables）④ 云盾/黑洞"
    )
    lines.append(f"🕒 {ts(ev.get('ts'))}")
    return "\n".join(lines)


def dns_text(ev: dict[str, Any]) -> str:
    dns = ev.get("dns") or []
    ok = sum(1 for d in dns if d.get("ok") == "1")
    lines = [
        f"🌐 <b>DNS 同步</b> {'（手动）' if ev.get('manual') else ''}".strip(),
        "",
        f"🎯 目标：<code>{esc(ev.get('target'))}</code>",
        f"📥 IP：<code>{esc(ev.get('ip'))}</code>",
        f"结果：{ok}/{len(dns)} 成功",
    ]
    for d in dns:
        mark = "✓" if d.get("ok") == "1" else "✗"
        lines.append(f"   {mark} <code>{esc(d.get('name'))}</code> {esc(d.get('detail') or '')}")
    lines.append(f"🕒 {ts(ev.get('ts'))}")
    return "\n".join(lines)


def settings_text(
    settings: Any,
    auto_states: dict[str, bool],
    auto_switch_on: list[str] | None = None,
) -> str:
    lines = [
        "⚙️ <b>当前设置</b>",
        "",
        f"自动换 IP：{'✅ 开' if settings.auto else '⛔ 关'}",
        f"检查间隔：{settings.interval}s",
        f"触发阈值：连续 {settings.failure_threshold} 次",
        f"冷却时间：{settings.cooldown}s",
        f"成功后释放旧 EIP：{'是' if settings.release_old else '否'}",
        f"频道通知：{'开' if settings.notify_channel else '关'}",
    ]
    if auto_switch_on:
        labels = ", ".join(VERDICT_LABELS.get(Verdict(v), v) for v in auto_switch_on)
        lines.append(f"自动换 IP 的判定类型：{labels}")
    if auto_states:
        lines.append("")
        lines.append("<b>目标开关</b>")
        for name, on in auto_states.items():
            lines.append(f"  {name}: {'开' if on else '关'}")
    lines.append("")
    lines.append("命令：/set interval 60 · /set threshold 3 · /set cooldown 900 · /set release on|off")
    lines.append("判定说明：/verdict")
    return "\n".join(lines)


def matrix_text(probe: ProbeOutcome | None) -> str:
    """告警里附带的国内外端口对照（纯文本，正则可读）。"""
    text = port_matrix(probe)
    if not text:
        return ""
    return text.replace("<b>", "").replace("</b>", "")


def pingpe_line(target: Any, ip: str = "") -> str:
    """给 /probe /status 附上 ping.pe 自查链接（人工复核）。"""
    if not ip:
        return ""
    port = getattr(target, "probe_port", 0) or 443
    host = f"{ip}:{port}"
    url = f"https://ping.pe/{host}"
    if getattr(target, "dns_records", None):
        url += f"?host={target.dns_records[0]}"
    return f"🔗 人工复核（ping.pe）：{esc(url)}"
