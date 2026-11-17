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


def layer_table(probe: ProbeOutcome | None) -> str:
    """把墙内/墙外每层结果列成表，便于一眼看出封在哪一层。"""
    if not probe or not probe.nodes:
        return ""
    order = ("icmp", "tcp", "tls", "http", "aux")
    rows = ["层 | 墙内 | 墙外"]
    for layer in order:
        cn_marks: list[str] = []
        os_marks: list[str] = []
        for node in probe.nodes:
            item = node.layers.get(layer)
            if item is None:
                continue
            mark = item.mark()
            if item.ok is False and item.kind:
                mark += f"({item.kind})"
            (cn_marks if node.zone == "cn" else os_marks).append(mark)
        if not cn_marks and not os_marks:
            continue
        names = {"icmp": "ICMP", "tcp": "TCP", "tls": "TLS", "http": "HTTP", "aux": "其它端口"}
        rows.append(f"{names[layer]} | {' '.join(cn_marks) or '–'} | {' '.join(os_marks) or '–'}")
    lines = ["<b>分层结果</b>"]
    for row in rows:
        cells = [c.strip() for c in row.split("|")]
        lines.append("  " + " · ".join(cells))
    return "\n".join(lines)


def status_block(name: str, state: TargetState, detail: dict[str, Any], auto: bool, threshold: int) -> str:
    target = detail["target"]
    eip = detail.get("eip")
    probe = detail.get("probe")
    lines = [
        f"{health_icon(state)} <b>{esc(name)}</b>"
        + (f" · {esc(target.notes)}" if target.notes else ""),
        f"  实例 <code>{esc(target.instance_id)}</code>",
    ]
    if eip:
        bound = f" → {esc(eip.instance_id)}" if eip.instance_id else " （未绑定）"
        lines.append(f"  IP <code>{esc(eip.ip)}</code>{bound}")
        lines.append(f"  EIP <code>{esc(eip.allocation_id)}</code> · {esc(eip.status or '?')}")
    elif detail.get("error"):
        lines.append(f"  ⚠️ {esc(detail['error'])}")
    if target.dns_records:
        port = target.probe_port or detail.get("port") or 443
        lines.append(f"  域名 {esc(', '.join(target.dns_records))} · 探测端口 {port}")
    lines.append(
        f"  连续异常 {state.failures}/{threshold} · 自动换IP {'开' if auto else '关'}"
        f" · 累计换 {state.switches} 次"
    )
    lines.append(f"  上次检查 {ago(state.last_check)} · 上次切换 {ago(state.last_switch)}")
    if probe:
        lines.append(probe_lines(probe))
        table = layer_table(probe)
        if table:
            lines.append(table)
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
        f"🎯 目标：<code>{esc(ev.get('target'))}</code>",
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
    if ev.get("advice"):
        lines.append(f"💡 建议：{esc(ev['advice'])}")
    if will:
        lines.append("🔄 正在自动更换 IP…")
    elif not switchable:
        lines.append("ℹ️ 这类封锁换 IP 通常无效，需要换端口/域名/协议。确认要换再发 /switch。")
    elif ev.get("auto_off"):
        lines.append("ℹ️ 该目标自动换 IP 已关闭，需要手动 /switch。")
    else:
        lines.append("ℹ️ 尚未达到阈值，暂不动作。")
    lines.append(f"🕒 {ts(ev.get('ts'))}")
    return "\n".join(lines)


def verdict_definitions_text() -> str:
    """给 /help 或 /verdict 用：每种封锁的定义和是否该换 IP。"""
    lines = ["<b>判定定义</b>", ""]
    rows = [
        (Verdict.IP_BLOCKED, "ping 可能通，但节点端口和其它端口全部连不上；墙外正常", "换 IP 有效"),
        (Verdict.PORT_BLOCKED, "只有节点端口不通，其它端口能连；墙外节点端口正常", "换 IP 无效，应换端口"),
        (Verdict.TLS_BLOCKED, "TCP 能建连，TLS 握手被重置/超时；墙外 TLS 正常", "换 IP 无效，按 SNI/域名阻断"),
        (Verdict.DATA_BLOCKED, "TCP 与 TLS 都通，一传 HTTP 数据就被断", "换 IP 无效，按流量特征阻断"),
        (Verdict.DOWN, "墙外也连不上，或端口根本没人监听", "实例/服务故障，先修服务"),
        (Verdict.OK, "各层都正常", "—"),
        (Verdict.UNKNOWN, "缺少墙内探针，无法区分被墙和故障", "补一个 zone: cn 的探针"),
    ]
    for verdict, desc, action in rows:
        lines.append(f"{VERDICT_ICONS[verdict]} <b>{VERDICT_LABELS[verdict]}</b>：{desc}")
        if action != "—":
            lines.append(f"    → {action}")
    lines.append("")
    lines.append("自动换 IP 只在判定为「IP 被墙」时触发（可在 switch.auto_switch_on 里加其它类型）。")
    return "\n".join(lines)


def service_down_text(ev: dict[str, Any]) -> str:
    """墙外也不通：是服务/实例故障，不是墙。"""
    return "\n".join(
        [
            "⚫ <b>服务不可用（不是被墙）</b>",
            "",
            f"🎯 目标：<code>{esc(ev.get('target'))}</code>",
            f"📤 IP：<code>{esc(ev.get('ip'))}</code>",
            f"🔎 {esc(ev.get('detail') or '')}",
            "💡 墙外节点也连不上，换 IP 解决不了。请检查：实例状态、安全组、"
            "系统防火墙、服务进程是否在监听该端口。",
            f"🕒 {ts(ev.get('ts'))}",
        ]
    )


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


def settings_text(settings: Any, auto_states: dict[str, bool], auto_switch_on: list[str] | None = None) -> str:
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
