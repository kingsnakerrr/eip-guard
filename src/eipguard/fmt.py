from __future__ import annotations

import html
import time
from typing import Any

from .detect.probe import ProbeOutcome
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
    return "🟠"


def probe_lines(probe: ProbeOutcome | None) -> str:
    if not probe:
        return ""
    icon = "🟢" if probe.ok else ("🔴" if probe.blocked else "🟠")
    lines = [f"{icon} 探测：{esc(probe.reason)}"]
    for node in probe.nodes:
        lines.append(f"   • {esc(node.brief())}")
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
        lines.append(f"  域名 {esc(', '.join(target.dns_records))}")
    lines.append(
        f"  连续失败 {state.failures}/{threshold} · 自动换IP {'开' if auto else '关'}"
        f" · 累计换 {state.switches} 次"
    )
    lines.append(f"  上次检查 {ago(state.last_check)} · 上次切换 {ago(state.last_switch)}")
    if probe:
        lines.append(probe_lines(probe))
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
    lines.append(f"🕒 {ts(ev.get('ts'))}")
    return "\n".join(lines)


def switch_started_text(ev: dict[str, Any]) -> str:
    tag = "（手动）" if ev.get("manual") else "（自动）"
    return "\n".join(
        [
            f"🚨 <b>检测到 IP 被墙，开始更换</b>{tag}",
            "",
            f"🎯 目标：<code>{esc(ev.get('target'))}</code>",
            f"📤 当前 IP：<code>{esc(ev.get('old_ip'))}</code>",
            f"🧭 原因：{esc(ev.get('reason'))}",
            f"🔎 {esc(ev.get('detail') or '')}",
            f"🕒 {ts(ev.get('ts'))}",
        ]
    )


def blocked_text(ev: dict[str, Any]) -> str:
    will = ev.get("will_switch")
    title = "🚨 <b>IP 被墙，已确认</b>" if will else "⚠️ <b>IP 探测异常</b>"
    lines = [
        title,
        "",
        f"🎯 目标：<code>{esc(ev.get('target'))}</code>",
        f"📤 IP：<code>{esc(ev.get('ip'))}</code>",
    ]
    if ev.get("count") and ev.get("threshold"):
        lines.append(f"📉 连续失败 {ev['count']}/{ev['threshold']} 次")
    lines.append(f"🔎 {esc(ev.get('detail') or '')}")
    if not will:
        lines.append("ℹ️ 尚未达到阈值，暂不动作")
    elif ev.get("auto_off"):
        lines.append("ℹ️ 该目标自动换 IP 已关闭，请手动 /switch")
    lines.append(f"🕒 {ts(ev.get('ts'))}")
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


def settings_text(settings: Any, auto_states: dict[str, bool]) -> str:
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
    if auto_states:
        lines.append("")
        lines.append("<b>目标开关</b>")
        for name, on in auto_states.items():
            lines.append(f"  {name}: {'开' if on else '关'}")
    lines.append("")
    lines.append("命令：/set interval 60 · /set threshold 3 · /set cooldown 900 · /set release on|off")
    return "\n".join(lines)
