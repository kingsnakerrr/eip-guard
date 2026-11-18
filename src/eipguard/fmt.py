from __future__ import annotations

import html
import time
from typing import Any


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


def pingpe_line(ip: str, port: int = 0, host: str = "") -> str:
    """人工复核链接。"""
    if not ip:
        return ""
    url = f"https://ping.pe/{ip}:{port}" if port else f"https://ping.pe/{ip}"
    if host:
        url += f"?host={host}"
    return f'🔗 <a href="{esc(url)}">ping.pe 自查</a>'


# ---------------------------------------------------------------- 进度推送
def started_text(ev: dict[str, Any]) -> str:
    dns = ev.get("dns") or []
    lines = [
        "🔁 <b>开始更换 IP</b>",
        "",
        f"🎯 目标：<code>{esc(ev.get('target'))}</code>"
        + (f" · 账号 {esc(ev['account'])}" if ev.get("account") else ""),
        f"📤 当前 IP：<code>{esc(ev.get('old_ip'))}</code>",
        f"🧭 触发：{esc(ev.get('reason') or '手动')}",
    ]
    if dns:
        tag = "（自动发现）" if ev.get("discovered") else ""
        lines.append(f"🌐 待更新域名{tag}：{esc(', '.join(dns))}")
    elif ev.get("warnings"):
        lines.append("⚠️ 本次只换 IP，不改域名（原因见下）")
    else:
        lines.append("ℹ️ 没有域名需要更新")
    for warning in ev.get("warnings") or []:
        lines.append(f"⚠️ {esc(warning)}")
    lines.append("")
    lines.append("流程：分配新 IP → 释放旧 IP → 绑定 → 改 CF 解析")
    return "\n".join(lines)


def allocated_text(ev: dict[str, Any]) -> str:
    return "\n".join(
        [
            "✅ <b>已分配新 IP</b>",
            "",
            f"🎯 目标：<code>{esc(ev.get('target'))}</code>",
            f"📥 新 IP：<code>{esc(ev.get('new_ip'))}</code>",
            f"🆔 EIP：<code>{esc(ev.get('new_allocation_id'))}</code>",
            "",
            "下一步：释放旧 IP → 绑定新 IP",
        ]
    )


def released_text(ev: dict[str, Any]) -> str:
    return "\n".join(
        [
            "✅ <b>旧 IP 已释放（停止计费）</b>",
            "",
            f"🎯 目标：<code>{esc(ev.get('target'))}</code>",
            f"📤 旧 IP：<code>{esc(ev.get('old_ip'))}</code>",
            f"🆔 已释放：<code>{esc(ev.get('allocation_id'))}</code>",
            "",
            "下一步：绑定新 IP 到实例",
        ]
    )


def bound_text(ev: dict[str, Any]) -> str:
    return "\n".join(
        [
            "✅ <b>新 IP 已绑定到实例</b>",
            "",
            f"🎯 目标：<code>{esc(ev.get('target'))}</code>",
            f"📥 新 IP：<code>{esc(ev.get('new_ip'))}</code>",
            f"🖥 实例：<code>{esc(ev.get('instance_id'))}</code>",
            "",
            "下一步：更新 Cloudflare 解析",
        ]
    )


def dns_text(ev: dict[str, Any]) -> str:
    dns = ev.get("dns") or []
    ok = sum(1 for d in dns if d.get("ok") == "1")
    lines = [
        f"✅ <b>Cloudflare 解析已更新</b>（{ok}/{len(dns)}）",
        "",
        f"🎯 目标：<code>{esc(ev.get('target'))}</code>",
        f"📥 指向：<code>{esc(ev.get('new_ip') or ev.get('ip'))}</code>",
        "",
    ]
    for d in dns:
        mark = "✓" if d.get("ok") == "1" else "✗"
        detail = d.get("detail") or ""
        name = d.get("name") or ""
        if detail.startswith(name):
            detail = detail[len(name):].lstrip(" →")
        lines.append(f"  {mark} <code>{esc(name)}</code> {esc(detail)}")
    if ok < len(dns):
        lines.append("")
        lines.append("⚠️ 有记录没更新成功，检查域名是否在同一个 zone、Token 是否有权限")
    return "\n".join(lines)


def success_text(ev: dict[str, Any]) -> str:
    lines = [
        "🎉 <b>换 IP 全部完成</b>",
        "",
        f"🎯 目标：<code>{esc(ev.get('target'))}</code>"
        + (f" · 账号 {esc(ev['account'])}" if ev.get("account") else ""),
        f"📤 旧 IP：<code>{esc(ev.get('old_ip') or '-')}</code>"
        + ("（已释放）" if ev.get("old_released") else "（未释放，仍在计费）"),
        f"📥 新 IP：<code>{esc(ev.get('new_ip') or '-')}</code>",
    ]
    dns = ev.get("dns") or []
    if dns:
        ok = sum(1 for d in dns if d.get("ok") == "1")
        lines.append(f"🌐 解析：{ok}/{len(dns)} 条已指向新 IP")
        for d in dns:
            mark = "✓" if d.get("ok") == "1" else "✗"
            lines.append(f"   {mark} <code>{esc(d.get('name'))}</code>")
    elif ev.get("warnings"):
        lines.append("🌐 域名：本次未更新")
    for warning in ev.get("warnings") or []:
        lines.append(f"⚠️ {esc(warning)}")
    elapsed = ev.get("elapsed")
    if elapsed:
        lines.append(f"⏱ 耗时 {elapsed:.1f}s")
    lines.append(f"🕒 {ts(ev.get('ts'))}")
    link = pingpe_line(ev.get("new_ip") or "", 443)
    if link:
        lines.append(link)
    return "\n".join(lines)


def failed_text(ev: dict[str, Any]) -> str:
    lines = [
        "❌ <b>换 IP 失败</b>",
        "",
        f"🎯 目标：<code>{esc(ev.get('target'))}</code>"
        + (f" · 账号 {esc(ev['account'])}" if ev.get("account") else ""),
    ]
    if ev.get("old_ip"):
        lines.append(f"📤 旧 IP：<code>{esc(ev['old_ip'])}</code>"
                     + ("（已释放）" if ev.get("old_released") else ""))
    if ev.get("new_ip"):
        lines.append(f"📥 新 IP：<code>{esc(ev['new_ip'])}</code>")
    lines.append(f"💥 原因：{esc(ev.get('error') or '未知')}")
    steps = ev.get("steps") or []
    if steps:
        lines.append("")
        lines.append("<b>过程</b>")
        for step in steps[-10:]:
            lines.append(f"· {esc(step)}")
    lines.append(f"🕒 {ts(ev.get('ts'))}")
    return "\n".join(lines)


# ---------------------------------------------------------------- 查看
def target_detail(name: str, detail: dict[str, Any], records: list[dict[str, str]] | None = None) -> str:
    target = detail["target"]
    eip = detail.get("eip")
    lines = [
        f"🎯 <b>{esc(name)}</b>" + (f" · {esc(target.notes)}" if target.notes else ""),
        f"  账号 <code>{esc(target.account)}</code> · 实例 <code>{esc(target.instance_id)}</code>",
    ]
    if eip:
        lines.append(f"  IP <code>{esc(eip.ip)}</code>" + (f" → {esc(eip.instance_id)}" if eip.instance_id else " （未绑定）"))
        lines.append(f"  EIP <code>{esc(eip.allocation_id)}</code> · {esc(eip.status or '?')}")
    elif detail.get("error"):
        lines.append(f"  ⚠️ {esc(detail['error'])}")
    if target.dns_records:
        lines.append(f"  🌐 {esc(', '.join(target.dns_records))}")
    if records:
        lines.append("")
        lines.append("<b>当前解析</b>")
        for rec in records:
            lines.append(f"  {esc(rec['name'])} → <code>{esc(rec['content'])}</code>")
    if eip and target.dns_records:
        lines.append("")
        lines.append(pingpe_line(eip.ip, 443, target.dns_records[0]))
    return "\n".join(lines)


def overview_text(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "还没有配置实例。用 /target add 添加，或直接改 config.yaml。"
    lines = ["<b>当前实例</b>", ""]
    for row in rows:
        target = row["target"]
        eip = row.get("eip")
        if eip:
            ip = f"<code>{esc(eip.ip)}</code>"
            state = esc(eip.status or "?")
        else:
            ip = "—"
            state = "查询失败" if row.get("error") else "无 EIP"
        dns = len(target.dns_records)
        lines.append(f"• <b>{esc(target.name)}</b> [{esc(target.account)}] {ip} · {state} · {dns} 条域名")
    lines.append("")
    lines.append("换 IP：/switch 目标名　详情：/status 目标名")
    return "\n".join(lines)


def accounts_text(accounts: list[Any], counts: dict[str, int]) -> str:
    if not accounts:
        return "还没有阿里云账号。用 /account add 添加。"
    lines = ["<b>阿里云账号</b>", ""]
    for acc in accounts:
        n = counts.get(acc.name, 0)
        lines.append(f"• <b>{esc(acc.name)}</b> · <code>{esc(acc.access_key_id[:8])}…</code> · {esc(acc.region)} · {n} 台实例")
    lines.append("")
    lines.append("添加：/account add　删除：/account del 名字　改地域：/account region 名字 cn-hongkong")
    return "\n".join(lines)


def settings_text(cfg: Any) -> str:
    cf = cfg.cloudflare
    lines = [
        "⚙️ <b>设置</b>",
        "",
        f"实测后释放旧 IP：{'✅ 是' if cfg.switch.release_old else '⛔ 否（会继续计费）'}",
        f"分配重试次数：{cfg.switch.max_attempts}",
        f"Cloudflare 域名：<code>{esc(cf.zone_name or cf.zone_id or '未设置')}</code>",
        f"CF 代理（小黄云）：{'开' if cf.proxied else '关'}",
        f"解析 TTL：{cf.ttl}s",
        f"频道通知：<code>{cfg.channel_id or '未设置'}</code>",
        f"管理员：{len(cfg.admin_chat_ids)} 人",
        f"阿里云账号：{len(cfg.accounts)} 个 · 实例：{len(cfg.targets)} 台",
    ]
    lines.append("")
    lines.append("改设置：/set release on|off · /set ttl 60 · /set proxied on|off")
    return "\n".join(lines)


def help_text() -> str:
    return """<b>EIP Guard</b> · 阿里云 EIP 手动换 IP + Cloudflare 解析

<b>换 IP（手动）</b>
/switch 目标名 — 换 IP：释放旧 IP → 绑定新 IP → 改解析
/switch all — 全部实例依次换
/dns 目标名 [ip] — 只重同步解析

<b>查看</b>
/status — 全部实例和当前 IP
/status 目标名 — 单个详情 + 当前解析
/accounts — 阿里云账号列表
/targets — 实例列表
/settings — 当前设置
/history — 最近操作记录

<b>管理（也可后期在 SSH 里改 config.yaml）</b>
/account add 名字 AK SK [地域]
/account del 名字
/account region 名字 地域
/target add 名字 账号 实例ID [域名...]
/target del 名字
/target dns 名字 域名1 域名2
/cf TOKEN 域名 — 设置 Cloudflare
/cf check [实例] — 看哪些域名指向当前 IP
/set release on|off — 换完是否释放旧 IP
/set proxied on|off — CF 小黄云
/channel -100xxx — 通知频道
/bind 口令 — 绑定自己为管理员
/health — 依赖自检

<b>说明</b>：不自动检测、不自动换。你发现被墙后手动发 /switch。
每一步（释放成功、拿到新 IP、解析成功）都会推送到你和频道。
"""


def help_short() -> str:
    return (
        "<b>常用命令</b>\n"
        "/status — 看 IP\n"
        "/switch 目标名 — 换 IP\n"
        "/accounts — 账号\n"
        "/targets — 实例\n"
        "/settings — 设置\n"
        "/help — 全部命令"
    )
