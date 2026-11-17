from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.error import TelegramError
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
)

from . import fmt
from .config import Config
from .engine import Engine, SwitchResult
from .state import Settings, StateStore

log = logging.getLogger(__name__)

HELP = """<b>EIP Guard</b> · 阿里云 EIP 被墙自动更换

<b>查看</b>
/status — 全部目标状态（实时探测）
/status &lt;目标&gt; — 单个目标详情
/ip — 快速看当前 IP
/probe [目标] — 只做探测，不改动
/history — 最近事件

<b>操作</b>
/switch &lt;目标&gt; — 手动换 IP（会二次确认）
/switch all — 依次处理有问题的目标
/dns &lt;目标&gt; [ip] — 重新同步 Cloudflare 解析
/autoswitch — 全部目标自动换 IP 开/关
/auto &lt;目标&gt; on|off — 单个目标开关

<b>设置</b>
/settings — 查看
/set interval 60 — 检查间隔（秒）
/set threshold 3 — 连续失败几次才换
/set cooldown 900 — 两次更换最小间隔（秒）
/set release on|off — 成功后是否释放旧 EIP
/channel [频道id|off] — 通知频道
/bind — 把当前聊天设为管理员（仅首次）
/health — 依赖连通性自检
"""

SETTING_KEYS = {
    "interval": ("interval", int, 15, 86400),
    "threshold": ("failure_threshold", int, 1, 20),
    "cooldown": ("cooldown", int, 0, 86400),
    "release": ("release_old", "bool", 0, 0),
    "auto": ("auto", "bool", 0, 0),
}


def reply(update: Update, text: str, **kwargs: Any) -> Any:
    """统一的安全回复（effective_message 可能为 None）。"""
    message = update.effective_message
    if message is None:
        raise RuntimeError("没有可回复的消息")
    return message.reply_text(text, **kwargs)


def callback_chat_id(query: Any) -> int:
    message = getattr(query, "message", None)
    if message is None or not hasattr(message, "chat_id"):
        raise RuntimeError("回调消息不可用")
    return int(message.chat_id)


class BotApp:
    def __init__(
        self, cfg: Config, engine: Engine | None, store: StateStore, settings: Settings
    ) -> None:
        self.cfg = cfg
        self._engine: Engine | None = engine
        self.store = store
        self.settings = settings
        self.app: Application | None = None
        self.admin_ids: set[int] = set(cfg.admin_chat_ids)
        if not self.admin_ids and store.settings.get("admin_ids"):
            self.admin_ids = {int(x) for x in store.settings["admin_ids"]}
        self._started_at = time.time()

    @property
    def engine(self) -> Engine:
        if self._engine is None:
            raise RuntimeError("engine 尚未注入")
        return self._engine

    @engine.setter
    def engine(self, value: Engine) -> None:
        self._engine = value

    # ------------------------------------------------------------ 通知
    def _targets_for_notify(self) -> list[int]:
        out = list(self.admin_ids)
        if self.settings.notify_channel and (self.cfg.channel_id or self.store.channel_id):
            channel = self.store.channel_id or self.cfg.channel_id
            if channel and channel not in out:
                out.append(int(channel))
        return out

    async def notify(self, ev: dict[str, Any]) -> None:
        kind = ev.get("type")
        renderers = {
            "switch_started": fmt.switch_started_text,
            "switch_success": fmt.switch_success_text,
            "switch_failed": fmt.switch_failed_text,
            "blocked_confirmed": fmt.blocked_text,
            "blocked_suspect": fmt.blocked_text,
            "recovered": fmt.recovered_text,
            "dns_sync": fmt.dns_text,
            "auto_disabled": fmt.blocked_text,
        }
        renderer = renderers.get(str(kind))
        if not renderer:
            return
        if kind == "blocked_suspect":
            # 未达阈值只发给管理员，避免频道噪音
            targets = list(self.admin_ids)
        else:
            targets = self._targets_for_notify()
        if not targets or self.app is None:
            return
        text = renderer(ev)
        for chat_id in targets:
            try:
                await self.app.bot.send_message(
                    chat_id=chat_id, text=text, parse_mode=ParseMode.HTML, disable_web_page_preview=True
                )
            except TelegramError as exc:
                log.warning("发送到 %s 失败：%s", chat_id, exc)

    # ------------------------------------------------------------ 权限
    def is_admin(self, update: Update) -> bool:
        """只有 admin_ids 里的 chat 才算管理员。

        频道/群里的管理员由群主另行指定，这里不自动信任，避免任何人在群里 @ 机器人拿到权限。
        """
        chat = update.effective_chat
        if not chat:
            return False
        return chat.id in self.admin_ids

    async def _deny(self, update: Update) -> None:
        if update.effective_message:
            await reply(update, 
                "⛔ 未授权。管理员私聊机器人发送 /bind 完成绑定，或把 chat id 填进 TG_ADMIN_IDS。"
                f"\n你的 chat id：<code>{update.effective_chat.id if update.effective_chat else '?'}</code>",
                parse_mode=ParseMode.HTML,
            )

    async def _guard(self, update: Update) -> bool:
        if self.is_admin(update):
            return True
        await self._deny(update)
        return False

    # ------------------------------------------------------------ 命令
    async def cmd_start(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
        if not self.is_admin(update):
            await self._deny(update)
            return
        await reply(update, HELP, parse_mode=ParseMode.HTML)

    async def cmd_help(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        await self.cmd_start(update, ctx)

    async def cmd_bind(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        chat = update.effective_chat
        if not chat:
            return
        if self.admin_ids and chat.id not in self.admin_ids:
            await self._deny(update)
            return
        # 可选的口令，防止别人抢先绑定
        token = self.cfg.bind_token
        if token:
            supplied = (ctx.args or [""])[0]
            if supplied != token:
                await reply(update, "用法：/bind <绑定口令>（见 config 的 telegram.bind_token）")
                return
        elif self.admin_ids:
            await reply(update, "已有管理员，无需重复绑定。")
            return
        self.admin_ids.add(chat.id)
        self.store.settings["admin_ids"] = sorted(self.admin_ids)
        self.store.save()
        await reply(update, 
            f"✅ 已绑定管理员 chat id：<code>{chat.id}</code>\n"
            "建议同时也填进 .env 的 TG_ADMIN_IDS，重启后依然有效。",
            parse_mode=ParseMode.HTML,
        )

    async def cmd_status(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if not await self._guard(update):
            return
        args = ctx.args or []
        names = [args[0]] if args else [t.name for t in self.cfg.targets]
        for name in names:
            try:
                self.cfg.target(name)
            except KeyError:
                await reply(update, f"没有目标 <code>{name}</code>", parse_mode=ParseMode.HTML)
                continue
            msg = await reply(update, f"⏳ 检查 {name} …")
            detail = await self.engine.inspect(name)
            state = self.engine.target_state(name)
            auto = self.settings.auto and state.auto
            await msg.edit_text(
                fmt.status_block(name, state, detail, auto, self.settings.failure_threshold),
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
            )
        self.store.save()

    async def cmd_ip(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
        if not await self._guard(update):
            return
        lines = ["<b>当前 IP</b>"]
        for target in self.cfg.targets:
            try:
                eip = await self.engine.resolve_eip(target)
            except Exception as exc:  # noqa: BLE001
                lines.append(f"• {target.name}: ⚠️ {fmt.esc(exc)}")
                continue
            if eip:
                lines.append(f"• {target.name}: <code>{fmt.esc(eip.ip)}</code> ({fmt.esc(eip.status or '?')})")
                if target.dns_records:
                    lines.append(f"   ↳ {fmt.esc(', '.join(target.dns_records))}")
            else:
                lines.append(f"• {target.name}: 无绑定 EIP")
        await reply(update, "\n".join(lines), parse_mode=ParseMode.HTML)

    async def cmd_probe(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if not await self._guard(update):
            return
        args = ctx.args or []
        names = [args[0]] if args else [t.name for t in self.cfg.targets]
        for name in names:
            try:
                detail = await self.engine.inspect(name)
            except KeyError:
                await reply(update, f"没有目标 {name}")
                continue
            probe = detail.get("probe")
            eip = detail.get("eip")
            if not probe:
                await reply(update, f"{name}: {detail.get('error') or '无探测结果'}")
                continue
            icon = "🟢" if probe.ok else ("🔴" if probe.blocked else "🟠")
            verdict = "正常" if probe.ok else ("判定被墙" if probe.blocked else "异常但不确定是墙")
            text = "\n".join(
                [
                    f"{icon} <b>{fmt.esc(name)}</b> · {fmt.esc(eip.ip if eip else '-')}",
                    f"结论：{verdict}",
                    fmt.probe_lines(probe),
                ]
            )
            await reply(update, text, parse_mode=ParseMode.HTML)

    async def cmd_switch(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if not await self._guard(update):
            return
        args = ctx.args or []
        if not args:
            names = [t.name for t in self.cfg.targets]
            kb = [
                [InlineKeyboardButton(f"🔁 {n}", callback_data=f"switch:{n}")] for n in names
            ]
            await reply(update, 
                "选择要更换 IP 的目标（会先确认）：",
                reply_markup=InlineKeyboardMarkup(kb),
            )
            return
        name = args[0]
        if name == "all":
            lines = []
            for target in self.cfg.targets:
                detail = await self.engine.inspect(target.name)
                probe = detail.get("probe")
                if probe and not probe.ok:
                    lines.append(f"• {target.name}: {probe.reason}")
            if not lines:
                await reply(update, "✅ 所有目标探测正常，无需更换。")
                return
            kb = [[InlineKeyboardButton("⚠️ 仍要全部更换", callback_data="switchall:confirm")],
                  [InlineKeyboardButton("取消", callback_data="cancel")]]
            await reply(update, 
                "以下目标异常：\n" + "\n".join(lines), reply_markup=InlineKeyboardMarkup(kb)
            )
            return
        if name not in {t.name for t in self.cfg.targets}:
            await reply(update, f"没有目标 {name}")
            return
        state = self.engine.target_state(name)
        kb = [
            [
                InlineKeyboardButton("✅ 确认更换", callback_data=f"confirm:{name}"),
                InlineKeyboardButton("取消", callback_data="cancel"),
            ]
        ]
        await reply(update, 
            f"⚠️ 即将为 <b>{fmt.esc(name)}</b> 更换 EIP\n"
            f"当前 IP：<code>{fmt.esc(state.current_ip or '-')}</code>\n"
            "流程：分配新 EIP → 解绑旧 EIP → 绑定新 EIP → 更新 Cloudflare → 验证 → 释放旧 EIP",
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup(kb),
        )

    async def cmd_dns(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if not await self._guard(update):
            return
        args = ctx.args or []
        if not args:
            names = [t.name for t in self.cfg.targets]
            kb = [[InlineKeyboardButton(f"🌐 {n}", callback_data=f"dns:{n}")] for n in names]
            await reply(update, "同步哪个目标的域名解析？", reply_markup=InlineKeyboardMarkup(kb))
            return
        name = args[0]
        ip = args[1] if len(args) > 1 else ""
        try:
            results = await self.engine.manual_dns(name, ip)
        except Exception as exc:  # noqa: BLE001
            await reply(update, f"❌ {exc}")
            return
        ok = sum(1 for r in results if r["ok"] == "1")
        lines = [f"🌐 <b>{fmt.esc(name)}</b> DNS：{ok}/{len(results)} 成功"]
        for r in results:
            mark = "✓" if r["ok"] == "1" else "✗"
            lines.append(f"{mark} <code>{fmt.esc(r['name'])}</code> {fmt.esc(r['detail'])}")
        await reply(update, "\n".join(lines), parse_mode=ParseMode.HTML)

    async def cmd_settings(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
        if not await self._guard(update):
            return
        states = {t.name: self.store.get(t.name).auto for t in self.cfg.targets}
        await reply(update, 
            fmt.settings_text(self.settings, states), parse_mode=ParseMode.HTML
        )

    async def cmd_set(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if not await self._guard(update):
            return
        args = ctx.args or []
        if len(args) < 2:
            await reply(update, 
                "用法：/set interval 60 | threshold 3 | cooldown 900 | release on|off | auto on|off"
            )
            return
        key, raw_value = args[0].lower(), args[1].lower()
        if key not in SETTING_KEYS:
            await reply(update, f"未知设置 {key}\n可选：{', '.join(SETTING_KEYS)}")
            return
        attr, cast, minimum, maximum = SETTING_KEYS[key]
        if cast == "bool":
            if raw_value not in {"on", "off", "true", "false", "1", "0", "开", "关"}:
                await reply(update, "只能是 on 或 off")
                return
            value: Any = raw_value in {"on", "true", "1", "开"}
        else:
            try:
                value = int(raw_value)
            except ValueError:
                await reply(update, "需要一个整数")
                return
            if not (minimum <= value <= maximum):
                await reply(update, f"{key} 范围 {minimum}~{maximum}")
                return
        setattr(self.settings, attr, value)
        self.store.settings.update(self.settings.to_dict())
        if key == "auto":
            for t in self.cfg.targets:
                self.store.get(t.name).auto = bool(value)
        self.store.save()
        await reply(update, f"✅ 已设置 {key} = {value}")

    async def cmd_autoswitch(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
        if not await self._guard(update):
            return
        self.settings.auto = not self.settings.auto
        for t in self.cfg.targets:
            self.store.get(t.name).auto = self.settings.auto
        self.store.settings.update(self.settings.to_dict())
        self.store.save()
        await reply(update, 
            f"自动换 IP 已{'开启 ✅' if self.settings.auto else '关闭 ⛔'}（所有目标）"
        )

    async def cmd_auto(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if not await self._guard(update):
            return
        args = ctx.args or []
        if len(args) < 2 or args[1].lower() not in {"on", "off", "开", "关"}:
            await reply(update, "用法：/auto 目标名 on|off")
            return
        name, flag = args[0], args[1].lower() in {"on", "开"}
        if name not in {t.name for t in self.cfg.targets}:
            await reply(update, f"没有目标 {name}")
            return
        self.store.get(name).auto = flag
        self.store.save()
        await reply(update, f"{name} 自动换 IP：{'开 ✅' if flag else '关 ⛔'}")

    async def cmd_channel(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if not await self._guard(update):
            return
        args = ctx.args or []
        if not args:
            current = self.store.channel_id or self.cfg.channel_id
            await reply(update, 
                f"当前频道：<code>{current or '未设置'}</code>\n"
                "设置：/channel -1001234567890\n关闭：/channel off\n"
                "（机器人需要是频道管理员）",
                parse_mode=ParseMode.HTML,
            )
            return
        if args[0].lower() in {"off", "none", "0"}:
            self.store.channel_id = None
            self.settings.notify_channel = False
            self.store.settings.update(self.settings.to_dict())
            self.store.save()
            await reply(update, "已关闭频道通知")
            return
        try:
            chat_id = int(args[0])
        except ValueError:
            await reply(update, "频道 id 需要是数字，例如 -1001234567890")
            return
        self.store.channel_id = chat_id
        self.settings.notify_channel = True
        self.store.settings.update(self.settings.to_dict())
        self.store.save()
        ok = "✅"
        try:
            assert self.app is not None
            await self.app.bot.send_message(
                chat_id=chat_id, text="✅ EIP Guard 通知频道已连接，后续告警与更换结果会发到这里。"
            )
        except TelegramError as exc:
            ok = f"⚠️ 测试消息发送失败：{exc}\n请确认机器人已在频道中并设为管理员。"
        await reply(update, f"{ok}\n频道已设为 <code>{chat_id}</code>", parse_mode=ParseMode.HTML)

    async def cmd_history(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
        if not await self._guard(update):
            return
        items = self.store.history[-15:]
        if not items:
            await reply(update, "还没有事件记录")
            return
        lines = ["<b>最近事件</b>"]
        for ev in reversed(items):
            kind = str(ev.get("type"))
            icon = {
                "switch_success": "✅",
                "switch_failed": "❌",
                "switch_started": "🔁",
                "blocked_confirmed": "🚨",
                "blocked_suspect": "⚠️",
                "recovered": "🟢",
                "dns_sync": "🌐",
                "auto_disabled": "⛔",
            }.get(kind, "•")
            detail = ev.get("new_ip") or ev.get("ip") or ev.get("old_ip") or ""
            extra = ev.get("error") or ev.get("detail") or ""
            extra = str(extra)[:60]
            lines.append(f"{icon} {fmt.ts(ev.get('ts'))} <code>{fmt.esc(ev.get('target'))}</code> {fmt.esc(detail)} {fmt.esc(extra)}")
        await reply(update, "\n".join(lines), parse_mode=ParseMode.HTML)

    async def cmd_health(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
        if not await self._guard(update):
            return
        msg = await reply(update, "⏳ 自检中…")
        lines = ["<b>自检</b>"]
        # 阿里云
        try:
            target = self.cfg.targets[0]
            eip = await self.engine.resolve_eip(target)
            lines.append(f"✅ 阿里云：{fmt.esc(eip.ip) if eip else '连通，但未找到 EIP'}")
        except Exception as exc:  # noqa: BLE001
            lines.append(f"❌ 阿里云：{fmt.esc(exc)}")
        # Cloudflare
        try:
            zone_id = await self.engine.cloudflare.resolve_zone_id()
            lines.append(f"✅ Cloudflare zone：<code>{fmt.esc(zone_id)}</code>")
        except Exception as exc:  # noqa: BLE001
            lines.append(f"❌ Cloudflare：{fmt.esc(exc)}")
        # 探针
        try:
            probe = await self.engine.probe_once("1.1.1.1", 443)
            lines.append(f"✅ 探针：{fmt.esc(probe.summary[:300])}")
        except Exception as exc:  # noqa: BLE001
            lines.append(f"❌ 探针：{fmt.esc(exc)}")
        channel = self.store.channel_id or self.cfg.channel_id
        lines.append(f"ℹ️ 管理员 {len(self.admin_ids)} 人 · 频道 <code>{channel or '无'}</code>")
        lines.append(f"ℹ️ 运行 {int((time.time() - self._started_at) // 3600)}h")
        await msg.edit_text("\n".join(lines), parse_mode=ParseMode.HTML)

    # ------------------------------------------------------------ 回调
    async def on_callback(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
        query = update.callback_query
        if not query:
            return
        if not self.is_admin(update):
            await query.answer("未授权", show_alert=True)
            return
        data = query.data or ""
        await query.answer()
        if data == "cancel":
            await query.edit_message_text("已取消")
            return
        if data.startswith("switch:"):
            name = data.split(":", 1)[1]
            await query.edit_message_text(
                f"⚠️ 确认为 <b>{fmt.esc(name)}</b> 更换 EIP？",
                parse_mode=ParseMode.HTML,
                reply_markup=InlineKeyboardMarkup(
                    [
                        [
                            InlineKeyboardButton("✅ 确认", callback_data=f"confirm:{name}"),
                            InlineKeyboardButton("取消", callback_data="cancel"),
                        ]
                    ]
                ),
            )
            return
        if data.startswith("dns:"):
            name = data.split(":", 1)[1]
            try:
                results = await self.engine.manual_dns(name)
                ok = sum(1 for r in results if r["ok"] == "1")
                await query.edit_message_text(
                    f"🌐 {name} DNS：{ok}/{len(results)} 成功\n"
                    + "\n".join(f"{'✓' if r['ok'] == '1' else '✗'} {r['name']} {r['detail']}" for r in results)
                )
            except Exception as exc:  # noqa: BLE001
                await query.edit_message_text(f"❌ {exc}")
            return
        if data.startswith("confirm:"):
            name = data.split(":", 1)[1]
            await self._run_switch(callback_chat_id(query), name)
            return
        if data == "switchall:confirm":
            chat_id = callback_chat_id(query)
            await query.edit_message_text("已开始处理异常目标…")
            for target in self.cfg.targets:
                detail = await self.engine.inspect(target.name)
                probe = detail.get("probe")
                if probe and not probe.ok:
                    await self._run_switch(chat_id, target.name)
            return

    async def _run_switch(self, chat_id: int, name: str) -> None:
        assert self.app is not None
        progress = await self.app.bot.send_message(
            chat_id, f"⏳ 正在为 <b>{fmt.esc(name)}</b> 更换 EIP，请稍候…", parse_mode=ParseMode.HTML
        )
        result: SwitchResult = await self.engine.switch(name, reason="手动：Telegram 命令", manual=True)
        text = self.render_result(result)
        try:
            await progress.edit_text(text, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
        except TelegramError:
            await self.app.bot.send_message(chat_id, text, parse_mode=ParseMode.HTML)

    def render_result(self, result: SwitchResult) -> str:
        if result.ok:
            head = f"✅ <b>{fmt.esc(result.target)}</b> 更换成功"
        else:
            head = f"❌ <b>{fmt.esc(result.target)}</b> 更换失败"
        lines = [head, ""]
        if result.old_ip:
            lines.append(f"📤 旧 IP：<code>{fmt.esc(result.old_ip)}</code>")
        if result.new_ip:
            lines.append(f"📥 新 IP：<code>{fmt.esc(result.new_ip)}</code>")
        if result.error:
            lines.append(f"💥 {fmt.esc(result.error)}")
        if result.dns:
            ok = sum(1 for d in result.dns if d.get("ok") == "1")
            lines.append(f"🌐 DNS：{ok}/{len(result.dns)} 成功")
            for d in result.dns:
                lines.append(f"   {'✓' if d['ok'] == '1' else '✗'} <code>{fmt.esc(d['name'])}</code>")
        if result.verify:
            lines.append(f"🔎 验证：{fmt.esc(result.verify.reason)}")
        for warning in result.warnings:
            lines.append(f"⚠️ {fmt.esc(warning)}")
        if result.steps:
            lines.append("")
            lines.append("<b>步骤</b>")
            for step in result.steps[-12:]:
                lines.append(f"· {fmt.esc(step)}")
        lines.append(f"⏱ {result.elapsed:.1f}s")
        return "\n".join(lines)

    # ------------------------------------------------------------ 启动
    def build(self) -> Application:
        app = Application.builder().token(self.cfg.telegram_token).build()
        self.app = app
        app.add_handler(CommandHandler("start", self.cmd_start))
        app.add_handler(CommandHandler("help", self.cmd_help))
        app.add_handler(CommandHandler("bind", self.cmd_bind))
        app.add_handler(CommandHandler("status", self.cmd_status))
        app.add_handler(CommandHandler("ip", self.cmd_ip))
        app.add_handler(CommandHandler("probe", self.cmd_probe))
        app.add_handler(CommandHandler("check", self.cmd_probe))
        app.add_handler(CommandHandler("switch", self.cmd_switch))
        app.add_handler(CommandHandler("dns", self.cmd_dns))
        app.add_handler(CommandHandler("settings", self.cmd_settings))
        app.add_handler(CommandHandler("set", self.cmd_set))
        app.add_handler(CommandHandler("autoswitch", self.cmd_autoswitch))
        app.add_handler(CommandHandler("auto", self.cmd_auto))
        app.add_handler(CommandHandler("channel", self.cmd_channel))
        app.add_handler(CommandHandler("history", self.cmd_history))
        app.add_handler(CommandHandler("health", self.cmd_health))
        app.add_handler(CallbackQueryHandler(self.on_callback))
        return app

    async def run(self) -> None:
        app = self.build()
        await app.initialize()
        await app.start()
        if app.updater is not None:
            await app.updater.start_polling(drop_pending_updates=True)
        log.info("Telegram 机器人已启动")
        # 启动通知
        for chat_id in self._targets_for_notify():
            try:
                await app.bot.send_message(
                    chat_id,
                    "🟢 <b>EIP Guard 已启动</b>\n"
                    f"监控目标：{', '.join(t.name for t in self.cfg.targets)}\n"
                    f"检查间隔 {self.settings.interval}s · 阈值 {self.settings.failure_threshold} 次 · "
                    f"自动 {'开' if self.settings.auto else '关'}\n发送 /help 查看命令",
                    parse_mode=ParseMode.HTML,
                )
            except TelegramError as exc:
                log.warning("启动通知发送失败 %s: %s", chat_id, exc)
        await asyncio.Event().wait()
