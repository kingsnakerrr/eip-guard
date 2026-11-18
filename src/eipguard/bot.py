from __future__ import annotations

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
    ConversationHandler,
    MessageHandler,
    filters,
)

from . import fmt
from .cloud.aliyun import AliyunError, AliyunVpc
from .cloud.cloudflare import Cloudflare, CloudflareError
from .config import Account, Config, ConfigError, Target
from .engine import Engine

log = logging.getLogger(__name__)

# 对话状态
ASK_ACCOUNT_NAME, ASK_ACCOUNT_AK, ASK_ACCOUNT_SK, ASK_ACCOUNT_REGION = range(4)
ASK_CF_TOKEN, ASK_CF_ZONE = range(10, 12)
ASK_TARGET_NAME, ASK_TARGET_ACCOUNT, ASK_TARGET_INSTANCE, ASK_TARGET_DNS = range(20, 24)
ASK_BIND = 30


def reply(update: Update, text: str, **kwargs: Any) -> Any:
    message = update.effective_message
    if message is None:
        raise RuntimeError("没有可回复的消息")
    return message.reply_text(text, **kwargs)


def msg_text(update: Update) -> str:
    """取用户发来的文本（可能为 None）。"""
    message = update.effective_message
    if message is None or message.text is None:
        return ""
    return message.text.strip()


def chat_id_of(update: Update) -> int:
    chat = update.effective_chat
    if chat is None:
        raise RuntimeError("没有 chat")
    return int(chat.id)


async def _delete_message(update: Update) -> None:
    """删掉含密钥的消息（失败无所谓）。"""
    message = update.effective_message
    if message is None:
        return
    try:
        await message.delete()
    except TelegramError:
        pass


def safe_chat_id(update: Update) -> int | None:
    chat = update.effective_chat
    return int(chat.id) if chat is not None else None


def _chat_id_str(update: Update) -> str:
    chat = update.effective_chat
    return str(chat.id) if chat is not None else "?"


def callback_chat_id(query: Any) -> int:
    message = getattr(query, "message", None)
    if message is None or not hasattr(message, "chat_id"):
        raise RuntimeError("回调消息不可用")
    return int(message.chat_id)


class BotApp:
    def __init__(self, cfg: Config, engine: Engine | None) -> None:
        self.cfg = cfg
        self._engine = engine
        self.app: Application | None = None
        self.admin_ids: set[int] = set(cfg.admin_chat_ids)
        self._started_at = time.time()
        self.history: list[dict[str, Any]] = []
        self._await_instance = False
        self._await_dns = False
        self._pending: dict[str, Any] = {}

    @property
    def engine(self) -> Engine:
        if self._engine is None:
            raise RuntimeError("engine 尚未注入")
        return self._engine

    @engine.setter
    def engine(self, value: Engine) -> None:
        self._engine = value

    # ------------------------------------------------------------ 通知
    def _notify_targets(self) -> list[int]:
        out = list(self.admin_ids)
        if self.cfg.channel_id and self.cfg.channel_id not in out:
            out.append(int(self.cfg.channel_id))
        return out

    async def notify(self, ev: dict[str, Any]) -> None:
        kind = str(ev.get("type") or "")
        renderers = {
            "switch_started": fmt.started_text,
            "ip_allocated": fmt.allocated_text,
            "old_ip_released": fmt.released_text,
            "ip_bound": fmt.bound_text,
            "dns_updated": fmt.dns_text,
            "switch_success": fmt.success_text,
            "switch_failed": fmt.failed_text,
            "dns_sync": fmt.dns_text,
        }
        renderer = renderers.get(kind)
        if not renderer:
            return
        if self.app is None:
            return
        self.history.append({**ev, "ts": time.time()})
        self.history = self.history[-100:]
        text = renderer(ev)
        for chat_id in self._notify_targets():
            try:
                await self.app.bot.send_message(
                    chat_id=chat_id,
                    text=text,
                    parse_mode=ParseMode.HTML,
                    disable_web_page_preview=True,
                )
            except TelegramError as exc:
                log.warning("发送到 %s 失败：%s", chat_id, exc)

    # ------------------------------------------------------------ 权限
    def is_admin(self, update: Update) -> bool:
        chat = update.effective_chat
        if not chat:
            return False
        return chat.id in self.admin_ids

    async def _guard(self, update: Update) -> bool:
        if self.is_admin(update):
            return True
        chat_id = _chat_id_str(update)
        await reply(
            update,
            "⛔ 未授权。\n"
            f"你的 chat id：<code>{chat_id}</code>\n"
            "管理员在服务器上执行：<code>eipguard bind " + str(chat_id) + "</code>\n"
            "或私聊机器人发 /bind 口令",
            parse_mode=ParseMode.HTML,
        )
        return False

    # ------------------------------------------------------------ 基础命令
    async def cmd_start(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
        if not self.is_admin(update):
            await self._guard(update)
            return
        unset = self._missing_setup()
        if unset:
            await reply(
                update,
                "👋 <b>还没配置完</b>\n\n缺少："
                + "、".join(unset)
                + "\n\n按顺序发：\n"
                + ("/account add — 添加阿里云账号\n" if "阿里云账号" in unset else "")
                + ("/cf — 设置 Cloudflare\n" if "Cloudflare" in unset else "")
                + ("/target add — 添加实例\n" if "实例" in unset else "")
                + "\n或直接看 /help",
                parse_mode=ParseMode.HTML,
            )
            return
        await reply(update, fmt.help_short() + "\n\n完整说明 /help", parse_mode=ParseMode.HTML)

    def _missing_setup(self) -> list[str]:
        missing = []
        if not self.cfg.accounts:
            missing.append("阿里云账号")
        if not self.cfg.cloudflare.api_token or not (self.cfg.cloudflare.zone_name or self.cfg.cloudflare.zone_id):
            missing.append("Cloudflare")
        if not self.cfg.targets:
            missing.append("实例")
        return missing

    async def cmd_help(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
        if not await self._guard(update):
            return
        await reply(update, fmt.help_text(), parse_mode=ParseMode.HTML)

    async def cmd_bind(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> int:
        chat = update.effective_chat
        if not chat:
            return ConversationHandler.END
        if chat.id in self.admin_ids:
            await reply(update, f"✅ 你已经是管理员（<code>{chat.id}</code>）", parse_mode=ParseMode.HTML)
            return ConversationHandler.END
        token = (ctx.args or [""])[0] if ctx.args else ""
        if self.cfg.bind_token and token == self.cfg.bind_token:
            await self._add_admin(chat.id)
            await reply(update, f"✅ 已绑定管理员：<code>{chat.id}</code>", parse_mode=ParseMode.HTML)
            return ConversationHandler.END
        if self.admin_ids and not self.cfg.bind_token:
            await reply(update, "已有管理员，且没设绑定口令。请管理员在服务器执行 eipguard bind " + str(chat.id))
            return ConversationHandler.END
        await reply(update, "发送绑定口令（config.yaml 里 telegram.bind_token）：")
        return ASK_BIND

    async def _ask_bind(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> int:
        text = msg_text(update)
        if self.cfg.bind_token and text == self.cfg.bind_token:
            await self._add_admin(chat_id_of(update))
            await reply(update, "✅ 已绑定", parse_mode=ParseMode.HTML)
        else:
            await reply(update, "❌ 口令不对")
        return ConversationHandler.END

    async def _add_admin(self, chat_id: int) -> None:
        self.admin_ids.add(chat_id)
        self.cfg.admin_chat_ids = tuple(sorted(self.admin_ids))
        try:
            self.cfg.save()
        except Exception:  # noqa: BLE001
            log.exception("保存管理员失败")

    # ------------------------------------------------------------ 查看
    async def cmd_status(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if not await self._guard(update):
            return
        args = ctx.args or []
        if args:
            name = args[0]
            try:
                self.cfg.target(name)
            except KeyError:
                await reply(update, f"没有实例 <code>{name}</code>", parse_mode=ParseMode.HTML)
                return
            msg = await reply(update, f"⏳ 查询 {name}…")
            detail = await self.engine.describe(self.cfg.target(name))
            records: list[dict[str, str]] = []
            if detail.get("eip") and self.cfg.target(name).dns_records:
                try:
                    for rec in await self.engine.cloudflare.list_records(
                        self.cfg.target(name).dns_records[0]
                    ):
                        records.append({"name": rec.name, "content": rec.content})
                except CloudflareError:
                    pass
            await msg.edit_text(
                fmt.target_detail(name, detail, records),
                parse_mode=ParseMode.HTML,
                disable_web_page_preview=True,
            )
            return

        msg = await reply(update, "⏳ 查询中…")
        rows = []
        for target in self.cfg.targets:
            detail = await self.engine.describe(target)
            rows.append(detail)
        await msg.edit_text(
            fmt.overview_text(rows), parse_mode=ParseMode.HTML, disable_web_page_preview=True
        )

    async def cmd_accounts(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
        if not await self._guard(update):
            return
        counts: dict[str, int] = {}
        for target in self.cfg.targets:
            counts[target.account] = counts.get(target.account, 0) + 1
        await reply(
            update,
            fmt.accounts_text(list(self.cfg.accounts.values()), counts),
            parse_mode=ParseMode.HTML,
        )

    async def cmd_targets(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
        if not await self._guard(update):
            return
        if not self.cfg.targets:
            await reply(update, "还没有实例。用 /target add 添加。")
            return
        lines = ["<b>实例列表</b>", ""]
        for t in self.cfg.targets:
            lines.append(f"• <code>{fmt.esc(t.brief())}</code>")
        lines.append("")
        lines.append("添加 /target add · 删除 /target del 名字 · 改域名 /target dns 名字 a.com b.com")
        await reply(update, "\n".join(lines), parse_mode=ParseMode.HTML)

    async def cmd_settings(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
        if not await self._guard(update):
            return
        await reply(update, fmt.settings_text(self.cfg), parse_mode=ParseMode.HTML)

    async def cmd_history(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
        if not await self._guard(update):
            return
        if not self.history:
            await reply(update, "还没有操作记录")
            return
        lines = ["<b>最近操作</b>", ""]
        for ev in self.history[-12:]:
            kind = str(ev.get("type"))
            icon = {
                "switch_started": "🔁",
                "ip_allocated": "📥",
                "old_ip_released": "🗑",
                "ip_bound": "🔗",
                "dns_updated": "🌐",
                "switch_success": "🎉",
                "switch_failed": "❌",
                "dns_sync": "🌐",
            }.get(kind, "•")
            detail = ev.get("new_ip") or ev.get("old_ip") or ev.get("ip") or ""
            lines.append(
                f"{icon} {fmt.ts(ev.get('ts'))} {fmt.esc(ev.get('target') or '')} {fmt.esc(detail)}"
            )
        await reply(update, "\n".join(lines), parse_mode=ParseMode.HTML)

    async def cmd_health(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
        if not await self._guard(update):
            return
        msg = await reply(update, "⏳ 自检中…")
        lines = ["<b>自检</b>", ""]
        # 阿里云
        if not self.cfg.accounts:
            lines.append("⛔ 阿里云：没有账号")
        else:
            for name, acc in self.cfg.accounts.items():
                try:
                    client = self.engine.aliyuns.get(name) or self.engine.make_client(acc)
                    eips = await client.describe_eips()
                    lines.append(f"✅ 阿里云 {name}：{len(eips)} 个 EIP")
                except Exception as exc:  # noqa: BLE001
                    lines.append(f"❌ 阿里云 {name}：{fmt.esc(exc)}")
        # Cloudflare
        try:
            if not self.cfg.cloudflare.api_token:
                lines.append("⛔ Cloudflare：没有 Token")
            else:
                zone = await self.engine.cloudflare.resolve_zone_id()
                lines.append(f"✅ Cloudflare：zone <code>{fmt.esc(zone)}</code>")
        except Exception as exc:  # noqa: BLE001
            lines.append(f"❌ Cloudflare：{fmt.esc(exc)}")
        lines.append("")
        lines.append(f"实例 {len(self.cfg.targets)} 台 · 管理员 {len(self.admin_ids)} 人")
        await msg.edit_text("\n".join(lines), parse_mode=ParseMode.HTML)

    # ------------------------------------------------------------ 换 IP
    async def cmd_switch(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if not await self._guard(update):
            return
        if not self.cfg.targets:
            await reply(update, "还没有实例，先 /target add")
            return
        args = ctx.args or []
        if not args:
            kb = [[InlineKeyboardButton(f"🔁 {t.name}", callback_data=f"sw:{t.name}")] for t in self.cfg.targets]
            await reply(update, "选择要换 IP 的实例：", reply_markup=InlineKeyboardMarkup(kb))
            return
        if args[0] == "all":
            for t in self.cfg.targets:
                await self._do_switch(chat_id_of(update), t.name)
            return
        name = args[0]
        if name not in self.cfg.target_names():
            await reply(update, f"没有实例 <code>{name}</code>\n可选：{', '.join(self.cfg.target_names())}",
                        parse_mode=ParseMode.HTML)
            return
        target = self.cfg.target(name)
        detail = await self.engine.describe(target)
        eip = detail.get("eip")
        kb = [
            [
                InlineKeyboardButton("✅ 确认换 IP", callback_data=f"ok:{name}"),
                InlineKeyboardButton("取消", callback_data="cancel"),
            ]
        ]
        text = [
            f"⚠️ 即将为 <b>{name}</b> 换 IP",
            "",
            f"当前 IP：<code>{eip.ip if eip else '查询中…'}</code>",
            f"账号：<code>{fmt.esc(target.account)}</code>",
            f"实例：<code>{fmt.esc(target.instance_id)}</code>",
            f"域名：{fmt.esc(', '.join(target.dns_records) or '未配置')}",
            "",
            "将执行：分配新 IP → 释放旧 IP（停止计费）→ 绑定 → 改 CF 解析",
            "每一步都会推送结果。",
        ]
        await reply(
            update,
            "\n".join(text),
            parse_mode=ParseMode.HTML,
            reply_markup=InlineKeyboardMarkup(kb),
        )

    async def _do_switch(self, chat_id: int, name: str) -> None:
        if self.app is None:
            return
        progress = await self.app.bot.send_message(
            chat_id,
            f"⏳ 正在为 <b>{fmt.esc(name)}</b> 换 IP…",
            parse_mode=ParseMode.HTML,
        )
        result = await self.engine.switch(name, reason="手动：Telegram")
        try:
            if result.ok:
                text = fmt.success_text(
                    {
                        "target": name,
                        "account": result.account,
                        "old_ip": result.old_ip,
                        "new_ip": result.new_ip,
                        "old_released": result.old_released,
                        "dns": result.dns,
                        "elapsed": result.elapsed,
                    }
                )
            else:
                text = fmt.failed_text(
                    {
                        "target": name,
                        "account": result.account,
                        "old_ip": result.old_ip,
                        "new_ip": result.new_ip,
                        "old_released": result.old_released,
                        "error": result.error,
                        "steps": result.steps,
                    }
                )
            await progress.edit_text(text, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
        except TelegramError:
            await self.app.bot.send_message(chat_id, text, parse_mode=ParseMode.HTML)

    async def cmd_dns(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if not await self._guard(update):
            return
        args = ctx.args or []
        if not args:
            kb = [[InlineKeyboardButton(f"🌐 {t.name}", callback_data=f"dns:{t.name}")] for t in self.cfg.targets]
            if not kb:
                await reply(update, "还没有实例")
                return
            await reply(update, "同步哪个实例的解析？", reply_markup=InlineKeyboardMarkup(kb))
            return
        name = args[0]
        ip = args[1] if len(args) > 1 else ""
        try:
            results = await self.engine.manual_dns(name, ip)
        except Exception as exc:  # noqa: BLE001
            await reply(update, f"❌ {exc}")
            return
        ok = sum(1 for r in results if r["ok"] == "1")
        lines = [f"🌐 <b>{fmt.esc(name)}</b>：{ok}/{len(results)} 条成功", ""]
        for r in results:
            mark = "✓" if r["ok"] == "1" else "✗"
            lines.append(f"{mark} <code>{fmt.esc(r['name'])}</code> {fmt.esc(r['detail'])}")
        await reply(update, "\n".join(lines), parse_mode=ParseMode.HTML)

    # ------------------------------------------------------------ 账号管理
    async def cmd_account(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> Any:
        if not await self._guard(update):
            return ConversationHandler.END
        args = ctx.args or []
        if not args:
            counts: dict[str, int] = {}
            for t in self.cfg.targets:
                counts[t.account] = counts.get(t.account, 0) + 1
            await reply(update, fmt.accounts_text(list(self.cfg.accounts.values()), counts),
                        parse_mode=ParseMode.HTML)
            return ConversationHandler.END

        sub = args[0].lower()
        if sub == "add":
            if len(args) >= 4:
                await self._add_account(args[1], args[2], args[3], args[4] if len(args) > 4 else "")
                return ConversationHandler.END
            await reply(
                update,
                "添加阿里云账号。先给个代号（英文，例如 main / second）：\n"
                "（建议用 RAM 子账号，只给 EIP 权限）",
            )
            return ASK_ACCOUNT_NAME

        if sub in {"del", "delete", "rm"}:
            if len(args) < 2:
                await reply(update, "用法：/account del 名字")
                return ConversationHandler.END
            await self._del_account(args[1])
            return ConversationHandler.END

        if sub == "region":
            if len(args) < 3:
                await reply(update, "用法：/account region 名字 cn-hongkong")
                return ConversationHandler.END
            try:
                acc = self.cfg.account(args[1])
            except ConfigError as exc:
                await reply(update, f"❌ {exc}")
                return ConversationHandler.END
            acc.region = args[2]
            self.cfg.save()
            self.engine.aliyuns[acc.name] = self.engine.make_client(acc)
            await reply(update, f"✅ {acc.name} 地域改为 {acc.region}")
            return ConversationHandler.END

        await reply(update, "用法：/account add | del 名字 | region 名字 地域")
        return ConversationHandler.END

    async def _ask_account_ak(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> int:
        name = msg_text(update)
        if not name or " " in name:
            await reply(update, "代号不能有空格，重新发：")
            return ASK_ACCOUNT_NAME
        if name in self.cfg.accounts:
            await reply(update, "这个名字已存在，换一个：")
            return ASK_ACCOUNT_NAME
        self._pending = {"name": name}
        await reply(update, f"账号 <b>{fmt.esc(name)}</b> 的 AccessKey ID：", parse_mode=ParseMode.HTML)
        return ASK_ACCOUNT_AK

    async def _ask_account_sk(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> int:
        ak = msg_text(update)
        if len(ak) < 8:
            await reply(update, "AccessKey ID 看起来不对，重新发：")
            return ASK_ACCOUNT_AK
        self._pending["ak"] = ak
        await reply(
            update,
            "AccessKey Secret：\n\n"
            "⚠️ 这条消息包含密钥，发出后请删除（长按 → 删除）。",
        )
        return ASK_ACCOUNT_SK

    async def _ask_account_region(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> int:
        sk = msg_text(update)
        if len(sk) < 10:
            await reply(update, "Secret 看起来不对，重新发：")
            return ASK_ACCOUNT_SK
        self._pending["sk"] = sk
        # 尝试删除含密钥的消息
        await _delete_message(update)
        region = (ctx.args or [""])
        kb = [
            [InlineKeyboardButton("cn-hongkong 香港", callback_data="reg:cn-hongkong")],
            [InlineKeyboardButton("ap-southeast-1 新加坡", callback_data="reg:ap-southeast-1")],
            [InlineKeyboardButton("cn-hangzhou 杭州", callback_data="reg:cn-hangzhou")],
            [InlineKeyboardButton("jp Osaka 日本", callback_data="reg:ap-northeast-1")],
            [InlineKeyboardButton("us 硅谷", callback_data="reg:us-west-1")],
        ]
        await reply(update, "选择这个账号的地域：", reply_markup=InlineKeyboardMarkup(kb))
        return ConversationHandler.END

    async def _finish_account(self, chat_id: int, region: str) -> None:
        pending = getattr(self, "_pending", {})
        name, ak, sk = pending.get("name"), pending.get("ak"), pending.get("sk")
        if not (name and ak and sk):
            return
        await self._add_account(name, ak, sk, region, chat_id=chat_id)

    async def _add_account(
        self, name: str, ak: str, sk: str, region: str = "", chat_id: int | None = None
    ) -> None:
        region = region or "cn-hongkong"
        acc = Account(name=name, access_key_id=ak, access_key_secret=sk, region=region)
        # 先验证 AK 是否可用
        try:
            client = self.engine.make_client(acc)
            eips = await client.describe_eips()
        except AliyunError as exc:
            text = f"❌ 这个 AK 验证失败：{fmt.esc(exc)}\n\n检查：AccessKey 是否正确、子账号是否只有 EIP 权限、地域是否支持"
            if chat_id:
                assert self.app is not None
                await self.app.bot.send_message(chat_id, text, parse_mode=ParseMode.HTML)
            return
        self.cfg.accounts[name] = acc
        self.cfg.save()
        self.engine.aliyuns[name] = self.engine.make_client(acc)
        text = (
            f"✅ 账号 <b>{fmt.esc(name)}</b> 已添加\n"
            f"地域：{fmt.esc(region)}\n"
            f"已有 EIP：{len(eips)} 个\n\n"
            "下一步：/target add 添加实例"
        )
        if chat_id:
            assert self.app is not None
            await self.app.bot.send_message(chat_id, text, parse_mode=ParseMode.HTML)

    async def _del_account(self, name: str) -> None:
        if name not in self.cfg.accounts:
            return
        used = [t.name for t in self.cfg.targets if t.account == name]
        if used:
            return
        del self.cfg.accounts[name]
        self.cfg.save()
        self.engine.aliyuns.pop(name, None)

    # ------------------------------------------------------------ 实例管理
    async def cmd_target(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> Any:
        if not await self._guard(update):
            return ConversationHandler.END
        args = ctx.args or []

        if not args:
            await self.cmd_targets(update, ctx)
            return ConversationHandler.END

        sub = args[0].lower()
        if sub == "add":
            if len(args) >= 4:
                await self._add_target(args[1], args[2], args[3], args[4:])
                return ConversationHandler.END
            if not self.cfg.accounts:
                await reply(update, "先添加阿里云账号：/account add")
                return ConversationHandler.END
            await reply(update, "实例代号（英文，例如 hk-main）：")
            return ASK_TARGET_NAME

        if sub in {"del", "delete", "rm"}:
            if len(args) < 2:
                await reply(update, "用法：/target del 名字")
                return ConversationHandler.END
            if args[1] in self.cfg.target_names():
                self.cfg.targets = [t for t in self.cfg.targets if t.name != args[1]]
                self.cfg.save()
                await reply(update, f"✅ 已删除 {args[1]}")
            else:
                await reply(update, "没有这个实例")
            return ConversationHandler.END

        if sub == "dns":
            if len(args) < 3:
                await reply(update, "用法：/target dns 名字 a.example.com b.example.com")
                return ConversationHandler.END
            try:
                target = self.cfg.target(args[1])
            except KeyError:
                await reply(update, "没有这个实例")
                return ConversationHandler.END
            target.dns_records = args[2:]
            self.cfg.save()
            await reply(update, f"✅ {target.name} 域名：{', '.join(target.dns_records)}")
            return ConversationHandler.END

        await reply(update, "用法：/target add | del 名字 | dns 名字 域名...")
        return ConversationHandler.END

    async def _ask_target_account(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> int:
        name = msg_text(update)
        if not name:
            await reply(update, "重新发代号：")
            return ASK_TARGET_NAME
        if name in self.cfg.target_names():
            await reply(update, "这个代号已存在，换一个：")
            return ASK_TARGET_NAME
        self._pending = {"name": name}
        if len(self.cfg.accounts) == 1:
            self._pending["account"] = next(iter(self.cfg.accounts))
            await reply(
                update,
                f"用账号 <b>{fmt.esc(self._pending['account'])}</b>\n实例 ID（i-xxxxxxxx）：",
                parse_mode=ParseMode.HTML,
            )
            return ASK_TARGET_INSTANCE
        kb = [[InlineKeyboardButton(n, callback_data=f"acc:{n}")] for n in self.cfg.accounts]
        await reply(update, "用哪个账号？", reply_markup=InlineKeyboardMarkup(kb))
        return ConversationHandler.END

    async def _ask_target_instance(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> int:
        iid = msg_text(update)
        if not iid.startswith("i-") or len(iid) < 6:
            await reply(update, "实例 ID 形如 i-j6cxxxxxxxx，重新发：")
            return ASK_TARGET_INSTANCE
        self._pending["instance"] = iid
        await reply(
            update,
            "要跟随的域名，用空格分隔（例如 hk.example.com api.example.com）\n"
            "只换 IP 不改解析就直接发 -",
        )
        return ASK_TARGET_DNS

    async def _ask_target_dns(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> int:
        text = msg_text(update)
        dns = [] if text in {"-", "", "无"} else text.split()
        pending = getattr(self, "_pending", {})
        await self._add_target(
            pending.get("name", ""),
            pending.get("account", ""),
            pending.get("instance", ""),
            dns,
            chat_id=safe_chat_id(update),
        )
        return ConversationHandler.END

    async def _add_target(
        self,
        name: str,
        account: str,
        instance_id: str,
        dns: list[str],
        chat_id: int | None = None,
    ) -> None:
        if not name or not account or not instance_id:
            return
        if account not in self.cfg.accounts:
            if chat_id and self.app:
                await self.app.bot.send_message(chat_id, f"❌ 账号 {account} 不存在")
            return
        target = Target(
            name=name, account=account, instance_id=instance_id, dns_records=list(dns)
        )
        # 验证实例是否存在、是否有 EIP
        try:
            engine_client = self.engine.aliyuns[account]
            eip = await engine_client.find_instance_eip(
                instance_id, region_id=self.cfg.region_for(target)
            )
        except AliyunError as exc:
            if chat_id and self.app:
                await self.app.bot.send_message(
                    chat_id, f"❌ 查询实例失败：{fmt.esc(exc)}", parse_mode=ParseMode.HTML
                )
            return
        if not eip:
            warn = "⚠️ 没查到这台实例绑定的 EIP，换 IP 会失败（先确认实例 ID 和地域）"
        else:
            warn = ""
        self.cfg.targets = [t for t in self.cfg.targets if t.name != name]
        self.cfg.targets.append(target)
        self.cfg.save()
        lines = [
            f"✅ 实例 <b>{fmt.esc(name)}</b> 已添加",
            f"账号：{fmt.esc(account)}",
            f"实例：<code>{fmt.esc(instance_id)}</code>",
        ]
        if eip:
            lines.append(f"当前 IP：<code>{fmt.esc(eip.ip)}</code>")
        if target.dns_records:
            lines.append(f"域名：{fmt.esc(', '.join(target.dns_records))}")
        if warn:
            lines.append("")
            lines.append(warn)
        lines.append("")
        lines.append(f"换 IP：/switch {name}")
        text = "\n".join(lines)
        if chat_id and self.app:
            await self.app.bot.send_message(chat_id, text, parse_mode=ParseMode.HTML)
        else:
            log.info("添加实例 %s", name)

    # ------------------------------------------------------------ Cloudflare
    async def cmd_cf(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> Any:
        if not await self._guard(update):
            return ConversationHandler.END
        args = ctx.args or []
        if len(args) >= 2:
            await self._set_cf(args[0], args[1])
            return ConversationHandler.END
        if args:
            await reply(update, "用法：/cf TOKEN 域名\n例如 /cf abc123... example.com")
            return ConversationHandler.END
        await reply(
            update,
            "设置 Cloudflare。\n\n"
            "需要 API Token，权限：\n"
            "· Zone → DNS → Edit\n"
            "· Zone → Zone → Read\n\n"
            "发 Token（发完请删除这条消息）：",
        )
        return ASK_CF_TOKEN

    async def _ask_cf_zone(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> int:
        token = msg_text(update)
        if len(token) < 20:
            await reply(update, "Token 看起来不对，重新发：")
            return ASK_CF_TOKEN
        self._pending = {"cf_token": token}
        await _delete_message(update)
        await reply(update, "域名（例如 example.com）：")
        return ASK_CF_ZONE

    async def _ask_cf_finish(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> int:
        zone = msg_text(update)
        token = getattr(self, "_pending", {}).get("cf_token", "")
        await self._set_cf(token, zone, chat_id=safe_chat_id(update))
        return ConversationHandler.END

    async def _set_cf(self, token: str, zone: str, chat_id: int | None = None) -> None:
        cf = Cloudflare(token, zone_name=zone, ttl=self.cfg.cloudflare.ttl,
                        proxied=self.cfg.cloudflare.proxied, api_base=self.cfg.cloudflare.api_base)
        try:
            zone_id = await cf.resolve_zone_id()
            await cf.close()
        except CloudflareError as exc:
            await cf.close()
            text = f"❌ Cloudflare 验证失败：{fmt.esc(exc)}\n\n检查 Token 权限（DNS:Edit + Zone:Read）和域名"
            if chat_id and self.app:
                await self.app.bot.send_message(chat_id, text, parse_mode=ParseMode.HTML)
            return
        self.cfg.cloudflare.api_token = token
        self.cfg.cloudflare.zone_name = zone
        self.cfg.cloudflare.zone_id = zone_id
        self.cfg.save()
        self.engine.cloudflare = Cloudflare(
            token,
            zone_id=zone_id,
            zone_name=zone,
            ttl=self.cfg.cloudflare.ttl,
            proxied=self.cfg.cloudflare.proxied,
            create_missing=self.cfg.cloudflare.create_missing,
            multi_record_policy=self.cfg.cloudflare.multi_record_policy,
            api_base=self.cfg.cloudflare.api_base,
        )
        text = f"✅ Cloudflare 已设置\n域名：{fmt.esc(zone)}\nzone id：<code>{fmt.esc(zone_id)}</code>"
        if chat_id and self.app:
            await self.app.bot.send_message(chat_id, text, parse_mode=ParseMode.HTML)

    # ------------------------------------------------------------ 设置
    async def cmd_set(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if not await self._guard(update):
            return
        args = ctx.args or []
        if len(args) < 2:
            await reply(update, "用法：/set release on|off · /set proxied on|off · /set ttl 60 · /set retries 3")
            return
        key, value = args[0].lower(), args[1].lower()
        if key in {"release", "release_old"}:
            if value not in {"on", "off"}:
                await reply(update, "只能是 on 或 off")
                return
            self.cfg.switch.release_old = value == "on"
            self.cfg.save()
            await reply(
                update,
                f"✅ 换完 IP 后{'释放' if self.cfg.switch.release_old else '保留'}旧 IP"
                + ("" if self.cfg.switch.release_old else "\n⚠️ 保留会继续计费"),
            )
            return
        if key in {"proxied", "proxy"}:
            if value not in {"on", "off"}:
                await reply(update, "只能是 on 或 off")
                return
            self.cfg.cloudflare.proxied = value == "on"
            self.cfg.save()
            self.engine.cloudflare.proxied = self.cfg.cloudflare.proxied
            await reply(update, f"✅ CF 小黄云：{'开' if self.cfg.cloudflare.proxied else '关'}")
            return
        if key == "ttl":
            try:
                ttl = int(value)
            except ValueError:
                await reply(update, "TTL 需要数字（秒）")
                return
            self.cfg.cloudflare.ttl = ttl
            self.cfg.save()
            self.engine.cloudflare.ttl = ttl
            await reply(update, f"✅ 解析 TTL = {ttl}s")
            return
        if key in {"retries", "attempts"}:
            try:
                n = max(1, min(10, int(value)))
            except ValueError:
                await reply(update, "需要数字")
                return
            self.cfg.switch.max_attempts = n
            self.cfg.save()
            await reply(update, f"✅ 分配重试 {n} 次")
            return
        await reply(update, "支持的设置：release / proxied / ttl / retries")

    async def cmd_channel(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if not await self._guard(update):
            return
        args = ctx.args or []
        if not args:
            await reply(
                update,
                f"当前频道：<code>{self.cfg.channel_id or '未设置'}</code>\n"
                "设置：/channel -1001234567890\n关闭：/channel off\n（机器人必须是频道管理员）",
                parse_mode=ParseMode.HTML,
            )
            return
        if args[0].lower() in {"off", "none", "0"}:
            self.cfg.channel_id = None
            self.cfg.save()
            await reply(update, "已关闭频道通知")
            return
        try:
            chat_id = int(args[0])
        except ValueError:
            await reply(update, "频道 id 是数字，形如 -1001234567890")
            return
        self.cfg.channel_id = chat_id
        self.cfg.save()
        ok = "✅"
        try:
            assert self.app is not None
            await self.app.bot.send_message(
                chat_id=chat_id, text="✅ EIP Guard 已连接此频道，换 IP 的每一步都会发到这里。"
            )
        except TelegramError as exc:
            ok = f"⚠️ 测试消息失败：{exc}\n确认机器人是频道管理员"
        await reply(update, f"{ok}\n频道：<code>{chat_id}</code>", parse_mode=ParseMode.HTML)

    # ------------------------------------------------------------ 回调
    async def on_callback(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> Any:
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

        if data.startswith("sw:"):
            name = data.split(":", 1)[1]
            target = self.cfg.target(name)
            detail = await self.engine.describe(target)
            eip = detail.get("eip")
            await query.edit_message_text(
                f"⚠️ 确认换 <b>{fmt.esc(name)}</b> 的 IP？\n\n"
                f"当前：<code>{fmt.esc(eip.ip if eip else '-')}</code>\n"
                f"域名：{fmt.esc(', '.join(target.dns_records) or '无')}",
                parse_mode=ParseMode.HTML,
                reply_markup=InlineKeyboardMarkup(
                    [[
                        InlineKeyboardButton("✅ 确认", callback_data=f"ok:{name}"),
                        InlineKeyboardButton("取消", callback_data="cancel"),
                    ]]
                ),
            )
            return

        if data.startswith("ok:"):
            name = data.split(":", 1)[1]
            await query.edit_message_text(f"⏳ 开始换 {fmt.esc(name)} 的 IP…", parse_mode=ParseMode.HTML)
            await self._do_switch(callback_chat_id(query), name)
            return

        if data.startswith("dns:"):
            name = data.split(":", 1)[1]
            try:
                results = await self.engine.manual_dns(name)
                ok = sum(1 for r in results if r["ok"] == "1")
                await query.edit_message_text(
                    f"🌐 {name}：{ok}/{len(results)} 成功\n"
                    + "\n".join(f"{'✓' if r['ok'] == '1' else '✗'} {r['name']} {r['detail']}" for r in results)
                )
            except Exception as exc:  # noqa: BLE001
                await query.edit_message_text(f"❌ {exc}")
            return

        if data.startswith("reg:"):
            region = data.split(":", 1)[1]
            await query.edit_message_text(f"⏳ 验证并保存账号（地域 {region}）…")
            await self._finish_account(callback_chat_id(query), region)
            return

        if data.startswith("acc:"):
            account = data.split(":", 1)[1]
            self._pending = {**getattr(self, "_pending", {}), "account": account}
            await query.edit_message_text(
                f"账号：<b>{fmt.esc(account)}</b>\n\n实例 ID（i-xxxxxxxx）：",
                parse_mode=ParseMode.HTML,
            )
            # 会话已结束，这里记下"等待实例 ID"，由 _on_plain_text 接住
            self._await_instance = True
            return

    # ------------------------------------------------------------ 构建
    def build(self) -> Application:
        builder = Application.builder().token(self.cfg.telegram_token)
        if self.cfg.tg_proxy:
            builder = builder.proxy(self.cfg.tg_proxy).get_updates_proxy(self.cfg.tg_proxy)
            log.info("Telegram 使用代理：%s", self.cfg.tg_proxy)
        app = builder.build()
        self.app = app

        account_conv = ConversationHandler(
            entry_points=[CommandHandler("account", self.cmd_account)],
            states={
                ASK_ACCOUNT_NAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, self._ask_account_ak)],
                ASK_ACCOUNT_AK: [MessageHandler(filters.TEXT & ~filters.COMMAND, self._ask_account_sk)],
                ASK_ACCOUNT_SK: [MessageHandler(filters.TEXT & ~filters.COMMAND, self._ask_account_region)],
            },
            fallbacks=[CommandHandler("cancel", self._cancel)],
        )

        cf_conv = ConversationHandler(
            entry_points=[CommandHandler("cf", self.cmd_cf)],
            states={
                ASK_CF_TOKEN: [MessageHandler(filters.TEXT & ~filters.COMMAND, self._ask_cf_zone)],
                ASK_CF_ZONE: [MessageHandler(filters.TEXT & ~filters.COMMAND, self._ask_cf_finish)],
            },
            fallbacks=[CommandHandler("cancel", self._cancel)],
        )

        target_conv = ConversationHandler(
            entry_points=[CommandHandler("target", self.cmd_target)],
            states={
                ASK_TARGET_NAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, self._ask_target_account)],
                ASK_TARGET_INSTANCE: [MessageHandler(filters.TEXT & ~filters.COMMAND, self._ask_target_instance)],
                ASK_TARGET_DNS: [MessageHandler(filters.TEXT & ~filters.COMMAND, self._ask_target_dns)],
            },
            fallbacks=[CommandHandler("cancel", self._cancel)],
        )

        bind_conv = ConversationHandler(
            entry_points=[CommandHandler("bind", self.cmd_bind)],
            states={ASK_BIND: [MessageHandler(filters.TEXT & ~filters.COMMAND, self._ask_bind)]},
            fallbacks=[CommandHandler("cancel", self._cancel)],
        )

        app.add_handler(account_conv)
        app.add_handler(cf_conv)
        app.add_handler(target_conv)
        app.add_handler(bind_conv)
        app.add_handler(CommandHandler("start", self.cmd_start))
        app.add_handler(CommandHandler("help", self.cmd_help))
        app.add_handler(CommandHandler("status", self.cmd_status))
        app.add_handler(CommandHandler("ip", self.cmd_status))
        app.add_handler(CommandHandler("accounts", self.cmd_accounts))
        app.add_handler(CommandHandler("targets", self.cmd_targets))
        app.add_handler(CommandHandler("settings", self.cmd_settings))
        app.add_handler(CommandHandler("history", self.cmd_history))
        app.add_handler(CommandHandler("health", self.cmd_health))
        app.add_handler(CommandHandler("switch", self.cmd_switch))
        app.add_handler(CommandHandler("dns", self.cmd_dns))
        app.add_handler(CommandHandler("set", self.cmd_set))
        app.add_handler(CommandHandler("channel", self.cmd_channel))
        app.add_handler(CallbackQueryHandler(self.on_callback))
        # 兜底：接住会话之外的实例 ID / 域名输入
        app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self._on_plain_text), group=1)
        app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self._on_dns_text), group=2)
        return app

    async def _on_plain_text(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        """会话结束后仍需接住的输入：选了账号之后的实例 ID。"""
        if not self.is_admin(update):
            return
        if not getattr(self, "_await_instance", False):
            return
        text = msg_text(update)
        if not text.startswith("i-"):
            await reply(update, "实例 ID 形如 i-j6cxxxxxxxx，重新发：")
            return
        self._await_instance = False
        self._pending = {**getattr(self, "_pending", {}), "instance": text}
        await reply(
            update,
            "要跟随的域名，空格分隔（例如 hk.example.com api.example.com）\n只换 IP 不改解析就发 -",
        )
        self._await_dns = True

    async def _on_dns_text(self, update: Update, ctx: ContextTypes.DEFAULT_TYPE) -> None:
        if not self.is_admin(update):
            return
        if not getattr(self, "_await_dns", False):
            return
        self._await_dns = False
        text = msg_text(update)
        dns = [] if text in {"-", "", "无"} else text.split()
        pending = getattr(self, "_pending", {})
        await self._add_target(
            pending.get("name", ""),
            pending.get("account", ""),
            pending.get("instance", ""),
            dns,
            chat_id=safe_chat_id(update),
        )

    async def _cancel(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> int:
        await reply(update, "已取消")
        return ConversationHandler.END

    async def run(self) -> None:
        import asyncio

        app = self.build()
        await app.initialize()
        await app.start()
        if app.updater is not None:
            await app.updater.start_polling(drop_pending_updates=True)
        log.info("Telegram 机器人已启动")
        for chat_id in self._notify_targets():
            try:
                await app.bot.send_message(
                    chat_id,
                    "🟢 <b>EIP Guard 已启动</b>\n\n"
                    f"实例 {len(self.cfg.targets)} 台 · 账号 {len(self.cfg.accounts)} 个\n"
                    "手动换 IP：/switch 目标名\n查看：/status\n说明：/help",
                    parse_mode=ParseMode.HTML,
                )
            except TelegramError as exc:
                log.warning("启动通知发送失败 %s：%s", chat_id, exc)
        await asyncio.Event().wait()
