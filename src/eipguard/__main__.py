from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
from typing import Any

from .bot import BotApp
from .config import Config, ConfigError
from .engine import Engine
from .log import setup_logging

log = logging.getLogger("eipguard")


async def watch_bot(bot: Any, retry_delay: float = 30.0) -> None:
    """机器人异常时只重试，不影响其它逻辑。"""
    attempt = 0
    while True:
        attempt += 1
        try:
            await bot.run()
            return
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            log.error("Telegram 异常（第 %d 次）：%s: %s", attempt, type(exc).__name__, exc)
            if "InvalidToken" in type(exc).__name__:
                log.error("Bot Token 无效，检查 .env 的 TG_BOT_TOKEN")
            else:
                log.warning("%.0fs 后重试", retry_delay)
            try:
                await asyncio.sleep(retry_delay)
            except asyncio.CancelledError:
                raise


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="eipguard", description="阿里云 EIP 手动换 IP + Cloudflare 解析 + Telegram 机器人"
    )
    ap.add_argument("-c", "--config", default="config.yaml", help="配置文件（默认 config.yaml）")
    ap.add_argument("--env", default=None, help=".env 路径（默认与配置文件同目录）")
    ap.add_argument("--check-config", action="store_true", help="只校验配置")
    ap.add_argument("--status", action="store_true", help="命令行查看当前 IP（不需要 Telegram）")
    ap.add_argument("--switch", metavar="TARGET", help="命令行换 IP（不需要 Telegram）")
    ap.add_argument("--dns", metavar="TARGET", help="命令行重同步解析")
    ap.add_argument("--no-bot", action="store_true", help="不启动机器人")
    ap.add_argument("--bind", metavar="CHAT_ID", help="把 chat id 加为管理员")
    ap.add_argument(
        "--migrate",
        action="store_true",
        help="把第一版配置改写成新格式（会先备份）",
    )
    # 子命令：account / target / cf（命令行管理，替代 TG 交互）
    ap.add_argument("command", nargs="?", help="account | target | cf")
    ap.add_argument("rest", nargs=argparse.REMAINDER, help=argparse.SUPPRESS)
    return ap.parse_args(argv)


async def handle_command(args: argparse.Namespace, cfg: Config) -> int:
    """命令行管理：account / target / cf。"""
    cmd = (args.command or "").lower()
    rest = [str(x) for x in (args.rest or [])]
    if rest and rest[0] == "--":
        rest = rest[1:]

    if cmd == "bind":
        if not rest:
            print("用法：eipguard bind 你的chatid", file=sys.stderr)
            return 2
        try:
            chat_id = int(rest[0])
        except ValueError:
            print(f"chat id 需要数字，收到：{rest[0]}", file=sys.stderr)
            return 2
        ids = set(cfg.admin_chat_ids)
        ids.add(chat_id)
        cfg.admin_chat_ids = tuple(sorted(ids))
        cfg.save()
        print(f"✅ 已添加管理员 {chat_id}")
        print(f"   现在共有：{', '.join(str(i) for i in cfg.admin_chat_ids)}")
        return 0

    if cmd == "account":
        if not rest:
            print("用法：eipguard account add 名字 AK SK [地域]")
            print("      eipguard account del 名字")
            print("      eipguard account region 名字 地域")
            print("      eipguard account list")
            return 0
        sub = rest[0].lower()
        if sub == "list":
            if not cfg.accounts:
                print("还没有账号")
            for acc in cfg.accounts.values():
                n = sum(1 for t in cfg.targets if t.account == acc.name)
                print(f"{acc.name}\t{acc.access_key_id[:8]}…\t{acc.region}\t{n} 台实例")
            return 0
        if sub == "add":
            if len(rest) < 4:
                print("用法：eipguard account add 名字 AK SK [地域]", file=sys.stderr)
                return 2
            from .config import Account

            name, ak, sk = rest[1], rest[2], rest[3]
            region = rest[4] if len(rest) > 4 else "cn-hongkong"
            acc = Account(name=name, access_key_id=ak, access_key_secret=sk, region=region)
            client = Engine(cfg).make_client(acc)
            try:
                eips = await client.describe_eips()
            except Exception as exc:  # noqa: BLE001
                print(f"❌ AK 验证失败：{exc}", file=sys.stderr)
                return 1
            cfg.accounts[name] = acc
            cfg.save()
            print(f"✅ 已添加账号 {name}（{region}），该账号已有 {len(eips)} 个 EIP")
            return 0
        if sub in {"del", "delete", "rm"}:
            if len(rest) < 2:
                print("用法：eipguard account del 名字", file=sys.stderr)
                return 2
            name = rest[1]
            if name not in cfg.accounts:
                print(f"没有账号 {name}", file=sys.stderr)
                return 2
            used = [t.name for t in cfg.targets if t.account == name]
            if used:
                print(f"❌ 账号 {name} 还被这些实例使用：{', '.join(used)}", file=sys.stderr)
                return 1
            del cfg.accounts[name]
            cfg.save()
            print(f"✅ 已删除账号 {name}")
            return 0
        if sub == "region":
            if len(rest) < 3:
                print("用法：eipguard account region 名字 地域", file=sys.stderr)
                return 2
            try:
                acc = cfg.account(rest[1])
            except Exception as exc:  # noqa: BLE001
                print(f"❌ {exc}", file=sys.stderr)
                return 2
            acc.region = rest[2]
            cfg.save()
            print(f"✅ {acc.name} 地域 = {acc.region}")
            return 0
        print(f"未知子命令 {sub}", file=sys.stderr)
        return 2

    if cmd == "target":
        if not rest:
            print("用法：eipguard target add 名字 账号 实例ID [域名...]")
            print("      eipguard target del 名字")
            print("      eipguard target dns 名字 域名...")
            print("      eipguard target list")
            return 0
        sub = rest[0].lower()
        if sub == "list":
            for t in cfg.targets:
                print(t.brief())
            if not cfg.targets:
                print("还没有实例")
            return 0
        if sub == "add":
            if len(rest) < 4:
                print("用法：eipguard target add 名字 账号 实例ID [域名...]", file=sys.stderr)
                return 2
            from .config import Target

            name, account, instance = rest[1], rest[2], rest[3]
            dns = rest[4:]
            if account not in cfg.accounts:
                print(f"❌ 账号 {account} 不存在（已有：{', '.join(cfg.accounts) or '无'}）", file=sys.stderr)
                return 2
            target = Target(name=name, account=account, instance_id=instance, dns_records=dns)
            engine = Engine(cfg)
            try:
                eip = await engine.resolve_eip(target)
            except Exception as exc:  # noqa: BLE001
                print(f"⚠️ 查询实例失败：{exc}")
                eip = None
            finally:
                await engine.close()
            cfg.targets = [t for t in cfg.targets if t.name != name]
            cfg.targets.append(target)
            cfg.save()
            print(f"✅ 已添加实例 {name}（{account} / {instance}）")
            if dns:
                print(f"   域名：{', '.join(dns)}")
            if eip:
                print(f"   当前 IP：{eip.ip}")
            else:
                print("   ⚠️ 没查到绑定的 EIP，确认实例 ID 和地域")
            return 0
        if sub in {"del", "delete", "rm"}:
            if len(rest) < 2:
                print("用法：eipguard target del 名字", file=sys.stderr)
                return 2
            if rest[1] not in cfg.target_names():
                print(f"没有实例 {rest[1]}", file=sys.stderr)
                return 2
            cfg.targets = [t for t in cfg.targets if t.name != rest[1]]
            cfg.save()
            print(f"✅ 已删除实例 {rest[1]}")
            return 0
        if sub == "dns":
            if len(rest) < 3:
                print("用法：eipguard target dns 名字 域名...", file=sys.stderr)
                return 2
            try:
                target = cfg.target(rest[1])
            except KeyError:
                print(f"没有实例 {rest[1]}", file=sys.stderr)
                return 2
            target.dns_records = rest[2:]
            cfg.save()
            print(f"✅ {target.name} 域名：{', '.join(target.dns_records)}")
            return 0
        print(f"未知子命令 {sub}", file=sys.stderr)
        return 2

    if cmd == "cf":
        if len(rest) < 2:
            print("用法：eipguard cf TOKEN 域名", file=sys.stderr)
            return 2
        token, zone = rest[0], rest[1]
        from .cloud.cloudflare import Cloudflare, CloudflareError

        cf = Cloudflare(token, zone_name=zone)
        try:
            zone_id = await cf.resolve_zone_id()
        except CloudflareError as exc:
            await cf.close()
            print(f"❌ Cloudflare 验证失败：{exc}", file=sys.stderr)
            return 1
        await cf.close()
        cfg.cloudflare.api_token = token
        cfg.cloudflare.zone_name = zone
        cfg.cloudflare.zone_id = zone_id
        cfg.save()
        print(f"✅ Cloudflare 已设置：{zone}（zone id {zone_id}）")
        return 0

    print(f"未知命令 {cmd}", file=sys.stderr)
    return 2


async def cmdline(args: argparse.Namespace, cfg: Config) -> int:
    engine = Engine(cfg)
    try:
        if args.status:
            for target in cfg.targets:
                detail = await engine.describe(target)
                eip = detail.get("eip")
                if eip:
                    print(f"{target.name}\t{eip.ip}\t{eip.status}\t{target.account}\t{','.join(target.dns_records)}")
                else:
                    print(f"{target.name}\t-\t-\t{target.account}\t{detail.get('error') or ''}")
            return 0

        if args.switch:
            name = args.switch
            if name not in cfg.target_names():
                print(f"没有实例 {name}，可选：{', '.join(cfg.target_names()) or '无'}", file=sys.stderr)
                return 2
            print(f"开始为 {name} 换 IP（不推送 Telegram，因为没启动机器人）")
            result = await engine.switch(name, reason="命令行")
            print(f"结果：{'成功' if result.ok else '失败'}")
            if result.old_ip:
                print(f"旧 IP：{result.old_ip}" + ("（已释放）" if result.old_released else ""))
            if result.new_ip:
                print(f"新 IP：{result.new_ip}")
            for d in result.dns:
                print(f"  {'✓' if d['ok'] == '1' else '✗'} {d['name']} {d['detail']}")
            if result.error:
                print(f"错误：{result.error}")
            for step in result.steps:
                print(f"  · {step}")
            return 0 if result.ok else 1

        if args.dns:
            results = await engine.manual_dns(args.dns)
            for r in results:
                print(f"{'✓' if r['ok'] == '1' else '✗'} {r['name']} {r['detail']}")
            return 0
    finally:
        await engine.close()
    return 0


async def amain(args: argparse.Namespace) -> int:
    try:
        cfg = Config.load(args.config, args.env)
    except ConfigError as exc:
        print(f"配置错误：{exc}", file=sys.stderr)
        return 2
    setup_logging(cfg.log_level)

    if args.bind:
        try:
            chat_id = int(args.bind)
        except ValueError:
            print("chat id 需要是数字", file=sys.stderr)
            return 2
        ids = set(cfg.admin_chat_ids)
        ids.add(chat_id)
        cfg.admin_chat_ids = tuple(sorted(ids))
        cfg.save()
        print(f"✅ 已添加管理员 {chat_id}")
        print(f"   现在共有：{', '.join(str(i) for i in cfg.admin_chat_ids)}")
        return 0

    if cfg.legacy_migrated:
        print("ℹ️ 检测到第一版配置，已自动兼容：")
        for item in cfg.legacy_migrated:
            print(f"    · {item}")
        print(f"    建议保存为新格式：eipguard -c {cfg.path} --migrate")
        print()

    if args.check_config:
        print("✅ 配置校验通过")
        print(f"  配置：{cfg.path}")
        print(f"  管理员：{', '.join(str(i) for i in cfg.admin_chat_ids) or '未设置'}")
        print(f"  频道：{cfg.channel_id or '未设置'}")
        print(f"  阿里云账号：{len(cfg.accounts)} 个")
        for acc in cfg.accounts.values():
            n = sum(1 for t in cfg.targets if t.account == acc.name)
            print(f"    - {acc.masked()} · {n} 台实例")
        cf = cfg.cloudflare
        print(f"  Cloudflare：{cf.zone_name or cf.zone_id or '未设置'} · proxied={cf.proxied} · ttl={cf.ttl}")
        print(f"  换完释放旧 IP：{'是' if cfg.switch.release_old else '否'}")
        if cfg.targets:
            print(f"  实例（{len(cfg.targets)} 台）：")
            for t in cfg.targets:
                print(f"    - {t.brief()}")
        else:
            print("  ⚠️ 还没有实例，用 /target add 或在 config.yaml 里添加")
        if not cfg.cloudflare.api_token:
            print("  ⚠️ 没有 Cloudflare Token，用 /cf 设置")
        return 0

    if args.migrate:
        if not cfg.legacy_migrated:
            print("配置已经是新格式，无需迁移")
            return 0
        backup = cfg.path.with_suffix(".yaml.bak")
        if not backup.exists():
            backup.write_text(cfg.path.read_text("utf-8"), "utf-8")
            print(f"📄 已备份原配置：{backup}")
        cfg.save()
        print(f"✅ 已迁移为新格式：{cfg.path}")
        for item in cfg.legacy_migrated:
            print(f"    · {item}")
        print()
        print("验证：eipguard --check-config")
        print("然后：systemctl restart eipguard")
        return 0

    if args.command in {"account", "target", "cf", "bind"}:
        return await handle_command(args, cfg)

    if args.status or args.switch or args.dns:
        return await cmdline(args, cfg)

    bot: BotApp | None = None
    if not args.no_bot:
        bot = BotApp(cfg, None)
    engine = Engine(cfg, notifier=bot.notify if bot else None)
    if bot:
        bot.engine = engine

    if args.no_bot:
        print("没有 --status / --switch / --dns，且指定了 --no-bot，无事可做", file=sys.stderr)
        return 2

    stop = asyncio.Event()

    def _stop(*_: object) -> None:
        stop.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _stop)
        except NotImplementedError:
            pass

    bot_task = asyncio.create_task(watch_bot(bot), name="telegram")
    stop_task = asyncio.create_task(stop.wait(), name="stop")
    done, _ = await asyncio.wait({bot_task, stop_task}, return_when=asyncio.FIRST_COMPLETED)
    for task in done:
        try:
            error = task.exception()
        except asyncio.CancelledError:
            continue
        if error and not isinstance(error, asyncio.CancelledError):
            log.error("任务 %s 退出：%s", task.get_name(), error)

    log.info("正在关闭…")
    for pending in (bot_task, stop_task):
        if pending and not pending.done():
            pending.cancel()
    await asyncio.gather(*[t for t in (bot_task, stop_task) if t], return_exceptions=True)
    if bot and bot.app:
        try:
            if bot.app.updater and bot.app.updater.running:
                await bot.app.updater.stop()
            await bot.app.stop()
            await bot.app.shutdown()
        except Exception:  # noqa: BLE001
            pass
    await engine.close()
    return 0


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    try:
        raise SystemExit(asyncio.run(amain(args)))
    except KeyboardInterrupt:
        raise SystemExit(130)


if __name__ == "__main__":
    main()
