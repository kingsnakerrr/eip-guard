from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
from typing import Any

from .bot import BotApp
from .config import Config, ConfigError
from .engine import Engine
from .log import setup_logging
from .state import Settings, StateStore

log = logging.getLogger("eipguard")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="eipguard", description="阿里云 EIP 被墙自动更换 + CF 解析 + TG 机器人")
    ap.add_argument("-c", "--config", default="config.yaml", help="配置文件路径（默认 config.yaml）")
    ap.add_argument("--env", default=None, help=".env 路径（默认与配置文件同目录）")
    ap.add_argument("--check-config", action="store_true", help="只校验配置并退出")
    ap.add_argument("--no-bot", action="store_true", help="不启动 Telegram 机器人，仅跑监控（调试用）")
    ap.add_argument("--once", action="store_true", help="立即检查一轮然后退出")
    return ap.parse_args(argv)


async def amain(args: argparse.Namespace) -> int:
    try:
        cfg = Config.load(args.config, args.env)
    except ConfigError as exc:
        print(f"配置错误：{exc}", file=sys.stderr)
        return 2
    setup_logging(cfg.log_level)
    log.info("配置文件 %s · %d 个目标", cfg.path, len(cfg.targets))

    base = {
        "auto": cfg.switch.auto,
        "interval": cfg.detect.interval,
        "failure_threshold": cfg.detect.failure_threshold,
        "cooldown": cfg.switch.cooldown,
        "release_old": cfg.switch.release_old,
    }
    store = StateStore.load(cfg.data_dir / "state.json", [t.name for t in cfg.targets], base)
    settings = Settings.from_values(base, store.settings)

    if args.check_config:
        print("✅ 配置校验通过")
        print(f"  目标：{', '.join(t.name for t in cfg.targets)}")
        print(f"  探测方式：{cfg.detect.provider} · 间隔 {settings.interval}s · 阈值 {settings.failure_threshold}")
        print(f"  Cloudflare zone：{cfg.cloudflare.zone_name or cfg.cloudflare.zone_id} · proxied={cfg.cloudflare.proxied}")
        print(f"  管理员：{len(cfg.admin_chat_ids)} 人 · 频道 {cfg.channel_id or '未设置'}")
        return 0

    bot: BotApp | None = None
    if not args.no_bot:
        bot = BotApp(cfg, None, store, settings)
    engine = Engine(cfg, store, settings, notifier=bot.notify if bot else None)
    if bot:
        bot.engine = engine

    if args.once:
        for target in cfg.targets:
            detail = await engine.inspect(target.name)
            probe = detail.get("probe")
            eip = detail.get("eip")
            status = "OK" if probe and probe.ok else ("BLOCKED" if probe and probe.blocked else "UNKNOWN")
            print(f"{target.name}: {eip.ip if eip else '-'} {status} {probe.reason if probe else detail.get('error')}")
        await engine.close()
        return 0

    stop = asyncio.Event()

    def _stop(*_: object) -> None:
        stop.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _stop)
        except NotImplementedError:
            pass

    monitor = asyncio.create_task(engine.monitor_loop(), name="monitor")
    bot_task: asyncio.Task[None] | None = None
    if bot:
        bot_task = asyncio.create_task(bot.run(), name="telegram")
    stop_task = asyncio.create_task(stop.wait(), name="stop")

    tasks: list[asyncio.Task[Any]] = [monitor, stop_task]
    if bot_task:
        tasks.append(bot_task)
    done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in done:
        try:
            error = task.exception()
        except asyncio.CancelledError:
            continue
        if error and not isinstance(error, asyncio.CancelledError):
            log.error("任务 %s 异常退出：%s", task.get_name(), error, exc_info=error)

    log.info("正在关闭…")
    for pending in (monitor, bot_task, stop_task):
        if pending and not pending.done():
            pending.cancel()
    await asyncio.gather(*[t for t in (monitor, bot_task, stop_task) if t], return_exceptions=True)
    if bot and bot.app:
        try:
            if bot.app.updater and bot.app.updater.running:
                await bot.app.updater.stop()
            await bot.app.stop()
            await bot.app.shutdown()
        except Exception:  # noqa: BLE001
            pass
    store.save()
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
