from __future__ import annotations

from typing import Any

import pytest

from eipguard import fmt
from eipguard.bot import BotApp
from eipguard.state import Settings, StateStore


class FakeMessage:
    def __init__(self) -> None:
        self.texts: list[str] = []
        self.edits: list[str] = []
        self.markups: list[Any] = []

    async def reply_text(self, text: str, **kw: Any) -> "FakeMessage":
        self.texts.append(text)
        self.markups.append(kw.get("reply_markup"))
        return self

    async def edit_text(self, text: str, **kw: Any) -> "FakeMessage":
        self.edits.append(text)
        return self

    @property
    def all_text(self) -> str:
        return "\n".join(self.texts + self.edits)


class FakeChat:
    def __init__(self, chat_id: int) -> None:
        self.id = chat_id


class FakeUser:
    def __init__(self, user_id: int) -> None:
        self.id = user_id


class FakeUpdate:
    def __init__(self, chat_id: int = 42, user_id: int | None = None) -> None:
        self.effective_chat = FakeChat(chat_id)
        self.effective_user = FakeUser(user_id if user_id is not None else chat_id)
        self.effective_message = FakeMessage()
        self.callback_query = None


class FakeCtx:
    def __init__(self, args: list[str] | None = None) -> None:
        self.args = args or []


@pytest.fixture
def app(tmp_path):
    from tests.test_engine import FakeAliyun, FakeCloudflare, WallDetector, make_cfg, make_engine

    cfg = make_cfg(tmp_path)
    cfg_path = cfg.path
    cfg = type(cfg).load(cfg_path)
    store = StateStore.load(cfg.data_dir / "state.json", ["hk"], {"auto": True})
    settings = Settings.from_values({"auto": True, "interval": 60, "failure_threshold": 3, "cooldown": 900}, {})
    aliyun = FakeAliyun()
    aliyun.seed("eip-old", "1.1.1.1", instance_id="i-1", status="InUse")
    engine, store, events = make_engine(tmp_path, WallDetector({"1.1.1.1"}), aliyun, FakeCloudflare())
    engine.cfg.telegram_token = cfg.telegram_token
    bot = BotApp(engine.cfg, engine, store, settings)
    bot.admin_ids = {42}
    return bot, engine, store, events


@pytest.mark.asyncio
async def test_settings_command(app):
    bot, _, _, _ = app
    update = FakeUpdate(42)
    await bot.cmd_settings(update, FakeCtx())
    assert "检查间隔：60s" in update.effective_message.all_text


@pytest.mark.asyncio
async def test_set_interval_and_validation(app):
    bot, _, store, _ = app
    update = FakeUpdate(42)
    await bot.cmd_set(update, FakeCtx(["interval", "30"]))
    assert bot.settings.interval == 30
    await bot.cmd_set(update, FakeCtx(["interval", "1"]))  # 低于下限
    assert bot.settings.interval == 30
    assert "范围" in update.effective_message.all_text
    await bot.cmd_set(update, FakeCtx(["cooldown", "abc"]))
    assert "整数" in update.effective_message.all_text


@pytest.mark.asyncio
async def test_set_boolean(app):
    bot, _, _, _ = app
    update = FakeUpdate(42)
    await bot.cmd_set(update, FakeCtx(["release", "off"]))
    assert bot.settings.release_old is False
    await bot.cmd_set(update, FakeCtx(["release", "maybe"]))
    assert "on 或 off" in update.effective_message.all_text


@pytest.mark.asyncio
async def test_autoswitch_toggle_updates_all_targets(app):
    bot, _, store, _ = app
    update = FakeUpdate(42)
    await bot.cmd_autoswitch(update, FakeCtx())
    assert bot.settings.auto is False
    assert store.get("hk").auto is False


@pytest.mark.asyncio
async def test_unauthorized_is_rejected(app):
    bot, _, _, _ = app
    update = FakeUpdate(999)
    await bot.cmd_status(update, FakeCtx())
    assert "未授权" in update.effective_message.all_text


@pytest.mark.asyncio
async def test_ip_command(app):
    bot, _, _, _ = app
    update = FakeUpdate(42)
    await bot.cmd_ip(update, FakeCtx())
    assert "1.1.1.1" in update.effective_message.all_text


@pytest.mark.asyncio
async def test_status_command_shows_probe(app):
    bot, _, _, _ = app
    update = FakeUpdate(42)
    await bot.cmd_status(update, FakeCtx(["hk"]))
    text = update.effective_message.all_text
    assert "1.1.1.1" in text
    assert "连续异常" in text
    assert "分层结果" in text
    assert "TCP" in text
    assert "hk.example.com" in text


@pytest.mark.asyncio
async def test_switch_without_args_shows_buttons(app):
    bot, _, _, _ = app
    update = FakeUpdate(42)
    await bot.cmd_switch(update, FakeCtx())
    kb = update.effective_message.markups[0]
    assert kb.inline_keyboard[0][0].callback_data == "switch:hk"


@pytest.mark.asyncio
async def test_unknown_target_message(app):
    bot, _, _, _ = app
    update = FakeUpdate(42)
    await bot.cmd_switch(update, FakeCtx(["nope"]))
    assert "没有目标" in update.effective_message.all_text


def test_render_result_contains_steps():
    from eipguard.engine import SwitchResult

    bot = BotApp.__new__(BotApp)
    result = SwitchResult(ok=True, target="hk", old_ip="1.1.1.1", new_ip="2.2.2.2", elapsed=12.3)
    result.steps = ["分配新 EIP", "更新 DNS"]
    text = bot.render_result(result)
    assert "更换成功" in text and "2.2.2.2" in text and "更新 DNS" in text


def test_fmt_escapes_html():
    assert fmt.esc("<b>x</b>") == "&lt;b&gt;x&lt;/b&gt;"
    text = fmt.blocked_text(
        {"target": "t", "ip": "1.1.1.1", "detail": "d", "will_switch": True, "verdict": "ip_blocked"}
    )
    assert "IP 被墙" in text and "准备更换 IP" in text
    assert "恢复正常" in fmt.recovered_text({"target": "t", "ip": "1.1.1.1"})


def test_fmt_port_blocked_says_no_switch():
    text = fmt.blocked_text(
        {
            "target": "t",
            "ip": "1.1.1.1",
            "detail": "仅端口被封",
            "verdict": "port_blocked",
            "switchable": False,
            "advice": "换端口",
        }
    )
    assert "换 IP 无效" in text
    assert "换端口" in text
    assert "准备更换 IP" not in text


def test_fmt_service_down_text():
    text = fmt.service_down_text({"target": "t", "ip": "1.1.1.1", "detail": "墙外也不通"})
    assert "不是被墙" in text
    assert "安全组" in text


def test_verdict_definitions_cover_all():
    text = fmt.verdict_definitions_text()
    for label in ("IP 被墙", "端口被墙", "TLS 被阻断", "数据面被阻断", "服务不可用"):
        assert label in text
