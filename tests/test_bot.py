from __future__ import annotations

from typing import Any

import pytest

from eipguard import fmt
from eipguard.bot import BotApp
from eipguard.config import Config
from eipguard.engine import Engine

CONFIG = """
telegram:
  token: "1:abc"
  admin_chat_ids: "42"
aliyun:
  accounts:
    - name: main
      access_key_id: ak1
      access_key_secret: sk1
      region: cn-hongkong
cloudflare:
  api_token: cf
  zone_name: example.com
targets:
  - name: hk
    account: main
    instance_id: i-1
    dns_records: ["hk.example.com"]
"""


class FakeMessage:
    def __init__(self) -> None:
        self.texts: list[str] = []
        self.edits: list[str] = []
        self.markups: list[Any] = []
        self.deleted = False

    async def reply_text(self, text: str, **kw: Any) -> "FakeMessage":
        self.texts.append(text)
        self.markups.append(kw.get("reply_markup"))
        return self

    async def edit_text(self, text: str, **kw: Any) -> "FakeMessage":
        self.edits.append(text)
        return self

    async def delete(self) -> None:
        self.deleted = True

    @property
    def text(self) -> str:
        return self.texts[-1] if self.texts else ""

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
    def __init__(self, chat_id: int = 42, text: str = "") -> None:
        self.effective_chat = FakeChat(chat_id)
        self.effective_user = FakeUser(chat_id)
        self.effective_message = FakeMessage()
        if text:
            self.effective_message.texts.append(text)
        self.callback_query = None

    @property
    def message_text(self) -> str:
        return self.effective_message.texts[-1] if self.effective_message.texts else ""


class FakeCtx:
    def __init__(self, args: list[str] | None = None) -> None:
        self.args = args or []
        self.user_data: dict[str, Any] = {}


class FakeAliyun:
    def __init__(self) -> None:
        from eipguard.cloud.aliyun import EipInfo

        self.eips: dict[str, EipInfo] = {
            "eip-a1": EipInfo(allocation_id="eip-a1", ip="1.1.1.1", status="InUse", instance_id="i-1")
        }
        self.calls: list[str] = []
        self._seq = 0
        self.validate_error: str = ""

    async def describe_eips(self, **kw):
        if self.validate_error:
            from eipguard.cloud.aliyun import AliyunError

            raise AliyunError("DescribeEipAddresses", "InvalidAccessKeyId.NotFound", self.validate_error)
        return list(self.eips.values())

    async def get_eip(self, allocation_id, region_id=None):
        return self.eips.get(allocation_id)

    async def find_instance_eip(self, instance_id, region_id=None):
        for e in self.eips.values():
            if e.instance_id == instance_id:
                return e
        return None

    async def allocate_eip(self, **kw):
        from eipguard.cloud.aliyun import EipInfo

        self._seq += 1
        info = EipInfo(allocation_id=f"new{self._seq}", ip=f"9.9.9.{self._seq}", status="Available")
        self.eips[info.allocation_id] = info
        return info

    async def associate(self, allocation_id, instance_id, region_id=None):
        self.calls.append(f"associate:{allocation_id}")
        e = self.eips[allocation_id]
        e.instance_id = instance_id
        e.status = "InUse"

    async def unassociate(self, allocation_id, instance_id="", region_id=None):
        self.calls.append(f"unassociate:{allocation_id}")
        e = self.eips[allocation_id]
        e.instance_id = ""
        e.status = "Available"

    async def release(self, allocation_id, region_id=None):
        self.calls.append(f"release:{allocation_id}")
        self.eips.pop(allocation_id, None)

    async def wait_status(self, allocation_id, wanted, **kw):
        e = self.eips[allocation_id]
        e.status = sorted(wanted)[0]
        return e


class FakeCloudflare:
    def __init__(self) -> None:
        self.points: dict[str, str] = {}

    async def point_many(self, names, ip):
        out = []
        for n in names:
            self.points[n] = ip
            out.append({"name": n, "action": "updated", "detail": f"{n} → {ip}", "ok": "1"})
        return out

    async def list_records(self, name, record_type="A"):
        return []

    async def resolve_zone_id(self):
        return "zone123"

    async def close(self):
        return None


@pytest.fixture
def app(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(CONFIG, "utf-8")
    cfg = Config.load(path)
    aliyun = FakeAliyun()
    cf = FakeCloudflare()
    events: list[dict[str, Any]] = []

    async def notify(ev):
        events.append(ev)

    engine = Engine(
        cfg,
        notifier=notify,
        aliyuns={"main": aliyun},  # type: ignore[arg-type]
        cloudflare=cf,  # type: ignore[arg-type]
    )
    engine.make_client = lambda acc: aliyun  # type: ignore[method-assign]
    bot = BotApp(cfg, engine)
    bot.admin_ids = {42}
    return bot, cfg, engine, events, aliyun, cf


# ---------------------------------------------------------------- 权限
@pytest.mark.asyncio
async def test_unauthorized_rejected(app):
    bot, *_ = app
    update = FakeUpdate(999)
    await bot.cmd_status(update, FakeCtx())
    assert "未授权" in update.effective_message.all_text
    assert "999" in update.effective_message.all_text


@pytest.mark.asyncio
async def test_bind_with_token(app):
    bot, cfg, *_ = app
    cfg.bind_token = "secret"
    bot.admin_ids = set()
    update = FakeUpdate(777)
    await bot.cmd_bind(update, FakeCtx(["secret"]))
    assert 777 in bot.admin_ids
    assert "已绑定" in update.effective_message.all_text


@pytest.mark.asyncio
async def test_bind_wrong_token(app):
    bot, cfg, *_ = app
    cfg.bind_token = "secret"
    bot.admin_ids = set()
    update = FakeUpdate(777)
    await bot.cmd_bind(update, FakeCtx(["wrong"]))
    assert 777 not in bot.admin_ids


# ---------------------------------------------------------------- 查看
@pytest.mark.asyncio
async def test_status_overview(app):
    bot, *_ = app
    update = FakeUpdate(42)
    await bot.cmd_status(update, FakeCtx())
    text = update.effective_message.all_text
    assert "hk" in text
    assert "1.1.1.1" in text


@pytest.mark.asyncio
async def test_status_single_target(app):
    bot, *_ = app
    update = FakeUpdate(42)
    await bot.cmd_status(update, FakeCtx(["hk"]))
    text = update.effective_message.all_text
    assert "1.1.1.1" in text
    assert "eip-a1" in text
    assert "hk.example.com" in text


@pytest.mark.asyncio
async def test_accounts_list(app):
    bot, *_ = app
    update = FakeUpdate(42)
    await bot.cmd_accounts(update, FakeCtx())
    text = update.effective_message.all_text
    assert "main" in text
    assert "sk1" not in text, "不能泄露 secret"


# ---------------------------------------------------------------- 换 IP
@pytest.mark.asyncio
async def test_switch_without_args_shows_buttons(app):
    bot, *_ = app
    update = FakeUpdate(42)
    await bot.cmd_switch(update, FakeCtx())
    kb = update.effective_message.markups[0]
    assert kb.inline_keyboard[0][0].callback_data == "sw:hk"


@pytest.mark.asyncio
async def test_switch_confirms_before_acting(app):
    bot, cfg, engine, events, aliyun, _ = app
    update = FakeUpdate(42)
    await bot.cmd_switch(update, FakeCtx(["hk"]))
    text = update.effective_message.all_text
    assert "确认换 IP" in str(update.effective_message.markups[0].inline_keyboard)
    assert "1.1.1.1" in text
    # 还没确认，不该动任何东西
    assert aliyun.calls == []
    assert events == []


@pytest.mark.asyncio
async def test_switch_unknown_target(app):
    bot, *_ = app
    update = FakeUpdate(42)
    await bot.cmd_switch(update, FakeCtx(["nope"]))
    assert "没有实例" in update.effective_message.all_text


@pytest.mark.asyncio
async def test_do_switch_runs_engine(app):
    bot, cfg, engine, events, aliyun, _ = app
    bot.app = _FakeBotApp()
    await bot._do_switch(42, "hk")
    kinds = [e["type"] for e in events]
    assert "old_ip_released" in kinds
    assert "switch_success" in kinds
    assert "release:eip-a1" in aliyun.calls


class _FakeBotApp:
    def __init__(self) -> None:
        self.bot = _FakeBot()
        self.sent: list[tuple[int, str]] = []


class _FakeBot:
    async def send_message(self, chat_id, text, **kw):
        _SENT.append((chat_id, text))
        return _FakeMsg()


class _FakeMsg:
    async def edit_text(self, text, **kw):
        _SENT.append((0, text))
        return self


_SENT: list[tuple[int, str]] = []


# ---------------------------------------------------------------- 设置
@pytest.mark.asyncio
async def test_set_release_off(app):
    bot, cfg, *_ = app
    update = FakeUpdate(42)
    await bot.cmd_set(update, FakeCtx(["release", "off"]))
    assert cfg.switch.release_old is False
    assert "计费" in update.effective_message.all_text


@pytest.mark.asyncio
async def test_set_retries_bounds(app):
    bot, cfg, *_ = app
    update = FakeUpdate(42)
    await bot.cmd_set(update, FakeCtx(["retries", "99"]))
    assert cfg.switch.max_attempts == 10


@pytest.mark.asyncio
async def test_settings_text_hides_secrets(app):
    bot, cfg, *_ = app
    update = FakeUpdate(42)
    await bot.cmd_settings(update, FakeCtx())
    text = update.effective_message.all_text
    assert "sk1" not in text
    assert "cf" not in text.lower() or "Cloudflare" in text


# ---------------------------------------------------------------- 账号添加
@pytest.mark.asyncio
async def test_add_account_validates_ak(app):
    """AK 验证失败时不能保存，并要告诉用户原因。"""
    bot, cfg, engine, *_ = app
    bot.app = _FakeBotApp()
    aliyun = engine.aliyuns["main"]
    aliyun.validate_error = "The specified access key is not found."
    bot._pending = {"name": "bad", "ak": "ak-bad", "sk": "sk-bad"}
    _SENT.clear()
    await bot._finish_account(42, "cn-hongkong")
    assert "bad" not in cfg.accounts
    assert any("验证失败" in text for _, text in _SENT)


@pytest.mark.asyncio
async def test_add_account_success(app):
    bot, cfg, engine, *_ = app
    bot.app = _FakeBotApp()
    _SENT.clear()
    await bot._add_account("third", "ak3", "sk3", "us-west-1", chat_id=42)
    assert "third" in cfg.accounts
    assert cfg.account("third").region == "us-west-1"
    assert any("已添加" in text for _, text in _SENT)


@pytest.mark.asyncio
async def test_del_account_blocked_when_in_use(app):
    bot, cfg, *_ = app
    await bot._del_account("main")
    assert "main" in cfg.accounts, "账号下还有实例时不能删"


@pytest.mark.asyncio
async def test_account_region_change(app):
    bot, cfg, engine, *_ = app
    update = FakeUpdate(42)
    await bot.cmd_account(update, FakeCtx(["region", "main", "cn-shanghai"]))
    assert cfg.account("main").region == "cn-shanghai"
    assert "cn-shanghai" in update.effective_message.all_text


# ---------------------------------------------------------------- 实例
@pytest.mark.asyncio
async def test_add_target_success(app):
    bot, cfg, engine, *_ = app
    bot.app = _FakeBotApp()
    _SENT.clear()
    await bot._add_target("hk2", "main", "i-1", ["new.example.com"], chat_id=42)
    assert "hk2" in cfg.target_names()
    assert any("已添加" in text for _, text in _SENT)


@pytest.mark.asyncio
async def test_add_target_unknown_account(app):
    bot, cfg, *_ = app
    bot.app = _FakeBotApp()
    _SENT.clear()
    await bot._add_target("x", "nope", "i-1", [], chat_id=42)
    assert "x" not in cfg.target_names()
    assert any("不存在" in text for _, text in _SENT)


@pytest.mark.asyncio
async def test_target_dns_update(app):
    bot, cfg, *_ = app
    update = FakeUpdate(42)
    await bot.cmd_target(update, FakeCtx(["dns", "hk", "a.example.com", "b.example.com"]))
    assert cfg.target("hk").dns_records == ["a.example.com", "b.example.com"]


@pytest.mark.asyncio
async def test_target_del(app):
    bot, cfg, *_ = app
    update = FakeUpdate(42)
    await bot.cmd_target(update, FakeCtx(["del", "hk"]))
    assert cfg.target_names() == []


# ---------------------------------------------------------------- fmt
def test_fmt_escapes_html():
    assert fmt.esc("<b>x</b>") == "&lt;b&gt;x&lt;/b&gt;"


def test_fmt_success_mentions_released():
    text = fmt.success_text(
        {"target": "hk", "old_ip": "1.1.1.1", "new_ip": "2.2.2.2", "old_released": True,
         "dns": [{"name": "a.com", "ok": "1"}]}
    )
    assert "已释放" in text
    assert "2.2.2.2" in text


def test_fmt_success_warns_not_released():
    text = fmt.success_text(
        {"target": "hk", "old_ip": "1.1.1.1", "new_ip": "2.2.2.2", "old_released": False, "dns": []}
    )
    assert "仍在计费" in text


def test_fmt_help_lists_switch():
    text = fmt.help_text()
    assert "/switch" in text
    assert "/account add" in text
    assert "/target add" in text
