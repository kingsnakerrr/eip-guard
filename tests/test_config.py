from __future__ import annotations

from pathlib import Path

import pytest

from eipguard.config import Config, ConfigError, parse_id_list


def write(tmp_path: Path, yaml_text: str, env_text: str = "") -> Path:
    (tmp_path / "config.yaml").write_text(yaml_text, "utf-8")
    if env_text:
        (tmp_path / ".env").write_text(env_text, "utf-8")
    return tmp_path / "config.yaml"


BASE = """
telegram:
  token: "${TG_BOT_TOKEN}"
  admin_chat_ids: "${TG_ADMIN_IDS:-}"
cloudflare:
  api_token: "${CF_API_TOKEN}"
  zone_name: "example.com"
  ttl: 60
  proxied: false
aliyun:
  access_key_id: "${ALIYUN_AK_ID}"
  access_key_secret: "${ALIYUN_AK_SECRET}"
detect:
  provider: probe_agent
  interval: 30
  failure_threshold: 2
  probe_agent:
    urls: "http://1.1.1.1:8787"
    token: "t"
switch:
  auto: false
  cooldown: 60
targets:
  - name: hk
    instance_id: i-abc
    dns_records: ["hk.example.com", "api"]
"""

ENV = """
TG_BOT_TOKEN=123:abc
TG_ADMIN_IDS=111,222
CF_API_TOKEN=cf-token
ALIYUN_AK_ID=ak
ALIYUN_AK_SECRET=sk
"""


def test_load_expands_env(tmp_path):
    cfg = Config.load(write(tmp_path, BASE, ENV))
    assert cfg.telegram_token == "123:abc"
    assert cfg.admin_chat_ids == (111, 222)
    assert cfg.cloudflare.zone_name == "example.com"
    assert cfg.targets[0].name == "hk"
    assert cfg.targets[0].probe_port == 443
    assert cfg.targets[0].dns_records == ["hk.example.com", "api"]
    assert cfg.detect.interval == 30
    assert cfg.detect.probe_agents[0]["url"] == "http://1.1.1.1:8787"
    assert cfg.switch.cooldown == 60


def test_missing_env_raises(tmp_path):
    with pytest.raises(ConfigError):
        Config.load(write(tmp_path, BASE, "TG_BOT_TOKEN=1:2\n"))


def test_env_default_empty_admin(tmp_path):
    env = ENV.replace("TG_ADMIN_IDS=111,222", "TG_ADMIN_IDS=")
    cfg = Config.load(write(tmp_path, BASE, env))
    assert cfg.admin_chat_ids == ()


def test_relative_data_dir_is_under_config(tmp_path):
    cfg = Config.load(write(tmp_path, BASE, ENV))
    assert cfg.data_dir == (tmp_path / "data").resolve()


def test_duplicate_target_names(tmp_path):
    text = BASE + """
  - name: hk
    instance_id: i-def
"""
    with pytest.raises(ConfigError, match="重复"):
        Config.load(write(tmp_path, text, ENV))


def test_unknown_provider(tmp_path):
    with pytest.raises(ConfigError):
        Config.load(write(tmp_path, BASE.replace("provider: probe_agent", "provider: nope"), ENV))


def test_parse_id_list():
    assert parse_id_list("1, 2 ,3") == (1, 2, 3)
    assert parse_id_list(["-100123", 5]) == (-100123, 5)
    assert parse_id_list("") == ()
    with pytest.raises(ConfigError):
        parse_id_list("abc")


MULTI = """
telegram:
  token: "1:abc"
  admin_chat_ids: "42"
cloudflare:
  api_token: cf
  zone_name: example.com
aliyun:
  accounts:
    - name: main
      access_key_id: ak1
      access_key_secret: sk1
      default_region: cn-hongkong
    - name: second
      access_key_id: ak2
      access_key_secret: sk2
      default_region: ap-southeast-1
detect:
  port: 443
  aux_ports: [22, 80]
  provider: tcp_self
targets:
  - name: hk
    account: main
    instance_id: i-1
    dns_records: [hk.example.com]
  - name: sg
    account: second
    instance_id: i-2
    probe_port: 8443
    aux_ports: [22]
    dns_records: [sg.example.com]
"""


def test_multi_account_config(tmp_path):
    cfg = Config.load(write(tmp_path, MULTI, ENV))
    assert set(cfg.aliyun.accounts) == {"main", "second"}
    assert cfg.aliyun.account("second").access_key_id == "ak2"
    assert cfg.aliyun.account("second").default_region == "ap-southeast-1"
    assert [t.account for t in cfg.targets] == ["main", "second"]


def test_aux_ports_fallback_and_override(tmp_path):
    cfg = Config.load(write(tmp_path, MULTI, ENV))
    hk, sg = cfg.targets
    assert hk.aux_ports == [22, 80], "没写 aux_ports 时用全局"
    assert sg.aux_ports == [22], "target 写了就覆盖"
    assert hk.all_ports(443) == [443, 22, 80]
    assert sg.all_ports(443) == [8443, 22], "业务端口排在最前"


def test_unknown_account_raises(tmp_path):
    text = MULTI.replace("account: second", "account: third")
    with pytest.raises(ConfigError, match="third"):
        Config.load(write(tmp_path, text, ENV))


def test_duplicate_account_name(tmp_path):
    text = MULTI.replace('name: "second"', 'name: "main"').replace("name: second", "name: main")
    with pytest.raises(ConfigError, match="重名"):
        Config.load(write(tmp_path, text, ENV))


def test_single_account_legacy_form(tmp_path):
    """旧的单账号写法仍然可用。"""
    cfg = Config.load(write(tmp_path, BASE, ENV))
    assert list(cfg.aliyun.accounts) == ["default"]
    assert cfg.targets[0].account == "default"


def test_probe_agents_zones(tmp_path):
    text = MULTI.replace(
        "  provider: tcp_self",
        """  provider: probe_agent
  probe_agent:
    agents:
      - {url: "http://1.1.1.1:8787", token: t, zone: cn, name: cn1}
      - {url: "http://2.2.2.2:8787", token: t, zone: overseas, name: os1}""",
    )
    cfg = Config.load(write(tmp_path, text, ENV))
    assert [(a["zone"], a["name"]) for a in cfg.detect.probe_agents] == [
        ("cn", "cn1"),
        ("overseas", "os1"),
    ]


def test_watch_bot_survives_token_failure(tmp_path):
    """Telegram token 无效时，监控不能停。"""
    import asyncio

    from eipguard.__main__ import watch_bot

    class BrokenBot:
        def __init__(self) -> None:
            self.calls = 0

        async def run(self) -> None:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("The token was rejected by the server.")
            raise asyncio.CancelledError

    async def scenario() -> None:
        bot = BrokenBot()
        with pytest.raises(asyncio.CancelledError):
            await watch_bot(bot, retry_delay=0.01)
        assert bot.calls == 2, "第一次失败后应该重试"

    asyncio.run(scenario())
