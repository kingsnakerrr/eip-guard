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
