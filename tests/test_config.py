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
aliyun:
  accounts:
    - name: main
      access_key_id: ak1
      access_key_secret: sk1
      region: cn-hongkong
    - name: second
      access_key_id: ak2
      access_key_secret: sk2
      region: ap-southeast-1
cloudflare:
  api_token: cf-token
  zone_name: example.com
targets:
  - name: hk
    account: main
    instance_id: i-abc
    dns_records: ["hk.example.com", "api"]
  - name: sg
    account: second
    instance_id: i-def
    dns_records: [sg.example.com]
"""

ENV = """
TG_BOT_TOKEN=123:abc
TG_ADMIN_IDS=111,222
"""


def test_load_accounts_and_targets(tmp_path):
    cfg = Config.load(write(tmp_path, BASE, ENV))
    assert cfg.telegram_token == "123:abc"
    assert cfg.admin_chat_ids == (111, 222)
    assert set(cfg.accounts) == {"main", "second"}
    assert cfg.account("second").region == "ap-southeast-1"
    assert [t.name for t in cfg.targets] == ["hk", "sg"]
    assert cfg.target("hk").dns_records == ["hk.example.com", "api"]
    assert cfg.region_for(cfg.target("sg")) == "ap-southeast-1"


def test_target_region_overrides_account(tmp_path):
    text = BASE.replace('instance_id: i-def', 'instance_id: i-def\n    region: cn-shanghai')
    cfg = Config.load(write(tmp_path, text, ENV))
    assert cfg.region_for(cfg.target("sg")) == "cn-shanghai"


def test_unknown_account_rejected(tmp_path):
    text = BASE.replace("account: second", "account: nope")
    with pytest.raises(ConfigError, match="nope"):
        Config.load(write(tmp_path, text, ENV))


def test_duplicate_target_names(tmp_path):
    text = BASE + """
  - name: hk
    account: main
    instance_id: i-xyz
"""
    with pytest.raises(ConfigError, match="重复"):
        Config.load(write(tmp_path, text, ENV))


def test_missing_telegram_token(tmp_path):
    """token 缺失时应该明确报错，不管是因为环境变量没设还是值是空。"""
    with pytest.raises(ConfigError, match="TG_BOT_TOKEN|telegram.token"):
        Config.load(write(tmp_path, BASE, "TG_ADMIN_IDS=1\n"))


def test_empty_accounts_allowed(tmp_path):
    """全新安装可以先不填账号，之后在 TG 里加。"""
    text = """
telegram:
  token: "${TG_BOT_TOKEN}"
aliyun:
  accounts: []
cloudflare:
  api_token: ""
targets: []
"""
    cfg = Config.load(write(tmp_path, text, "TG_BOT_TOKEN=1:2\n"))
    assert cfg.accounts == {}
    assert cfg.targets == []
    assert cfg.cloudflare.api_token == ""


def test_save_roundtrip(tmp_path):
    cfg = Config.load(write(tmp_path, BASE, ENV))
    cfg.admin_chat_ids = (111, 222, 333)
    cfg.targets[0].dns_records = ["x.example.com"]
    cfg.save()

    again = Config.load(cfg.path)
    assert again.admin_chat_ids == (111, 222, 333)
    assert again.target("hk").dns_records == ["x.example.com"]
    assert set(again.accounts) == {"main", "second"}
    # 密钥已落盘（因此文件权限必须是 600）
    assert (cfg.path.stat().st_mode & 0o777) == 0o600


def test_save_new_account(tmp_path):
    cfg = Config.load(write(tmp_path, BASE, ENV))
    from eipguard.config import Account

    cfg.accounts["third"] = Account(
        name="third", access_key_id="ak3", access_key_secret="sk3", region="us-west-1"
    )
    cfg.save()
    again = Config.load(cfg.path)
    assert again.account("third").access_key_id == "ak3"
    assert again.account("third").region == "us-west-1"


def test_masked_does_not_leak_secret(tmp_path):
    cfg = Config.load(write(tmp_path, BASE, ENV))
    text = cfg.account("main").masked()
    assert "sk1" not in text
    assert "main" in text


def test_parse_id_list():
    assert parse_id_list("1, 2 ,3") == (1, 2, 3)
    assert parse_id_list([-100123, 5]) == (-100123, 5)
    assert parse_id_list("") == ()
    with pytest.raises(ConfigError):
        parse_id_list("abc")


def test_save_keeps_file_private(tmp_path):
    cfg = Config.load(write(tmp_path, BASE, ENV))
    cfg.save()
    assert (cfg.path.stat().st_mode & 0o777) == 0o600


def test_save_writes_accounts_and_targets_verbatim(tmp_path):
    import yaml

    cfg = Config.load(write(tmp_path, BASE, ENV))
    cfg.save()
    data = yaml.safe_load(cfg.path.read_text("utf-8"))
    assert data["aliyun"]["accounts"][0]["access_key_id"] == "ak1"
    assert data["targets"][0]["instance_id"] == "i-abc"
    # 占位符已被展开成真实值（TG 新增的账号必须能落盘）
    assert "${" not in cfg.path.read_text("utf-8")


LEGACY_V1 = """
telegram:
  token: "${TG_BOT_TOKEN}"
  admin_chat_ids: "${TG_ADMIN_IDS:-}"
  channel_id: "${TG_CHANNEL_ID:-}"
aliyun:
  access_key_id: "${ALIYUN_AK_ID}"
  access_key_secret: "${ALIYUN_AK_SECRET}"
  region_id: "cn-hongkong"
cloudflare:
  api_token: "${CF_API_TOKEN}"
  zone_name: "example.com"
detect:
  provider: probe_agent
  probe_agent:
    urls: "${PROBE_AGENT_URL}"
    token: "${PROBE_AGENT_TOKEN}"
targets:
  - name: hk-main
    instance_id: "i-abc"
    probe_port: 443
    aux_ports: [22, 80]
    dns_records: ["hk.example.com"]
"""

LEGACY_ENV = """
TG_BOT_TOKEN=111:REAL
TG_ADMIN_IDS=555666
TG_CHANNEL_ID=-1001234567890
ALIYUN_AK_ID=akREAL
ALIYUN_AK_SECRET=skREAL
CF_API_TOKEN=cfREAL
CF_ZONE_NAME=realdomain.com
PROBE_AGENT_URL=http://1.1.1.1:8787
PROBE_AGENT_TOKEN=ptok
"""


def test_legacy_v1_config_migrates_accounts(tmp_path):
    """第一版平铺的 aliyun.access_key_id 要变成 accounts[default]。"""
    cfg = Config.load(write(tmp_path, LEGACY_V1, LEGACY_ENV))
    assert list(cfg.accounts) == ["default"]
    assert cfg.account("default").access_key_id == "akREAL"
    assert cfg.account("default").access_key_secret == "skREAL"
    assert cfg.account("default").region == "cn-hongkong"


def test_legacy_target_gets_default_account(tmp_path):
    cfg = Config.load(write(tmp_path, LEGACY_V1, LEGACY_ENV))
    assert cfg.target("hk-main").account == "default"
    assert cfg.target("hk-main").dns_records == ["hk.example.com"]


def test_legacy_ignores_probe_fields(tmp_path):
    cfg = Config.load(write(tmp_path, LEGACY_V1, LEGACY_ENV))
    assert any("probe_port" in item for item in cfg.legacy_migrated)


def test_legacy_zone_name_from_env(tmp_path):
    """第一版把 zone_name 写死 example.com，真域名在 .env 里，要纠正。"""
    cfg = Config.load(write(tmp_path, LEGACY_V1, LEGACY_ENV))
    assert cfg.cloudflare.zone_name == "realdomain.com"


def test_legacy_keeps_admin_channel(tmp_path):
    cfg = Config.load(write(tmp_path, LEGACY_V1, LEGACY_ENV))
    assert cfg.admin_chat_ids == (555666,)
    assert cfg.channel_id == -1001234567890


def test_legacy_migrate_saves_new_format(tmp_path):
    cfg = Config.load(write(tmp_path, LEGACY_V1, LEGACY_ENV))
    cfg.save()
    again = Config.load(cfg.path)
    assert again.account("default").access_key_id == "akREAL"
    assert again.cloudflare.zone_name == "realdomain.com"
    assert again.target("hk-main").account == "default"
    # 迁移后不再需要 .env
    assert again.legacy_migrated == [] or "第一版" not in str(again.legacy_migrated)
    text = cfg.path.read_text("utf-8")
    assert "accounts:" in text
    assert "access_key_id: akREAL" in text


def test_new_format_not_treated_as_legacy(tmp_path):
    cfg = Config.load(write(tmp_path, BASE, ENV))
    assert cfg.legacy_migrated == []


def test_import_env_helper_skips_placeholders():
    """确认占位符检测不会把真密钥误判为占位符。"""
    from eipguard.__main__ import usable

    assert usable("LTAI5tAbCdEf123456") is True
    assert usable("your_bot_token") is False
    assert usable("LTAI5txxxxxxxxxxxxxxxx") is False
    assert usable("change-me-to-a-long-random-string") is False
    assert usable("") is False
