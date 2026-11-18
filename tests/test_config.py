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
