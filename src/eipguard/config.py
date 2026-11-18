"""配置加载 / 校验 / 回写。

支持多阿里云账号；配置可被 Telegram 机器人和 CLI 修改后写回 YAML。
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from dotenv import dotenv_values

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


class ConfigError(RuntimeError):
    pass


def _expand(value: Any, env: dict[str, str] | None = None) -> Any:
    if isinstance(value, dict):
        return {k: _expand(v, env) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v, env) for v in value]
    if not isinstance(value, str):
        return value

    lookup = env if env is not None else os.environ

    whole = _ENV_PATTERN.fullmatch(value)
    if whole:
        name, default = whole.group(1), whole.group(2)
        raw = lookup.get(name)
        if raw is None or raw == "":
            if default is None:
                raise ConfigError(f"环境变量 {name} 未设置，且没有默认值")
            raw = default
        return raw

    def repl(m: re.Match[str]) -> str:
        name, default = m.group(1), m.group(2)
        raw = lookup.get(name)
        if raw is None or raw == "":
            if default is None:
                raise ConfigError(f"环境变量 {name} 未设置，且没有默认值")
            return default
        return raw

    return _ENV_PATTERN.sub(repl, value)


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_bool(value: Any, default: bool) -> bool:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def parse_id_list(raw: Any) -> tuple[int, ...]:
    if raw is None:
        return ()
    items: list[Any] = []
    if isinstance(raw, (list, tuple, set)):
        items = list(raw)
    else:
        items = str(raw).replace(";", ",").split(",")
    out: list[int] = []
    for item in items:
        text = str(item).strip()
        if not text:
            continue
        try:
            out.append(int(text))
        except ValueError as exc:
            raise ConfigError(f"Telegram id 必须是数字：{text!r}") from exc
    return tuple(dict.fromkeys(out))


@dataclass
class Account:
    """一个阿里云账号。"""

    name: str
    access_key_id: str
    access_key_secret: str
    region: str = "cn-hongkong"
    endpoint: str = "vpc.aliyuncs.com"
    api_version: str = "2016-04-28"

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Account":
        name = str(raw.get("name") or "").strip()
        ak = str(raw.get("access_key_id") or "").strip()
        sk = str(raw.get("access_key_secret") or "").strip()
        if not name:
            raise ConfigError("account 的 name 不能为空")
        if not ak or not sk:
            raise ConfigError(f"账号 {name} 缺 access_key_id / access_key_secret")
        return cls(
            name=name,
            access_key_id=ak,
            access_key_secret=sk,
            region=str(raw.get("region") or raw.get("default_region") or "cn-hongkong"),
            endpoint=str(raw.get("endpoint") or "vpc.aliyuncs.com"),
            api_version=str(raw.get("api_version") or "2016-04-28"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "access_key_id": self.access_key_id,
            "access_key_secret": self.access_key_secret,
            "region": self.region,
        }

    def masked(self) -> str:
        ak = self.access_key_id
        shown = f"{ak[:8]}…{ak[-4:]}" if len(ak) > 14 else f"{ak[:4]}…"
        return f"{self.name} · {shown} · {self.region}"


@dataclass
class Target:
    """一台要换 IP 的实例。"""

    name: str
    account: str
    instance_id: str
    eip_allocation_id: str = ""
    region: str = ""
    dns_records: list[str] = field(default_factory=list)
    notes: str = ""

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Target":
        name = str(raw.get("name") or "").strip()
        instance_id = str(raw.get("instance_id") or "").strip()
        if not name:
            raise ConfigError("target 的 name 不能为空")
        if not instance_id:
            raise ConfigError(f"target {name}: instance_id 不能为空")
        records = raw.get("dns_records") or []
        if isinstance(records, str):
            records = [records]
        return cls(
            name=name,
            account=str(raw.get("account") or "default").strip(),
            instance_id=instance_id,
            eip_allocation_id=str(raw.get("eip_allocation_id") or "").strip(),
            region=str(raw.get("region") or "").strip(),
            dns_records=[str(r).strip() for r in records if str(r).strip()],
            notes=str(raw.get("notes") or "").strip(),
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "name": self.name,
            "account": self.account,
            "instance_id": self.instance_id,
        }
        if self.eip_allocation_id:
            out["eip_allocation_id"] = self.eip_allocation_id
        if self.region:
            out["region"] = self.region
        if self.dns_records:
            out["dns_records"] = list(self.dns_records)
        if self.notes:
            out["notes"] = self.notes
        return out

    def brief(self) -> str:
        dns = ", ".join(self.dns_records) if self.dns_records else "无域名"
        return f"{self.name} · {self.account} · {self.instance_id} · {dns}"


@dataclass
class CloudflareConfig:
    api_token: str = ""
    zone_id: str = ""
    zone_name: str = ""
    ttl: int = 60
    proxied: bool = False
    create_missing: bool = True
    multi_record_policy: str = "replace"
    api_base: str = "https://api.cloudflare.com/client/v4"

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "CloudflareConfig":
        policy = str(raw.get("multi_record_policy") or "replace").lower()
        if policy not in {"replace", "keep"}:
            raise ConfigError("cloudflare.multi_record_policy 只能是 replace 或 keep")
        return cls(
            api_token=str(raw.get("api_token") or "").strip(),
            zone_id=str(raw.get("zone_id") or "").strip(),
            zone_name=str(raw.get("zone_name") or "").strip(),
            ttl=_as_int(raw.get("ttl"), 60) or 1,
            proxied=_as_bool(raw.get("proxied"), False),
            create_missing=_as_bool(raw.get("create_missing"), True),
            multi_record_policy=policy,
            api_base=str(raw.get("api_base") or cls.api_base).rstrip("/"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "api_token": self.api_token,
            "zone_id": self.zone_id,
            "zone_name": self.zone_name,
            "ttl": self.ttl,
            "proxied": self.proxied,
            "create_missing": self.create_missing,
            "multi_record_policy": self.multi_record_policy,
        }

    def validate(self) -> None:
        if not self.api_token:
            raise ConfigError("cloudflare.api_token 为空（用 /cf 或 .env 的 CF_API_TOKEN 设置）")
        if not self.zone_id and not self.zone_name:
            raise ConfigError("cloudflare.zone_id 与 zone_name 至少填一个")


@dataclass
class SwitchConfig:
    max_attempts: int = 3
    release_old: bool = True
    # 先释放旧 EIP 再绑定新 EIP（省几秒计费，但绑定失败会有短暂空窗）
    release_before_bind: bool = True
    internet_charge_type: str = ""
    bandwidth_mbps: int | None = None
    isp: str = ""

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "SwitchConfig":
        bw = raw.get("bandwidth_mbps")
        return cls(
            max_attempts=max(1, _as_int(raw.get("max_attempts"), 3)),
            release_old=_as_bool(raw.get("release_old"), True),
            release_before_bind=_as_bool(raw.get("release_before_bind"), True),
            internet_charge_type=str(raw.get("internet_charge_type") or "").strip(),
            bandwidth_mbps=_as_int(bw, 0) or None,
            isp=str(raw.get("isp") or "").strip(),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_attempts": self.max_attempts,
            "release_old": self.release_old,
            "release_before_bind": self.release_before_bind,
            "internet_charge_type": self.internet_charge_type,
            "bandwidth_mbps": self.bandwidth_mbps,
            "isp": self.isp,
        }


@dataclass
class Config:
    path: Path
    telegram_token: str
    admin_chat_ids: tuple[int, ...] = ()
    channel_id: int | None = None
    bind_token: str = ""
    tg_proxy: str = ""
    accounts: dict[str, Account] = field(default_factory=dict)
    targets: list[Target] = field(default_factory=list)
    cloudflare: CloudflareConfig = field(default_factory=CloudflareConfig)
    switch: SwitchConfig = field(default_factory=SwitchConfig)
    data_dir: Path = Path("./data")
    timezone: str = "Asia/Shanghai"
    log_level: str = "INFO"
    raw: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------ 查询
    def target(self, name: str) -> Target:
        for item in self.targets:
            if item.name == name:
                return item
        raise KeyError(name)

    def target_names(self) -> list[str]:
        return [t.name for t in self.targets]

    def account(self, name: str) -> Account:
        if name in self.accounts:
            return self.accounts[name]
        raise ConfigError(f"账号不存在：{name}（已有：{', '.join(self.accounts) or '无'}）")

    def region_for(self, target: Target) -> str:
        if target.region:
            return target.region
        return self.account(target.account).region

    # ------------------------------------------------------------------ 加载
    @classmethod
    def load(cls, path: str | Path, env_file: str | Path | None = None) -> "Config":
        cfg_path = Path(path).expanduser().resolve()
        env_path = Path(env_file).expanduser().resolve() if env_file else cfg_path.parent / ".env"
        env: dict[str, str] = dict(os.environ)
        if env_path.exists():
            env.update({k: v for k, v in dotenv_values(env_path).items() if v is not None})

        if not cfg_path.exists():
            raise ConfigError(f"配置文件不存在：{cfg_path}")
        with cfg_path.open("r", encoding="utf-8") as fh:
            raw_original = yaml.safe_load(fh) or {}
        raw = _expand(raw_original, env)

        tg = raw.get("telegram") or {}
        token = str(tg.get("token") or "").strip()
        if not token:
            raise ConfigError("telegram.token 为空（检查 .env 的 TG_BOT_TOKEN）")
        channel = tg.get("channel_id")
        channel_id = int(str(channel).strip()) if channel not in (None, "") else None

        accounts_raw = (raw.get("aliyun") or {}).get("accounts") or []
        accounts: dict[str, Account] = {}
        for item in accounts_raw:
            if not isinstance(item, dict):
                raise ConfigError("aliyun.accounts[] 必须是对象")
            account = Account.from_dict(item)
            if account.name in accounts:
                raise ConfigError(f"阿里云账号重名：{account.name}")
            accounts[account.name] = account

        targets = [Target.from_dict(t) for t in (raw.get("targets") or [])]
        names = [t.name for t in targets]
        if len(set(names)) != len(names):
            raise ConfigError("targets[].name 不能重复")
        for target in targets:
            if accounts and target.account not in accounts:
                raise ConfigError(
                    f"target {target.name} 引用了不存在的账号 {target.account}"
                    f"（已有：{', '.join(accounts)}）"
                )

        data_dir = Path(str(raw.get("data_dir") or "./data")).expanduser()
        if not data_dir.is_absolute():
            data_dir = (cfg_path.parent / data_dir).resolve()

        return cls(
            path=cfg_path,
            telegram_token=token,
            admin_chat_ids=parse_id_list(tg.get("admin_chat_ids")),
            channel_id=channel_id,
            bind_token=str(tg.get("bind_token") or "").strip(),
            tg_proxy=str(tg.get("proxy") or "").strip(),
            accounts=accounts,
            targets=targets,
            cloudflare=CloudflareConfig.from_dict(raw.get("cloudflare") or {}),
            switch=SwitchConfig.from_dict(raw.get("switch") or {}),
            data_dir=data_dir,
            timezone=str(raw.get("timezone") or "Asia/Shanghai"),
            log_level=str(raw.get("log_level") or "INFO"),
            raw=raw_original,
        )

    # ------------------------------------------------------------------ 回写
    def save(self) -> None:
        """把当前状态写回 YAML。

        注意：YAML 里的 ${VAR} 占位符会变成实际值——因为 TG 里新增的账号必须落盘。
        因此写回后 .env 不再被这些字段引用，密钥只存在于 config.yaml（权限 600）。
        """
        payload: dict[str, Any] = {
            "telegram": {
                "token": self.telegram_token,
                "admin_chat_ids": ",".join(str(i) for i in self.admin_chat_ids),
                "bind_token": self.bind_token,
                "channel_id": self.channel_id or "",
                "proxy": self.tg_proxy,
            },
            "aliyun": {"accounts": [a.to_dict() for a in self.accounts.values()]},
            "cloudflare": self.cloudflare.to_dict(),
            "switch": self.switch.to_dict(),
            "timezone": self.timezone,
            "data_dir": str(self.data_dir),
            "log_level": self.log_level,
            "targets": [t.to_dict() for t in self.targets],
        }
        tmp = self.path.with_suffix(".yaml.tmp")
        tmp.write_text(yaml.safe_dump(payload, allow_unicode=True, sort_keys=False), "utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)
        # 回写后 raw 与磁盘一致，避免后续 save 覆盖丢失
        self.raw = payload
