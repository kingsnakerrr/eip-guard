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
    """递归展开 ${VAR} / ${VAR:-default}，并保留 None/数字/布尔类型。"""
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


def _as_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_bool(value: Any, default: bool) -> bool:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def parse_id_list(raw: Any) -> tuple[int, ...]:
    """支持 '123,456' 或 [123, '456']。"""
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
class TargetConfig:
    name: str
    instance_id: str
    eip_allocation_id: str = ""
    region_id: str = ""
    probe_port: int = 0
    dns_records: list[str] = field(default_factory=list)
    notes: str = ""

    @classmethod
    def from_dict(cls, raw: dict[str, Any], default_port: int) -> "TargetConfig":
        name = str(raw.get("name") or "").strip()
        instance_id = str(raw.get("instance_id") or "").strip()
        if not name:
            raise ConfigError("targets[].name 不能为空")
        if not instance_id:
            raise ConfigError(f"target {name}: instance_id 不能为空")
        records = raw.get("dns_records") or []
        if isinstance(records, str):
            records = [records]
        return cls(
            name=name,
            instance_id=instance_id,
            eip_allocation_id=str(raw.get("eip_allocation_id") or "").strip(),
            region_id=str(raw.get("region_id") or "").strip(),
            probe_port=_as_int(raw.get("probe_port"), default_port),
            dns_records=[str(r).strip() for r in records if str(r).strip()],
            notes=str(raw.get("notes") or "").strip(),
        )


def parse_agents(raw: dict[str, Any] | None) -> list[dict[str, Any]]:
    """解析多探针配置，返回 [{url, token, zone, name}]。"""
    if not raw:
        return []
    urls = raw.get("urls") or ""
    if isinstance(urls, str):
        urls = [u.strip() for u in urls.replace(";", ",").split(",") if u.strip()]
    default_token = str(raw.get("token") or "").strip()
    agents_raw = raw.get("agents")
    if agents_raw:
        out = []
        for a in agents_raw:
            url = str(a.get("url") or "").strip()
            if not url:
                continue
            out.append(
                {
                    "url": url,
                    "token": str(a.get("token") or default_token),
                    "zone": str(a.get("zone") or "cn").lower(),
                    "name": str(a.get("name") or ""),
                }
            )
        if out:
            return out
    return [
        {"url": u, "token": default_token, "zone": str(raw.get("zone") or "cn").lower(), "name": ""}
        for u in urls
    ]


@dataclass
class DetectConfig:
    provider: str = "probe_agent"
    port: int = 443
    interval: int = 60
    failure_threshold: int = 3
    fail_ratio: float = 0.6
    min_samples: int = 2
    timeout: float = 6.0
    tls_check: bool = True
    verify_delay: int = 20
    verify_attempts: int = 3
    verify_success_needed: int = 1
    probe_agents: list[dict[str, Any]] = field(default_factory=list)
    checkhost_max_nodes: int = 6
    checkhost_timeout: int = 20

    @classmethod
    def from_dict(cls, raw: dict[str, Any], default_port: int) -> "DetectConfig":
        provider = str(raw.get("provider") or "probe_agent").lower()
        if provider not in {"probe_agent", "checkhost", "hybrid", "tcp_self"}:
            raise ConfigError(f"未知 detect.provider: {provider}")
        agents = parse_agents(raw.get("probe_agent"))
        if provider in {"probe_agent", "hybrid"} and not agents:
            raise ConfigError("detect.provider 需要探针，但 detect.probe_agent 为空")
        return cls(
            provider=provider,
            port=_as_int(raw.get("port"), default_port),
            interval=max(15, _as_int(raw.get("interval"), 60)),
            failure_threshold=max(1, _as_int(raw.get("failure_threshold"), 3)),
            fail_ratio=min(1.0, max(0.0, _as_float(raw.get("fail_ratio"), 0.6))),
            min_samples=max(1, _as_int(raw.get("min_samples"), 2)),
            timeout=_as_float(raw.get("timeout"), 6.0),
            tls_check=_as_bool(raw.get("tls_check"), True),
            verify_delay=max(0, _as_int(raw.get("verify_delay"), 20)),
            verify_attempts=max(1, _as_int(raw.get("verify_attempts"), 3)),
            verify_success_needed=max(1, _as_int(raw.get("verify_success_needed"), 1)),
            probe_agents=agents,
            checkhost_max_nodes=_as_int(raw.get("checkhost_max_nodes"), 6),
            checkhost_timeout=_as_int(raw.get("checkhost_timeout"), 20),
        )


@dataclass
class SwitchConfig:
    auto: bool = True
    max_attempts: int = 3
    cooldown: int = 900
    release_old: bool = True
    restore_old_on_failure: bool = True
    internet_charge_type: str = ""
    bandwidth_mbps: int | None = None
    isp: str = ""

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "SwitchConfig":
        bw = raw.get("bandwidth_mbps")
        return cls(
            auto=_as_bool(raw.get("auto"), True),
            max_attempts=max(1, _as_int(raw.get("max_attempts"), 3)),
            cooldown=max(0, _as_int(raw.get("cooldown"), 900)),
            release_old=_as_bool(raw.get("release_old"), True),
            restore_old_on_failure=_as_bool(raw.get("restore_old_on_failure"), True),
            internet_charge_type=str(raw.get("internet_charge_type") or "").strip(),
            bandwidth_mbps=_as_int(bw, 0) or None,
            isp=str(raw.get("isp") or "").strip(),
        )


@dataclass
class CloudflareConfig:
    api_token: str
    zone_id: str = ""
    zone_name: str = ""
    ttl: int = 60
    proxied: bool = False
    create_missing: bool = True
    multi_record_policy: str = "replace"  # replace | keep
    api_base: str = "https://api.cloudflare.com/client/v4"

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "CloudflareConfig":
        token = str(raw.get("api_token") or "").strip()
        zone_id = str(raw.get("zone_id") or "").strip()
        zone_name = str(raw.get("zone_name") or "").strip()
        if not token:
            raise ConfigError("cloudflare.api_token 为空（CF_API_TOKEN）")
        if not zone_id and not zone_name:
            raise ConfigError("cloudflare.zone_id 与 zone_name 至少填一个")
        policy = str(raw.get("multi_record_policy") or "replace").lower()
        if policy not in {"replace", "keep"}:
            raise ConfigError("cloudflare.multi_record_policy 只能是 replace 或 keep")
        return cls(
            api_token=token,
            zone_id=zone_id,
            zone_name=zone_name,
            ttl=_as_int(raw.get("ttl"), 60) or 1,
            proxied=_as_bool(raw.get("proxied"), False),
            create_missing=_as_bool(raw.get("create_missing"), True),
            multi_record_policy=policy,
            api_base=str(raw.get("api_base") or cls.api_base).rstrip("/"),
        )


@dataclass
class AliyunConfig:
    access_key_id: str
    access_key_secret: str
    region_id: str = "cn-hongkong"
    endpoint: str = "vpc.aliyuncs.com"
    api_version: str = "2016-04-28"

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "AliyunConfig":
        ak = str(raw.get("access_key_id") or "").strip()
        sk = str(raw.get("access_key_secret") or "").strip()
        if not ak or not sk:
            raise ConfigError("缺少 aliyun.access_key_id / access_key_secret")
        return cls(
            access_key_id=ak,
            access_key_secret=sk,
            region_id=str(raw.get("region_id") or "cn-hongkong"),
            endpoint=str(raw.get("endpoint") or "vpc.aliyuncs.com"),
            api_version=str(raw.get("api_version") or "2016-04-28"),
        )


@dataclass
class Config:
    path: Path
    telegram_token: str
    admin_chat_ids: tuple[int, ...]
    channel_id: int | None
    aliyun: AliyunConfig
    cloudflare: CloudflareConfig
    detect: DetectConfig
    switch: SwitchConfig
    targets: list[TargetConfig]
    data_dir: Path
    timezone: str = "Asia/Shanghai"
    log_level: str = "INFO"
    bind_token: str = ""

    def target(self, name: str) -> TargetConfig:
        for t in self.targets:
            if t.name == name:
                return t
        raise KeyError(name)

    @classmethod
    def load(cls, path: str | Path, env_file: str | Path | None = None) -> "Config":
        cfg_path = Path(path).expanduser().resolve()
        env_path = Path(env_file).expanduser().resolve() if env_file else cfg_path.parent / ".env"
        # 不修改 os.environ：同一进程跑多份配置、或测试时互不污染
        env: dict[str, str] = dict(os.environ)
        if env_path.exists():
            env.update({k: v for k, v in dotenv_values(env_path).items() if v is not None})

        if not cfg_path.exists():
            raise ConfigError(f"配置文件不存在：{cfg_path}")
        with cfg_path.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        raw = _expand(raw, env)

        tg = raw.get("telegram") or {}
        token = str(tg.get("token") or "").strip()
        if not token:
            raise ConfigError("telegram.token 为空（TG_BOT_TOKEN）")
        channel = tg.get("channel_id")
        channel_id = int(str(channel).strip()) if channel not in (None, "") else None

        detect_default_port = _as_int((raw.get("web") or {}).get("port"), 443)
        detect = DetectConfig.from_dict(raw.get("detect") or {}, detect_default_port)
        targets_raw = raw.get("targets") or []
        if not targets_raw:
            raise ConfigError("targets 至少配置一个实例")
        targets = [TargetConfig.from_dict(t, detect.port) for t in targets_raw]
        names = [t.name for t in targets]
        if len(set(names)) != len(names):
            raise ConfigError("targets[].name 不能重复")

        data_dir = Path(str(raw.get("data_dir") or "./data")).expanduser()
        if not data_dir.is_absolute():
            data_dir = (cfg_path.parent / data_dir).resolve()

        return cls(
            path=cfg_path,
            telegram_token=token,
            admin_chat_ids=parse_id_list(tg.get("admin_chat_ids")),
            channel_id=channel_id,
            aliyun=AliyunConfig.from_dict(raw.get("aliyun") or {}),
            cloudflare=CloudflareConfig.from_dict(raw.get("cloudflare") or {}),
            detect=detect,
            switch=SwitchConfig.from_dict(raw.get("switch") or {}),
            targets=targets,
            data_dir=data_dir,
            timezone=str(raw.get("timezone") or "Asia/Shanghai"),
            log_level=str(raw.get("log_level") or "INFO"),
            bind_token=str(tg.get("bind_token") or "").strip(),
        )
