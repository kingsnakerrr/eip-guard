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
    account: str = "default"
    eip_allocation_id: str = ""
    region_id: str = ""
    probe_port: int = 0
    aux_ports: list[int] = field(default_factory=list)
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
        aux_raw = raw.get("aux_ports") or []
        if isinstance(aux_raw, str):
            aux_raw = [x for x in aux_raw.replace("，", ",").split(",") if x.strip()]
        probe_port = _as_int(raw.get("probe_port"), default_port)
        aux_ports: list[int] = []
        for item in aux_raw:
            try:
                port = int(item)
            except (TypeError, ValueError):
                continue
            if 1 <= port <= 65535 and port != probe_port and port not in aux_ports:
                aux_ports.append(port)
        return cls(
            name=name,
            instance_id=instance_id,
            account=str(raw.get("account") or "default").strip(),
            eip_allocation_id=str(raw.get("eip_allocation_id") or "").strip(),
            region_id=str(raw.get("region_id") or "").strip(),
            probe_port=probe_port,
            aux_ports=aux_ports,
            dns_records=[str(r).strip() for r in records if str(r).strip()],
            notes=str(raw.get("notes") or "").strip(),
        )

    def all_ports(self, default_port: int) -> list[int]:
        """探测端口在最前，其余为辅助端口。"""
        main = self.probe_port or default_port
        return [main] + [p for p in self.aux_ports if p != main]


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
    min_samples: int = 1
    timeout: float = 6.0
    attempts: int = 2
    # 分层探测：icmp / tls / http。tcp 对每个端口必测，不用写。
    layers: list[str] = field(default_factory=lambda: ["icmp", "tls"])
    # 全局默认辅助端口；target 里也可单独写 aux_ports 覆盖
    aux_ports: list[int] = field(default_factory=list)
    # 需要 http 层时请求的路径（配合 tls 之上发真实请求）
    http_path: str = "/"
    verify_delay: int = 20
    verify_attempts: int = 3
    verify_success_needed: int = 1
    probe_agents: list[dict[str, Any]] = field(default_factory=list)
    checkhost_max_nodes: int = 6
    checkhost_timeout: int = 20
    # 反向探针（家宽/NAT 机器主动连过来），和服务端模式可同时用
    hub_enabled: bool = False
    hub_port: int = 8790
    hub_token: str = ""

    @classmethod
    def from_dict(cls, raw: dict[str, Any], default_port: int) -> "DetectConfig":
        provider = str(raw.get("provider") or "probe_agent").lower()
        if provider not in {"probe_agent", "checkhost", "hybrid", "tcp_self", "hub"}:
            raise ConfigError(f"未知 detect.provider: {provider}")
        agents = parse_agents(raw.get("probe_agent"))
        hub_enabled = _as_bool((raw.get("hub") or {}).get("enabled"), False)
        if provider in {"probe_agent", "hybrid"} and not agents and not hub_enabled:
            raise ConfigError(
                "detect.provider 需要探针，但 detect.probe_agent 为空"
                "（家宽机器请改用反向模式：detect.hub.enabled: true）"
            )
        if provider == "hub" and not hub_enabled:
            raise ConfigError("provider: hub 需要同时设置 detect.hub.enabled: true")

        default_layers = ["icmp", "tls"]
        layers_raw = raw.get("layers", default_layers)
        if isinstance(layers_raw, str):
            layers_raw = [x.strip().lower() for x in layers_raw.replace("，", ",").split(",") if x.strip()]
        layers: list[str] = []
        for layer in layers_raw or []:
            name = str(layer).strip().lower()
            if name not in {"icmp", "tcp", "tls", "http"}:
                raise ConfigError(f"detect.layers 里有未知层：{name}（只支持 icmp/tcp/tls/http）")
            if name not in layers:
                layers.append(name)
        if "tcp" not in layers:
            layers.insert(0, "tcp")

        aux_raw = raw.get("aux_ports") or []
        if isinstance(aux_raw, str):
            aux_raw = [x for x in aux_raw.replace("，", ",").split(",") if x.strip()]
        aux_ports: list[int] = []
        for item in aux_raw:
            try:
                port = int(item)
            except (TypeError, ValueError):
                continue
            if 1 <= port <= 65535 and port != _as_int(raw.get("port"), default_port):
                aux_ports.append(port)

        return cls(
            provider=provider,
            port=_as_int(raw.get("port"), default_port),
            interval=max(15, _as_int(raw.get("interval"), 60)),
            failure_threshold=max(1, _as_int(raw.get("failure_threshold"), 3)),
            fail_ratio=min(1.0, max(0.0, _as_float(raw.get("fail_ratio"), 0.6))),
            min_samples=max(1, _as_int(raw.get("min_samples"), 1)),
            timeout=_as_float(raw.get("timeout"), 6.0),
            attempts=max(1, min(5, _as_int(raw.get("attempts"), 2))),
            layers=layers,
            aux_ports=aux_ports,
            http_path=str(raw.get("http_path") or "/"),
            verify_delay=max(0, _as_int(raw.get("verify_delay"), 20)),
            verify_attempts=max(1, _as_int(raw.get("verify_attempts"), 3)),
            verify_success_needed=max(1, _as_int(raw.get("verify_success_needed"), 1)),
            probe_agents=agents,
            checkhost_max_nodes=_as_int(raw.get("checkhost_max_nodes"), 6),
            checkhost_timeout=_as_int(raw.get("checkhost_timeout"), 20),
            hub_enabled=_as_bool((raw.get("hub") or {}).get("enabled"), False),
            hub_port=_as_int((raw.get("hub") or {}).get("port"), 8790),
            hub_token=str((raw.get("hub") or {}).get("token") or "").strip(),
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
    # 哪些结论允许自动换 IP。默认只有 ip_blocked（端口/TLS/数据面封锁换 IP 无效）
    auto_switch_on: list[str] = field(default_factory=lambda: ["ip_blocked"])

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "SwitchConfig":
        bw = raw.get("bandwidth_mbps")
        allowed = raw.get("auto_switch_on")
        if allowed is None:
            verdicts = ["ip_blocked"]
        elif isinstance(allowed, str):
            verdicts = [x.strip().lower() for x in allowed.replace("，", ",").split(",") if x.strip()]
        else:
            verdicts = [str(x).strip().lower() for x in allowed if str(x).strip()]
        return cls(
            auto=_as_bool(raw.get("auto"), True),
            max_attempts=max(1, _as_int(raw.get("max_attempts"), 3)),
            cooldown=max(0, _as_int(raw.get("cooldown"), 900)),
            release_old=_as_bool(raw.get("release_old"), True),
            restore_old_on_failure=_as_bool(raw.get("restore_old_on_failure"), True),
            internet_charge_type=str(raw.get("internet_charge_type") or "").strip(),
            bandwidth_mbps=_as_int(bw, 0) or None,
            isp=str(raw.get("isp") or "").strip(),
            auto_switch_on=verdicts,
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
class AliyunAccount:
    name: str
    access_key_id: str
    access_key_secret: str
    endpoint: str = "vpc.aliyuncs.com"
    api_version: str = "2016-04-28"
    default_region: str = "cn-hongkong"

    @classmethod
    def from_dict(cls, raw: dict[str, Any], fallback_region: str) -> "AliyunAccount":
        name = str(raw.get("name") or "").strip()
        ak = str(raw.get("access_key_id") or "").strip()
        sk = str(raw.get("access_key_secret") or "").strip()
        if not name:
            raise ConfigError("aliyun.accounts[].name 不能为空")
        if not ak or not sk:
            raise ConfigError(f"账号 {name} 缺 access_key_id / access_key_secret")
        return cls(
            name=name,
            access_key_id=ak,
            access_key_secret=sk,
            endpoint=str(raw.get("endpoint") or "vpc.aliyuncs.com"),
            api_version=str(raw.get("api_version") or "2016-04-28"),
            default_region=str(raw.get("default_region") or raw.get("region_id") or fallback_region),
        )


@dataclass
class AliyunConfig:
    """支持多个阿里云账号；targets 里用 account 指定用哪个。"""

    accounts: dict[str, AliyunAccount] = field(default_factory=dict)
    region_id: str = "cn-hongkong"

    def __post_init__(self) -> None:
        # 兼容旧写法：单账号直接放在 aliyun 下
        pass

    @property
    def access_key_id(self) -> str:
        first = next(iter(self.accounts.values()), None)
        return first.access_key_id if first else ""

    @property
    def access_key_secret(self) -> str:
        first = next(iter(self.accounts.values()), None)
        return first.access_key_secret if first else ""

    @property
    def endpoint(self) -> str:
        first = next(iter(self.accounts.values()), None)
        return first.endpoint if first else "vpc.aliyuncs.com"

    @property
    def api_version(self) -> str:
        first = next(iter(self.accounts.values()), None)
        return first.api_version if first else "2016-04-28"

    def account(self, name: str) -> AliyunAccount:
        if name in self.accounts:
            return self.accounts[name]
        raise ConfigError(f"target 引用了不存在的阿里云账号：{name}（已配置：{', '.join(self.accounts)}）")

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "AliyunConfig":
        region = str(raw.get("region_id") or raw.get("default_region") or "cn-hongkong")
        accounts_raw = raw.get("accounts")
        accounts: dict[str, AliyunAccount] = {}
        if accounts_raw:
            if not isinstance(accounts_raw, list):
                raise ConfigError("aliyun.accounts 必须是列表")
            for item in accounts_raw:
                if not isinstance(item, dict):
                    raise ConfigError("aliyun.accounts[] 必须是对象")
                account = AliyunAccount.from_dict(item, region)
                if account.name in accounts:
                    raise ConfigError(f"阿里云账号重名：{account.name}")
                accounts[account.name] = account
        else:
            ak = str(raw.get("access_key_id") or "").strip()
            sk = str(raw.get("access_key_secret") or "").strip()
            if not ak or not sk:
                raise ConfigError("缺少 aliyun.accounts，或 access_key_id / access_key_secret")
            accounts["default"] = AliyunAccount(
                name="default",
                access_key_id=ak,
                access_key_secret=sk,
                endpoint=str(raw.get("endpoint") or "vpc.aliyuncs.com"),
                api_version=str(raw.get("api_version") or "2016-04-28"),
                default_region=region,
            )
        return cls(accounts=accounts, region_id=region)


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
    # 机器人所在机器连不上 Telegram 时用的代理，如 http://127.0.0.1:7890 或 socks5://127.0.0.1:1080
    tg_proxy: str = ""

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

        aliyun = AliyunConfig.from_dict(raw.get("aliyun") or {})
        for target in targets:
            if target.account not in aliyun.accounts:
                raise ConfigError(
                    f"target {target.name} 的 account='{target.account}' 不存在。"
                    f"已配置账号：{', '.join(aliyun.accounts)}"
                )
            # 没写 aux_ports 时用全局的
            if not target.aux_ports and detect.aux_ports:
                target.aux_ports = list(detect.aux_ports)

        data_dir = Path(str(raw.get("data_dir") or "./data")).expanduser()
        if not data_dir.is_absolute():
            data_dir = (cfg_path.parent / data_dir).resolve()

        return cls(
            path=cfg_path,
            telegram_token=token,
            admin_chat_ids=parse_id_list(tg.get("admin_chat_ids")),
            channel_id=channel_id,
            aliyun=aliyun,
            cloudflare=CloudflareConfig.from_dict(raw.get("cloudflare") or {}),
            detect=detect,
            switch=SwitchConfig.from_dict(raw.get("switch") or {}),
            targets=targets,
            data_dir=data_dir,
            timezone=str(raw.get("timezone") or "Asia/Shanghai"),
            log_level=str(raw.get("log_level") or "INFO"),
            bind_token=str(tg.get("bind_token") or "").strip(),
            tg_proxy=str(tg.get("proxy") or "").strip(),
        )
