from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


@dataclass
class TargetState:
    name: str
    current_ip: str = ""
    allocation_id: str = ""
    failures: int = 0
    last_check: float = 0.0
    last_ok: float = 0.0
    last_reason: str = ""
    last_verdict: str = ""
    last_advice: str = ""
    last_switch: float = 0.0
    last_switch_ok: bool = True
    auto: bool = True
    switches: int = 0
    paused_until: float = 0.0
    notified_stage: int = 0  # 0 无 / 1 疑似 / 2 已确认 / 3 已提示无法自动换

    @property
    def blocked(self) -> bool:
        return self.failures > 0


@dataclass
class StateStore:
    """轻量状态持久化：重启后不会丢冷却/统计，也不会重复告警。"""

    path: Path
    targets: dict[str, TargetState] = field(default_factory=dict)
    channel_id: int | None = None
    settings: dict[str, Any] = field(default_factory=dict)
    history: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path, target_names: list[str], defaults: dict[str, Any] | None = None) -> "StateStore":
        store = cls(path=path)
        if path.exists():
            try:
                raw = json.loads(path.read_text("utf-8"))
                store.channel_id = raw.get("channel_id")
                store.settings = dict(defaults or {})
                store.settings.update(raw.get("settings") or {})
                store.history = list(raw.get("history") or [])[-200:]
                for name, item in (raw.get("targets") or {}).items():
                    if isinstance(item, dict):
                        known = {f for f in TargetState.__dataclass_fields__}
                        store.targets[name] = TargetState(**{k: v for k, v in item.items() if k in known})
            except Exception as exc:  # noqa: BLE001 - 状态文件损坏不应阻止启动
                log.warning("读取状态文件失败（忽略）：%s", exc)
        else:
            store.settings = dict(defaults or {})
        for name in target_names:
            if name not in store.targets:
                store.targets[name] = TargetState(name=name, auto=store.settings.get("auto", True))
        return store

    def get(self, name: str) -> TargetState:
        if name not in self.targets:
            self.targets[name] = TargetState(name=name, auto=self.settings.get("auto", True))
        return self.targets[name]

    def add_history(self, event: dict[str, Any]) -> None:
        event.setdefault("ts", time.time())
        self.history.append(event)
        self.history = self.history[-200:]

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "saved_at": time.time(),
            "channel_id": self.channel_id,
            "settings": self.settings,
            "targets": {k: asdict(v) for k, v in self.targets.items()},
            "history": self.history[-200:],
        }
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), "utf-8")
        os.replace(tmp, self.path)


@dataclass
class Settings:
    """可在机器人里动态修改的设置，和配置文件的默认值合并。"""

    auto: bool = True
    interval: int = 60
    failure_threshold: int = 3
    cooldown: int = 900
    release_old: bool = True
    notify_channel: bool = True

    @classmethod
    def from_values(cls, base: Any, stored: dict[str, Any]) -> "Settings":
        s = cls(
            auto=bool(base.get("auto", True)),
            interval=int(base.get("interval", 60)),
            failure_threshold=int(base.get("failure_threshold", 3)),
            cooldown=int(base.get("cooldown", 900)),
            release_old=bool(base.get("release_old", True)),
        )
        for key in ("auto", "interval", "failure_threshold", "cooldown", "release_old", "notify_channel"):
            if key in stored and stored[key] is not None:
                setattr(s, key, stored[key])
        return s

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
