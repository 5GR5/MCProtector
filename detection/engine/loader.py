from __future__ import annotations
import time
from pathlib import Path
from typing import Any, Dict
import yaml
from .registry import RuleRegistry
from .state import DetectionState
from .types import RuleContext
from detection.packs.filesystem_pack import get_rules as filesystem_rules
from detection.packs.abuse_pack import get_rules as abuse_rules
from detection.packs.identity_pack import get_rules as identity_rules

PACK_LOADERS = {
    "filesystem_pack": filesystem_rules,
    "abuse_pack": abuse_rules,
    "identity_pack": identity_rules,
}

class DetectionEngine:
    def __init__(self, config_path: str | None = None):
        self.config_path = config_path or str(Path(__file__).resolve().parents[1] / "config.yaml")
        self.registry = RuleRegistry()
        self.state = DetectionState()
        self.context = RuleContext(environment="dev", settings={})
        self.policy_id = "product-policy-v1"
        self.reload_seconds = 5
        self._last_loaded = 0.0
        self.reload()

    def maybe_reload(self) -> None:
        now = time.time()
        if (now - self._last_loaded) >= self.reload_seconds:
            self.reload()

    def reload(self) -> None:
        with open(self.config_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        self.policy_id = cfg.get("policy_id", "product-policy-v1")
        env = cfg.get("default_env", "dev")
        self.reload_seconds = int(cfg.get("config_reload_seconds", 5))
        packs_cfg: Dict[str, bool] = cfg.get("packs", {})
        rules_cfg: Dict[str, bool] = cfg.get("rules", {})
        settings: Dict[str, Any] = cfg.get("settings", {})
        registry = RuleRegistry()
        for pack_name, pack_enabled in packs_cfg.items():
            if not pack_enabled:
                continue
            loader = PACK_LOADERS.get(pack_name)
            if not loader:
                continue
            for rule in loader():
                rule.enabled = bool(rules_cfg.get(rule.id, True))
                registry.register(rule)
        self.registry = registry
        self.context = RuleContext(environment=env, settings=settings)
        self._last_loaded = time.time()

    def list_rules(self):
        return self.registry.list_rule_ids()
