from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import yaml

@dataclass
class PolicyConfig:
    policy_id: str = "mcprotector-policy-v1"
    strategy: str = "deterministic_priority"
    config_reload_seconds: int = 5
    model_block_threshold: float = 0.95
    model_challenge_threshold: float = 0.80
    allow_without_model: bool = True
    unknown_rule_result_decision: str = "CHALLENGE"

    @staticmethod
    def load(path: str | None = None) -> "PolicyConfig":
        config_path = path or str(Path(__file__).resolve().parent / "config.yaml")
        data = {}
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

        thresholds = data.get("thresholds", {}) or {}
        behavior = data.get("behavior", {}) or {}

        return PolicyConfig(
            policy_id=data.get("policy_id", "mcprotector-policy-v1"),
            strategy=data.get("strategy", "deterministic_priority"),
            config_reload_seconds=int(data.get("config_reload_seconds", 5)),
            model_block_threshold=float(thresholds.get("model_block_threshold", 0.95)),
            model_challenge_threshold=float(thresholds.get("model_challenge_threshold", 0.80)),
            allow_without_model=bool(behavior.get("allow_without_model", True)),
            unknown_rule_result_decision=str(behavior.get("unknown_rule_result_decision", "CHALLENGE")).upper(),
        )
