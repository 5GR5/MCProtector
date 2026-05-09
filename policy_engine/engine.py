from __future__ import annotations

import time
from typing import Any, Dict, Optional
from .config import PolicyConfig
from .models import PolicyDecision, PolicyInput
from .strategies import DeterministicPriorityStrategy

class PolicyEngine:
    def __init__(self, config_path: str | None = None):
        self.config_path = config_path
        self.config = PolicyConfig.load(config_path)
        self._last_loaded = time.time()
        self._strategy = self._load_strategy(self.config.strategy)

    def _load_strategy(self, strategy_name: str):
        if strategy_name == "deterministic_priority":
            return DeterministicPriorityStrategy()
        raise ValueError(f"Unsupported policy strategy: {strategy_name}")

    def maybe_reload(self) -> None:
        now = time.time()
        if (now - self._last_loaded) >= self.config.config_reload_seconds:
            self.reload()

    def reload(self) -> None:
        self.config = PolicyConfig.load(self.config_path)
        self._strategy = self._load_strategy(self.config.strategy)
        self._last_loaded = time.time()

    def evaluate(self, policy_input: PolicyInput) -> PolicyDecision:
        self.maybe_reload()
        return self._strategy.evaluate(policy_input, self.config)

_ENGINE: Optional[PolicyEngine] = None

def get_policy_engine() -> PolicyEngine:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = PolicyEngine()
    return _ENGINE

def reload_policy_engine() -> None:
    global _ENGINE
    _ENGINE = PolicyEngine()

def _to_dict(obj: Any) -> Dict[str, Any]:
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if hasattr(obj, "dict"):
        return obj.dict()
    raise TypeError(f"Cannot convert {type(obj).__name__} to dict")

def evaluate_policy(rule_evaluation: Any, risk_evaluation: Any = None, request_context: Any = None) -> PolicyDecision:
    engine = get_policy_engine()
    policy_input = PolicyInput(
        rule_evaluation=_to_dict(rule_evaluation),
        risk_evaluation=_to_dict(risk_evaluation) if risk_evaluation is not None else None,
        request_context=_to_dict(request_context) if request_context is not None else {},
    )
    return engine.evaluate(policy_input)
