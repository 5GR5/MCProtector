from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Iterable, List
from proxy.models import NormalizedRequest
from .base import DetectionRule
from .types import RuleContext, RuleResult

@dataclass
class RuleRegistry:
    rules: Dict[str, DetectionRule] = field(default_factory=dict)

    def register(self, rule: DetectionRule) -> None:
        self.rules[rule.id] = rule

    def register_many(self, rules: Iterable[DetectionRule]) -> None:
        for rule in rules:
            self.register(rule)

    def list_rule_ids(self) -> List[str]:
        return list(self.rules.keys())

    def evaluate_all(self, req: NormalizedRequest, state, ctx: RuleContext) -> List[RuleResult]:
        results: List[RuleResult] = []
        for rule in self.rules.values():
            if not rule.enabled:
                continue
            if not rule.supports(req):
                continue
            result = rule.evaluate(req, state, ctx)
            if result.matched:
                results.append(result)
        return results
