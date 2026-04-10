from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from proxy.models import RuleViolation

@dataclass
class RuleResult:
    rule_id: str
    matched: bool
    detail: str = ""
    severity: str = "medium"

    def to_violation(self) -> RuleViolation:
        return RuleViolation(rule=self.rule_id, detail=self.detail)

@dataclass
class RuleConfig:
    enabled: bool = True
    envs: Optional[List[str]] = None

@dataclass
class RuleContext:
    environment: str
    settings: Dict[str, Any] = field(default_factory=dict)
