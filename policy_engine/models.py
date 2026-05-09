from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

Decision = Literal["ALLOW", "DENY", "CHALLENGE"]

class PolicyInput(BaseModel):
    rule_evaluation: Dict[str, Any]
    risk_evaluation: Optional[Dict[str, Any]] = None
    request_context: Dict[str, Any] = Field(default_factory=dict)

class PolicyDecision(BaseModel):
    decision: Decision
    decision_reason_code: str
    decision_reason: str
    evidence_refs: List[str] = Field(default_factory=list)

    policy_id: str
    policy_strategy: str
    source: str
    thresholds_used: Dict[str, Any] = Field(default_factory=dict)
    matched_conditions: List[str] = Field(default_factory=list)
