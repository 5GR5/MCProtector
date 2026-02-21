from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# Normalized request data structure used internally in the pipeline
class NormalizedRequest(BaseModel):
    request_id: str
    trace_id: str
    client_ip: str
    session_id: Optional[str] = None
    mcp_method: str  # e.g., tools/call
    tool_name: Optional[str] = None
    tool_args: Dict[str, Any] = Field(default_factory=dict)
    received_at: str  # ISO-8601
    auth_token: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    payload_size_bytes: int = 0
    raw_body: Dict[str, Any] = Field(default_factory=dict)


# Rule violation details
class RuleViolation(BaseModel):
    rule: str
    detail: str


# Rule evaluation result structure
class RuleEvaluation(BaseModel):
    opa_policy_id: str = "poc-policy-v1"
    opa_result: str  # ALLOW / DENY
    opa_matched_rules: List[str] = Field(default_factory=list)
    violations: List[RuleViolation] = Field(default_factory=list)
    reason_code: str = "RULES_EVALUATED"
    reason: str = "Rules evaluated"


# Risk evaluation result structure
class RiskEvaluation(BaseModel):
    model_name: str = "poc-llm-risk-scorer"
    model_version: str = "0.1"
    risk_score: float
    risk_threshold: float
    model_reason_summary: str
    reason_code: str = "MODEL_EVALUATED"
    reason: str = "Model evaluated"
