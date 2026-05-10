from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, field_serializer


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventType(str, Enum):
    REQUEST_RECEIVED = "REQUEST_RECEIVED"
    DETECTION_RULE_EVALUATED = "DETECTION_RULE_EVALUATED"
    DETECTION_MODEL_EVALUATED = "DETECTION_MODEL_EVALUATED"
    DECISION_MADE = "DECISION_MADE"
    ACTION_APPLIED = "ACTION_APPLIED"
    REQUEST_FORWARDED = "REQUEST_FORWARDED"
    RESPONSE_RETURNED = "RESPONSE_RETURNED"
    ERROR = "ERROR"


class ComponentName(str, Enum):
    PROXY = "proxy"
    OPA = "opa"
    MODEL = "model"
    LOGGER = "logger"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    CHALLENGE = "CHALLENGE"
    NONE = "NONE"


class OPAResult(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class EventViolation(BaseModel):
    model_config = ConfigDict(extra="forbid", protected_namespaces=())

    rule: str
    detail: str


class PoCEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", protected_namespaces=())

    timestamp: datetime
    level: LogLevel
    event_type: EventType
    component: ComponentName
    request_id: UUID
    trace_id: UUID
    session_id: Optional[str] = None
    client_ip: str
    mcp_method: str
    tool_name: Optional[str] = None
    decision: Decision
    reason_code: str
    reason: str

    opa_policy_id: Optional[str] = None
    opa_result: Optional[OPAResult] = None
    opa_matched_rules: Optional[list[str]] = None
    violations: Optional[list[EventViolation]] = None

    model_name: Optional[str] = None
    model_version: Optional[str] = None
    risk_score: Optional[float] = None
    risk_threshold: Optional[float] = None
    model_reason_summary: Optional[str] = None

    action_type: Optional[str] = None
    action_target: Optional[str] = None
    action_duration_sec: Optional[int] = None

    severity: Severity = Severity.LOW

    latency_ms: Optional[float] = None
    stage_latency_ms: Optional[float] = None

    payload_size_bytes: Optional[int] = None
    upstream_status: Optional[int] = None

    @field_serializer("timestamp")
    def _serialize_timestamp(self, value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
