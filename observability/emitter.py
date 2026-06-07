from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Optional
from uuid import UUID

from .events import ComponentName, Decision, EventType, OPAResult, PoCEvent, Severity


_CRITICAL_REASON_CODES = frozenset({
    "UNSAFE_FILE_ACCESS", "SQL_INJECTION", "FORBIDDEN_PATH",
})
_HIGH_REASON_CODES = frozenset({
    "BLOCKLIST_ACTIVE", "LLM_HIGH_RISK", "MITIGATION_BLOCK", "PROXY_ERROR",
})


def _rule_severity(matched_rules: list[str], opa_result: str) -> Severity:
    if opa_result == "DENY":
        if any(r in _CRITICAL_REASON_CODES for r in matched_rules):
            return Severity.CRITICAL
        return Severity.HIGH
    if matched_rules:
        return Severity.MEDIUM
    return Severity.LOW


def _risk_severity(risk_score: float, risk_threshold: float) -> Severity:
    if risk_score >= 0.8:
        return Severity.CRITICAL
    if risk_score >= risk_threshold:
        return Severity.HIGH
    if risk_score >= 0.3:
        return Severity.MEDIUM
    return Severity.LOW


def _decision_severity(decision: Decision, reason_code: str) -> Severity:
    if decision == Decision.DENY:
        if reason_code in _CRITICAL_REASON_CODES:
            return Severity.CRITICAL
        return Severity.HIGH
    if decision == Decision.CHALLENGE:
        return Severity.MEDIUM
    return Severity.LOW


@dataclass
class EventEmitter:
    log_mode: str = "console_json"
    log_file_path: str = "logs/poc.jsonl"
    demo_human_log: bool = True
    trace_filter: Optional[str] = None

    def emit(self, event: PoCEvent | Mapping[str, Any]) -> PoCEvent:
        normalized = event if isinstance(event, PoCEvent) else PoCEvent.model_validate(event)
        line = normalized.model_dump_json(exclude_none=False)

        if self.log_mode == "console_json_and_file":
            os.makedirs(os.path.dirname(self.log_file_path) or ".", exist_ok=True)
            with open(self.log_file_path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")

        if self.trace_filter and str(normalized.trace_id) != self.trace_filter:
            return normalized

        print(line, flush=True)
        if self.demo_human_log:
            self._human_line(normalized)
        return normalized

    def emit_request_received(
        self,
        *,
        timestamp: str | datetime,
        request_id: str | UUID,
        trace_id: str | UUID,
        session_id: Optional[str],
        client_ip: str,
        mcp_method: str,
        tool_name: Optional[str],
        reason_code: str,
        reason: str,
        payload_size_bytes: Optional[int] = None,
        client_id: Optional[str] = None,
        upstream_name: Optional[str] = None,
    ) -> PoCEvent:
        return self.emit(
            PoCEvent(
                timestamp=timestamp,
                level="INFO",
                event_type=EventType.REQUEST_RECEIVED,
                component=ComponentName.PROXY,
                request_id=request_id,
                trace_id=trace_id,
                session_id=session_id,
                client_id=client_id,
                client_ip=client_ip,
                mcp_method=mcp_method,
                tool_name=tool_name,
                decision=Decision.NONE,
                reason_code=reason_code,
                reason=reason,
                severity=Severity.LOW,
                payload_size_bytes=payload_size_bytes,
                upstream_name=upstream_name,
            )
        )

    def emit_rule_evaluated(
        self,
        *,
        timestamp: str | datetime,
        request_id: str | UUID,
        trace_id: str | UUID,
        session_id: Optional[str],
        client_ip: str,
        mcp_method: str,
        tool_name: Optional[str],
        opa_policy_id: str,
        opa_result: str | OPAResult,
        opa_matched_rules: list[str],
        violations: list[Mapping[str, Any]],
        reason_code: str,
        reason: str,
        stage_latency_ms: Optional[float] = None,
        client_id: Optional[str] = None,
        upstream_name: Optional[str] = None,
    ) -> PoCEvent:
        opa_result_enum = OPAResult(opa_result)
        level = "WARN" if opa_result_enum == OPAResult.DENY else "INFO"
        severity = _rule_severity(list(opa_matched_rules), str(opa_result))
        return self.emit(
            PoCEvent(
                timestamp=timestamp,
                level=level,
                event_type=EventType.DETECTION_RULE_EVALUATED,
                component=ComponentName.OPA,
                request_id=request_id,
                trace_id=trace_id,
                session_id=session_id,
                client_id=client_id,
                client_ip=client_ip,
                mcp_method=mcp_method,
                tool_name=tool_name,
                decision=Decision.NONE,
                reason_code=reason_code,
                reason=reason,
                severity=severity,
                opa_policy_id=opa_policy_id,
                opa_result=opa_result,
                opa_matched_rules=opa_matched_rules,
                violations=list(violations),
                stage_latency_ms=stage_latency_ms,
                upstream_name=upstream_name,
            )
        )

    def emit_model_evaluated(
        self,
        *,
        timestamp: str | datetime,
        request_id: str | UUID,
        trace_id: str | UUID,
        session_id: Optional[str],
        client_ip: str,
        mcp_method: str,
        tool_name: Optional[str],
        model_name: str,
        model_version: str,
        risk_score: float,
        risk_threshold: float,
        model_reason_summary: str,
        reason_code: str,
        reason: str,
        stage_latency_ms: Optional[float] = None,
        client_id: Optional[str] = None,
        upstream_name: Optional[str] = None,
    ) -> PoCEvent:
        level = "WARN" if risk_score >= risk_threshold else "INFO"
        severity = _risk_severity(risk_score, risk_threshold)
        return self.emit(
            PoCEvent(
                timestamp=timestamp,
                level=level,
                event_type=EventType.DETECTION_MODEL_EVALUATED,
                component=ComponentName.MODEL,
                request_id=request_id,
                trace_id=trace_id,
                session_id=session_id,
                client_id=client_id,
                client_ip=client_ip,
                mcp_method=mcp_method,
                tool_name=tool_name,
                decision=Decision.NONE,
                reason_code=reason_code,
                reason=reason,
                severity=severity,
                model_name=model_name,
                model_version=model_version,
                risk_score=risk_score,
                risk_threshold=risk_threshold,
                model_reason_summary=model_reason_summary,
                stage_latency_ms=stage_latency_ms,
                upstream_name=upstream_name,
            )
        )

    def emit_decision_made(
        self,
        *,
        timestamp: str | datetime,
        request_id: str | UUID,
        trace_id: str | UUID,
        session_id: Optional[str],
        client_ip: str,
        mcp_method: str,
        tool_name: Optional[str],
        decision: str | Decision,
        reason_code: str,
        reason: str,
        client_id: Optional[str] = None,
        upstream_name: Optional[str] = None,
    ) -> PoCEvent:
        decision_value = Decision(decision)
        level = "WARN" if decision_value in (Decision.DENY, Decision.CHALLENGE) else "INFO"
        severity = _decision_severity(decision_value, reason_code)
        return self.emit(
            PoCEvent(
                timestamp=timestamp,
                level=level,
                event_type=EventType.DECISION_MADE,
                component=ComponentName.PROXY,
                request_id=request_id,
                trace_id=trace_id,
                session_id=session_id,
                client_id=client_id,
                client_ip=client_ip,
                mcp_method=mcp_method,
                tool_name=tool_name,
                decision=decision_value,
                reason_code=reason_code,
                reason=reason,
                severity=severity,
                upstream_name=upstream_name,
            )
        )

    def emit_action_applied(
        self,
        *,
        timestamp: str | datetime,
        request_id: str | UUID,
        trace_id: str | UUID,
        session_id: Optional[str],
        client_ip: str,
        mcp_method: str,
        tool_name: Optional[str],
        decision: str | Decision,
        action_type: str,
        action_target: str,
        action_duration_sec: int,
        reason_code: str,
        reason: str,
        client_id: Optional[str] = None,
        upstream_name: Optional[str] = None,
    ) -> PoCEvent:
        return self.emit(
            PoCEvent(
                timestamp=timestamp,
                level="INFO",
                event_type=EventType.ACTION_APPLIED,
                component=ComponentName.PROXY,
                request_id=request_id,
                trace_id=trace_id,
                session_id=session_id,
                client_id=client_id,
                client_ip=client_ip,
                mcp_method=mcp_method,
                tool_name=tool_name,
                decision=decision,
                reason_code=reason_code,
                reason=reason,
                severity=Severity.HIGH,
                action_type=action_type,
                action_target=action_target,
                action_duration_sec=action_duration_sec,
                upstream_name=upstream_name,
            )
        )

    def emit_request_forwarded(
        self,
        *,
        timestamp: str | datetime,
        request_id: str | UUID,
        trace_id: str | UUID,
        session_id: Optional[str],
        client_ip: str,
        mcp_method: str,
        tool_name: Optional[str],
        decision: str | Decision,
        reason_code: str,
        reason: str,
        client_id: Optional[str] = None,
        upstream_name: Optional[str] = None,
    ) -> PoCEvent:
        return self.emit(
            PoCEvent(
                timestamp=timestamp,
                level="INFO",
                event_type=EventType.REQUEST_FORWARDED,
                component=ComponentName.PROXY,
                request_id=request_id,
                trace_id=trace_id,
                session_id=session_id,
                client_id=client_id,
                client_ip=client_ip,
                mcp_method=mcp_method,
                tool_name=tool_name,
                decision=decision,
                reason_code=reason_code,
                reason=reason,
                severity=Severity.LOW,
                upstream_name=upstream_name,
            )
        )

    def emit_response_returned(
        self,
        *,
        timestamp: str | datetime,
        request_id: str | UUID,
        trace_id: str | UUID,
        session_id: Optional[str],
        client_ip: str,
        mcp_method: str,
        tool_name: Optional[str],
        decision: str | Decision,
        reason_code: str,
        reason: str,
        upstream_status: Optional[int] = None,
        latency_ms: Optional[float] = None,
        client_id: Optional[str] = None,
        upstream_name: Optional[str] = None,
    ) -> PoCEvent:
        return self.emit(
            PoCEvent(
                timestamp=timestamp,
                level="INFO",
                event_type=EventType.RESPONSE_RETURNED,
                component=ComponentName.PROXY,
                request_id=request_id,
                trace_id=trace_id,
                session_id=session_id,
                client_id=client_id,
                client_ip=client_ip,
                mcp_method=mcp_method,
                tool_name=tool_name,
                decision=decision,
                reason_code=reason_code,
                reason=reason,
                severity=Severity.LOW,
                upstream_status=upstream_status,
                latency_ms=latency_ms,
                upstream_name=upstream_name,
            )
        )

    def emit_error(
        self,
        *,
        timestamp: str | datetime,
        request_id: str | UUID,
        trace_id: str | UUID,
        session_id: Optional[str],
        client_ip: str,
        mcp_method: str,
        tool_name: Optional[str],
        reason_code: str,
        reason: str,
        client_id: Optional[str] = None,
        upstream_name: Optional[str] = None,
    ) -> PoCEvent:
        return self.emit(
            PoCEvent(
                timestamp=timestamp,
                level="ERROR",
                event_type=EventType.ERROR,
                component=ComponentName.PROXY,
                request_id=request_id,
                trace_id=trace_id,
                session_id=session_id,
                client_id=client_id,
                client_ip=client_ip,
                mcp_method=mcp_method,
                tool_name=tool_name,
                decision=Decision.NONE,
                reason_code=reason_code,
                reason=reason,
                severity=Severity.HIGH,
                upstream_name=upstream_name,
            )
        )

    def _human_line(self, event: PoCEvent) -> None:
        msg = (
            f"[{event.event_type.value}] "
            f"trace={event.trace_id} "
            f"decision={event.decision.value} "
            f"reason={event.reason_code} "
            f"method={event.mcp_method} "
            f"tool={event.tool_name or '-'}"
        )
        if event.risk_score is not None:
            msg += f" risk={event.risk_score}"
        print(msg, file=sys.stderr, flush=True)
