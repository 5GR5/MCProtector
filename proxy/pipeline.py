from __future__ import annotations

import time
import uuid
from typing import Any, Dict, Optional, Tuple

from fastapi import Request

from observability import EventEmitter, now_iso

from .config import ProxyConfig
from .errors import error_payload
from .forwarder import forward_json
from .mitigation import Blocklist
from .models import NormalizedRequest, RiskEvaluation, RuleEvaluation
from detection import evaluate_rules, evaluate_risk 

# Try to import the real detection module. Fallback to stub if not available.
try:
    from detection import evaluate_rules, evaluate_risk  # type: ignore
except Exception:
    from .detection_stub import evaluate_rules, evaluate_risk  # type: ignore


def _client_ip(req: Request) -> str:
    xff = req.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    if req.client and req.client.host:
        return req.client.host
    return "unknown"


def _bearer_token(req: Request) -> Optional[str]:
    auth = req.headers.get("authorization")
    if not auth:
        return None
    parts = auth.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


def _extract_tool(method: str, body: Dict[str, Any]) -> Tuple[Optional[str], Dict[str, Any]]:
    tool_name = None
    tool_args: Dict[str, Any] = {}
    params = body.get("params") or {}
    if method == "tools/call":
        tool_name = params.get("name")
        tool_args = params.get("arguments") or {}
    return tool_name, tool_args


def _normalized_request(req: Request, body: Dict[str, Any], request_id: str) -> NormalizedRequest:
    trace_id = request_id
    method = body.get("method") or "unknown"
    tool_name, tool_args = _extract_tool(method, body)
    headers = {k: v for k, v in req.headers.items()}

    return NormalizedRequest(
        request_id=request_id,
        trace_id=trace_id,
        client_ip=_client_ip(req),
        session_id=req.headers.get("x-session-id"),
        mcp_method=method,
        tool_name=tool_name,
        tool_args=tool_args,
        received_at=now_iso(),
        auth_token=_bearer_token(req),
        headers=headers,
        payload_size_bytes=len(str(body).encode("utf-8")),
        raw_body=body,
    )


async def handle_mcp_message(
    http_request: Request,
    body: Dict[str, Any],
    cfg: ProxyConfig,
    emitter: EventEmitter,
    blocklist: Blocklist,
) -> Tuple[int, Dict[str, Any], Dict[str, str]]:
    request_id = str(uuid.uuid4())
    trace_id = request_id
    ip = _client_ip(http_request)
    method = (body.get("method") or "unknown") if isinstance(body, dict) else "unknown"
    session_id = http_request.headers.get("x-session-id")
    tool_name = None
    if isinstance(body, dict):
        tool_name, _ = _extract_tool(method, body)

    if blocklist.is_blocked(ip):
        emitter.emit_decision_made(
            timestamp=now_iso(),
            request_id=request_id,
            trace_id=trace_id,
            session_id=session_id,
            client_ip=ip,
            mcp_method=method,
            tool_name=tool_name,
            decision="DENY",
            reason_code="BLOCKLIST_ACTIVE",
            reason=f"Client IP is blocked (remaining_sec={blocklist.remaining_sec(ip)}).",
        )
        return 403, error_payload(trace_id, "BLOCKLIST_ACTIVE", "Client IP blocked"), {
            "x-trace-id": trace_id,
            "x-request-id": request_id,
        }

    try:
        nreq = _normalized_request(http_request, body, request_id)
        headers_out = {"x-trace-id": nreq.trace_id, "x-request-id": nreq.request_id}

        emitter.emit_request_received(
            timestamp=now_iso(),
            request_id=nreq.request_id,
            trace_id=nreq.trace_id,
            session_id=nreq.session_id,
            client_ip=nreq.client_ip,
            mcp_method=nreq.mcp_method,
            tool_name=nreq.tool_name,
            reason_code="RECEIVED",
            reason="Request received and queued for evaluation",
            payload_size_bytes=nreq.payload_size_bytes,
        )

        rule_started = time.perf_counter()
        rule_eval: RuleEvaluation = evaluate_rules(nreq)
        rule_latency_ms = round((time.perf_counter() - rule_started) * 1000.0, 3)
        emitter.emit_rule_evaluated(
            timestamp=now_iso(),
            request_id=nreq.request_id,
            trace_id=nreq.trace_id,
            session_id=nreq.session_id,
            client_ip=nreq.client_ip,
            mcp_method=nreq.mcp_method,
            tool_name=nreq.tool_name,
            opa_policy_id=rule_eval.opa_policy_id,
            opa_result=rule_eval.opa_result,
            opa_matched_rules=rule_eval.opa_matched_rules,
            violations=[violation.model_dump() for violation in rule_eval.violations],
            reason_code=rule_eval.reason_code,
            reason=rule_eval.reason,
            stage_latency_ms=rule_latency_ms,
        )

        risk_eval: Optional[RiskEvaluation] = None
        if cfg.enable_model_eval:
            risk_started = time.perf_counter()
            risk_eval = evaluate_risk(nreq, cfg.risk_threshold)
            risk_latency_ms = round((time.perf_counter() - risk_started) * 1000.0, 3)
            emitter.emit_model_evaluated(
                timestamp=now_iso(),
                request_id=nreq.request_id,
                trace_id=nreq.trace_id,
                session_id=nreq.session_id,
                client_ip=nreq.client_ip,
                mcp_method=nreq.mcp_method,
                tool_name=nreq.tool_name,
                model_name=risk_eval.model_name,
                model_version=risk_eval.model_version,
                risk_score=risk_eval.risk_score,
                risk_threshold=risk_eval.risk_threshold,
                model_reason_summary=risk_eval.model_reason_summary,
                reason_code=risk_eval.reason_code,
                reason=risk_eval.reason,
                stage_latency_ms=risk_latency_ms,
            )

        decision = "ALLOW"
        reason_code = "ALLOW"
        reason = "Request allowed"
        if rule_eval.opa_result == "DENY":
            decision = "DENY"
            reason_code = rule_eval.reason_code or "RULE_DENY"
            reason = rule_eval.reason or "Denied by deterministic rule"
        elif cfg.enable_model_eval and risk_eval is not None and risk_eval.risk_score >= risk_eval.risk_threshold:
            decision = cfg.model_decision.upper()
            if decision not in ("CHALLENGE", "DENY"):
                decision = "CHALLENGE"
            reason_code = "LLM_HIGH_RISK"
            reason = f"Risk score {risk_eval.risk_score:.2f} >= threshold {risk_eval.risk_threshold:.2f}"

        emitter.emit_decision_made(
            timestamp=now_iso(),
            request_id=nreq.request_id,
            trace_id=nreq.trace_id,
            session_id=nreq.session_id,
            client_ip=nreq.client_ip,
            mcp_method=nreq.mcp_method,
            tool_name=nreq.tool_name,
            decision=decision,
            reason_code=reason_code,
            reason=reason,
        )

        if decision == "DENY" and cfg.enable_mitigation:
            expires_at = blocklist.block(nreq.client_ip, cfg.blocklist_duration_sec)
            emitter.emit_action_applied(
                timestamp=now_iso(),
                request_id=nreq.request_id,
                trace_id=nreq.trace_id,
                session_id=nreq.session_id,
                client_ip=nreq.client_ip,
                mcp_method=nreq.mcp_method,
                tool_name=nreq.tool_name,
                decision="DENY",
                action_type="BLOCK_IP",
                action_target=nreq.client_ip,
                action_duration_sec=cfg.blocklist_duration_sec,
                reason_code="MITIGATION_BLOCK",
                reason=f"Blocked IP until epoch={int(expires_at)}",
            )

        if decision == "DENY":
            return 403, error_payload(nreq.trace_id, reason_code, reason), headers_out

        if decision == "CHALLENGE":
            return 403, {"error": "challenge_required", "trace_id": nreq.trace_id, "reason": reason}, headers_out

        forward_headers = {
            key: value
            for key, value in http_request.headers.items()
            if key.lower() not in ("content-length", "host", "connection", "transfer-encoding", "accept-encoding")
        }
        forward_headers["x-trace-id"] = nreq.trace_id
        forward_headers["x-request-id"] = nreq.request_id

        emitter.emit_request_forwarded(
            timestamp=now_iso(),
            request_id=nreq.request_id,
            trace_id=nreq.trace_id,
            session_id=nreq.session_id,
            client_ip=nreq.client_ip,
            mcp_method=nreq.mcp_method,
            tool_name=nreq.tool_name,
            decision="ALLOW",
            reason_code="FORWARD",
            reason=f"Forwarding to upstream: {cfg.upstream_url}",
        )

        status, data, latency_ms = await forward_json(cfg.upstream_url, nreq.raw_body, forward_headers)
        emitter.emit_response_returned(
            timestamp=now_iso(),
            request_id=nreq.request_id,
            trace_id=nreq.trace_id,
            session_id=nreq.session_id,
            client_ip=nreq.client_ip,
            mcp_method=nreq.mcp_method,
            tool_name=nreq.tool_name,
            decision="ALLOW",
            reason_code="UPSTREAM_RESPONSE",
            reason=f"Upstream responded with status={status}",
            upstream_status=status,
            latency_ms=round(latency_ms, 3),
        )

        return status, data, headers_out

    except Exception as exc:
        emitter.emit_error(
            timestamp=now_iso(),
            request_id=request_id,
            trace_id=trace_id,
            session_id=session_id,
            client_ip=ip,
            mcp_method=method,
            tool_name=tool_name,
            reason_code="PROXY_ERROR",
            reason=f"{type(exc).__name__}: {exc}",
        )
        return 500, error_payload(trace_id, "PROXY_ERROR", "Unhandled proxy error"), {
            "x-trace-id": trace_id,
            "x-request-id": request_id,
        }
