from __future__ import annotations
import time
from typing import Optional
from proxy.models import NormalizedRequest, RuleEvaluation, RiskEvaluation
from .loader import DetectionEngine

_ENGINE: Optional[DetectionEngine] = None

def get_engine() -> DetectionEngine:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = DetectionEngine()
    _ENGINE.maybe_reload()
    return _ENGINE

def reload_engine() -> None:
    global _ENGINE
    _ENGINE = DetectionEngine()

def get_registry():
    return get_engine().registry

def evaluate_rules(req: NormalizedRequest) -> RuleEvaluation:
    try:
        engine = get_engine()
        rapid_win = int(engine.context.settings.get("rapid_repeat_window_sec", 15))
        token_win = int(engine.context.settings.get("token_multi_ip_window_sec", 60))
        engine.state.evict_expired(time.time(), rapid_win, token_win)
        matches = engine.registry.evaluate_all(req, engine.state, engine.context)
        if matches:
            matched_ids = [m.rule_id for m in matches]
            violations = [m.to_violation() for m in matches]
            return RuleEvaluation(
                opa_policy_id=engine.policy_id,
                opa_result="DENY",
                opa_matched_rules=matched_ids,
                violations=violations,
                reason_code=matched_ids[0],
                reason=violations[0].detail,
            )
        return RuleEvaluation(
            opa_policy_id=engine.policy_id,
            opa_result="ALLOW",
            opa_matched_rules=[],
            violations=[],
            reason_code="RULES_ALLOW",
            reason="No violations detected.",
        )
    except Exception as exc:
        return RuleEvaluation(
            opa_policy_id="product-policy-v1",
            opa_result="ALLOW",
            opa_matched_rules=[],
            violations=[],
            reason_code="DETECTION_ERROR",
            reason=f"Detection error (safe fallback): {type(exc).__name__}: {exc}",
        )

def evaluate_risk(req: NormalizedRequest, threshold: float) -> RiskEvaluation:
    try:
        engine = get_engine()
        score = 0.10
        reasons = []
        args = req.tool_args if isinstance(req.tool_args, dict) else {}
        path = args.get("path")
        allowed_base = str(engine.context.settings.get("allowed_base", "/project/data"))
        if path and not str(path).startswith(allowed_base):
            score += 0.40
            reasons.append("path outside allowed base (+0.40)")
        if req.payload_size_bytes > int(engine.context.settings.get("large_payload_threshold_bytes", 4096)):
            score += 0.10
            reasons.append("large payload (+0.10)")
        if req.tool_name and req.tool_name.startswith("filesystem."):
            score += 0.10
            reasons.append("filesystem tool (+0.10)")
        if req.mcp_method == "tools/call" and not req.auth_token:
            score += 0.10
            reasons.append("no auth token (+0.10)")
        risk_score = round(min(score, 1.0), 4)
        return RiskEvaluation(
            model_name="heuristic-risk-scorer-v2",
            model_version="2.0",
            risk_score=risk_score,
            risk_threshold=threshold,
            model_reason_summary="; ".join(reasons) if reasons else "no suspicious indicators",
            reason_code="MODEL_SCORE",
            reason="Risk score computed.",
        )
    except Exception as exc:
        return RiskEvaluation(
            model_name="heuristic-risk-scorer-v2",
            model_version="2.0",
            risk_score=0.0,
            risk_threshold=threshold,
            model_reason_summary=f"Scorer error: {type(exc).__name__}: {exc}",
            reason_code="DETECTION_ERROR",
            reason="Risk scorer failed — defaulting to 0.0.",
        )
