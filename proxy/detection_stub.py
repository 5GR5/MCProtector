from __future__ import annotations

from .models import NormalizedRequest, RuleEvaluation, RiskEvaluation


from .models import NormalizedRequest, RuleEvaluation, RuleViolation


# Temporary stub implementations for rule and risk evaluation logic, to be replaced with real OPA and ML model calls in the future.
# Using for demonstration and testing purposes


def evaluate_rules(req: NormalizedRequest) -> RuleEvaluation:
    # FORBIDDEN_PATH demo rule: deny if filesystem.* touches /etc/passwd or .ssh
    path = None
    if isinstance(req.tool_args, dict):
        path = req.tool_args.get("path")

    forbidden = (path is not None) and ("/etc/passwd" in path or ".ssh" in path)

    if req.tool_name and req.tool_name.startswith("filesystem.") and forbidden:
        return RuleEvaluation(
            opa_policy_id="poc-policy-v1",
            opa_result="DENY",
            opa_matched_rules=["FORBIDDEN_PATH"],
            violations=[RuleViolation(rule="FORBIDDEN_PATH", detail=f"Forbidden path requested: {path}")],
            reason_code="FORBIDDEN_PATH",
            reason="Denied: filesystem access to forbidden path",
        )

    return RuleEvaluation(
        opa_policy_id="poc-policy-v1",
        opa_result="ALLOW",
        opa_matched_rules=[],
        violations=[],
        reason_code="RULES_ALLOW",
        reason="No deterministic violations detected.",
    )


def evaluate_risk(req: NormalizedRequest, threshold: float) -> RiskEvaluation:
    # Simple heuristic stub
    score = 0.2
    if (req.tool_name or "").startswith("filesystem."):
        score = 0.6
    return RiskEvaluation(
        model_name="poc-llm-risk-scorer",
        model_version="0.1",
        risk_score=score,
        risk_threshold=threshold,
        model_reason_summary="Heuristic score (stub).",
        reason_code="MODEL_SCORE",
        reason="Risk score computed (stub).",
    )
