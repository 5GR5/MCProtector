from __future__ import annotations

from typing import Any, Dict, List, Optional
from .config import PolicyConfig
from .models import PolicyDecision, PolicyInput

def _rule_refs(rule_evaluation: Dict[str, Any]) -> List[str]:
    return [f"rule:{rule_id}" for rule_id in (rule_evaluation.get("opa_matched_rules") or [])]

def _violation_conditions(rule_evaluation: Dict[str, Any]) -> List[str]:
    result = []
    for violation in rule_evaluation.get("violations") or []:
        rule = violation.get("rule", "unknown_rule")
        detail = violation.get("detail", "")
        result.append(f"{rule}: {detail}")
    return result

def _risk_score(risk_evaluation: Optional[Dict[str, Any]]) -> Optional[float]:
    if not risk_evaluation:
        return None
    value = risk_evaluation.get("risk_score")
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None

class DeterministicPriorityStrategy:
    name = "deterministic_priority"

    def evaluate(self, policy_input: PolicyInput, cfg: PolicyConfig) -> PolicyDecision:
        rule_eval = policy_input.rule_evaluation or {}
        risk_eval = policy_input.risk_evaluation or None
        opa_result = str(rule_eval.get("opa_result", "ALLOW")).upper()

        thresholds_used = {
            "model_block_threshold": cfg.model_block_threshold,
            "model_challenge_threshold": cfg.model_challenge_threshold,
        }

        # 1. RULE_DENY
        if opa_result == "DENY":
            refs = _rule_refs(rule_eval)
            if not refs and rule_eval.get("reason_code"):
                refs.append(f"rule:{rule_eval.get('reason_code')}")
            conditions = _violation_conditions(rule_eval) or [f"opa_result={opa_result}"]
            return PolicyDecision(
                decision="DENY",
                decision_reason_code="RULE_DENY",
                decision_reason=rule_eval.get("reason") or "Rule evaluation returned DENY.",
                evidence_refs=refs,
                policy_id=cfg.policy_id,
                policy_strategy=self.name,
                source="rule",
                thresholds_used=thresholds_used,
                matched_conditions=conditions,
            )

        # Unexpected rule result safety
        if opa_result not in ("ALLOW", "DENY"):
            fallback = cfg.unknown_rule_result_decision
            if fallback not in ("ALLOW", "DENY", "CHALLENGE"):
                fallback = "CHALLENGE"
            return PolicyDecision(
                decision=fallback,
                decision_reason_code="UNKNOWN_RULE_RESULT",
                decision_reason=f"Unexpected opa_result={opa_result}; applying configured fallback.",
                evidence_refs=[f"rule_result:{opa_result}"],
                policy_id=cfg.policy_id,
                policy_strategy=self.name,
                source="rule",
                thresholds_used=thresholds_used,
                matched_conditions=[f"unexpected_opa_result={opa_result}"],
            )

        score = _risk_score(risk_eval)

        # 2. MODEL_BLOCK
        if score is not None and score >= cfg.model_block_threshold:
            return PolicyDecision(
                decision="DENY",
                decision_reason_code="MODEL_BLOCK",
                decision_reason=f"Model risk score {score:.4f} exceeded block threshold {cfg.model_block_threshold:.4f}.",
                evidence_refs=[f"model:RISK_{score:.4f}", f"threshold:block_{cfg.model_block_threshold:.4f}"],
                policy_id=cfg.policy_id,
                policy_strategy=self.name,
                source="model",
                thresholds_used=thresholds_used,
                matched_conditions=[f"risk_score={score:.4f}", f"risk_score >= model_block_threshold({cfg.model_block_threshold:.4f})"],
            )

        # 3. MODEL_CHALLENGE
        if score is not None and score >= cfg.model_challenge_threshold:
            return PolicyDecision(
                decision="CHALLENGE",
                decision_reason_code="MODEL_CHALLENGE",
                decision_reason=f"Model risk score {score:.4f} exceeded challenge threshold {cfg.model_challenge_threshold:.4f}.",
                evidence_refs=[f"model:RISK_{score:.4f}", f"threshold:challenge_{cfg.model_challenge_threshold:.4f}"],
                policy_id=cfg.policy_id,
                policy_strategy=self.name,
                source="model",
                thresholds_used=thresholds_used,
                matched_conditions=[f"risk_score={score:.4f}", f"risk_score >= model_challenge_threshold({cfg.model_challenge_threshold:.4f})"],
            )

        # 4. ALLOW
        conditions = ["opa_result=ALLOW"]
        if score is not None:
            conditions.append(f"risk_score={score:.4f} below thresholds")
        else:
            conditions.append("risk_evaluation_absent_or_disabled")

        return PolicyDecision(
            decision="ALLOW",
            decision_reason_code="ALLOW",
            decision_reason="No rule denial and no model threshold violation.",
            evidence_refs=[],
            policy_id=cfg.policy_id,
            policy_strategy=self.name,
            source="default",
            thresholds_used=thresholds_used,
            matched_conditions=conditions,
        )
