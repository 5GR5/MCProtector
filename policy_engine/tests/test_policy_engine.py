from proxy.models import RuleEvaluation, RiskEvaluation, RuleViolation
from policy_engine import evaluate_policy, reload_policy_engine

def test_rule_deny_wins():
    reload_policy_engine()
    rule_eval = RuleEvaluation(
        opa_policy_id="test",
        opa_result="DENY",
        opa_matched_rules=["filesystem.path_outside_allowed_base"],
        violations=[RuleViolation(rule="filesystem.path_outside_allowed_base", detail="bad path")],
        reason_code="filesystem.path_outside_allowed_base",
        reason="bad path",
    )
    risk_eval = RiskEvaluation(risk_score=0.1, risk_threshold=0.8, model_reason_summary="low", reason_code="MODEL_SCORE", reason="score")
    decision = evaluate_policy(rule_eval, risk_eval, {})
    assert decision.decision == "DENY"
    assert decision.decision_reason_code == "RULE_DENY"

def test_model_block():
    reload_policy_engine()
    rule_eval = RuleEvaluation(opa_policy_id="test", opa_result="ALLOW", reason_code="RULES_ALLOW", reason="ok")
    risk_eval = RiskEvaluation(risk_score=0.96, risk_threshold=0.8, model_reason_summary="high", reason_code="MODEL_SCORE", reason="score")
    decision = evaluate_policy(rule_eval, risk_eval, {})
    assert decision.decision == "DENY"
    assert decision.decision_reason_code == "MODEL_BLOCK"

def test_model_challenge():
    reload_policy_engine()
    rule_eval = RuleEvaluation(opa_policy_id="test", opa_result="ALLOW", reason_code="RULES_ALLOW", reason="ok")
    risk_eval = RiskEvaluation(risk_score=0.85, risk_threshold=0.8, model_reason_summary="medium", reason_code="MODEL_SCORE", reason="score")
    decision = evaluate_policy(rule_eval, risk_eval, {})
    assert decision.decision == "CHALLENGE"
    assert decision.decision_reason_code == "MODEL_CHALLENGE"

def test_allow():
    reload_policy_engine()
    rule_eval = RuleEvaluation(opa_policy_id="test", opa_result="ALLOW", reason_code="RULES_ALLOW", reason="ok")
    risk_eval = RiskEvaluation(risk_score=0.2, risk_threshold=0.8, model_reason_summary="low", reason_code="MODEL_SCORE", reason="score")
    decision = evaluate_policy(rule_eval, risk_eval, {})
    assert decision.decision == "ALLOW"
