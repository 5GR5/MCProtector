# MCProtector Policy Engine

## Purpose
The policy engine moves final ALLOW / DENY / CHALLENGE decision logic out of the proxy.

Detection answers: "What did we find?"
Policy answers: "What should we do?"

## Priority
RULE_DENY > MODEL_BLOCK > MODEL_CHALLENGE > ALLOW

## Proxy integration
Add:

```python
from policy_engine import evaluate_policy
```

Then replace proxy-local decision logic with:

```python
policy_decision = evaluate_policy(
    rule_evaluation=rule_eval,
    risk_evaluation=risk_eval,
    request_context=nreq,
)

decision = policy_decision.decision
reason_code = policy_decision.decision_reason_code
reason = policy_decision.decision_reason
```

Add these to DECISION_MADE logs:

```python
"policy_id": policy_decision.policy_id,
"policy_strategy": policy_decision.policy_strategy,
"decision_source": policy_decision.source,
"evidence_refs": policy_decision.evidence_refs,
"thresholds_used": policy_decision.thresholds_used,
"matched_conditions": policy_decision.matched_conditions,
```
