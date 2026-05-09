# Integration patch for proxy/pipeline.py

## 1. Add import
```python
from policy_engine import evaluate_policy
```

## 2. Replace local decision logic
Replace the existing if/elif decision block with:

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

## 3. Add policy fields to DECISION_MADE log
```python
"policy_id": policy_decision.policy_id,
"policy_strategy": policy_decision.policy_strategy,
"decision_source": policy_decision.source,
"evidence_refs": policy_decision.evidence_refs,
"thresholds_used": policy_decision.thresholds_used,
"matched_conditions": policy_decision.matched_conditions,
```

## 4. Expected behavior
Scenario A stays ALLOW and forwarded.
Scenario B stays DENY and not forwarded.
