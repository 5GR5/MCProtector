from __future__ import annotations
from proxy.models import NormalizedRequest
from detection.engine.base import DetectionRule
from detection.engine.types import RuleContext, RuleResult

class MissingAuthTokenRule(DetectionRule):
    id = "identity.missing_auth_token"
    pack = "identity_pack"

    def supports(self, req: NormalizedRequest) -> bool:
        return req.mcp_method == "tools/call"

    def evaluate(self, req: NormalizedRequest, state, ctx: RuleContext) -> RuleResult:
        if not req.auth_token:
            return RuleResult(self.id, True, "Tool invocation was sent without an Authorization bearer token.", "low")
        return RuleResult(self.id, False)

def get_rules():
    return [MissingAuthTokenRule()]
