from __future__ import annotations
import re, time
from proxy.models import NormalizedRequest
from detection.engine.base import DetectionRule
from detection.engine.types import RuleContext, RuleResult

_SQL_PATTERNS = [
    re.compile(r"'\s*OR\s+['\w]", re.IGNORECASE),
    re.compile(r"\bOR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?", re.IGNORECASE),
    re.compile(r"\bUNION\s+(?:ALL\s+)?SELECT\b", re.IGNORECASE),
    re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE),
    re.compile(r";\s*(?:DROP|DELETE|INSERT|UPDATE|CREATE|ALTER)\b", re.IGNORECASE),
    re.compile(r"'\s*;\s*--", re.IGNORECASE),
    re.compile(r"\bEXEC\s*\(", re.IGNORECASE),
    re.compile(r"\bxp_cmdshell\b", re.IGNORECASE),
    re.compile(r"--\s*(\r?\n|$)", re.MULTILINE),
]

class SqlInjectionRule(DetectionRule):
    id = "abuse.sql_injection"
    pack = "abuse_pack"

    def supports(self, req: NormalizedRequest) -> bool:
        return isinstance(req.tool_args, dict)

    def evaluate(self, req: NormalizedRequest, state, ctx: RuleContext) -> RuleResult:
        for key, value in req.tool_args.items():
            if not isinstance(value, str):
                continue
            for pat in _SQL_PATTERNS:
                if pat.search(value):
                    return RuleResult(self.id, True, f"Argument '{key}' matched SQL injection pattern {pat.pattern!r}.", "high")
        return RuleResult(self.id, False)

class LargePayloadRule(DetectionRule):
    id = "abuse.large_payload"
    pack = "abuse_pack"

    def evaluate(self, req: NormalizedRequest, state, ctx: RuleContext) -> RuleResult:
        threshold = int(ctx.settings.get("large_payload_threshold_bytes", 4096))
        if req.payload_size_bytes > threshold:
            return RuleResult(self.id, True, f"Payload size {req.payload_size_bytes}B exceeded threshold {threshold}B.", "medium")
        return RuleResult(self.id, False)

class RapidRepeatIpRule(DetectionRule):
    id = "abuse.rapid_repeat_ip"
    pack = "abuse_pack"

    def evaluate(self, req: NormalizedRequest, state, ctx: RuleContext) -> RuleResult:
        now_ts = time.time()
        window = int(ctx.settings.get("rapid_repeat_window_sec", 15))
        limit = int(ctx.settings.get("rapid_repeat_limit", 5))
        state.add_request_for_ip(req.client_ip, now_ts)
        count = state.count_requests_for_ip(req.client_ip, window, now_ts)
        if count > limit:
            return RuleResult(self.id, True, f"Client IP {req.client_ip} made {count} requests in {window}s (limit={limit}).", "medium")
        return RuleResult(self.id, False)

class ReusedTokenMultiIpRule(DetectionRule):
    id = "abuse.reused_token_multi_ip"
    pack = "abuse_pack"

    def supports(self, req: NormalizedRequest) -> bool:
        return bool(req.auth_token)

    def evaluate(self, req: NormalizedRequest, state, ctx: RuleContext) -> RuleResult:
        now_ts = time.time()
        window = int(ctx.settings.get("token_multi_ip_window_sec", 60))
        max_ips = int(ctx.settings.get("token_multi_ip_max_ips", 1))
        state.add_token_ip(req.auth_token, req.client_ip, now_ts)
        unique_ips = state.unique_ips_for_token(req.auth_token, window, now_ts)
        if len(unique_ips) > max_ips:
            return RuleResult(self.id, True, f"Token reused across multiple IPs in {window}s: {sorted(unique_ips)}.", "high")
        return RuleResult(self.id, False)

def get_rules():
    return [SqlInjectionRule(), LargePayloadRule(), RapidRepeatIpRule(), ReusedTokenMultiIpRule()]
