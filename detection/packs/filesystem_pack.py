from __future__ import annotations
import posixpath
from proxy.models import NormalizedRequest
from detection.engine.base import DetectionRule
from detection.engine.types import RuleContext, RuleResult

def _normalize(path: str) -> str:
    return posixpath.normpath(path)

def _inside_allowed_base(path: str, allowed_base: str) -> bool:
    norm_path = _normalize(path)
    norm_base = _normalize(allowed_base)
    return norm_path == norm_base or norm_path.startswith(norm_base + "/")

class PathOutsideAllowedBaseRule(DetectionRule):
    id = "filesystem.path_outside_allowed_base"
    pack = "filesystem_pack"

    def supports(self, req: NormalizedRequest) -> bool:
        return isinstance(req.tool_args, dict) and "path" in req.tool_args

    def evaluate(self, req: NormalizedRequest, state, ctx: RuleContext) -> RuleResult:
        path = str(req.tool_args.get("path"))
        allowed_base = str(ctx.settings.get("allowed_base", "/project/data"))
        if path and not _inside_allowed_base(path, allowed_base):
            return RuleResult(self.id, True, f"Path '{path}' resolves outside allowed base '{allowed_base}'.", "high")
        return RuleResult(self.id, False)

class PathTraversalRule(DetectionRule):
    id = "filesystem.path_traversal"
    pack = "filesystem_pack"

    def supports(self, req: NormalizedRequest) -> bool:
        return isinstance(req.tool_args, dict)

    def evaluate(self, req: NormalizedRequest, state, ctx: RuleContext) -> RuleResult:
        for key, value in req.tool_args.items():
            text = str(value)
            if "../" in text or "..\\" in text:
                return RuleResult(self.id, True, f"Argument '{key}' contains path traversal pattern.", "high")
        return RuleResult(self.id, False)

class MissingRequiredArgsRule(DetectionRule):
    id = "filesystem.missing_required_args"
    pack = "filesystem_pack"

    def supports(self, req: NormalizedRequest) -> bool:
        return bool(req.tool_name)

    def evaluate(self, req: NormalizedRequest, state, ctx: RuleContext) -> RuleResult:
        schemas = ctx.settings.get("tool_schemas", {})
        expected = schemas.get(req.tool_name)
        if not expected:
            return RuleResult(self.id, False)
        args = req.tool_args if isinstance(req.tool_args, dict) else {}
        missing = [name for name in expected if name not in args]
        if missing:
            return RuleResult(self.id, True, f"Tool '{req.tool_name}' is missing required argument(s): {missing}. Expected: {expected}.", "medium")
        return RuleResult(self.id, False)

def get_rules():
    return [PathOutsideAllowedBaseRule(), PathTraversalRule(), MissingRequiredArgsRule()]
