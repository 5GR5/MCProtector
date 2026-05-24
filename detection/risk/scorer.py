from __future__ import annotations
import posixpath
from typing import Any, Dict, List
from proxy.models import NormalizedRequest, RiskEvaluation


class HeuristicScorer:
    """Config-driven, pluggable heuristic scorer.

    Reads weight configuration from engine.context.settings under keys in
    `risk_weights`. Returns a RiskEvaluation-like dict with structured evidence.
    """

    DEFAULTS = {
        "base_score": 0.10,
        "path_outside_base": 0.40,
        "large_payload": 0.10,
        "filesystem_tool": 0.10,
        "missing_auth_token": 0.10,
    }

    def __init__(self, settings: Dict[str, Any]):
        weights = settings.get("risk_weights") or {}
        self.weights = {k: float(weights.get(k, v)) for k, v in self.DEFAULTS.items()}

    @staticmethod
    def _inside_allowed_base(path: str, allowed_base: str) -> bool:
        if path is None:
            return True
        try:
            norm_path = posixpath.normpath(str(path))
            norm_base = posixpath.normpath(str(allowed_base))
            if not norm_path.startswith("/"):
                norm_path = "/" + norm_path
            if not norm_base.startswith("/"):
                norm_base = "/" + norm_base
            return norm_path == norm_base or norm_path.startswith(norm_base + "/")
        except Exception:
            return False

    def score(self, req: NormalizedRequest, engine_context: Any, threshold: float) -> RiskEvaluation:
        base = float(self.weights.get("base_score", 0.10))
        score = base
        details: List[Dict[str, Any]] = []

        args = req.tool_args if isinstance(req.tool_args, dict) else {}
        path = args.get("path")
        allowed_base = str(engine_context.settings.get("allowed_base", "/project/data"))

        if path is not None and not self._inside_allowed_base(path, allowed_base):
            delta = float(self.weights.get("path_outside_base", 0.4))
            score += delta
            details.append({"feature": "path_outside_allowed_base", "delta": delta, "value": str(path)})

        if req.payload_size_bytes > int(engine_context.settings.get("large_payload_threshold_bytes", 4096)):
            delta = float(self.weights.get("large_payload", 0.1))
            score += delta
            details.append({"feature": "large_payload", "delta": delta, "value": req.payload_size_bytes})

        if req.tool_name and str(req.tool_name).startswith("filesystem."):
            delta = float(self.weights.get("filesystem_tool", 0.1))
            score += delta
            details.append({"feature": "filesystem_tool", "delta": delta, "value": req.tool_name})

        if req.mcp_method == "tools/call" and not req.auth_token:
            delta = float(self.weights.get("missing_auth_token", 0.1))
            score += delta
            details.append({"feature": "missing_auth_token", "delta": delta, "value": None})

        risk_score = round(min(score, 1.0), 4)

        return RiskEvaluation(
            model_name="heuristic-risk-scorer-v2",
            model_version="2.0",
            risk_score=risk_score,
            risk_threshold=threshold,
            model_reason_summary=("; ".join([f"{d['feature']} (+{d['delta']})" for d in details]) if details else "no suspicious indicators"),
            model_reason_details=details,
            reason_code="MODEL_SCORE",
            reason="Risk score computed.",
        )


def get_default_scorer(engine) -> HeuristicScorer:
    return HeuristicScorer(engine.context.settings)
