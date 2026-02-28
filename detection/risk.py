from __future__ import annotations

import posixpath
from typing import List

from proxy.models import NormalizedRequest, RiskEvaluation
from .rules import ALLOWED_BASE, TOOL_SCHEMAS, _sql_matched_pattern

# ── Scoring weights ───────────────────────────────────────────────────────────
_BASE_SCORE            = 0.1   # every request starts here
_W_PATH_OUTSIDE_BASE   = 0.5   # path resolves outside allowed base (near-miss or bypass)
_W_PATH_TRAVERSAL      = 0.3   # ../../ pattern in any string arg
_W_SQL_INJECTION       = 0.4   # SQL injection pattern in any string arg
_W_MISSING_ARGS        = 0.2   # known tool called with missing required args
_W_FILESYSTEM_TOOL     = 0.1   # tool name suggests filesystem access
_W_NO_AUTH_TOKEN       = 0.1   # no bearer token on a tool call
_W_LARGE_PAYLOAD       = 0.1   # payload > 2 KB


def _normalize(path: str) -> str:
    return posixpath.normpath(path)


def _is_inside_allowed_base(path: str) -> bool:
    norm_path = _normalize(path)
    norm_base = _normalize(ALLOWED_BASE)
    return norm_path == norm_base or norm_path.startswith(norm_base + "/")


def _has_path_traversal(args: dict) -> bool:
    return any("../" in str(v) or "..\\" in str(v) for v in args.values())


def _has_missing_required_args(req: NormalizedRequest) -> bool:
    if not req.tool_name:
        return False
    schema = TOOL_SCHEMAS.get(req.tool_name)
    if schema is None:
        return False
    args = req.tool_args if isinstance(req.tool_args, dict) else {}
    return any(key not in args for key in schema)


def _score_reasons(req: NormalizedRequest) -> tuple[float, List[str]]:
    """Return (raw_score, list_of_reason_snippets)."""
    score = _BASE_SCORE
    reasons: List[str] = []
    args = req.tool_args if isinstance(req.tool_args, dict) else {}

    # Path outside allowed base
    path = args.get("path")
    if path and not _is_inside_allowed_base(path):
        score += _W_PATH_OUTSIDE_BASE
        reasons.append(f"path outside allowed base (+{_W_PATH_OUTSIDE_BASE})")

    # Path traversal pattern
    if _has_path_traversal(args):
        score += _W_PATH_TRAVERSAL
        reasons.append(f"path traversal pattern detected (+{_W_PATH_TRAVERSAL})")

    # SQL injection pattern in any string arg
    for val in args.values():
        if isinstance(val, str) and _sql_matched_pattern(val):
            score += _W_SQL_INJECTION
            reasons.append(f"SQL injection pattern in args (+{_W_SQL_INJECTION})")
            break  # count once per request

    # Missing required arguments
    if _has_missing_required_args(req):
        score += _W_MISSING_ARGS
        reasons.append(f"missing required tool args (+{_W_MISSING_ARGS})")

    # Filesystem tool
    tool = req.tool_name or ""
    if tool.startswith("filesystem.") or tool in ("read_file", "write_file", "delete_file", "list_directory"):
        score += _W_FILESYSTEM_TOOL
        reasons.append(f"filesystem tool (+{_W_FILESYSTEM_TOOL})")

    # No auth token on a tool call
    if req.mcp_method == "tools/call" and not req.auth_token:
        score += _W_NO_AUTH_TOKEN
        reasons.append(f"no auth token (+{_W_NO_AUTH_TOKEN})")

    # Large payload
    if req.payload_size_bytes > 2048:
        score += _W_LARGE_PAYLOAD
        reasons.append(f"payload {req.payload_size_bytes}B > 2048B (+{_W_LARGE_PAYLOAD})")

    return min(score, 1.0), reasons


# ── Public API ────────────────────────────────────────────────────────────────

def evaluate_risk(req: NormalizedRequest, threshold: float) -> RiskEvaluation:
    """
    Compute a heuristic risk score (0.0 – 1.0) for a normalized MCP request.

    Scoring is additive and independent from rule evaluation — even a request
    that passed all rules may receive a high score if it shows suspicious patterns.

    Never raises — any internal error returns score=0.0 so the proxy never breaks.
    """
    try:
        score, reasons = _score_reasons(req)
        summary = "; ".join(reasons) if reasons else "no suspicious indicators"

        return RiskEvaluation(
            model_name="heuristic-risk-scorer-v1",
            model_version="1.0",
            risk_score=round(score, 4),
            risk_threshold=threshold,
            model_reason_summary=summary,
            reason_code="MODEL_SCORE",
            reason="Risk score computed.",
        )

    except Exception as exc:
        return RiskEvaluation(
            model_name="heuristic-risk-scorer-v1",
            model_version="1.0",
            risk_score=0.0,
            risk_threshold=threshold,
            model_reason_summary=f"Scorer error: {type(exc).__name__}: {exc}",
            reason_code="DETECTION_ERROR",
            reason="Risk scorer failed — defaulting to 0.0.",
        )
