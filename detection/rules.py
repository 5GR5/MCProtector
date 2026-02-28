from __future__ import annotations

import os
import posixpath
import re
from typing import Dict, List, Optional

from proxy.models import NormalizedRequest, RuleEvaluation, RuleViolation

# ── R1 configuration ──────────────────────────────────────────────────────────
# The only directory tools are allowed to access.
# Override via env var: DETECTION_ALLOWED_BASE=/some/path
ALLOWED_BASE: str = os.getenv("DETECTION_ALLOWED_BASE", "/project/data")

# ── R3 configuration ──────────────────────────────────────────────────────────
# Maps tool name → list of argument keys that MUST be present.
# Add or extend this dict as new tools are registered on the MCP server.
TOOL_SCHEMAS: Dict[str, List[str]] = {
    # Slide example tool names
    "read_file":       ["path"],
    "write_file":      ["path", "content"],
    "list_directory":  ["path"],
    "delete_file":     ["path"],
    # filesystem.* naming convention used in proxy stub
    "filesystem.read":  ["path"],
    "filesystem.write": ["path", "content"],
    "filesystem.list":  ["path"],
    "filesystem.delete": ["path"],
    # database tools
    "query_db": ["query"],
}

# ── R2 configuration ──────────────────────────────────────────────────────────
# Compiled regex patterns that indicate SQL injection attempts.
# Scanned against every string value in tool_args.
_SQL_PATTERNS: List[re.Pattern] = [
    re.compile(r"'\s*OR\s+['\w]", re.IGNORECASE),                              # 'OR '1 / 'OR x
    re.compile(r"\bOR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?", re.IGNORECASE),  # OR 1=1
    re.compile(r"\bUNION\s+(?:ALL\s+)?SELECT\b", re.IGNORECASE),               # UNION SELECT
    re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE),                            # DROP TABLE
    re.compile(r";\s*(?:DROP|DELETE|INSERT|UPDATE|CREATE|ALTER)\b", re.IGNORECASE),  # ; DML/DDL
    re.compile(r"'\s*;\s*--", re.IGNORECASE),                                  # '; --
    re.compile(r"\bEXEC\s*\(", re.IGNORECASE),                                 # EXEC(
    re.compile(r"\bxp_cmdshell\b", re.IGNORECASE),                             # SQL Server RCE
    re.compile(r"--\s*(\r?\n|$)", re.MULTILINE),                               # -- comment
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _normalize(path: str) -> str:
    """Normalize a POSIX-style path, collapsing .. and extra slashes."""
    return posixpath.normpath(path)


def _is_inside_allowed_base(path: str) -> bool:
    """Return True if `path` resolves to inside ALLOWED_BASE."""
    norm_path = _normalize(path)
    norm_base = _normalize(ALLOWED_BASE)
    # Path must start with base + "/" OR be exactly the base
    return norm_path == norm_base or norm_path.startswith(norm_base + "/")


def _args_strings(tool_args: dict) -> List[str]:
    """Collect all string values from tool_args (shallow)."""
    return [v for v in tool_args.values() if isinstance(v, str)]


# ── Shared helpers ────────────────────────────────────────────────────────────

def _sql_matched_pattern(value: str) -> Optional[str]:
    """Return the first SQL injection pattern description that matches value, or None."""
    for pat in _SQL_PATTERNS:
        if pat.search(value):
            return pat.pattern
    return None


# ── Rule checkers ─────────────────────────────────────────────────────────────

def _r1_unsafe_file_access(req: NormalizedRequest) -> Optional[RuleViolation]:
    """
    R1 — Unsafe file access.
    Triggered when a tool receives a 'path' argument that resolves
    outside the allowed base directory.
    """
    if not isinstance(req.tool_args, dict):
        return None
    path = req.tool_args.get("path")
    if path is None:
        return None  # no path arg → R1 does not apply

    if not _is_inside_allowed_base(path):
        return RuleViolation(
            rule="UNSAFE_FILE_ACCESS",
            detail=(
                f"Path '{path}' resolves outside allowed base "
                f"'{ALLOWED_BASE}'. Access denied."
            ),
        )
    return None


def _r2_sql_injection(req: NormalizedRequest) -> Optional[RuleViolation]:
    """
    R2 — SQL Injection.
    Triggered when any string argument contains patterns associated with
    SQL injection (tautologies, UNION SELECT, stacked queries, comments, etc.).
    Scans all string values in tool_args, not just 'query'.
    """
    if not isinstance(req.tool_args, dict):
        return None

    for key, value in req.tool_args.items():
        if not isinstance(value, str):
            continue
        matched = _sql_matched_pattern(value)
        if matched:
            return RuleViolation(
                rule="SQL_INJECTION",
                detail=(
                    f"Argument '{key}' contains a SQL injection pattern "
                    f"(matched: {matched!r}). Value excerpt: {value[:120]!r}"
                ),
            )
    return None


def _r3_invalid_arguments(req: NormalizedRequest) -> Optional[RuleViolation]:
    """
    R3 — Invalid arguments.
    Triggered when a known tool is called without its required arguments,
    or when tool_args is not a dict at all.
    """
    if not req.tool_name:
        return None

    schema = TOOL_SCHEMAS.get(req.tool_name)
    if schema is None:
        return None  # unknown tool — outside our validation scope

    # tool_args must be a dict
    args = req.tool_args if isinstance(req.tool_args, dict) else {}

    missing = [key for key in schema if key not in args]
    if missing:
        return RuleViolation(
            rule="INVALID_ARGUMENTS",
            detail=(
                f"Tool '{req.tool_name}' is missing required argument(s): "
                f"{missing}. Expected: {schema}."
            ),
        )
    return None


# ── Public API ────────────────────────────────────────────────────────────────

def evaluate_rules(req: NormalizedRequest) -> RuleEvaluation:
    """
    Run all detection rules against a normalized MCP request.

    Rules are evaluated in priority order (R1 first, then R3).
    The first violation triggers a DENY — all violations are still
    collected and logged.

    Never raises — any internal error returns a safe ALLOW with
    reason_code DETECTION_ERROR so the proxy demo never breaks.
    """
    try:
        violations: List[RuleViolation] = []
        matched: List[str] = []

        # R1 — Unsafe file access
        v = _r1_unsafe_file_access(req)
        if v:
            violations.append(v)
            matched.append("UNSAFE_FILE_ACCESS")

        # R2 — SQL injection
        v = _r2_sql_injection(req)
        if v:
            violations.append(v)
            matched.append("SQL_INJECTION")

        # R3 — Invalid arguments
        v = _r3_invalid_arguments(req)
        if v:
            violations.append(v)
            matched.append("INVALID_ARGUMENTS")

        if violations:
            return RuleEvaluation(
                opa_policy_id="poc-policy-v1",
                opa_result="DENY",
                opa_matched_rules=matched,
                violations=violations,
                reason_code=matched[0],        # first-matched rule wins
                reason=violations[0].detail,
            )

        return RuleEvaluation(
            opa_policy_id="poc-policy-v1",
            opa_result="ALLOW",
            opa_matched_rules=[],
            violations=[],
            reason_code="RULES_ALLOW",
            reason="No violations detected.",
        )

    except Exception as exc:
        # Safety net — never let detection crash the proxy
        return RuleEvaluation(
            opa_policy_id="poc-policy-v1",
            opa_result="ALLOW",
            opa_matched_rules=[],
            violations=[],
            reason_code="DETECTION_ERROR",
            reason=f"Detection error (safe fallback): {type(exc).__name__}: {exc}",
        )
