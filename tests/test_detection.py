"""
Unit tests for the detection module.

Run with:
    pytest tests/test_detection.py -v

Each test uses a known input and asserts the exact expected output so the
proxy team can verify integration quickly without running the full stack.
"""
import pytest
from detection.rules import evaluate_rules
from detection.risk import evaluate_risk
from proxy.models import NormalizedRequest


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_req(**kwargs) -> NormalizedRequest:
    """Build a minimal NormalizedRequest with sensible defaults."""
    defaults = dict(
        request_id="test-req-1",
        trace_id="test-trace-1",
        client_ip="127.0.0.1",
        session_id="sess-test",
        mcp_method="tools/call",
        tool_name=None,
        tool_args={},
        received_at="2026-01-01T00:00:00.000Z",
        auth_token="Bearer test-token",
        headers={},
        payload_size_bytes=100,
        raw_body={},
    )
    defaults.update(kwargs)
    return NormalizedRequest(**defaults)


# ── R1: Unsafe file access ────────────────────────────────────────────────────

class TestR1UnsafeFileAccess:

    def test_bad_path_denied(self):
        """R1: path outside allowed base → DENY with UNSAFE_FILE_ACCESS."""
        req = make_req(
            tool_name="read_file",
            tool_args={"path": "/etc/passwd"},
        )
        result = evaluate_rules(req)
        assert result.opa_result == "DENY"
        assert "UNSAFE_FILE_ACCESS" in result.opa_matched_rules
        assert result.reason_code == "UNSAFE_FILE_ACCESS"

    def test_traversal_path_denied(self):
        """R1: path traversal that escapes allowed base → DENY."""
        req = make_req(
            tool_name="read_file",
            tool_args={"path": "/project/data/../../etc/passwd"},
        )
        result = evaluate_rules(req)
        assert result.opa_result == "DENY"
        assert "UNSAFE_FILE_ACCESS" in result.opa_matched_rules

    def test_good_path_allowed(self):
        """R1: path inside allowed base → ALLOW."""
        req = make_req(
            tool_name="read_file",
            tool_args={"path": "/project/data/report.txt"},
        )
        result = evaluate_rules(req)
        assert result.opa_result == "ALLOW"
        assert result.opa_matched_rules == []

    def test_nested_good_path_allowed(self):
        """R1: deeply nested path inside allowed base → ALLOW."""
        req = make_req(
            tool_name="write_file",
            tool_args={"path": "/project/data/subdir/notes.txt", "content": "hello"},
        )
        result = evaluate_rules(req)
        assert result.opa_result == "ALLOW"

    def test_no_path_arg_skips_r1(self):
        """R1: tool with no path argument → R1 does not apply."""
        req = make_req(
            tool_name="read_file",
            tool_args={"query": "SELECT 1"},   # no path
        )
        # R3 will fire (missing 'path') but R1 should not
        result = evaluate_rules(req)
        assert "UNSAFE_FILE_ACCESS" not in result.opa_matched_rules


# ── R3: Invalid arguments ─────────────────────────────────────────────────────

class TestR3InvalidArguments:

    def test_missing_required_arg_denied(self):
        """R3: known tool missing required arg → DENY with INVALID_ARGUMENTS."""
        req = make_req(
            tool_name="read_file",
            tool_args={},   # missing 'path'
        )
        result = evaluate_rules(req)
        assert result.opa_result == "DENY"
        assert "INVALID_ARGUMENTS" in result.opa_matched_rules
        assert result.reason_code == "INVALID_ARGUMENTS"

    def test_write_file_missing_content_denied(self):
        """R3: write_file with only path (missing content) → DENY."""
        req = make_req(
            tool_name="write_file",
            tool_args={"path": "/project/data/out.txt"},  # missing 'content'
        )
        result = evaluate_rules(req)
        assert result.opa_result == "DENY"
        assert "INVALID_ARGUMENTS" in result.opa_matched_rules

    def test_all_args_present_allowed(self):
        """R3: all required args present → ALLOW."""
        req = make_req(
            tool_name="write_file",
            tool_args={"path": "/project/data/out.txt", "content": "data"},
        )
        result = evaluate_rules(req)
        assert result.opa_result == "ALLOW"

    def test_unknown_tool_not_validated(self):
        """R3: unknown tool → not our responsibility, ALLOW."""
        req = make_req(
            tool_name="custom_tool_xyz",
            tool_args={},
        )
        result = evaluate_rules(req)
        assert result.opa_result == "ALLOW"

    def test_no_tool_name_skips_r3(self):
        """R3: no tool_name (e.g. tools/list) → ALLOW."""
        req = make_req(
            mcp_method="tools/list",
            tool_name=None,
            tool_args={},
        )
        result = evaluate_rules(req)
        assert result.opa_result == "ALLOW"


# ── R2: SQL Injection ─────────────────────────────────────────────────────────

class TestR2SqlInjection:

    def test_classic_or_injection_denied(self):
        """R2: classic OR '1'='1' tautology → DENY with SQL_INJECTION."""
        req = make_req(
            tool_name="query_db",
            tool_args={"query": "SELECT * FROM users WHERE username = 'admin' OR '1'='1'"},
        )
        result = evaluate_rules(req)
        assert result.opa_result == "DENY"
        assert "SQL_INJECTION" in result.opa_matched_rules
        assert result.reason_code == "SQL_INJECTION"

    def test_union_select_denied(self):
        """R2: UNION SELECT exfiltration attempt → DENY."""
        req = make_req(
            tool_name="query_db",
            tool_args={"query": "SELECT name FROM products UNION SELECT password FROM users"},
        )
        result = evaluate_rules(req)
        assert result.opa_result == "DENY"
        assert "SQL_INJECTION" in result.opa_matched_rules

    def test_drop_table_denied(self):
        """R2: DROP TABLE destructive statement → DENY."""
        req = make_req(
            tool_name="query_db",
            tool_args={"query": "SELECT 1; DROP TABLE users --"},
        )
        result = evaluate_rules(req)
        assert result.opa_result == "DENY"
        assert "SQL_INJECTION" in result.opa_matched_rules

    def test_sql_in_non_query_arg_denied(self):
        """R2: injection pattern in any arg, not just 'query' → DENY."""
        req = make_req(
            tool_name="query_db",
            tool_args={"query": "SELECT * FROM orders WHERE id = ?",
                       "user_input": "1 OR 1=1"},
        )
        result = evaluate_rules(req)
        assert result.opa_result == "DENY"
        assert "SQL_INJECTION" in result.opa_matched_rules

    def test_parameterized_query_allowed(self):
        """R2: safe parameterized query with clean value → ALLOW."""
        req = make_req(
            tool_name="query_db",
            tool_args={"query": "SELECT * FROM users WHERE username = ?",
                       "params": "admin"},
        )
        result = evaluate_rules(req)
        assert result.opa_result == "ALLOW"
        assert "SQL_INJECTION" not in result.opa_matched_rules

    def test_normal_query_allowed(self):
        """R2: plain safe query → ALLOW."""
        req = make_req(
            tool_name="query_db",
            tool_args={"query": "SELECT id, name FROM products WHERE category = 'electronics'"},
        )
        result = evaluate_rules(req)
        assert result.opa_result == "ALLOW"

    def test_xp_cmdshell_denied(self):
        """R2: SQL Server RCE via xp_cmdshell → DENY."""
        req = make_req(
            tool_name="query_db",
            tool_args={"query": "EXEC xp_cmdshell('whoami')"},
        )
        result = evaluate_rules(req)
        assert result.opa_result == "DENY"
        assert "SQL_INJECTION" in result.opa_matched_rules


# ── Combined: both rules violated ────────────────────────────────────────────

class TestCombinedViolations:

    def test_r1_and_r3_both_logged(self):
        """Both R1 and R3 fire: bad path AND missing required arg."""
        req = make_req(
            tool_name="write_file",
            # path is bad (R1) AND content is missing (R3)
            tool_args={"path": "/etc/shadow"},
        )
        result = evaluate_rules(req)
        assert result.opa_result == "DENY"
        assert "UNSAFE_FILE_ACCESS" in result.opa_matched_rules
        assert "INVALID_ARGUMENTS" in result.opa_matched_rules
        assert len(result.violations) == 2
        # First matched rule wins for reason_code
        assert result.reason_code == "UNSAFE_FILE_ACCESS"

    def test_safe_request_fully_allowed(self):
        """Happy path: good tool, good path, all args present → ALLOW."""
        req = make_req(
            tool_name="read_file",
            tool_args={"path": "/project/data/safe.txt"},
        )
        result = evaluate_rules(req)
        assert result.opa_result == "ALLOW"
        assert result.violations == []
        assert result.reason_code == "RULES_ALLOW"


# ── Risk scorer ───────────────────────────────────────────────────────────────

class TestRiskScorer:

    def test_safe_request_low_score(self):
        """Non-filesystem, safe tool → risk score close to base (≤ 0.3)."""
        req = make_req(
            tool_name="calculator.add",
            tool_args={"a": 5, "b": 3},
        )
        result = evaluate_risk(req, threshold=0.80)
        assert result.risk_score <= 0.3
        assert result.risk_threshold == 0.80
        assert result.model_name == "heuristic-risk-scorer-v1"

    def test_filesystem_tool_higher_score(self):
        """Filesystem tool → risk score is elevated (≥ 0.2)."""
        req = make_req(
            tool_name="read_file",
            tool_args={"path": "/project/data/report.txt"},
        )
        result = evaluate_risk(req, threshold=0.80)
        assert result.risk_score >= 0.2

    def test_bad_path_very_high_score(self):
        """Path outside allowed base → high risk score (≥ 0.5)."""
        req = make_req(
            tool_name="read_file",
            tool_args={"path": "/etc/passwd"},
        )
        result = evaluate_risk(req, threshold=0.80)
        assert result.risk_score >= 0.5

    def test_no_auth_token_adds_to_score(self):
        """Missing auth token → slightly higher score than same request with token."""
        req_with_token = make_req(
            tool_name="read_file",
            tool_args={"path": "/project/data/f.txt"},
            auth_token="Bearer abc",
        )
        req_no_token = make_req(
            tool_name="read_file",
            tool_args={"path": "/project/data/f.txt"},
            auth_token=None,
        )
        score_with = evaluate_risk(req_with_token, 0.8).risk_score
        score_without = evaluate_risk(req_no_token, 0.8).risk_score
        assert score_without > score_with

    def test_score_capped_at_1(self):
        """Score never exceeds 1.0 even with all bad signals."""
        req = make_req(
            tool_name="write_file",
            tool_args={"path": "/etc/shadow", "content": "../../evil"},
            auth_token=None,
            payload_size_bytes=9999,
        )
        result = evaluate_risk(req, threshold=0.80)
        assert result.risk_score <= 1.0

    def test_threshold_is_echoed(self):
        """risk_threshold in result must match the threshold passed in."""
        req = make_req(tool_name="read_file", tool_args={"path": "/project/data/x"})
        result = evaluate_risk(req, threshold=0.55)
        assert result.risk_threshold == 0.55

    def test_reason_summary_present(self):
        """model_reason_summary must be a non-empty string."""
        req = make_req(tool_name="read_file", tool_args={"path": "/project/data/x"})
        result = evaluate_risk(req, threshold=0.80)
        assert isinstance(result.model_reason_summary, str)
        assert len(result.model_reason_summary) > 0

    def test_sql_injection_high_score(self):
        """SQL injection pattern → risk score elevated (≥ 0.4)."""
        req = make_req(
            tool_name="query_db",
            tool_args={"query": "SELECT * FROM users WHERE id = 1 OR 1=1"},
        )
        result = evaluate_risk(req, threshold=0.80)
        assert result.risk_score >= 0.4

    def test_clean_query_low_score(self):
        """Safe parameterized query → low risk score (≤ 0.3)."""
        req = make_req(
            tool_name="query_db",
            tool_args={"query": "SELECT * FROM users WHERE username = ?", "params": "alice"},
        )
        result = evaluate_risk(req, threshold=0.80)
        assert result.risk_score <= 0.3
