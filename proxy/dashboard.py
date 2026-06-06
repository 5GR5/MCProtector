from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import secrets
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from mcp_client.client import MCPClient, run_scenario
from observability import PoCEvent, Severity, now_iso

from .config import ProxyConfig
from .mitigation import Blocklist

SESSION_COOKIE_NAME = "mcprotector_dashboard_session"
SESSION_TTL_SEC = 60 * 60 * 12
TOOL_TEST_CASES: dict[str, dict[str, Any]] = {
    "filesystem.read": {
        "name": "filesystem.read",
        "description": "Read contents from the simulated filesystem.",
        "allowed": {
            "title": "Allowed read",
            "summary": "Reads a known file inside the approved /project/data directory.",
            "arguments": {"path": "/project/data/config.json"},
            "expected_decision": "ALLOW",
        },
      "disallowed": {
        "title": "Blocked secret read",
        "summary": "Attempts to read a demonstration secrets file inside the project data directory.",
        "arguments": {"path": "/project/data/secrets/passwords.txt"},
        "expected_decision": "DENY",
      },
    },
    "filesystem.write": {
        "name": "filesystem.write",
        "description": "Write content to the simulated filesystem.",
        "allowed": {
            "title": "Allowed write",
            "summary": "Writes sample content into the approved /project/data directory.",
            "arguments": {
                "path": "/project/data/dashboard-test.txt",
                "content": "Dashboard tool test content",
            },
            "expected_decision": "ALLOW",
        },
        "disallowed": {
            "title": "Blocked unsafe write",
            "summary": "Attempts to write into /root, which is outside the allowed base.",
            "arguments": {"path": "/root/.bashrc", "content": "malicious content"},
            "expected_decision": "DENY",
        },
    },
    "net.http_get": {
        "name": "net.http_get",
        "description": "Fetch a URL through the deterministic HTTP GET stub.",
        "allowed": {
            "title": "Allowed HTTP GET",
            "summary": "Fetches the stubbed status endpoint.",
            "arguments": {"url": "https://api.example.com/status"},
            "expected_decision": "ALLOW",
        },
        "disallowed": {
            "title": "Blocked suspicious URL",
            "summary": "Sends a URL containing a SQL injection pattern so the proxy denies it.",
            "arguments": {"url": "https://api.example.com/search?q=' OR 1=1 --"},
            "expected_decision": "DENY",
        },
    },
    "query_db": {
        "name": "query_db",
        "description": "Run a read-only SQL query against a simulated database.",
        "allowed": {
            "title": "Allowed database query",
            "summary": "Runs a predefined read-only query against the simulated users table.",
            "arguments": {"query": "SELECT id, username, role FROM users"},
            "expected_decision": "ALLOW",
        },
        "disallowed": {
            "title": "Blocked SQL injection",
            "summary": "Attempts a tautology-based SQL injection payload in the query string.",
            "arguments": {"query": "SELECT id, username, role FROM users WHERE username = 'admin' OR 1=1 --"},
            "expected_decision": "DENY",
        },
    },
    "filesystem.delete": {
        "name": "filesystem.delete",
        "description": "Delete a file from the simulated filesystem.",
        "allowed": {
            "title": "Allowed delete",
            "summary": "Deletes a file inside the approved /project/data directory.",
            "arguments": {"path": "/project/data/temp-file.txt"},
            "expected_decision": "ALLOW",
        },
        "disallowed": {
            "title": "Blocked unsafe delete",
            "summary": "Attempts to delete /etc/passwd, which is outside the allowed base.",
            "arguments": {"path": "/etc/passwd"},
            "expected_decision": "DENY",
        },
    },
    "filesystem.list": {
        "name": "filesystem.list",
        "description": "List contents of a directory.",
        "allowed": {
            "title": "Allowed directory listing",
            "summary": "Lists files in the approved /project/data directory.",
            "arguments": {"path": "/project/data"},
            "expected_decision": "ALLOW",
        },
        "disallowed": {
            "title": "Blocked path traversal",
            "summary": "Attempts directory traversal using ../ pattern.",
            "arguments": {"path": "/project/data/../../../etc"},
            "expected_decision": "DENY",
        },
    },
    "net.http_post": {
        "name": "net.http_post",
        "description": "Send data via HTTP POST request.",
        "allowed": {
            "title": "Allowed HTTP POST",
            "summary": "Posts data to a legitimate API endpoint.",
            "arguments": {"url": "https://api.example.com/data", "body": {"action": "update", "value": 42}},
            "expected_decision": "ALLOW",
        },
        "disallowed": {
            "title": "Blocked SQL injection in URL",
            "summary": "POST request with DROP TABLE SQL injection pattern.",
            "arguments": {"url": "https://api.example.com/users; DROP TABLE users--"},
            "expected_decision": "DENY",
        },
    },
    "shell.execute": {
        "name": "shell.execute",
        "description": "Execute shell commands on the server.",
        "allowed": {
            "title": "Allowed safe command",
            "summary": "Runs a harmless whoami command.",
            "arguments": {"command": "whoami"},
            "expected_decision": "ALLOW",
        },
        "disallowed": {
            "title": "Blocked SQL injection in command",
            "summary": "Command contains SQL injection pattern.",
            "arguments": {"command": "echo 'test' OR 1=1 --"},
            "expected_decision": "DENY",
        },
    },
    "secrets.get": {
        "name": "secrets.get",
        "description": "Retrieve secrets and credentials by name.",
        "allowed": {
            "title": "Allowed secret access",
            "summary": "Retrieves an authorized API key.",
            "arguments": {"name": "api_key"},
            "expected_decision": "ALLOW",
        },
        "disallowed": {
            "title": "Blocked SQL injection in name",
            "summary": "Secret name contains UNION SELECT injection.",
            "arguments": {"name": "api_key' UNION SELECT password FROM users--"},
            "expected_decision": "DENY",
        },
    },
    "email.send": {
        "name": "email.send",
        "description": "Send email messages.",
        "allowed": {
            "title": "Allowed email",
            "summary": "Sends email to a legitimate address.",
            "arguments": {"to": "admin@company.com", "subject": "Report", "body": "Weekly report."},
            "expected_decision": "ALLOW",
        },
        "disallowed": {
            "title": "Blocked SQL injection in recipient",
            "summary": "Email recipient contains SQL injection pattern.",
            "arguments": {"to": "admin@company.com' OR '1'='1", "subject": "Test", "body": "Test"},
            "expected_decision": "DENY",
        },
    },
    "crypto.encode": {
        "name": "crypto.encode",
        "description": "Base64 encode data.",
        "allowed": {
            "title": "Allowed encoding",
            "summary": "Encodes a simple message.",
            "arguments": {"data": "Hello World"},
            "expected_decision": "ALLOW",
        },
        "disallowed": {
            "title": "Blocked large payload",
            "summary": "Payload exceeds 4KB threshold (triggers large_payload rule).",
            "arguments": {"data": "A" * 5000},
            "expected_decision": "DENY",
        },
    },
}


@dataclass
class DashboardState:
    cfg: ProxyConfig
    blocklist: Blocklist
    proxy_url: str
    scenario_history: list[dict[str, Any]] = field(default_factory=list)
    scenario_lock: threading.Lock = field(default_factory=threading.Lock)
    closed_alerts: set[str] = field(default_factory=set)
    closed_alerts_lock: threading.Lock = field(default_factory=threading.Lock)
    product_enabled: bool = True

    def record_scenario(self, result: dict[str, Any]) -> None:
        self.scenario_history.insert(0, result)
        del self.scenario_history[10:]

    def close_alert(self, alert_id: str) -> None:
        with self.closed_alerts_lock:
            self.closed_alerts.add(alert_id)

    def reopen_alert(self, alert_id: str) -> None:
        with self.closed_alerts_lock:
            self.closed_alerts.discard(alert_id)

    def blocklist_entries(self) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        for ip in sorted(list(self.blocklist.entries.keys())):
            remaining = self.blocklist.remaining_sec(ip)
            if remaining is None:
                continue
            entries.append({"ip": ip, "remaining_sec": remaining})
        return entries

    def set_product_enabled(self, enabled: bool) -> None:
        self.product_enabled = bool(enabled)

    def is_product_enabled(self) -> bool:
        return bool(self.product_enabled)


@dataclass
class DashboardServerHandle:
    app: FastAPI
    server: uvicorn.Server
    thread: threading.Thread


def _session_signature(secret: str, issued_at: int) -> str:
    payload = str(issued_at).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def _create_session_cookie(secret: str) -> str:
    issued_at = int(time.time())
    return f"{issued_at}.{_session_signature(secret, issued_at)}"


def _session_is_valid(secret: str, value: str | None) -> bool:
    if not value:
        return False
    try:
        issued_at_raw, signature = value.split(".", 1)
        issued_at = int(issued_at_raw)
    except (TypeError, ValueError):
        return False

    expected = _session_signature(secret, issued_at)
    if not hmac.compare_digest(signature, expected):
        return False
    return (time.time() - issued_at) <= SESSION_TTL_SEC


def _read_events(log_file_path: str, limit: int | None = None) -> list[PoCEvent]:
    path = Path(log_file_path)
    if not path.exists():
        return []

    events: list[PoCEvent] = []
    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
                events.append(PoCEvent.model_validate(payload))
            except Exception:
                continue

    events.sort(key=lambda event: event.timestamp, reverse=True)
    if limit is not None:
        return events[:limit]
    return events


def _serialize_events(events: list[PoCEvent]) -> list[dict[str, Any]]:
    return [event.model_dump(mode="json", exclude_none=False) for event in events]


_SEVERITY_RANK: dict[str, int] = {
    Severity.CRITICAL.value: 4,
    Severity.HIGH.value: 3,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 1,
}


def _alert_priority_key(event: PoCEvent) -> tuple[int, int]:
    sev = _SEVERITY_RANK.get(event.severity.value, 1)
    decision_rank = {"DENY": 2, "ALLOW": 1, "NONE": 0}
    dec = decision_rank.get(event.decision.value, 0)
    return (-sev, -dec)


_INTERMEDIATE_EVENT_TYPES = {"DETECTION_RULE_EVALUATED", "DETECTION_MODEL_EVALUATED", "REQUEST_RECEIVED", "REQUEST_FORWARDED", "RESPONSE_RETURNED"}

def _is_alert(event: PoCEvent) -> bool:
    if event.event_type.value in _INTERMEDIATE_EVENT_TYPES:
        return False
    return (
        event.level.value in ("WARN", "ERROR")
        or event.decision.value == "DENY"
        or event.event_type.value in ("ACTION_APPLIED", "ERROR")
        or event.severity.value in ("HIGH", "CRITICAL")
    )


def _build_overview(state: DashboardState) -> dict[str, Any]:
    events = _read_events(state.cfg.log_file_path)
    decision_counts = Counter(
        event.decision.value for event in events if event.decision.value not in ("NONE", "CHALLENGE")
    )
    tool_counts = Counter(event.tool_name or event.mcp_method for event in events)
    unique_trace_count = len({str(event.trace_id) for event in events})
    unique_client_count = len({event.client_ip for event in events})
    alert_events = [e for e in events if _is_alert(e)]
    alert_count = len(alert_events)
    open_high_alert_count = sum(
        1 for e in alert_events
        if e.severity.value in ("HIGH", "CRITICAL") and str(e.request_id) not in state.closed_alerts
    )
    security_score = max(0, 100 - 3 * open_high_alert_count)
    latest_event = events[0].model_dump(mode="json", exclude_none=False) if events else None

    # Track most common alert type by reason_code
    alert_reason_counts = Counter(e.reason_code for e in alert_events if e.reason_code)
    top_alert = alert_reason_counts.most_common(1)[0] if alert_reason_counts else None

    return {
        "generated_at": now_iso(),
        "proxy_url": state.proxy_url,
        "dashboard_port": state.cfg.dashboard_port,
        "total_events": len(events),
        "alert_count": alert_count,
        "open_high_alert_count": open_high_alert_count,
        "security_score": security_score,
        "unique_trace_count": unique_trace_count,
        "unique_client_count": unique_client_count,
        "blocklist_count": len(state.blocklist_entries()),
        "decision_counts": dict(decision_counts),
        "top_tools": [
            {"name": name, "count": count}
            for name, count in tool_counts.most_common(5)
        ],
        "top_alert": {"reason_code": top_alert[0], "count": top_alert[1]} if top_alert else None,
        "latest_event": latest_event,
    }


def _build_timeline(state: DashboardState, max_traces: int = 6) -> list[dict[str, Any]]:
    events = _read_events(state.cfg.log_file_path)

    by_trace: dict[str, list[PoCEvent]] = {}
    for event in events:
        tid = str(event.trace_id)
        by_trace.setdefault(tid, []).append(event)

    for trace_events in by_trace.values():
        trace_events.sort(key=lambda e: e.timestamp)

    recent_traces = sorted(
        by_trace.keys(),
        key=lambda tid: max(e.timestamp for e in by_trace[tid]),
        reverse=True,
    )[:max_traces]

    result: list[dict[str, Any]] = []
    for tid in recent_traces:
        trace_events = by_trace[tid]
        first = trace_events[0]
        final_decision = next(
            (e.decision.value for e in reversed(trace_events) if e.decision.value != "NONE"),
            "NONE",
        )
        max_severity = max(
            (_SEVERITY_RANK.get(e.severity.value, 1) for e in trace_events),
            default=1,
        )
        max_severity_label = next(k for k, v in _SEVERITY_RANK.items() if v == max_severity)
        result.append({
            "trace_id": tid,
            "tool_name": first.tool_name or first.mcp_method,
            "decision": final_decision,
            "max_severity": max_severity_label,
            "steps": _serialize_events(trace_events),
        })

    return result


def _tool_test_definitions() -> list[dict[str, Any]]:
    return [
        {
            "name": name,
            "description": config["description"],
            "allowed": config["allowed"],
            "disallowed": config["disallowed"],
        }
        for name, config in TOOL_TEST_CASES.items()
    ]


def _dashboard_test_ip() -> str:
    first = secrets.randbelow(200) + 20
    second = secrets.randbelow(254) + 1
    return f"10.250.{first}.{second}"


def _events_for_trace(log_file_path: str, trace_id: str | None) -> list[PoCEvent]:
    if not trace_id:
        return []
    events = [
        event
        for event in _read_events(log_file_path)
        if str(event.trace_id) == trace_id or str(event.request_id) == trace_id
    ]
    return sorted(events, key=lambda event: event.timestamp)


def _extract_decision_event(events: list[PoCEvent]) -> PoCEvent | None:
    for event in reversed(events):
        if event.event_type.value == "DECISION_MADE":
            return event
    return None


async def _run_tool_access_test(
    state: DashboardState,
    tool_name: str,
    scenario: str,
    arguments: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if tool_name not in TOOL_TEST_CASES:
        raise HTTPException(status_code=404, detail="Unknown test tool")
    if scenario not in ("allowed", "disallowed"):
        raise HTTPException(status_code=400, detail="Scenario must be allowed or disallowed")

    test_case = TOOL_TEST_CASES[tool_name][scenario]
    request_arguments = arguments if isinstance(arguments, dict) else test_case["arguments"]
    expected_decision = test_case["expected_decision"]
    client_id = f"dashboard-test-{tool_name.replace('.', '-')}-{scenario}-{uuid_suffix()}"
    request_body = {
        "jsonrpc": "2.0",
        "id": int(time.time() * 1000),
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": request_arguments,
        },
    }
    headers = {
        "Content-Type": "application/json",
        "X-Client-ID": client_id,
        "X-Session-Id": client_id,
        "X-Forwarded-For": _dashboard_test_ip(),
        "Authorization": f"Bearer dashboard-test-{secrets.token_hex(8)}",
    }

    response_status = 0
    response_payload: dict[str, Any]
    response_headers: dict[str, str] = {}
    started_at = now_iso()
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(state.proxy_url, json=request_body, headers=headers)
        response_status = response.status_code
        response_headers = {key.lower(): value for key, value in response.headers.items()}
        try:
            response_payload = response.json()
        except Exception:
            response_payload = {"raw": response.text}
    except httpx.RequestError as exc:
        response_payload = {
            "error": {
                "code": "REQUEST_ERROR",
                "message": f"{type(exc).__name__}: {exc}",
            }
        }

    trace_id = response_headers.get("x-trace-id") or response_headers.get("x-request-id")
    trace_events = _events_for_trace(state.cfg.log_file_path, trace_id)
    decision_event = _extract_decision_event(trace_events)
    actual_decision = (
        decision_event.decision.value
        if decision_event is not None
        else ("DENY" if response_status >= 400 else "ALLOW")
    )
    passed = actual_decision == expected_decision

    return {
        "tool_name": tool_name,
        "scenario": scenario,
        "title": test_case["title"],
        "summary": test_case["summary"],
        "expected_decision": expected_decision,
        "actual_decision": actual_decision,
        "passed": passed,
        "started_at": started_at,
        "completed_at": now_iso(),
        "proxy_url": state.proxy_url,
        "trace_id": trace_id,
        "http_status": response_status,
        "request": request_body,
        "response": response_payload,
        "decision_reason_code": decision_event.reason_code if decision_event else None,
        "decision_reason": decision_event.reason if decision_event else None,
        "events": _serialize_events(trace_events),
    }


def _login_page(error_message: str | None = None) -> str:
    error_html = f"<p class='error'>{error_message}</p>" if error_message else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MCProtector Admin Login</title>
  <style>
    :root {{
      color-scheme: light;
      --ink: #14213d;
      --accent: #e76f51;
      --panel: rgba(255, 255, 255, 0.92);
      --line: rgba(20, 33, 61, 0.14);
      --bg-a: #f7ede2;
      --bg-b: #dbeafe;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      font-family: "Segoe UI", Tahoma, sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(231, 111, 81, 0.22), transparent 32%),
        radial-gradient(circle at bottom right, rgba(59, 130, 246, 0.18), transparent 28%),
        linear-gradient(135deg, var(--bg-a), var(--bg-b));
      display: grid;
      place-items: center;
      padding: 24px;
    }}
    .card {{
      width: min(420px, 100%);
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 20px;
      padding: 32px;
      box-shadow: 0 24px 70px rgba(20, 33, 61, 0.16);
      backdrop-filter: blur(18px);
    }}
    h1 {{
      margin: 0 0 10px;
      font-size: 2rem;
    }}
    p {{
      margin: 0 0 20px;
      line-height: 1.5;
    }}
    label {{
      display: block;
      font-weight: 600;
      margin-bottom: 8px;
    }}
    input {{
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 14px 16px;
      font-size: 1rem;
      margin-bottom: 16px;
    }}
    button {{
      width: 100%;
      border: none;
      border-radius: 999px;
      background: var(--ink);
      color: white;
      padding: 14px 18px;
      font-size: 1rem;
      font-weight: 700;
      cursor: pointer;
    }}
    .hint {{
      margin-top: 16px;
      font-size: 0.92rem;
      color: rgba(20, 33, 61, 0.74);
    }}
    .error {{
      margin: 0 0 16px;
      padding: 12px 14px;
      border-radius: 12px;
      background: rgba(231, 111, 81, 0.14);
      color: #9f2d10;
      font-weight: 600;
    }}
  </style>
</head>
<body>
  <main class="card">
    <h1>MCProtector Dashboard</h1>
    <p>Enter the admin password to view proxy activity, alerts, and scenario controls.</p>
    {error_html}
    <form method="post" action="/login">
      <label for="password">Admin password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required>
      <button type="submit">Sign In</button>
    </form>
    <p class="hint">Default password: <code>admin123</code>. Override with <code>DASHBOARD_ADMIN_PASSWORD</code>.</p>
  </main>
</body>
</html>"""


def _dashboard_page(state: DashboardState) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MCProtector Dashboard</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f4f7fb;
      --bg-soft: #eef3fa;
      --panel: #ffffff;
      --panel-soft: #edf3fb;
      --line: #d9e2ee;
      --line-strong: #c7d4e6;
      --text: #182433;
      --muted: #627084;
      --blue: #2457ff;
      --blue-deep: #143eb7;
      --blue-soft: #e7efff;
      --green: #159f63;
      --green-soft: rgba(21, 159, 99, 0.14);
      --amber: #d08611;
      --amber-soft: rgba(208, 134, 17, 0.16);
      --red: #cf3b32;
      --red-soft: rgba(207, 59, 50, 0.14);
      --slate: #708198;
      --slate-soft: rgba(112, 129, 152, 0.14);
      --shadow: 0 18px 48px rgba(24, 36, 51, 0.08);
      --radius-xl: 28px;
      --radius-lg: 22px;
      --radius-md: 18px;
      --radius-sm: 14px;
      --sev-low: #6b7280;
      --sev-low-soft: rgba(107, 114, 128, 0.12);
      --sev-medium: #0369a1;
      --sev-medium-soft: rgba(3, 105, 161, 0.13);
      --sev-high: #d08611;
      --sev-high-soft: rgba(208, 134, 17, 0.16);
      --sev-critical: #cf3b32;
      --sev-critical-soft: rgba(207, 59, 50, 0.14);
      font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
    }}
    * {{ box-sizing: border-box; }}
    html {{ scroll-behavior: smooth; }}
    body {{
      margin: 0;
      color: var(--text);
      background:
        radial-gradient(circle at top left, rgba(36, 87, 255, 0.08), transparent 28%),
        radial-gradient(circle at bottom right, rgba(21, 159, 99, 0.08), transparent 24%),
        linear-gradient(180deg, #f9fbfe 0%, var(--bg) 100%);
    }}
    a {{ color: inherit; }}
    code {{
      font-family: "IBM Plex Mono", Consolas, monospace;
      font-size: 0.92em;
    }}
    .shell {{
      max-width: 1440px;
      margin: 0 auto;
      padding: 28px 20px 48px;
    }}
    .topbar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      margin-bottom: 20px;
    }}
    .brand {{
      display: flex;
      align-items: center;
      gap: 12px;
      font-weight: 700;
      letter-spacing: -0.03em;
    }}
    .brand-mark {{
      width: 44px;
      height: 44px;
      border-radius: 14px;
      background: linear-gradient(135deg, var(--blue), var(--blue-deep));
      box-shadow: 0 10px 26px rgba(36, 87, 255, 0.24);
      position: relative;
      flex-shrink: 0;
    }}
    .brand-mark::before,
    .brand-mark::after {{
      content: "";
      position: absolute;
      border: 2px solid rgba(255, 255, 255, 0.82);
      border-radius: 8px;
    }}
    .brand-mark::before {{ inset: 10px; }}
    .brand-mark::after {{
      inset: 15px;
      border-radius: 4px;
    }}
    .brand-copy small {{
      display: block;
      color: var(--muted);
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      margin-bottom: 2px;
    }}
    .actions {{
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }}
    .actions form {{
      margin: 0;
    }}
    .btn {{
      border: 1px solid var(--line);
      background: var(--panel);
      color: var(--text);
      border-radius: 999px;
      padding: 10px 16px;
      font-weight: 700;
      text-decoration: none;
      cursor: pointer;
      box-shadow: 0 8px 24px rgba(24, 36, 51, 0.05);
      transition: transform 140ms ease, box-shadow 140ms ease;
    }}
    .btn:hover {{
      transform: translateY(-1px);
      box-shadow: 0 12px 28px rgba(24, 36, 51, 0.08);
    }}
    .btn-primary {{
      background: var(--blue);
      color: #fff;
      border-color: transparent;
    }}
    .hero {{
      background: var(--panel);
      border: 1px solid rgba(255, 255, 255, 0.64);
      box-shadow: var(--shadow);
      border-radius: var(--radius-xl);
      padding: 28px;
      display: grid;
      grid-template-columns: 1.65fr 1fr;
      gap: 28px;
      margin-bottom: 18px;
    }}
    .eyebrow,
    .meta-label,
    .metric-label,
    .section-copy,
    .card-note,
    .list-meta,
    .table-caption,
    .footer {{
      font-size: 12px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--muted);
      font-weight: 700;
    }}
    .hero-copy h1 {{
      margin: 0;
      font-size: 34px;
      line-height: 1.05;
      letter-spacing: -0.04em;
      max-width: 15ch;
    }}
    .hero-copy p {{
      margin: 14px 0 0;
      color: var(--muted);
      max-width: 72ch;
      line-height: 1.6;
    }}
    .hero-meta {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
      margin-top: 24px;
    }}
    .meta-card,
    .metric-card,
    .surface-card,
    .table-card,
    .detail-card,
    .list-card,
    .scenario-card {{
      background: var(--panel);
      border: 1px solid rgba(24, 36, 51, 0.06);
      box-shadow: var(--shadow);
    }}
    .meta-card {{
      border-radius: var(--radius-md);
      padding: 16px;
      background: var(--panel-soft);
      box-shadow: none;
      border-color: transparent;
    }}
    .meta-value {{
      margin-top: 8px;
      font-size: 16px;
      font-weight: 700;
      word-break: break-word;
    }}
    .score-panel {{
      border-radius: 24px;
      padding: 24px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      background: linear-gradient(180deg, #f7faff 0%, #fff 100%);
      border: 1px solid rgba(24, 36, 51, 0.06);
      box-shadow: var(--shadow);
    }}
    .score-wrap {{
      display: flex;
      align-items: center;
      gap: 20px;
    }}
    .score-stack {{
      position: relative;
      display: grid;
      place-items: center;
      flex-shrink: 0;
    }}
    .score-ring {{
      --score: 0;
      --ring-color: var(--green);
      width: 148px;
      height: 148px;
      border-radius: 50%;
      background: conic-gradient(var(--ring-color) calc(var(--score) * 1%), #e6ebf4 0);
      display: grid;
      place-items: center;
    }}
    .score-ring::before {{
      content: "";
      width: 110px;
      height: 110px;
      border-radius: 50%;
      background: #fff;
      box-shadow: inset 0 0 0 1px rgba(24, 36, 51, 0.06);
      display: block;
    }}
    .score-ring.good {{ --ring-color: var(--green); }}
    .score-ring.moderate {{ --ring-color: var(--amber); }}
    .score-ring.high {{ --ring-color: var(--red); }}
    .score-ring.neutral {{ --ring-color: var(--slate); }}
    .score-center {{
      position: absolute;
      text-align: center;
      width: 86px;
    }}
    .score-overline {{
      font-size: 11px;
      color: var(--muted);
      font-weight: 800;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      margin-bottom: 2px;
    }}
    .score-number {{
      font-size: 34px;
      font-weight: 800;
      letter-spacing: -0.05em;
      line-height: 1;
    }}
    .score-max {{
      font-size: 14px;
      color: var(--muted);
      font-weight: 700;
    }}
    .score-text h2 {{
      margin: 0;
      font-size: 30px;
      letter-spacing: -0.04em;
    }}
    .score-text p {{
      margin: 10px 0 0;
      color: var(--muted);
      line-height: 1.6;
    }}
    .pill-nav {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      align-items: center;
      margin-bottom: 20px;
      position: sticky;
      top: 0;
      padding: 10px 0;
      z-index: 5;
      background: linear-gradient(180deg, rgba(244, 247, 251, 0.98), rgba(244, 247, 251, 0.78));
      backdrop-filter: blur(10px);
    }}
    .pill-nav a,
    .live-chip {{
      text-decoration: none;
      padding: 10px 14px;
      border-radius: 999px;
      background: #fff;
      border: 1px solid var(--line);
      color: var(--muted);
      font-weight: 700;
      font-size: 13px;
      box-shadow: 0 8px 20px rgba(24, 36, 51, 0.04);
    }}
    .live-chip {{
      margin-left: auto;
      color: var(--text);
    }}
    .stack {{
      display: grid;
      gap: 18px;
    }}
    .section {{
      border-radius: 24px;
      padding: 24px;
      background: var(--panel);
      border: 1px solid rgba(24, 36, 51, 0.06);
      box-shadow: var(--shadow);
    }}
    .section-head {{
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: flex-start;
      margin-bottom: 18px;
    }}
    .section-head h2 {{
      margin: 4px 0 0;
      font-size: 24px;
      letter-spacing: -0.03em;
    }}
    .section-copy-block {{
      color: var(--muted);
      max-width: 78ch;
      line-height: 1.6;
    }}
    .grid-4,
    .grid-3,
    .grid-2 {{
      display: grid;
      gap: 14px;
    }}
    .grid-4 {{ grid-template-columns: repeat(4, minmax(0, 1fr)); }}
    .grid-3 {{ grid-template-columns: repeat(3, minmax(0, 1fr)); }}
    .grid-2 {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
    .metric-card,
    .surface-card,
    .table-card,
    .detail-card,
    .list-card,
    .scenario-card {{
      border-radius: 20px;
      padding: 18px;
    }}
    .metric-value {{
      margin-top: 10px;
      font-size: 30px;
      font-weight: 800;
      letter-spacing: -0.05em;
      line-height: 1;
    }}
    .metric-note {{
      margin-top: 12px;
      color: var(--muted);
      line-height: 1.55;
      font-size: 14px;
    }}
    .metric-card.alert {{
      background: linear-gradient(180deg, rgba(207, 59, 50, 0.06), rgba(255, 255, 255, 0.96));
    }}
    .metric-card.allow {{
      background: linear-gradient(180deg, rgba(21, 159, 99, 0.08), rgba(255, 255, 255, 0.96));
    }}
    .metric-card.challenge {{
      background: linear-gradient(180deg, rgba(208, 134, 17, 0.08), rgba(255, 255, 255, 0.96));
    }}
    .summary-list,
    .list-stack,
    .scenario-list,
    .table-stack,
    .detail-stack {{
      display: grid;
      gap: 12px;
    }}
    .summary-item,
    .tool-row,
    .block-row,
    .detail-row,
    .scenario-step {{
      padding: 14px 16px;
      border-radius: 16px;
      background: var(--panel-soft);
    }}
    .summary-item {{
      display: flex;
      gap: 12px;
      align-items: flex-start;
    }}
    .summary-index {{
      width: 28px;
      height: 28px;
      border-radius: 50%;
      display: grid;
      place-items: center;
      background: var(--blue);
      color: #fff;
      font-weight: 800;
      font-size: 12px;
      flex-shrink: 0;
    }}
    .surface-card h3,
    .table-card h3,
    .detail-card h3,
    .list-card h3,
    .scenario-card h3 {{
      margin: 8px 0 12px;
      font-size: 18px;
      letter-spacing: -0.02em;
    }}
    .pill {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      border-radius: 999px;
      padding: 7px 12px;
      font-size: 12px;
      font-weight: 800;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      border: 1px solid transparent;
      white-space: nowrap;
    }}
    .pill.allow {{
      background: var(--green-soft);
      color: #11784c;
    }}
    .pill.deny,
    .pill.high {{
      background: var(--red-soft);
      color: var(--red);
    }}
    .pill.challenge,
    .pill.moderate {{
      background: var(--amber-soft);
      color: #9b6400;
    }}
    .pill.neutral {{
      background: var(--slate-soft);
      color: #516074;
    }}
    .pill.sev-low,
    .pill.sev-medium,
    .pill.sev-high,
    .pill.sev-critical {{
      font-size: 0.72rem;
      letter-spacing: 0;
      padding: 3px 8px;
      white-space: nowrap;
    }}
    .pill.sev-low {{ background: var(--sev-low-soft); color: var(--sev-low); }}
    .pill.sev-medium {{ background: var(--sev-medium-soft); color: var(--sev-medium); }}
    .pill.sev-high {{ background: var(--sev-high-soft); color: var(--sev-high); }}
    .pill.sev-critical {{ background: var(--sev-critical-soft); color: var(--sev-critical); }}
    .alert-filters {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 14px;
      align-items: center;
    }}
    .filter-group {{
      display: flex;
      align-items: center;
      gap: 6px;
    }}
    .filter-group label {{
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.07em;
      text-transform: uppercase;
      color: var(--muted);
      white-space: nowrap;
    }}
    .filter-select {{
      border: 1px solid var(--line);
      background: var(--panel-soft);
      color: var(--text);
      border-radius: 8px;
      padding: 6px 28px 6px 10px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      appearance: none;
      -webkit-appearance: none;
      background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%236b7280' d='M6 8L1 3h10z'/%3E%3C/svg%3E");
      background-repeat: no-repeat;
      background-position: right 9px center;
      min-width: 130px;
    }}
    .filter-select:focus {{
      outline: none;
      border-color: var(--blue);
    }}
    #alerts td:first-child,
    #events td:first-child {{
      padding-right: 16px;
    }}
    #alerts td:nth-child(2),
    #events td:nth-child(2) {{
      font-size: 0.82rem;
      color: var(--muted);
    }}
    .tl-list {{
      display: grid;
      gap: 14px;
    }}
    .tl-trace {{
      border: 1px solid var(--line);
      border-radius: var(--radius-md);
      padding: 16px;
      background: var(--panel-soft);
    }}
    .tl-header {{
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
      margin-bottom: 14px;
    }}
    .tl-steps {{
      display: flex;
      flex-wrap: wrap;
      gap: 0;
      align-items: flex-start;
    }}
    .tl-step {{
      display: flex;
      flex-direction: column;
      align-items: center;
      flex: 1 1 100px;
      max-width: 160px;
      min-width: 0;
      position: relative;
    }}
    .tl-step::after {{
      content: "";
      position: absolute;
      top: 15px;
      left: calc(50% + 16px);
      right: calc(-50% + 16px);
      height: 2px;
      background: var(--line);
      z-index: 0;
    }}
    .tl-step:last-child::after {{ display: none; }}
    .tl-dot {{
      width: 30px;
      height: 30px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 0.68rem;
      font-weight: 800;
      border: 2px solid white;
      box-shadow: 0 2px 6px rgba(24, 36, 51, 0.12);
      z-index: 1;
      flex-shrink: 0;
    }}
    .tl-dot.sev-low {{ background: var(--sev-low-soft); color: var(--sev-low); border-color: var(--sev-low); }}
    .tl-dot.sev-medium {{ background: var(--sev-medium-soft); color: var(--sev-medium); border-color: var(--sev-medium); }}
    .tl-dot.sev-high {{ background: var(--sev-high-soft); color: var(--sev-high); border-color: var(--sev-high); }}
    .tl-dot.sev-critical {{ background: var(--sev-critical-soft); color: var(--sev-critical); border-color: var(--sev-critical); }}
    .tl-label {{
      margin-top: 6px;
      font-size: 0.7rem;
      text-align: center;
      color: var(--muted);
      line-height: 1.3;
      word-break: break-word;
      padding: 0 4px;
      max-width: 100%;
    }}
    .severity-bars {{
      display: grid;
      gap: 12px;
    }}
    .severity-row {{
      display: grid;
      grid-template-columns: 110px 1fr 48px;
      gap: 14px;
      align-items: center;
    }}
    .severity-rail {{
      height: 10px;
      border-radius: 999px;
      background: #e9eef7;
      overflow: hidden;
    }}
    .severity-fill {{
      height: 100%;
      border-radius: inherit;
    }}
    .severity-fill.allow {{
      background: var(--green);
    }}
    .severity-fill.deny {{
      background: var(--red);
    }}
    .severity-fill.challenge {{
      background: var(--amber);
    }}
    .severity-fill.neutral {{
      background: var(--slate);
    }}
    .list-line {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
      padding: 10px 0;
      border-bottom: 1px solid var(--line);
    }}
    .list-line:last-child {{
      border-bottom: none;
    }}
    .list-line strong {{
      font-size: 14px;
    }}
    .list-line span {{
      color: var(--muted);
      font-size: 14px;
      word-break: break-word;
    }}
    .mini-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
      margin: 14px 0;
    }}
    .mini-card {{
      padding: 12px 14px;
      border-radius: 14px;
      background: var(--panel-soft);
    }}
    .mini-card span {{
      display: block;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }}
    .mini-card strong {{
      display: block;
      margin-top: 8px;
      font-size: 20px;
      letter-spacing: -0.03em;
      word-break: break-word;
    }}
    .toolbar {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-bottom: 16px;
    }}
    .toolbar .btn {{
      box-shadow: none;
    }}
    .tool-row-head,
    .scenario-head,
    .detail-row {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: flex-start;
    }}
    .tool-title,
    .block-title,
    .scenario-title {{
      font-weight: 700;
    }}
    .tool-desc,
    .block-desc,
    .scenario-desc,
    .detail-copy {{
      margin-top: 6px;
      color: var(--muted);
      line-height: 1.55;
      word-break: break-word;
    }}
    .bar-track {{
      margin-top: 10px;
      height: 8px;
      border-radius: 999px;
      background: #e9eef7;
      overflow: hidden;
    }}
    .bar-fill {{
      height: 100%;
      border-radius: inherit;
      background: linear-gradient(90deg, var(--blue), var(--blue-deep));
    }}
    .scenario-list {{
      max-height: 420px;
      overflow: auto;
      padding-right: 4px;
    }}
    .scenario-step {{
      padding: 10px 12px;
    }}
    .scenario-steps {{
      display: grid;
      gap: 10px;
      margin-top: 12px;
    }}
    .table-card {{
      min-width: 0;
    }}
    .table-wrap {{
      overflow: auto;
      border-radius: 18px;
      border: 1px solid rgba(24, 36, 51, 0.08);
      background: rgba(255, 255, 255, 0.78);
      max-height: 480px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.94rem;
      table-layout: fixed;
    }}
    th,
    td {{
      padding: 12px 10px;
      text-align: left;
      border-bottom: 1px solid rgba(24, 36, 51, 0.08);
      vertical-align: top;
      word-break: break-word;
      overflow-wrap: anywhere;
    }}
    th {{
      position: sticky;
      top: 0;
      z-index: 1;
      background: rgba(248, 251, 255, 0.98);
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
    }}
    .table-cell-title {{
      font-weight: 700;
    }}
    .table-cell-copy {{
      margin-top: 4px;
      color: var(--muted);
      line-height: 1.5;
      font-size: 13px;
    }}
    .trace {{
      display: inline-block;
      max-width: 240px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      vertical-align: bottom;
    }}
    .empty-state {{
      padding: 18px;
      border-radius: 16px;
      background: var(--panel-soft);
      color: var(--muted);
    }}
    .footer {{
      margin-top: 22px;
      text-align: center;
    }}
    @media (max-width: 1100px) {{
      .hero,
      .grid-4,
      .grid-3,
      .grid-2 {{
        grid-template-columns: 1fr;
      }}
      .live-chip {{
        margin-left: 0;
      }}
    }}
    @media (max-width: 720px) {{
      .shell {{
        padding: 20px 14px 36px;
      }}
      .topbar,
      .section-head,
      .score-wrap,
      .scenario-head,
      .tool-row-head,
      .detail-row {{
        flex-direction: column;
        align-items: flex-start;
      }}
      .hero-copy h1 {{
        font-size: 28px;
      }}
      .score-ring {{
        width: 128px;
        height: 128px;
      }}
      .score-ring::before {{
        width: 96px;
        height: 96px;
      }}
      .hero-meta,
      .mini-grid {{
        grid-template-columns: 1fr;
      }}
      .severity-row {{
        grid-template-columns: 90px 1fr 40px;
      }}
      .trace {{
        max-width: 180px;
      }}
    }}
  </style>
</head>
<body>
  <div class="shell">
    <header class="topbar">
      <div class="brand">
        <div class="brand-mark" aria-hidden="true"></div>
        <div class="brand-copy">
          <small>Security Platform</small>
          <div>MCProtector Dashboard</div>
        </div>
      </div>
      <div class="actions">
        <button class="btn btn-primary" type="button" onclick="refreshDashboard()">Refresh</button>
        <a class="btn" href="/tests">Tests</a>
        <a class="btn" href="#events-section">Event Log</a>
        <form method="post" action="/logout">
          <button class="btn" type="submit">Log Out</button>
        </form>
      </div>
    </header>

    <section class="hero">
      <div class="hero-copy">
        <div class="eyebrow">Live Proxy Dashboard</div>
        <h1>Readable protection telemetry for the MCProtector proxy.</h1>
        <p>Track decisions, alert pressure, scenario runs, and recent request activity on <code>{state.proxy_url}</code> through a cleaner dashboard that keeps the most important signals easy to spot.</p>
        <div class="hero-meta" id="hero-meta"></div>
      </div>
      <aside class="score-panel">
        <div class="eyebrow">Live posture</div>
        <div class="score-wrap">
          <div class="score-stack">
            <div class="score-ring neutral" id="score-ring" style="--score: 100;">
              <div class="score-center">
                <div class="score-overline">Score</div>
                <div class="score-number" id="score-value">100</div>
                <div class="score-max">/ 100</div>
              </div>
            </div>
          </div>
          <div class="score-text">
            <h2 id="score-label">Waiting for traffic</h2>
            <p><strong>Alert pressure:</strong> <span id="score-copy">No proxy events yet.</span></p>
            <p id="score-summary">Once traffic arrives, this panel will summarize how noisy or calm the current activity looks.</p>
          </div>
        </div>
      </aside>
    </section>

    <nav class="pill-nav">
      <a href="#summary">Executive Summary</a>
      <a href="#operations">Operations</a>
      <a href="#alerts-section">Alerts</a>
      <a href="#events-section">Recent Events</a>
      <div class="live-chip" id="status">Loading live data...</div>
    </nav>

    <div class="stack">
      <section class="section" id="summary">
        <div class="section-head">
          <div>
            <div class="eyebrow">Executive Summary</div>
            <h2>Fast read of current proxy activity</h2>
          </div>
          <span class="pill neutral" id="summary-badge">Waiting for traffic</span>
        </div>
        <div class="section-copy-block">This view keeps the main numbers, current decision mix, and a short human-readable summary above the more detailed operational data.</div>
        <div class="grid-4" style="margin-top: 18px;" id="summary-metrics"></div>
        <div class="grid-2" style="margin-top: 18px;">
          <article class="surface-card">
            <div class="eyebrow">Key Takeaways</div>
            <h3>What matters most right now</h3>
            <div class="summary-list" id="summary-bullets"></div>
          </article>
          <article class="surface-card">
            <div class="eyebrow">Decision Breakdown</div>
            <h3>Current request outcomes</h3>
            <div class="severity-bars" id="decision-breakdown"></div>
          </article>
        </div>
      </section>

      <section class="section" id="operations">
        <div class="section-head">
          <div>
            <div class="eyebrow">Operations</div>
            <h2>Scenarios, tool traffic, and active controls</h2>
          </div>
        </div>
        <div class="grid-3">
          <article class="surface-card">
            <div class="eyebrow">Scenario Launcher</div>
            <h3>Generate known-good or blocked traffic</h3>
            <div class="toolbar">
              <button class="btn btn-primary" type="button" onclick="runScenario('allowed')">Run Allowed</button>
              <button class="btn" type="button" onclick="runScenario('denied')">Run Denied</button>
            </div>
            <div class="mini-grid" id="system-overview"></div>
            <div class="card-note">These built-in checks send sample traffic through the proxy so you can validate both normal flow and enforcement behavior.</div>
          </article>

          <article class="scenario-card">
            <div class="eyebrow">Recent Test Runs</div>
            <h3>Latest scenario history</h3>
            <div class="scenario-list" id="scenarios"></div>
          </article>

          <article class="list-card">
            <div class="eyebrow">Traffic Focus</div>
            <h3>Most-used tools and blocklist status</h3>
            <div class="table-stack">
              <div>
                <div class="table-caption">Top tools</div>
                <div class="list-stack" id="top-tools"></div>
              </div>
              <div>
                <div class="table-caption">Blocklist</div>
                <div class="list-stack" id="blocklist"></div>
              </div>
            </div>
          </article>
        </div>
      </section>

      <section class="section" id="alerts-section">
        <div class="section-head">
          <div>
            <div class="eyebrow">Alerts</div>
            <h2>Recent warnings, blocks, and mitigation activity</h2>
          </div>
        </div>
        <article class="table-card">
          <div class="eyebrow">Alert Stream</div>
          <div class="alert-filters">
            <div class="filter-group">
              <label for="filter-time">Time</label>
              <select id="filter-time" class="filter-select" onchange="setAlertFilter('time', this.value)">
                <option value="all">All time</option>
                <option value="1h">Last 1 hour</option>
                <option value="6h">Last 6 hours</option>
                <option value="24h">Last 24 hours</option>
              </select>
            </div>
            <div class="filter-group">
              <label for="filter-severity">Severity</label>
              <select id="filter-severity" class="filter-select" onchange="setAlertFilter('severity', this.value)">
                <option value="all">All severities</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>
            <div class="filter-group">
              <label for="filter-status">Status</label>
              <select id="filter-status" class="filter-select" onchange="setAlertFilter('status', this.value)">
                <option value="all">All</option>
                <option value="open">Open</option>
                <option value="closed">Closed</option>
              </select>
            </div>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th style="width: 11%; white-space: nowrap;">Severity</th>
                  <th style="width: 13%;">Time</th>
                  <th style="width: 19%;">Alert Title</th>
                  <th style="width: 10%;">Decision</th>
                  <th style="width: 25%;">Summary</th>
                  <th style="width: 10%;">Status</th>
                  <th style="width: 12%;"></th>
                </tr>
              </thead>
              <tbody id="alerts"></tbody>
            </table>
          </div>
        </article>
      </section>

      <section class="section" id="events-section">
        <div class="section-head">
          <div>
            <div class="eyebrow">Recent Events</div>
            <h2>Full event stream from the proxy log</h2>
          </div>
        </div>
        <div class="table-card" style="padding: 0; border: none; box-shadow: none; background: transparent;">
          <div class="table-wrap" style="max-height: 560px;">
            <table>
              <thead>
                <tr>
                  <th style="width: 10%;">Severity</th>
                  <th style="width: 14%;">Time</th>
                  <th style="width: 16%;">Event</th>
                  <th style="width: 16%;">Trace</th>
                  <th style="width: 12%;">Decision</th>
                  <th style="width: 12%;">Tool</th>
                  <th style="width: 20%;">Reason</th>
                </tr>
              </thead>
              <tbody id="events"></tbody>
            </table>
          </div>
        </div>
      </section>
    </div>

    <div id="trace-modal" style="display:none;position:fixed;inset:0;z-index:9999;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.45);">
      <div id="trace-modal-content" style="max-width:1000px;width:min(96%,1000px);background:var(--panel);border-radius:12px;padding:18px;overflow:auto;max-height:80vh;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
          <h3 style="margin:0;">Request Lifecycle</h3>
          <button class="btn" onclick="hideTrace()">Close</button>
        </div>
        <div id="trace-modal-body"></div>
      </div>
    </div>

    <div class="footer">Generated by MCProtector • Consolidated live proxy dashboard</div>
  </div>

  <script>
    function escapeHtml(value) {{
      return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
    }}

    function formatTimestamp(value) {{
      if (!value) {{
        return "No data";
      }}
      const parsed = new Date(value);
      if (Number.isNaN(parsed.getTime())) {{
        return String(value);
      }}
      return parsed.toLocaleString();
    }}

    function humanizeConstant(value) {{
      return String(value || "Unknown")
        .toLowerCase()
        .split("_")
        .map((part) => part ? part[0].toUpperCase() + part.slice(1) : "")
        .join(" ");
    }}

    function percentage(part, total) {{
      if (!total) {{
        return 0;
      }}
      return Math.round((part / total) * 100);
    }}

    function decisionClass(decision) {{
      const lower = String(decision || "NONE").toLowerCase();
      if (lower === "allow") {{
        return "allow";
      }}
      if (lower === "deny") {{
        return "deny";
      }}
      if (lower === "challenge") {{
        return "challenge";
      }}
      return "neutral";
    }}

    function decisionPill(decision, label) {{
      const text = label || decision || "None";
      return `<span class="pill ${{decisionClass(decision)}}">${{escapeHtml(text)}}</span>`;
    }}

    function severityBadge(sev) {{
      const s = String(sev || "LOW").toUpperCase();
      const css = s === "CRITICAL" ? "sev-critical" : s === "HIGH" ? "sev-high" : s === "MEDIUM" ? "sev-medium" : "sev-low";
      return `<span class="pill ${{css}}">${{escapeHtml(s)}}</span>`;
    }}

    const TL_ABBREV = {{
      REQUEST_RECEIVED: "RCV",
      DETECTION_RULE_EVALUATED: "RULE",
      DETECTION_MODEL_EVALUATED: "RISK",
      DECISION_MADE: "DEC",
      ACTION_APPLIED: "ACT",
      REQUEST_FORWARDED: "FWD",
      RESPONSE_RETURNED: "RSP",
      ERROR: "ERR",
    }};

    function metricCard(label, value, note, cssClass) {{
      return `
        <article class="metric-card ${{cssClass || ""}}">
          <div class="metric-label">${{escapeHtml(label)}}</div>
          <div class="metric-value">${{escapeHtml(value)}}</div>
          <div class="metric-note">${{escapeHtml(note)}}</div>
        </article>
      `;
    }}

    function emptyState(message) {{
      return `<div class="empty-state">${{escapeHtml(message)}}</div>`;
    }}

    function buildPosture(data) {{
      const score = data.security_score ?? 100;
      const openHigh = data.open_high_alert_count || 0;
      const alertCount = data.alert_count || 0;
      if (!data.total_events) {{
        return {{
          label: "Waiting for traffic",
          tone: "neutral",
          value: 100,
          summary: "No alerts yet — score starts at 100.",
          detail: "Each unclosed high-severity alert deducts 3 points. The score floors at 0.",
        }};
      }}
      if (score >= 85) {{
        return {{
          label: "Secure",
          tone: "good",
          value: score,
          summary: `${{openHigh}} open high-severity alert${{openHigh === 1 ? "" : "s"}} — score ${{score}}/100.`,
          detail: "No significant threats outstanding. Close alerts as you review them to keep the score current.",
        }};
      }}
      if (score >= 60) {{
        return {{
          label: "At Risk",
          tone: "moderate",
          value: score,
          summary: `${{openHigh}} open high-severity alert${{openHigh === 1 ? "" : "s"}} — score ${{score}}/100.`,
          detail: "Multiple unresolved high-severity alerts are dragging the score down. Review and close alerts you have handled.",
        }};
      }}
      return {{
        label: "Under Attack",
        tone: "high",
        value: score,
        summary: `${{openHigh}} open high-severity alert${{openHigh === 1 ? "" : "s"}} — score ${{score}}/100.`,
        detail: `${{alertCount}} total alerts, ${{openHigh}} unclosed high-severity (${{openHigh}} × −3 pts). Close resolved alerts to recover the score.`,
      }};
    }}

    async function api(path, options) {{
      const response = await fetch(path, Object.assign({{ credentials: "same-origin" }}, options || {{}}));
      if (response.status === 401) {{
        window.location = "/login";
        return null;
      }}
      if (!response.ok) {{
        const error = await response.json().catch(() => ({{}}));
        throw new Error(error.detail || `Request failed with status ${{response.status}}.`);
      }}
      return response.json();
    }}

    function renderHeroMeta(data) {{
      const latest = data.latest_event || null;
      document.getElementById("hero-meta").innerHTML = [
        {{
          label: "Proxy endpoint",
          value: data.proxy_url || "Unknown",
        }},
        {{
          label: "Dashboard port",
          value: data.dashboard_port || "Unknown",
        }},
        {{
          label: "Unique clients",
          value: data.unique_client_count || 0,
        }},
        {{
          label: "Latest event",
          value: latest ? `${{humanizeConstant(latest.event_type)}} • ${{formatTimestamp(latest.timestamp)}}` : "No events yet",
        }},
      ].map((item) => `
        <div class="meta-card">
          <div class="meta-label">${{escapeHtml(item.label)}}</div>
          <div class="meta-value">${{escapeHtml(item.value)}}</div>
        </div>
      `).join("");
    }}

    function renderScorePanel(data) {{
      const posture = buildPosture(data);
      const ring = document.getElementById("score-ring");
      ring.className = `score-ring ${{posture.tone}}`;
      ring.style.setProperty("--score", String(posture.value));
      document.getElementById("score-value").textContent = posture.value;
      document.getElementById("score-label").textContent = posture.label;
      document.getElementById("score-copy").textContent = posture.summary;
      document.getElementById("score-summary").textContent = posture.detail;
      document.getElementById("summary-badge").className = `pill ${{posture.tone}}`;
      document.getElementById("summary-badge").textContent = posture.label;
    }}

    function renderSummaryMetrics(data) {{
      const decisions = data.decision_counts || {{}};
      document.getElementById("summary-metrics").innerHTML = [
        metricCard("Total alerts", data.alert_count || 0, "Warnings, errors, denies, and mitigation actions.", "alert"),
        metricCard("Open high alerts", data.open_high_alert_count || 0, "Unclosed high-severity alerts — each deducts 3 points from the score.", "alert"),
        metricCard("Allowed requests", decisions.ALLOW || 0, "Traffic that passed through to the upstream server.", "allow"),
        metricCard("Blocked sources", data.blocklist_count || 0, "IPs that are currently on the in-memory blocklist.", "deny"),
      ].join("");
    }}

    function renderSummaryBullets(data, scenarios, blocklist) {{
      const decisions = data.decision_counts || {{}};
      const decisionTotal = (decisions.ALLOW || 0) + (decisions.DENY || 0);
      const topTool = (data.top_tools || [])[0];
      const latestRun = (scenarios.runs || [])[0];
      const bullets = [];

      if (!data.total_events) {{
        bullets.push("No proxy traffic has been captured yet, so the dashboard is currently waiting for live events.");
      }} else {{
        bullets.push(`${{data.total_events}} events have been recorded, with ${{data.alert_count || 0}} currently counted as alerts.`);
      }}

      const topAlert = data.top_alert;
      if (topAlert) {{
        bullets.push(`The most common alert is "${{topAlert.reason_code}}" with ${{topAlert.count}} occurrence${{topAlert.count === 1 ? "" : "s"}}.`);
      }} else {{
        bullets.push("No alerts have been triggered yet.");
      }}

      if (topTool) {{
        bullets.push(`The busiest tool right now is "${{topTool.name}}" with ${{topTool.count}} observed events.`);
      }} else {{
        bullets.push("No tool stands out yet because the proxy has not seen enough traffic.");
      }}

      if ((blocklist.entries || []).length) {{
        bullets.push(`${{blocklist.entries.length}} IP${{blocklist.entries.length === 1 ? "" : "s"}} are actively blocked at the moment.`);
      }} else {{
        bullets.push("The active blocklist is currently empty.");
      }}

      if (latestRun) {{
        bullets.push(`The latest scenario run was "${{latestRun.title || latestRun.name}}" and it ${{latestRun.passed ? "completed as expected" : "returned unexpected results"}}.`);
      }}

      document.getElementById("summary-bullets").innerHTML = bullets.slice(0, 5).map((bullet, index) => `
        <div class="summary-item">
          <div class="summary-index">${{index + 1}}</div>
          <div>${{escapeHtml(bullet)}}</div>
        </div>
      `).join("");
    }}

    function renderDecisionBreakdown(data) {{
      const decisions = data.decision_counts || {{}};
      const rows = [
        {{ label: "Allowed", key: "ALLOW", css: "allow" }},
        {{ label: "Denied", key: "DENY", css: "deny" }},
      ];
      const total = rows.reduce((sum, row) => sum + (decisions[row.key] || 0), 0);
      document.getElementById("decision-breakdown").innerHTML = rows.map((row) => {{
        const value = decisions[row.key] || 0;
        const width = total ? Math.max((value / total) * 100, value ? 6 : 0) : 0;
        return `
          <div class="severity-row">
            <div class="table-cell-title">${{escapeHtml(row.label)}}</div>
            <div class="severity-rail">
              <div class="severity-fill ${{row.css}}" style="width: ${{width}}%;"></div>
            </div>
            <strong>${{value}}</strong>
          </div>
        `;
      }}).join("") || emptyState("No decision data yet.");
    }}

    function renderSystemOverview(data) {{
      const latest = data.latest_event || null;
      document.getElementById("system-overview").innerHTML = [
        {{
          label: "Dashboard port",
          value: data.dashboard_port || "Unknown",
        }},
        {{
          label: "Unique traces",
          value: data.unique_trace_count || 0,
        }},
        {{
          label: "Unique clients",
          value: data.unique_client_count || 0,
        }},
        {{
          label: "Latest event",
          value: latest ? humanizeConstant(latest.event_type) : "None yet",
        }},
      ].map((item) => `
        <div class="mini-card">
          <span>${{escapeHtml(item.label)}}</span>
          <strong>${{escapeHtml(item.value)}}</strong>
        </div>
      `).join("");
    }}

    function renderScenarios(rows) {{
      const target = document.getElementById("scenarios");
      if (!rows.length) {{
        target.innerHTML = emptyState("Run a scenario to generate sample traffic through the proxy.");
        return;
      }}
      target.innerHTML = rows.map((run) => `
        <div class="scenario-card" style="padding: 0; box-shadow: none; border-color: var(--line);">
          <div style="padding: 16px;">
            <div class="scenario-head">
              <div>
                <div class="scenario-title">${{escapeHtml(run.title || run.name)}}</div>
                <div class="scenario-desc">${{escapeHtml(run.description || "Scenario activity routed through the proxy.")}}</div>
              </div>
              ${{decisionPill(run.passed ? "ALLOW" : "DENY", run.passed ? "Passed" : "Needs review")}}
            </div>
            <div class="list-meta" style="margin-top: 10px;">Completed ${{escapeHtml(formatTimestamp(run.completed_at))}}</div>
            <div class="scenario-steps">
              ${{(run.steps || []).map((step) => `
                <div class="scenario-step">
                  <div class="tool-row-head">
                    <div class="tool-title">${{escapeHtml(step.title)}}</div>
                    ${{decisionPill(step.passed ? "ALLOW" : "DENY", step.passed ? "Pass" : "Fail")}}
                  </div>
                  <div class="tool-desc">${{escapeHtml(step.detail)}}</div>
                  <div class="list-meta" style="margin-top: 8px;">Expected ${{escapeHtml(step.expected_outcome)}}, got ${{escapeHtml(step.actual_outcome)}}</div>
                </div>
              `).join("")}}
            </div>
          </div>
        </div>
      `).join("");
    }}

    function renderTopTools(tools) {{
      const target = document.getElementById("top-tools");
      if (!tools.length) {{
        target.innerHTML = emptyState("No tool traffic has been recorded yet.");
        return;
      }}
      const max = Math.max(...tools.map((tool) => tool.count), 1);
      target.innerHTML = tools.map((tool) => `
        <div class="tool-row">
          <div class="tool-row-head">
            <div>
              <div class="tool-title"><code>${{escapeHtml(tool.name)}}</code></div>
              <div class="tool-desc">${{escapeHtml(tool.count)}} observed events</div>
            </div>
            <span class="pill neutral">${{tool.count}}</span>
          </div>
          <div class="bar-track">
            <div class="bar-fill" style="width: ${{Math.max(8, Math.round((tool.count / max) * 100))}}%;"></div>
          </div>
        </div>
      `).join("");
    }}

    function renderBlocklist(entries) {{
      const target = document.getElementById("blocklist");
      if (!entries.length) {{
        target.innerHTML = emptyState("No IPs are currently blocked.");
        return;
      }}
      target.innerHTML = entries.map((entry) => `
        <div class="block-row">
          <div class="tool-row-head">
            <div>
              <div class="block-title"><code>${{escapeHtml(entry.ip)}}</code></div>
              <div class="block-desc">Remaining block duration</div>
            </div>
            <span class="pill deny">${{entry.remaining_sec}}s</span>
          </div>
        </div>
      `).join("");
    }}

    const ALERT_TITLES = {{
      "filesystem.path_outside_allowed_base": "File Access Outside Allowed Directory",
      "filesystem.path_traversal":            "Directory Traversal Attempt",
      "filesystem.missing_required_args":     "Missing Required Tool Arguments",
      "identity.missing_session_id":          "Request Missing Session Identity",
      "identity.invalid_token_format":        "Invalid Authentication Token",
      "abuse.high_request_rate":              "Abnormally High Request Rate",
      "abuse.oversized_payload":              "Oversized Request Payload",
      "BLOCKLIST_ACTIVE":                     "Request Blocked — IP on Blocklist",
      "UNSAFE_FILE_ACCESS":                   "Unsafe File Access Attempt",
      "SQL_INJECTION":                        "SQL Injection Pattern Detected",
      "DISALLOWED_TOOL":                      "Disallowed Tool Called",
      "INVALID_ARGUMENTS":                    "Invalid or Missing Tool Arguments",
      "R1_DISALLOWED_TOOL":                   "Disallowed Tool Called",
      "R2_UNSAFE_PARAMETER":                  "Unsafe Parameter Detected",
      "R3_INVALID_ARGUMENTS":                 "Invalid Tool Arguments",
      "ACTION_APPLIED":                       "Mitigation Action Applied",
      "ERROR":                                "Internal Proxy Error",
    }};

    function alertTitle(event) {{
      const rc = event.reason_code || "";
      const et = event.event_type  || "";
      return ALERT_TITLES[rc] || ALERT_TITLES[et] || humanizeConstant(rc || et);
    }}

    async function toggleAlertStatus(alertId, currentStatus) {{
      const next = currentStatus === "open" ? "close" : "open";
      await api(`/api/alerts/${{encodeURIComponent(alertId)}}/${{next}}`, {{ method: "POST" }});
      await refreshDashboard();
    }}

    function statusBadge(status) {{
      const closed = status === "closed";
      return `<span class="pill ${{closed ? "allow" : "deny"}}" style="font-size:0.72rem;">${{closed ? "Closed" : "Open"}}</span>`;
    }}

    function renderAlerts(rows) {{
      const target = document.getElementById("alerts");
      if (!rows.length) {{
        target.innerHTML = `<tr><td colspan="7" class="empty-state" style="background: transparent;">No alerts yet.</td></tr>`;
        return;
      }}
      target.innerHTML = rows.map((event) => {{
        const isClosed = event.status === "closed";
        const alertId = event.alert_id || event.request_id || "";
        return `
        <tr style="${{isClosed ? "opacity:0.55;" : ""}}">
          <td>${{severityBadge(event.severity)}}</td>
          <td>${{escapeHtml(formatTimestamp(event.timestamp))}}</td>
          <td>
            <div class="table-cell-title">${{escapeHtml(alertTitle(event))}}</div>
            <div class="table-cell-copy">${{escapeHtml(event.tool_name || event.mcp_method || "—")}}</div>
          </td>
          <td>${{decisionPill(event.decision)}}</td>
          <td>
            <div class="table-cell-copy">${{escapeHtml(event.reason || "—")}}</div>
          </td>
          <td>${{statusBadge(event.status || "open")}}</td>
          <td>
            <button class="btn btn-${{isClosed ? "primary" : "danger"}}" style="padding:4px 10px;font-size:0.78rem;" onclick="toggleAlertStatus('${{escapeHtml(alertId)}}','${{event.status || "open"}}')">${{isClosed ? "Reopen" : "Close"}}</button>
          </td>
        </tr>`;
      }}).join("");
    }}

    function renderLatestEvent(event) {{
      const target = document.getElementById("latest-event");
      if (!event) {{
        target.innerHTML = emptyState("No events have been logged yet.");
        return;
      }}
      const detailRows = [
        {{
          label: "Decision",
          value: decisionPill(event.decision),
          html: true,
        }},
        {{
          label: "Event type",
          value: humanizeConstant(event.event_type),
        }},
        {{
          label: "Tool",
          value: event.tool_name || event.mcp_method || "Unknown",
        }},
        {{
          label: "Client IP",
          value: event.client_ip || "Unknown",
        }},
        {{
          label: "Trace",
          value: event.trace_id || "Unknown",
        }},
        {{
          label: "Timestamp",
          value: formatTimestamp(event.timestamp),
        }},
      ];
      target.innerHTML = `
        <div class="detail-row">
          <div>
            <div class="table-cell-title">${{escapeHtml(humanizeConstant(event.event_type))}}</div>
            <div class="detail-copy">${{escapeHtml(event.reason || "No reason details available.")}}</div>
          </div>
          ${{decisionPill(event.decision)}}
        </div>
        <div class="summary-item" style="margin-top: 6px;">
          <div class="summary-index">!</div>
          <div>
            <div class="table-cell-title">${{escapeHtml(event.reason_code || "No reason code")}}</div>
            <div class="detail-copy">Latest explanation emitted by the proxy for this event.</div>
          </div>
        </div>
        ${{detailRows.map((row) => `
          <div class="detail-row">
            <div>
              <div class="list-meta">${{escapeHtml(row.label)}}</div>
              <div class="table-cell-title">${{row.html ? row.value : escapeHtml(row.value)}}</div>
            </div>
          </div>
        `).join("")}}
      `;
    }}

    function renderEvents(rows) {{
      const target = document.getElementById("events");
      if (!rows.length) {{
        target.innerHTML = `<tr><td colspan="7" class="empty-state" style="background: transparent;">No events recorded yet.</td></tr>`;
        return;
      }}
      function abbreviateId(id) {{
        if (!id) return "Unknown";
        const s = String(id);
        const take = Math.ceil(s.length / 2);
        return escapeHtml(s.slice(0, take) + "...");
      }}

      target.innerHTML = rows.map((event) => `
        <tr onclick="showTrace('${{escapeHtml(event.trace_id)}}')" style="cursor:pointer">
          <td>${{severityBadge(event.severity)}}</td>
          <td>${{escapeHtml(formatTimestamp(event.timestamp))}}</td>
          <td>
            <div class="table-cell-title">${{escapeHtml(humanizeConstant(event.event_type))}}</div>
            <div class="table-cell-copy">${{escapeHtml(event.component || "proxy")}}</div>
          </td>
          <td><code class="trace" title="${{escapeHtml(event.trace_id)}}">${{abbreviateId(event.trace_id)}}</code></td>
          <td>${{decisionPill(event.decision)}}</td>
          <td><code>${{escapeHtml(event.tool_name || event.mcp_method || "unknown")}}</code></td>
          <td>
            <div class="table-cell-title">${{escapeHtml(event.reason_code || "No reason code")}}</div>
            <div class="table-cell-copy">${{escapeHtml(event.reason || "")}}</div>
          </td>
        </tr>
      `).join("");
    }}

    

    let _allAlerts = [];
    const _alertFilter = {{ time: "all", severity: "all", status: "all" }};

    function setAlertFilter(type, value) {{
      _alertFilter[type] = value;
      applyAlertFilters();
    }}

    function applyAlertFilters() {{
      let rows = _allAlerts;
      if (_alertFilter.time !== "all") {{
        const hours = parseInt(_alertFilter.time, 10);
        const cutoff = new Date(Date.now() - hours * 3600 * 1000);
        rows = rows.filter((e) => new Date(e.timestamp) >= cutoff);
      }}
      if (_alertFilter.severity !== "all") {{
        rows = rows.filter((e) => (e.severity || "").toUpperCase() === _alertFilter.severity);
      }}
      if (_alertFilter.status !== "all") {{
        rows = rows.filter((e) => (e.status || "open") === _alertFilter.status);
      }}
      renderAlerts(rows);
    }}

    function hideTrace() {{
      const modal = document.getElementById('trace-modal');
      if (modal) {{
        modal.style.display = 'none';
      }}
      const body = document.getElementById('trace-modal-body');
      if (body) {{ body.innerHTML = ''; }}
    }}

    async function showTrace(traceId) {{
      if (!traceId) {{
        alert('Trace id is missing');
        return;
      }}
      document.getElementById('status').textContent = 'Loading trace ' + traceId + '...';
      try {{
        const data = await api('/api/trace/' + encodeURIComponent(traceId));
        if (!data) return;
        const events = data.events || [];
        const finalDecision = (events.slice().reverse().find(e => e.decision && e.decision !== 'NONE') || {{}}).decision || 'NONE';
        const sevRank = {{ LOW:1, MEDIUM:2, HIGH:3, CRITICAL:4 }};
        let maxRank = 1;
        for (const e of events) {{
          const r = sevRank[(String(e.severity || 'LOW')).toUpperCase()] || 1;
          if (r > maxRank) maxRank = r;
        }}
        const revMap = {{ 1:'LOW', 2:'MEDIUM', 3:'HIGH', 4:'CRITICAL' }};
        const maxSeverityLabel = revMap[maxRank] || 'LOW';
        const body = document.getElementById('trace-modal-body');
        if (!events.length) {{
          body.innerHTML = '<div class="empty-state">No events found for this trace.</div>';
        }} else {{
          const steps = events.map((step) => {{
            const sev = String(step.severity || 'LOW').toLowerCase();
            const abbrev = TL_ABBREV[step.event_type] || (step.event_type || '').slice(0,4);
            const latency = step.stage_latency_ms != null ? `${{step.stage_latency_ms}}ms` : step.latency_ms != null ? `${{step.latency_ms}}ms` : '';
            return `
              <div class="tl-step">
                <div class="tl-dot sev-${{sev}}" title="${{escapeHtml(step.event_type)}} — ${{escapeHtml(step.severity || 'LOW')}}">${{escapeHtml(abbrev)}}</div>
                <div class="tl-label">
                  <div>${{escapeHtml(humanizeConstant(step.event_type))}}</div>
                  ${{latency ? `<div style="font-size:0.65rem;color:var(--muted)">${{escapeHtml(latency)}}</div>` : ''}}
                  ${{step.decision && step.decision !== 'NONE' ? decisionPill(step.decision) : ''}}
                </div>
              </div>
            `;
          }}).join('');
          body.innerHTML = `
            <div class="tl-trace" style="margin:0;">
              <div class="tl-header">
                <code class="trace" title="${{escapeHtml(traceId)}}" style="font-size:0.82rem;">${{escapeHtml(traceId)}}</code>
                ${{severityBadge(maxSeverityLabel)}}
                ${{decisionPill(finalDecision)}}
              </div>
              <div class="tl-steps">${{steps}}</div>
            </div>
          `;
        }}
        document.getElementById('trace-modal').style.display = 'flex';
      }} catch (err) {{
        alert(err.message || err);
      }} finally {{
        document.getElementById('status').textContent = 'Last updated ' + new Date().toLocaleTimeString();
      }}
    }}

    async function refreshDashboard() {{
      document.getElementById("status").textContent = "Refreshing live data...";
      try {{
        const [overview, alerts, events, scenarios, blocklist] = await Promise.all([
          api("/api/overview"),
          api("/api/alerts"),
          api("/api/events"),
          api("/api/scenarios"),
          api("/api/blocklist"),
        ]);
        if (!overview) {{
          return;
        }}
        renderHeroMeta(overview);
        renderScorePanel(overview);
        renderSummaryMetrics(overview);
        renderSummaryBullets(overview, scenarios || {{ runs: [] }}, blocklist || {{ entries: [] }});
        renderDecisionBreakdown(overview);
        renderSystemOverview(overview);
        renderScenarios((scenarios && scenarios.runs) || []);
        renderTopTools(overview.top_tools || []);
        renderBlocklist((blocklist && blocklist.entries) || []);
        _allAlerts = (alerts && alerts.alerts) || [];
        applyAlertFilters();
        renderEvents((events && events.events) || []);
        document.getElementById("status").textContent = "Last updated " + new Date().toLocaleTimeString();
      }} catch (error) {{
        document.getElementById("status").textContent = error.message || "Refresh failed.";
      }}
    }}

    async function runScenario(name) {{
      document.getElementById("status").textContent = `Running ${{name}} scenario...`;
      try {{
        await api(`/api/scenarios/${{name}}/run`, {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
        }});
        await refreshDashboard();
      }} catch (error) {{
        document.getElementById("status").textContent = error.message || "Scenario run failed.";
      }}
    }}

    refreshDashboard();
    setInterval(refreshDashboard, 5000);
  </script>
</body>
</html>"""


def _tests_page(state: DashboardState) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MCProtector Tool Tests</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f5f7fb;
      --panel: #ffffff;
      --panel-soft: #eef3f8;
      --line: #d9e2ee;
      --text: #182433;
      --muted: #627084;
      --blue: #2457ff;
      --blue-deep: #143eb7;
      --green: #159f63;
      --green-soft: rgba(21, 159, 99, 0.14);
      --amber: #d08611;
      --amber-soft: rgba(208, 134, 17, 0.16);
      --red: #cf3b32;
      --red-soft: rgba(207, 59, 50, 0.14);
      --slate-soft: rgba(112, 129, 152, 0.14);
      --shadow: 0 14px 36px rgba(24, 36, 51, 0.08);
      font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      color: var(--text);
      background: linear-gradient(180deg, #f9fbfe 0%, var(--bg) 100%);
    }}
    code,
    pre,
    textarea {{
      font-family: "IBM Plex Mono", Consolas, monospace;
    }}
    .shell {{
      max-width: 1440px;
      margin: 0 auto;
      padding: 28px 20px 48px;
    }}
    .topbar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      margin-bottom: 20px;
    }}
    .brand {{
      display: flex;
      align-items: center;
      gap: 12px;
      font-weight: 700;
    }}
    .brand-mark {{
      width: 42px;
      height: 42px;
      border-radius: 8px;
      background: linear-gradient(135deg, var(--blue), var(--blue-deep));
      box-shadow: 0 10px 24px rgba(36, 87, 255, 0.24);
      position: relative;
      flex-shrink: 0;
    }}
    .brand-mark::before,
    .brand-mark::after {{
      content: "";
      position: absolute;
      border: 2px solid rgba(255, 255, 255, 0.82);
      border-radius: 6px;
    }}
    .brand-mark::before {{ inset: 10px; }}
    .brand-mark::after {{
      inset: 15px;
      border-radius: 3px;
    }}
    .brand-copy small,
    .eyebrow,
    .label,
    .meta {{
      display: block;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }}
    .actions {{
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }}
    .btn {{
      border: 1px solid var(--line);
      background: var(--panel);
      color: var(--text);
      border-radius: 999px;
      padding: 10px 16px;
      font-weight: 700;
      text-decoration: none;
      cursor: pointer;
      box-shadow: 0 8px 22px rgba(24, 36, 51, 0.05);
    }}
    .btn-primary {{
      background: var(--blue);
      color: #fff;
      border-color: transparent;
    }}
    .btn-danger {{
      background: var(--red-soft);
      color: var(--red);
      border-color: transparent;
      box-shadow: none;
    }}
    .hero {{
      background: var(--panel);
      border: 1px solid rgba(24, 36, 51, 0.06);
      border-radius: 8px;
      box-shadow: var(--shadow);
      padding: 24px;
      margin-bottom: 18px;
    }}
    .hero h1 {{
      margin: 6px 0 10px;
      font-size: 32px;
      line-height: 1.1;
      letter-spacing: 0;
    }}
    .hero p {{
      margin: 0;
      max-width: 78ch;
      color: var(--muted);
      line-height: 1.6;
    }}
    .status {{
      margin-top: 16px;
      display: inline-flex;
      border: 1px solid var(--line);
      background: var(--panel-soft);
      border-radius: 999px;
      padding: 8px 12px;
      font-weight: 700;
      color: var(--muted);
      font-size: 13px;
    }}
    .layout {{
      display: grid;
      grid-template-columns: minmax(0, 1.1fr) minmax(360px, 0.9fr);
      gap: 18px;
      align-items: start;
    }}
    .section {{
      background: var(--panel);
      border: 1px solid rgba(24, 36, 51, 0.06);
      border-radius: 8px;
      box-shadow: var(--shadow);
      padding: 18px;
      min-width: 0;
    }}
    .section-head {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 12px;
      margin-bottom: 16px;
    }}
    .section h2,
    .section h3 {{
      margin: 4px 0 0;
      letter-spacing: 0;
    }}
    .section h2 {{
      font-size: 22px;
    }}
    .section h3 {{
      font-size: 17px;
    }}
    .tool-grid {{
      display: grid;
      gap: 14px;
    }}
    .tool-card,
    .scenario-card,
    .result-card {{
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      padding: 16px;
    }}
    .tool-head {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: flex-start;
      margin-bottom: 12px;
    }}
    .tool-copy,
    .scenario-copy,
    .result-copy {{
      color: var(--muted);
      line-height: 1.55;
      margin-top: 6px;
    }}
    .scenario-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }}
    textarea {{
      width: 100%;
      min-height: 130px;
      resize: vertical;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fbfdff;
      padding: 12px;
      color: var(--text);
      line-height: 1.5;
      font-size: 13px;
      margin: 12px 0;
    }}
    .pill {{
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      padding: 7px 11px;
      font-size: 12px;
      font-weight: 800;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      white-space: nowrap;
    }}
    .pill.allow,
    .pill.pass {{
      background: var(--green-soft);
      color: #11784c;
    }}
    .pill.deny,
    .pill.fail {{
      background: var(--red-soft);
      color: var(--red);
    }}
    .pill.neutral {{
      background: var(--slate-soft);
      color: #516074;
    }}
    .pill.warn {{
      background: var(--amber-soft);
      color: #9b6400;
    }}
    .detail-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
      margin: 14px 0;
    }}
    .detail {{
      border-radius: 8px;
      background: var(--panel-soft);
      padding: 12px;
      min-width: 0;
    }}
    .detail strong {{
      display: block;
      margin-top: 6px;
      word-break: break-word;
    }}
    .reason {{
      border-left: 4px solid var(--blue);
      background: var(--panel-soft);
      border-radius: 8px;
      padding: 14px;
      margin: 14px 0;
    }}
    .table-wrap {{
      max-height: 360px;
      overflow: auto;
      border: 1px solid var(--line);
      border-radius: 8px;
      margin-top: 12px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
      table-layout: fixed;
    }}
    th,
    td {{
      padding: 10px;
      text-align: left;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
      overflow-wrap: anywhere;
    }}
    th {{
      position: sticky;
      top: 0;
      background: #f8fbff;
      color: var(--muted);
      font-size: 11px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      z-index: 1;
    }}
    pre {{
      margin: 12px 0 0;
      background: #111827;
      color: #dbeafe;
      padding: 14px;
      border-radius: 8px;
      overflow: auto;
      white-space: pre-wrap;
      word-break: break-word;
      line-height: 1.55;
      font-size: 12px;
      max-height: 360px;
    }}
    .history {{
      display: grid;
      gap: 10px;
      max-height: 360px;
      overflow: auto;
      padding-right: 4px;
    }}
    .history-item {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      cursor: pointer;
      background: #fff;
    }}
    .history-item:hover {{
      border-color: var(--blue);
    }}
    .empty {{
      border-radius: 8px;
      background: var(--panel-soft);
      color: var(--muted);
      padding: 16px;
      line-height: 1.5;
    }}
    @media (max-width: 1100px) {{
      .layout,
      .scenario-grid {{
        grid-template-columns: 1fr;
      }}
    }}
    @media (max-width: 720px) {{
      .shell {{
        padding: 20px 14px 36px;
      }}
      .topbar,
      .section-head,
      .tool-head {{
        flex-direction: column;
        align-items: flex-start;
      }}
      .hero h1 {{
        font-size: 26px;
      }}
      .detail-grid {{
        grid-template-columns: 1fr;
      }}
    }}
  </style>
</head>
<body>
  <div class="shell">
    <header class="topbar">
      <div class="brand">
        <div class="brand-mark" aria-hidden="true"></div>
        <div class="brand-copy">
          <small>Security Platform</small>
          <div>MCProtector Tool Tests</div>
        </div>
      </div>
      <div class="actions">
        <a class="btn" href="/">Dashboard</a>
        <button class="btn btn-primary" type="button" onclick="loadDefinitions()">Reload Tests</button>
      </div>
    </header>

    <section class="hero">
      <div class="eyebrow">Real Proxy Test Flow</div>
      <h1>Run allowed and blocked checks for each MCP tool.</h1>
      <p>Every test on this page sends a real <code>tools/call</code> request to <code>{state.proxy_url}</code>, then reads the matching trace from the proxy log so you can inspect the rule evaluation, final decision, mitigation action, and upstream response.</p>
      <div style="display:flex;gap:12px;align-items:center;">
        <div class="status" id="status">Loading tool tests...</div>
        <div style="display:flex;gap:8px;align-items:center;">
          <button class="btn" id="product-toggle" type="button" onclick="toggleProduct()">Toggle Protection</button>
          <span id="product-state" class="pill neutral">Unknown</span>
        </div>
      </div>
    </section>

    <main class="layout">
      <section class="section">
        <div class="section-head">
          <div>
            <div class="eyebrow">Tool Matrix</div>
            <h2>Per-tool access tests</h2>
          </div>
          <span class="pill neutral" id="tool-count">0 tools</span>
        </div>
        <div class="tool-grid" id="tool-grid"></div>
      </section>

      <aside class="section">
        <div class="section-head">
          <div>
            <div class="eyebrow">Latest Result</div>
            <h2>Decision and trace logs</h2>
          </div>
          <span class="pill neutral" id="latest-badge">No run</span>
        </div>
        <div id="latest-result" class="empty">Run an allowed or blocked test to see the proxy decision and trace events here.</div>
        <div style="margin-top: 18px;">
          <div class="eyebrow">Run History</div>
          <div class="history" id="history" style="margin-top: 10px;"></div>
        </div>
      </aside>
    </main>
  </div>

  <script>
    const runHistory = [];

    function escapeHtml(value) {{
      return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
    }}

    function formatTimestamp(value) {{
      if (!value) {{
        return "No data";
      }}
      const parsed = new Date(value);
      return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString();
    }}

    function humanize(value) {{
      return String(value || "Unknown")
        .toLowerCase()
        .split("_")
        .map((part) => part ? part[0].toUpperCase() + part.slice(1) : "")
        .join(" ");
    }}

    function pill(value, label) {{
      const text = label || value || "None";
      const lower = String(value || "neutral").toLowerCase();
      let css = "neutral";
      if (lower === "allow" || lower === "passed" || lower === "pass") {{
        css = "allow";
      }} else if (lower === "deny" || lower === "failed" || lower === "fail") {{
        css = "deny";
      }} else if (lower === "challenge") {{
        css = "warn";
      }}
      return `<span class="pill ${{css}}">${{escapeHtml(text)}}</span>`;
    }}

    function safeId(toolName, scenario) {{
      return `${{toolName.replaceAll(".", "-")}}-${{scenario}}`;
    }}

    async function api(path, options) {{
      const response = await fetch(path, Object.assign({{ credentials: "same-origin" }}, options || {{}}));
      if (response.status === 401) {{
        window.location = "/login";
        return null;
      }}
      if (!response.ok) {{
        const error = await response.json().catch(() => ({{}}));
        throw new Error(error.detail || `Request failed with status ${{response.status}}.`);
      }}
      return response.json();
    }}

    async function loadDefinitions() {{
      document.getElementById("status").textContent = "Loading tool definitions...";
      try {{
        const data = await api("/api/tests/definitions");
        renderToolGrid(data.tools || []);
        document.getElementById("status").textContent = "Ready to run real proxy tests.";
      }} catch (error) {{
        document.getElementById("status").textContent = error.message || "Could not load tests.";
      }}
    }}

    function renderToolGrid(tools) {{
      document.getElementById("tool-count").textContent = `${{tools.length}} tool${{tools.length === 1 ? "" : "s"}}`;
      const grid = document.getElementById("tool-grid");
      if (!tools.length) {{
        grid.innerHTML = `<div class="empty">No tool definitions were found.</div>`;
        return;
      }}
      grid.innerHTML = tools.map((tool) => `
        <article class="tool-card">
          <div class="tool-head">
            <div>
              <div class="eyebrow">MCP Tool</div>
              <h3><code>${{escapeHtml(tool.name)}}</code></h3>
              <div class="tool-copy">${{escapeHtml(tool.description)}}</div>
            </div>
            <span class="pill neutral">tools/call</span>
          </div>
          <div class="scenario-grid">
            ${{renderScenario(tool, "allowed")}}
            ${{renderScenario(tool, "disallowed")}}
          </div>
        </article>
      `).join("");
    }}

    function renderScenario(tool, scenario) {{
      const config = tool[scenario];
      const id = safeId(tool.name, scenario);
      const buttonClass = scenario === "allowed" ? "btn btn-primary" : "btn btn-danger";
      return `
        <div class="scenario-card">
          <div class="tool-head">
            <div>
              <div class="label">${{escapeHtml(scenario)}}</div>
              <h3>${{escapeHtml(config.title)}}</h3>
            </div>
            ${{pill(config.expected_decision)}}
          </div>
          <div class="scenario-copy">${{escapeHtml(config.summary)}}</div>
          <textarea id="args-${{id}}" spellcheck="false">${{escapeHtml(JSON.stringify(config.arguments, null, 2))}}</textarea>
          <button class="${{buttonClass}}" type="button" onclick="runToolTest('${{escapeHtml(tool.name)}}', '${{scenario}}')">Run ${{escapeHtml(scenario)}} test</button>
        </div>
      `;
    }}

    async function runToolTest(toolName, scenario) {{
      const id = safeId(toolName, scenario);
      const textarea = document.getElementById(`args-${{id}}`);
      let args;
      try {{
        args = JSON.parse(textarea.value || "{{}}");
      }} catch (error) {{
        document.getElementById("status").textContent = `Invalid JSON arguments for ${{toolName}} ${{scenario}}.`;
        textarea.focus();
        return;
      }}

      document.getElementById("status").textContent = `Running ${{toolName}} ${{scenario}} through the proxy...`;
      try {{
        const result = await api("/api/tests/run", {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: JSON.stringify({{ tool_name: toolName, scenario, arguments: args }}),
        }});
        runHistory.unshift(result);
        runHistory.splice(12);
        renderResult(result);
        renderHistory();
        document.getElementById("status").textContent = `Completed ${{toolName}} ${{scenario}} test.`;
      }} catch (error) {{
        document.getElementById("status").textContent = error.message || "Test run failed.";
      }}
    }}

    async function getProductState() {{
      try {{
        const resp = await api('/api/product');
        const enabled = resp && resp.enabled;
        const el = document.getElementById('product-state');
        el.textContent = enabled ? 'Protection: ON' : 'Protection: OFF';
        el.className = 'pill ' + (enabled ? 'pass' : 'fail');
        window._product_enabled = !!enabled;
      }} catch (err) {{
        console.warn('Could not fetch product state', err);
      }}
    }}

    async function toggleProduct() {{
      const currently = !!window._product_enabled;
      try {{
        const resp = await api('/api/product', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ enabled: !currently }}),
        }});
        window._product_enabled = !!resp.enabled;
        getProductState();
      }} catch (err) {{
        alert('Failed to toggle product: ' + (err.message || err));
      }}
    }}

    function renderResult(result) {{
      const badge = document.getElementById("latest-badge");
      badge.className = `pill ${{result.actual_decision === "DENY" ? "deny" : result.actual_decision === "ALLOW" ? "allow" : "warn"}}`;
      badge.textContent = result.actual_decision || "No decision";

      const events = result.events || [];
      document.getElementById("latest-result").className = "";
      document.getElementById("latest-result").innerHTML = `
        <div class="result-card">
          <div class="tool-head">
            <div>
              <div class="eyebrow">${{escapeHtml(result.scenario)}} test</div>
              <h3><code>${{escapeHtml(result.tool_name)}}</code></h3>
              <div class="result-copy">${{escapeHtml(result.summary)}}</div>
            </div>
            ${{pill(result.actual_decision)}}
          </div>
          <div style="margin-top: 10px;">${{pill(result.passed ? "pass" : "fail", result.passed ? "Expected result" : "Unexpected result")}}</div>
          <div class="detail-grid">
            <div class="detail"><span class="meta">Expected</span><strong>${{escapeHtml(result.expected_decision)}}</strong></div>
            <div class="detail"><span class="meta">Actual</span><strong>${{escapeHtml(result.actual_decision)}}</strong></div>
            <div class="detail"><span class="meta">HTTP status</span><strong>${{escapeHtml(result.http_status)}}</strong></div>
            <div class="detail"><span class="meta">Trace id</span><strong><code>${{escapeHtml(result.trace_id || "Unavailable")}}</code></strong></div>
          </div>
          <div class="reason">
            <div class="meta">Proxy decision reason</div>
            <strong>${{escapeHtml(result.decision_reason_code || "No decision event found")}}</strong>
            <div class="result-copy">${{escapeHtml(result.decision_reason || "The proxy did not emit a decision reason for this request.")}}</div>
          </div>
          <div class="eyebrow">Trace Events</div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th style="width: 18%;">Time</th>
                  <th style="width: 22%;">Event</th>
                  <th style="width: 16%;">Decision</th>
                  <th style="width: 44%;">Reason</th>
                </tr>
              </thead>
              <tbody>
                ${{events.length ? events.map(renderEventRow).join("") : `<tr><td colspan="4">No trace events were found in the log file.</td></tr>`}}
              </tbody>
            </table>
          </div>
          <div style="margin-top: 16px;" class="eyebrow">Proxy Response</div>
          <pre>${{escapeHtml(JSON.stringify(result.response, null, 2))}}</pre>
          <div style="margin-top: 16px;" class="eyebrow">Request Payload</div>
          <pre>${{escapeHtml(JSON.stringify(result.request, null, 2))}}</pre>
        </div>
      `;
    }}

    function renderEventRow(event) {{
      return `
        <tr>
          <td>${{escapeHtml(formatTimestamp(event.timestamp))}}</td>
          <td>
            <strong>${{escapeHtml(humanize(event.event_type))}}</strong>
            <div class="meta">${{escapeHtml(event.component || "proxy")}}</div>
          </td>
          <td>${{pill(event.decision)}}</td>
          <td>
            <strong>${{escapeHtml(event.reason_code || "No reason code")}}</strong>
            <div class="result-copy">${{escapeHtml(event.reason || "")}}</div>
          </td>
        </tr>
      `;
    }}

    function renderHistory() {{
      const target = document.getElementById("history");
      if (!runHistory.length) {{
        target.innerHTML = `<div class="empty">No runs yet.</div>`;
        return;
      }}
      target.innerHTML = runHistory.map((item, index) => `
        <div class="history-item" onclick="renderResult(runHistory[${{index}}])">
          <div class="tool-head" style="margin-bottom: 0;">
            <div>
              <strong><code>${{escapeHtml(item.tool_name)}}</code></strong>
              <div class="meta">${{escapeHtml(item.scenario)}} • ${{escapeHtml(formatTimestamp(item.completed_at))}}</div>
            </div>
            ${{pill(item.actual_decision)}}
          </div>
        </div>
      `).join("");
    }}

    renderHistory();
    loadDefinitions();
    getProductState();
  </script>
</body>
</html>"""


def _require_auth(request: Request, state: DashboardState) -> None:
    if not _session_is_valid(state.cfg.dashboard_session_secret, request.cookies.get(SESSION_COOKIE_NAME)):
        raise HTTPException(status_code=401, detail="Authentication required")


def _proxy_bind_host(cfg: ProxyConfig) -> str:
    return "127.0.0.1" if cfg.listen_host in ("0.0.0.0", "::") else cfg.listen_host


def create_dashboard_app(state: DashboardState) -> FastAPI:
    app = FastAPI(title="MCProtector Dashboard", version="0.1")

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/login", response_class=HTMLResponse)
    async def login_page() -> HTMLResponse:
        return HTMLResponse(_login_page())

    @app.post("/login")
    async def login(request: Request) -> RedirectResponse:
        body = (await request.body()).decode("utf-8")
        form = parse_qs(body)
        password = (form.get("password") or [""])[0]
        if not secrets.compare_digest(password, state.cfg.dashboard_admin_password):
            return HTMLResponse(_login_page("Incorrect password."), status_code=401)

        response = RedirectResponse(url="/", status_code=303)
        response.set_cookie(
            SESSION_COOKIE_NAME,
            _create_session_cookie(state.cfg.dashboard_session_secret),
            httponly=True,
            max_age=SESSION_TTL_SEC,
            samesite="lax",
        )
        return response

    @app.post("/logout")
    async def logout() -> RedirectResponse:
        response = RedirectResponse(url="/login", status_code=303)
        response.delete_cookie(SESSION_COOKIE_NAME)
        return response

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        if not _session_is_valid(state.cfg.dashboard_session_secret, request.cookies.get(SESSION_COOKIE_NAME)):
            return RedirectResponse(url="/login", status_code=303)
        return HTMLResponse(_dashboard_page(state))

    @app.get("/tests", response_class=HTMLResponse)
    async def tests_page(request: Request):
        if not _session_is_valid(state.cfg.dashboard_session_secret, request.cookies.get(SESSION_COOKIE_NAME)):
            return RedirectResponse(url="/login", status_code=303)
        return HTMLResponse(_tests_page(state))

    @app.get("/api/overview")
    async def overview(request: Request) -> JSONResponse:
        _require_auth(request, state)
        return JSONResponse(_build_overview(state))

    @app.get("/api/events")
    async def events(request: Request, limit: int = 150) -> JSONResponse:
        _require_auth(request, state)
        return JSONResponse({"events": _serialize_events(_read_events(state.cfg.log_file_path, max(1, min(limit, 500))))})

    @app.get("/api/alerts")
    async def alerts(request: Request, limit: int = 50) -> JSONResponse:
        _require_auth(request, state)
        alerts_only = [event for event in _read_events(state.cfg.log_file_path) if _is_alert(event)]
        alerts_only.sort(key=_alert_priority_key)
        rows = []
        for event in alerts_only[:max(1, min(limit, 200))]:
            d = event.model_dump(mode="json", exclude_none=False)
            d["alert_id"] = str(event.request_id)
            d["status"] = "closed" if str(event.request_id) in state.closed_alerts else "open"
            rows.append(d)
        return JSONResponse({"alerts": rows})

    @app.post("/api/alerts/{alert_id}/close")
    async def close_alert(alert_id: str, request: Request) -> JSONResponse:
        _require_auth(request, state)
        state.close_alert(alert_id)
        return JSONResponse({"alert_id": alert_id, "status": "closed"})

    @app.post("/api/alerts/{alert_id}/open")
    async def reopen_alert(alert_id: str, request: Request) -> JSONResponse:
        _require_auth(request, state)
        state.reopen_alert(alert_id)
        return JSONResponse({"alert_id": alert_id, "status": "open"})

    @app.get("/api/timeline")
    async def timeline(request: Request, max_traces: int = 6) -> JSONResponse:
        _require_auth(request, state)
        return JSONResponse({"traces": _build_timeline(state, max(1, min(max_traces, 20)))})

    @app.get("/api/trace/{trace_id}")
    async def trace(request: Request, trace_id: str) -> JSONResponse:
      _require_auth(request, state)
      events = _events_for_trace(state.cfg.log_file_path, trace_id)
      return JSONResponse({"trace_id": trace_id, "events": _serialize_events(events)})

    @app.get("/api/blocklist")
    async def blocklist(request: Request) -> JSONResponse:
        _require_auth(request, state)
        return JSONResponse({"entries": state.blocklist_entries()})

    @app.get("/api/scenarios")
    async def scenarios(request: Request) -> JSONResponse:
        _require_auth(request, state)
        return JSONResponse({"runs": state.scenario_history})

    @app.get("/api/product")
    async def product_status(request: Request) -> JSONResponse:
      _require_auth(request, state)
      return JSONResponse({"enabled": state.is_product_enabled()})

    @app.post("/api/product")
    async def set_product(request: Request) -> JSONResponse:
      _require_auth(request, state)
      payload = await request.json()
      enabled = payload.get("enabled")
      if not isinstance(enabled, bool):
        raise HTTPException(status_code=400, detail="'enabled' must be a boolean")
      state.set_product_enabled(enabled)
      return JSONResponse({"enabled": state.is_product_enabled()})

    @app.get("/api/tests/definitions")
    async def test_definitions(request: Request) -> JSONResponse:
        _require_auth(request, state)
        return JSONResponse({"tools": _tool_test_definitions()})

    @app.post("/api/tests/run")
    async def run_tool_test(request: Request) -> JSONResponse:
        _require_auth(request, state)
        payload = await request.json()
        tool_name = payload.get("tool_name")
        scenario = payload.get("scenario")
        arguments = payload.get("arguments")
        if not isinstance(tool_name, str):
            raise HTTPException(status_code=400, detail="tool_name is required")
        if not isinstance(scenario, str):
            raise HTTPException(status_code=400, detail="scenario is required")
        if arguments is not None and not isinstance(arguments, dict):
            raise HTTPException(status_code=400, detail="arguments must be an object")
        return JSONResponse(await _run_tool_access_test(state, tool_name, scenario, arguments))

    @app.post("/api/scenarios/{scenario_name}/run")
    async def run_dashboard_scenario(request: Request, scenario_name: str) -> JSONResponse:
        _require_auth(request, state)
        if scenario_name not in {"allowed", "denied"}:
            raise HTTPException(status_code=404, detail="Unknown scenario")
        if not state.scenario_lock.acquire(blocking=False):
            raise HTTPException(status_code=409, detail="Another scenario is already running")

        try:
            client = MCPClient(
                server_url=state.proxy_url,
                client_id=f"dashboard-{scenario_name}-{uuid_suffix()}",
            )
            result = await asyncio.to_thread(run_scenario, client, scenario_name)
            state.record_scenario(result)
            return JSONResponse(result)
        finally:
            state.scenario_lock.release()

    return app


def uuid_suffix() -> str:
    return secrets.token_hex(4)


def start_dashboard_server(state: DashboardState) -> DashboardServerHandle:
    app = create_dashboard_app(state)
    config = uvicorn.Config(
        app=app,
        host=state.cfg.dashboard_host,
        port=state.cfg.dashboard_port,
        log_level="info",
        access_log=False,
    )
    server = uvicorn.Server(config=config)

    def _runner() -> None:
        asyncio.set_event_loop(asyncio.new_event_loop())
        server.run()

    thread = threading.Thread(target=_runner, name="mcprotector-dashboard", daemon=True)
    thread.start()
    return DashboardServerHandle(app=app, server=server, thread=thread)


def stop_dashboard_server(handle: DashboardServerHandle | None) -> None:
    if handle is None:
        return
    handle.server.should_exit = True
    handle.thread.join(timeout=5)


def build_dashboard_state(cfg: ProxyConfig, blocklist: Blocklist) -> DashboardState:
    proxy_host = _proxy_bind_host(cfg)
    proxy_url = f"http://{proxy_host}:{cfg.listen_port}/mcp/message"
    return DashboardState(cfg=cfg, blocklist=blocklist, proxy_url=proxy_url)
