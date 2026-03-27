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

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from mcp_client.client import MCPClient, run_scenario
from observability import PoCEvent, now_iso

from .config import ProxyConfig
from .mitigation import Blocklist

SESSION_COOKIE_NAME = "mcprotector_dashboard_session"
SESSION_TTL_SEC = 60 * 60 * 12


@dataclass
class DashboardState:
    cfg: ProxyConfig
    blocklist: Blocklist
    proxy_url: str
    scenario_history: list[dict[str, Any]] = field(default_factory=list)
    scenario_lock: threading.Lock = field(default_factory=threading.Lock)

    def record_scenario(self, result: dict[str, Any]) -> None:
        self.scenario_history.insert(0, result)
        del self.scenario_history[10:]

    def blocklist_entries(self) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        for ip in sorted(list(self.blocklist.entries.keys())):
            remaining = self.blocklist.remaining_sec(ip)
            if remaining is None:
                continue
            entries.append({"ip": ip, "remaining_sec": remaining})
        return entries


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


def _is_alert(event: PoCEvent) -> bool:
    return (
        event.level.value in ("WARN", "ERROR")
        or event.decision.value in ("DENY", "CHALLENGE")
        or event.event_type.value in ("ACTION_APPLIED", "ERROR")
    )


def _build_overview(state: DashboardState) -> dict[str, Any]:
    events = _read_events(state.cfg.log_file_path)
    decision_counts = Counter(
        event.decision.value for event in events if event.decision.value != "NONE"
    )
    tool_counts = Counter(event.tool_name or event.mcp_method for event in events)
    unique_trace_count = len({str(event.trace_id) for event in events})
    unique_client_count = len({event.client_ip for event in events})
    alert_count = sum(1 for event in events if _is_alert(event))
    latest_event = events[0].model_dump(mode="json", exclude_none=False) if events else None
    return {
        "generated_at": now_iso(),
        "proxy_url": state.proxy_url,
        "dashboard_port": state.cfg.dashboard_port,
        "total_events": len(events),
        "alert_count": alert_count,
        "unique_trace_count": unique_trace_count,
        "unique_client_count": unique_client_count,
        "blocklist_count": len(state.blocklist_entries()),
        "decision_counts": dict(decision_counts),
        "top_tools": [
            {"name": name, "count": count}
            for name, count in tool_counts.most_common(5)
        ],
        "latest_event": latest_event,
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
      --ink: #10233b;
      --muted: #5d7088;
      --panel: rgba(255, 255, 255, 0.9);
      --panel-strong: rgba(255, 255, 255, 0.98);
      --border: rgba(16, 35, 59, 0.1);
      --shadow: 0 20px 48px rgba(16, 35, 59, 0.08);
      --accent: #0f766e;
      --accent-soft: rgba(15, 118, 110, 0.12);
      --allow: #14804a;
      --allow-soft: rgba(20, 128, 74, 0.12);
      --warn: #b7791f;
      --warn-soft: rgba(183, 121, 31, 0.14);
      --danger: #c2413c;
      --danger-soft: rgba(194, 65, 60, 0.14);
      --sky: #0f5f9a;
      --bg-a: #f6fbff;
      --bg-b: #edf6f2;
      --bg-c: #f9f6ef;
      --panel-radius: 24px;
      --card-radius: 18px;
      --panel-height: 380px;
      --table-height: 500px;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", "Helvetica Neue", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(15, 118, 110, 0.1), transparent 22%),
        radial-gradient(circle at top right, rgba(15, 95, 154, 0.12), transparent 24%),
        linear-gradient(135deg, var(--bg-a), var(--bg-b) 55%, var(--bg-c));
      min-height: 100vh;
    }}
    .page {{
      width: min(1520px, calc(100vw - 32px));
      margin: 0 auto;
      padding: 20px 0 28px;
    }}
    .topbar {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 18px;
      align-items: end;
      margin-bottom: 18px;
    }}
    .hero {{
      min-width: 0;
    }}
    .eyebrow {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 7px 12px;
      border-radius: 999px;
      background: rgba(255, 255, 255, 0.72);
      border: 1px solid var(--border);
      color: var(--muted);
      font-size: 0.82rem;
      font-weight: 700;
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }}
    .hero h1 {{
      margin: 0;
      font-size: clamp(2.1rem, 4vw, 3.5rem);
      line-height: 1.02;
      letter-spacing: -0.04em;
    }}
    .hero p {{
      margin: 10px 0 0;
      color: var(--muted);
      max-width: 760px;
      line-height: 1.5;
    }}
    .header-actions {{
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: flex-end;
      gap: 12px;
    }}
    .status-chip {{
      padding: 11px 14px;
      border-radius: 999px;
      background: rgba(255, 255, 255, 0.78);
      border: 1px solid var(--border);
      color: var(--muted);
      font-weight: 600;
      font-size: 0.9rem;
      white-space: nowrap;
    }}
    .dashboard-grid {{
      display: grid;
      gap: 18px;
      grid-template-columns: repeat(12, minmax(0, 1fr));
    }}
    .span-12 {{ grid-column: span 12; }}
    .span-7 {{ grid-column: span 7; }}
    .span-5 {{ grid-column: span 5; }}
    .span-4 {{ grid-column: span 4; }}
    .stack {{
      display: grid;
      gap: 18px;
      min-width: 0;
    }}
    .panel {{
      position: relative;
      min-width: 0;
      overflow: hidden;
      background: linear-gradient(180deg, var(--panel-strong), var(--panel));
      border: 1px solid var(--border);
      border-radius: var(--panel-radius);
      padding: 20px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(18px);
    }}
    .panel::before {{
      content: "";
      position: absolute;
      inset: 0 auto auto 0;
      width: 100%;
      height: 1px;
      background: linear-gradient(90deg, rgba(15, 118, 110, 0.32), rgba(15, 95, 154, 0));
    }}
    .panel-head {{
      display: flex;
      justify-content: space-between;
      align-items: start;
      gap: 12px;
      margin-bottom: 16px;
    }}
    .panel-head h2 {{
      margin: 0;
      font-size: 1.15rem;
      letter-spacing: -0.02em;
    }}
    .panel-head p {{
      margin: 6px 0 0;
      color: var(--muted);
      font-size: 0.92rem;
      line-height: 1.45;
    }}
    .metric-grid {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 14px;
    }}
    .metric {{
      min-width: 0;
      min-height: 136px;
      padding: 18px;
      border-radius: var(--card-radius);
      background: rgba(255, 255, 255, 0.72);
      border: 1px solid rgba(16, 35, 59, 0.08);
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }}
    .metric .label {{
      display: block;
      font-size: 0.82rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
      margin-bottom: 8px;
    }}
    .metric strong {{
      font-size: clamp(1.8rem, 3vw, 2.45rem);
      line-height: 1;
    }}
    .metric-note {{
      color: var(--muted);
      font-size: 0.92rem;
      line-height: 1.4;
    }}
    .toolbar {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }}
    button, .ghost {{
      border: none;
      border-radius: 999px;
      padding: 11px 16px;
      font-weight: 700;
      cursor: pointer;
      transition: transform 140ms ease, box-shadow 140ms ease, opacity 140ms ease;
    }}
    button {{
      background: linear-gradient(135deg, var(--ink), var(--sky));
      color: white;
      box-shadow: 0 12px 24px rgba(15, 95, 154, 0.18);
    }}
    button.secondary {{
      background: var(--accent-soft);
      color: var(--accent);
      box-shadow: none;
    }}
    .ghost {{
      background: rgba(16, 35, 59, 0.06);
      color: var(--ink);
    }}
    button:hover, .ghost:hover {{
      transform: translateY(-1px);
    }}
    .status {{
      color: var(--muted);
      font-size: 0.92rem;
      white-space: nowrap;
    }}
    .panel-body {{
      min-width: 0;
    }}
    .panel-fixed {{
      height: var(--panel-height);
      max-height: var(--panel-height);
    }}
    .table-panel {{
      height: var(--table-height);
      max-height: var(--table-height);
    }}
    .scroll-y {{
      overflow-y: auto;
      overflow-x: hidden;
      max-height: calc(100% - 56px);
      padding-right: 4px;
      scrollbar-width: thin;
    }}
    .table-wrap {{
      overflow: auto;
      max-height: calc(100% - 56px);
      border-radius: 18px;
      border: 1px solid rgba(16, 35, 59, 0.08);
      background: rgba(255, 255, 255, 0.65);
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.94rem;
      table-layout: fixed;
    }}
    th, td {{
      padding: 10px 8px;
      text-align: left;
      border-bottom: 1px solid rgba(16, 35, 59, 0.08);
      vertical-align: top;
      word-break: break-word;
      overflow-wrap: anywhere;
    }}
    th {{
      position: sticky;
      top: 0;
      z-index: 1;
      background: rgba(248, 251, 255, 0.96);
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
    }}
    .pill {{
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      padding: 4px 10px;
      font-size: 0.78rem;
      font-weight: 700;
      background: rgba(16, 35, 59, 0.08);
    }}
    .allow {{ color: var(--allow); background: var(--allow-soft); }}
    .deny {{ color: var(--danger); background: var(--danger-soft); }}
    .challenge {{ color: var(--warn); background: var(--warn-soft); }}
    .muted {{ color: var(--muted); }}
    code {{
      font-family: Consolas, "Courier New", monospace;
      font-size: 0.9em;
    }}
    .list {{
      display: grid;
      gap: 10px;
    }}
    .card {{
      min-width: 0;
      border: 1px solid rgba(16, 35, 59, 0.08);
      border-radius: var(--card-radius);
      padding: 14px;
      background: rgba(255, 255, 255, 0.72);
    }}
    .card-row {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
    }}
    .micro-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
    }}
    .mini-stat {{
      min-width: 0;
      padding: 12px;
      border-radius: 16px;
      background: rgba(248, 251, 255, 0.88);
      border: 1px solid rgba(16, 35, 59, 0.08);
    }}
    .mini-stat .value {{
      display: block;
      margin-top: 4px;
      font-size: 1.15rem;
      font-weight: 700;
      color: var(--ink);
    }}
    .kicker {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 5px 10px;
      border-radius: 999px;
      background: rgba(16, 35, 59, 0.05);
      color: var(--muted);
      font-size: 0.78rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }}
    .chart-grid {{
      display: grid;
      grid-template-columns: 220px minmax(0, 1fr);
      gap: 18px;
      align-items: center;
      min-height: 0;
      height: calc(100% - 56px);
    }}
    .chart-wrap {{
      display: grid;
      place-items: center;
      min-height: 220px;
    }}
    .pie-chart {{
      --allow-angle: 0deg;
      --deny-angle: 0deg;
      width: min(220px, 100%);
      aspect-ratio: 1;
      border-radius: 50%;
      background:
        radial-gradient(circle at center, rgba(255, 255, 255, 0.94) 0 33%, transparent 34%),
        conic-gradient(
          var(--allow) 0deg var(--allow-angle),
          var(--danger) var(--allow-angle) calc(var(--allow-angle) + var(--deny-angle)),
          var(--warn) calc(var(--allow-angle) + var(--deny-angle)) 360deg
        );
      border: 16px solid rgba(255, 255, 255, 0.62);
      box-shadow: inset 0 0 0 1px rgba(16, 35, 59, 0.08);
      position: relative;
    }}
    .pie-center {{
      position: absolute;
      inset: 50% auto auto 50%;
      transform: translate(-50%, -50%);
      text-align: center;
      width: 110px;
    }}
    .pie-center strong {{
      display: block;
      font-size: 1.9rem;
      line-height: 1;
    }}
    .pie-center span {{
      color: var(--muted);
      font-size: 0.82rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }}
    .legend {{
      display: grid;
      gap: 12px;
      align-content: start;
    }}
    .legend-item {{
      display: grid;
      grid-template-columns: auto minmax(0, 1fr) auto;
      gap: 10px;
      align-items: center;
      padding: 12px 14px;
      border-radius: 16px;
      background: rgba(255, 255, 255, 0.72);
      border: 1px solid rgba(16, 35, 59, 0.08);
    }}
    .swatch {{
      width: 12px;
      height: 12px;
      border-radius: 50%;
    }}
    .swatch.allow {{ background: var(--allow); }}
    .swatch.deny {{ background: var(--danger); }}
    .swatch.challenge {{ background: var(--warn); }}
    .legend strong {{
      font-size: 1rem;
    }}
    .legend small {{
      color: var(--muted);
      font-size: 0.84rem;
    }}
    .tool-item, .block-item {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
    }}
    .bar-track {{
      flex: 1 1 auto;
      height: 8px;
      border-radius: 999px;
      background: rgba(16, 35, 59, 0.08);
      overflow: hidden;
      min-width: 60px;
    }}
    .bar-fill {{
      height: 100%;
      border-radius: inherit;
      background: linear-gradient(90deg, var(--accent), var(--sky));
    }}
    .scenario-steps {{
      margin-top: 10px;
      border-top: 1px solid rgba(16, 35, 59, 0.08);
    }}
    .scenario-step {{
      padding: 10px 0;
      border-top: 1px solid rgba(16, 35, 59, 0.08);
    }}
    .scenario-step:first-child {{
      border-top: none;
    }}
    .timestamp {{
      white-space: nowrap;
    }}
    .trace {{
      display: inline-block;
      max-width: 220px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      vertical-align: bottom;
    }}
    .subtle {{
      color: var(--muted);
      font-size: 0.84rem;
    }}
    @media (max-width: 1280px) {{
      .metric-grid {{
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }}
      .span-7, .span-5, .span-4 {{
        grid-column: span 12;
      }}
    }}
    @media (max-width: 980px) {{
      .page {{
        width: calc(100vw - 16px);
        padding-top: 16px;
      }}
      .topbar {{
        grid-template-columns: 1fr;
        align-items: start;
      }}
      .header-actions {{
        justify-content: flex-start;
      }}
      .chart-grid {{
        grid-template-columns: 1fr;
      }}
      .metric-grid {{
        grid-template-columns: 1fr;
      }}
      .panel-fixed, .table-panel {{
        height: auto;
        max-height: none;
      }}
      .scroll-y, .table-wrap {{
        max-height: 420px;
      }}
      .micro-grid {{
        grid-template-columns: 1fr;
      }}
    }}
  </style>
</head>
<body>
  <main class="page">
    <section class="topbar">
      <div class="hero">
        <span class="eyebrow">MCProtector Proxy Control Surface</span>
        <h1>Clear signal, live numbers, and zero-overflow monitoring.</h1>
        <p>Track proxy decisions, alert pressure, scenario runs, and upstream traffic on <code>{state.proxy_url}</code> through a bounded grid layout designed to stay readable on both desktop and mobile.</p>
      </div>
      <div class="header-actions">
        <span class="status-chip" id="status">Loading live data...</span>
        <form method="post" action="/logout">
          <button class="ghost" type="submit">Log Out</button>
        </form>
      </div>
    </section>

    <section class="dashboard-grid">
      <section class="panel span-12">
        <div class="panel-head">
          <div>
            <span class="kicker">Numbers</span>
            <h2>Operational snapshot</h2>
            <p>Fast totals for events, alerts, traces, and blocked sources.</p>
          </div>
        </div>
        <div class="metric-grid" id="metrics"></div>
      </section>

      <section class="panel panel-fixed span-4">
        <div class="panel-head">
          <div>
            <span class="kicker">Chart</span>
            <h2>Decision split</h2>
            <p>Pie view of current allow, deny, and challenge outcomes.</p>
          </div>
        </div>
        <div class="chart-grid panel-body">
          <div class="chart-wrap">
            <div class="pie-chart" id="decision-chart">
              <div class="pie-center">
                <strong id="decision-total">0</strong>
                <span>decisions</span>
              </div>
            </div>
          </div>
          <div class="legend" id="decision-legend"></div>
        </div>
      </section>

      <section class="panel panel-fixed span-4">
        <div class="panel-head">
          <div>
            <span class="kicker">Controls</span>
            <h2>Scenario launcher</h2>
            <p>Send clean or malicious test traffic through the proxy.</p>
          </div>
        </div>
        <div class="stack panel-body">
          <div class="toolbar">
            <button type="button" onclick="runScenario('allowed')">Run Allowed Scenario</button>
            <button class="secondary" type="button" onclick="runScenario('denied')">Run Denied Scenario</button>
            <button class="ghost" type="button" onclick="refreshDashboard()">Refresh</button>
          </div>
          <div class="micro-grid" id="system-overview"></div>
          <div class="scroll-y">
            <div class="list" id="scenarios"></div>
          </div>
        </div>
      </section>

      <section class="panel panel-fixed span-4">
        <div class="panel-head">
          <div>
            <span class="kicker">Capacity</span>
            <h2>Traffic focus</h2>
            <p>Top-used tools and active blocklist entries.</p>
          </div>
        </div>
        <div class="stack panel-body">
          <div>
            <div class="subtle" style="margin-bottom:10px;">Top tools</div>
            <div class="list" id="top-tools"></div>
          </div>
          <div>
            <div class="subtle" style="margin-bottom:10px;">Blocklist</div>
            <div class="scroll-y" style="max-height: 150px;">
              <div class="list" id="blocklist"></div>
            </div>
          </div>
        </div>
      </section>

      <section class="panel panel-fixed span-7">
        <div class="panel-head">
          <div>
            <span class="kicker">Alerts</span>
            <h2>Recent alert stream</h2>
            <p>Warnings, denies, challenges, and mitigation actions.</p>
          </div>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th style="width: 22%;">Time</th>
                <th style="width: 21%;">Event</th>
                <th style="width: 17%;">Decision</th>
                <th style="width: 20%;">Tool</th>
                <th style="width: 20%;">Reason</th>
              </tr>
            </thead>
            <tbody id="alerts"></tbody>
          </table>
        </div>
      </section>

      <section class="panel panel-fixed span-5">
        <div class="panel-head">
          <div>
            <span class="kicker">Latest</span>
            <h2>Latest event detail</h2>
            <p>The newest event emitted by the proxy log stream.</p>
          </div>
        </div>
        <div class="scroll-y">
          <div id="latest-event"></div>
        </div>
      </section>

      <section class="panel table-panel span-12">
        <div class="panel-head">
          <div>
            <span class="kicker">Logs</span>
            <h2>Recent proxy events</h2>
            <p>Bounded event table with sticky headers and controlled overflow.</p>
          </div>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th style="width: 16%;">Time</th>
                <th style="width: 18%;">Type</th>
                <th style="width: 19%;">Trace</th>
                <th style="width: 12%;">Decision</th>
                <th style="width: 15%;">Tool</th>
                <th style="width: 20%;">Reason</th>
              </tr>
            </thead>
            <tbody id="events"></tbody>
          </table>
        </div>
      </section>
    </section>
  </main>

  <script>
    function escapeHtml(value) {{
      return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
    }}

    function decisionPill(decision) {{
      const lower = String(decision || "NONE").toLowerCase();
      const css = lower === "allow" ? "allow" : lower === "deny" ? "deny" : lower === "challenge" ? "challenge" : "";
      return `<span class="pill ${{css}}">${{escapeHtml(decision || "NONE")}}</span>`;
    }}

    function metricCard(label, value, note, tone) {{
      return `
        <article class="metric" style="${{tone || ''}}">
          <span class="label">${{escapeHtml(label)}}</span>
          <strong>${{escapeHtml(value)}}</strong>
          <div class="metric-note">${{escapeHtml(note)}}</div>
        </article>
      `;
    }}

    function percentage(part, total) {{
      if (!total) {{
        return 0;
      }}
      return Math.round((part / total) * 100);
    }}

    async function api(path, options) {{
      const response = await fetch(path, Object.assign({{ credentials: "same-origin" }}, options || {{}}));
      if (response.status === 401) {{
        window.location = "/login";
        return null;
      }}
      return response.json();
    }}

    function renderMetrics(data) {{
      const decisions = data.decision_counts || {{}};
      const latest = data.latest_event?.timestamp || "No events yet";
      document.getElementById("metrics").innerHTML = [
        metricCard("Total events", data.total_events || 0, "All structured log events currently loaded.", ""),
        metricCard("Alerts", data.alert_count || 0, "Warn, error, deny, challenge, and mitigation events.", "background: linear-gradient(180deg, rgba(194,65,60,0.09), rgba(255,255,255,0.8));"),
        metricCard("Unique traces", data.unique_trace_count || 0, "Distinct request lifecycles seen in the log file.", ""),
        metricCard("Blocked IPs", data.blocklist_count || 0, "Currently active entries in the in-memory blocklist.", ""),
        metricCard("Allowed", decisions.ALLOW || 0, "Requests that were forwarded upstream.", "background: linear-gradient(180deg, rgba(20,128,74,0.08), rgba(255,255,255,0.8));"),
        metricCard("Denied", decisions.DENY || 0, "Requests blocked by policy or blocklist.", "background: linear-gradient(180deg, rgba(194,65,60,0.08), rgba(255,255,255,0.8));"),
        metricCard("Challenged", decisions.CHALLENGE || 0, "High-risk requests flagged for challenge.", "background: linear-gradient(180deg, rgba(183,121,31,0.08), rgba(255,255,255,0.8));"),
        metricCard("Last event", latest, "Most recent event timestamp from the proxy.", ""),
      ].join("");
    }}

    function renderTopTools(tools) {{
      const target = document.getElementById("top-tools");
      if (!tools.length) {{
        target.innerHTML = `<div class="card muted">No traffic yet.</div>`;
        return;
      }}
      const max = Math.max(...tools.map(tool => tool.count), 1);
      target.innerHTML = tools.map(tool => `
        <div class="card">
          <div class="tool-item">
            <strong><code>${{escapeHtml(tool.name)}}</code></strong>
            <span class="pill">${{tool.count}}</span>
          </div>
          <div style="margin-top:10px;" class="bar-track">
            <div class="bar-fill" style="width:${{Math.max(8, Math.round((tool.count / max) * 100))}}%;"></div>
          </div>
        </div>
      `).join("");
    }}

    function renderBlocklist(entries) {{
      const target = document.getElementById("blocklist");
      if (!entries.length) {{
        target.innerHTML = `<div class="card muted">No IPs are currently blocked.</div>`;
        return;
      }}
      target.innerHTML = entries.map(entry => `
        <div class="card">
          <div class="block-item">
            <strong><code>${{escapeHtml(entry.ip)}}</code></strong>
            <span class="pill deny">${{entry.remaining_sec}}s</span>
          </div>
          <div class="subtle" style="margin-top:8px;">Remaining block duration</div>
        </div>
      `).join("");
    }}

    function renderAlerts(rows) {{
      const target = document.getElementById("alerts");
      if (!rows.length) {{
        target.innerHTML = `<tr><td colspan="5" class="muted">No alerts yet.</td></tr>`;
        return;
      }}
      target.innerHTML = rows.map(event => `
        <tr>
          <td class="timestamp">${{escapeHtml(event.timestamp)}}</td>
          <td>${{escapeHtml(event.event_type)}}</td>
          <td>${{decisionPill(event.decision)}}</td>
          <td><code>${{escapeHtml(event.tool_name || event.mcp_method)}}</code></td>
          <td>${{escapeHtml(event.reason_code)}}<br><span class="muted">${{escapeHtml(event.reason)}}</span></td>
        </tr>
      `).join("");
    }}

    function renderEvents(rows) {{
      const target = document.getElementById("events");
      if (!rows.length) {{
        target.innerHTML = `<tr><td colspan="6" class="muted">No events recorded yet.</td></tr>`;
        return;
      }}
      target.innerHTML = rows.map(event => `
        <tr>
          <td class="timestamp">${{escapeHtml(event.timestamp)}}</td>
          <td>${{escapeHtml(event.event_type)}}</td>
          <td><code class="trace" title="${{escapeHtml(event.trace_id)}}">${{escapeHtml(event.trace_id)}}</code></td>
          <td>${{decisionPill(event.decision)}}</td>
          <td><code>${{escapeHtml(event.tool_name || event.mcp_method)}}</code></td>
          <td>${{escapeHtml(event.reason_code)}}</td>
        </tr>
      `).join("");
    }}

    function renderScenarios(rows) {{
      const target = document.getElementById("scenarios");
      if (!rows.length) {{
        target.innerHTML = `<div class="card muted">Run a scenario to generate traffic through the proxy.</div>`;
        return;
      }}
      target.innerHTML = rows.map(run => `
        <div class="card">
          <div class="card-row">
            <strong>${{escapeHtml(run.title || run.name)}}</strong>
            ${{decisionPill(run.passed ? "ALLOW" : "DENY")}}
          </div>
          <div class="muted" style="margin-top:8px;">Completed at ${{escapeHtml(run.completed_at)}}</div>
          <div class="scenario-steps">${{run.steps.map(step => `
            <div class="scenario-step">
              <strong>${{escapeHtml(step.title)}}</strong>:
              ${{escapeHtml(step.detail)}}
              <div class="muted">Expected ${{escapeHtml(step.expected_outcome)}}, got ${{escapeHtml(step.actual_outcome)}}</div>
            </div>
          `).join("")}}</div>
        </div>
      `).join("");
    }}

    function renderDecisionChart(data) {{
      const decisions = data.decision_counts || {{}};
      const allow = decisions.ALLOW || 0;
      const deny = decisions.DENY || 0;
      const challenge = decisions.CHALLENGE || 0;
      const total = allow + deny + challenge;
      const allowAngle = total ? Math.round((allow / total) * 360) : 0;
      const denyAngle = total ? Math.round((deny / total) * 360) : 0;
      const chart = document.getElementById("decision-chart");
      chart.style.setProperty("--allow-angle", allowAngle + "deg");
      chart.style.setProperty("--deny-angle", denyAngle + "deg");
      document.getElementById("decision-total").textContent = total;
      document.getElementById("decision-legend").innerHTML = [
        {{ label: "Allowed", count: allow, css: "allow" }},
        {{ label: "Denied", count: deny, css: "deny" }},
        {{ label: "Challenged", count: challenge, css: "challenge" }},
      ].map(item => `
        <div class="legend-item">
          <span class="swatch ${{item.css}}"></span>
          <div>
            <strong>${{item.label}}</strong>
            <small>${{percentage(item.count, total)}}% of all decisions</small>
          </div>
          <span class="pill ${{item.css}}">${{item.count}}</span>
        </div>
      `).join("");
    }}

    function renderOverviewCards(data) {{
      const latest = data.latest_event || null;
      const proxyPort = (() => {{
        try {{
          return new URL(data.proxy_url).port || "80";
        }} catch (error) {{
          return "?";
        }}
      }})();
      document.getElementById("system-overview").innerHTML = `
        <div class="mini-stat">
          <span class="subtle">Proxy endpoint</span>
          <span class="value"><code>${{escapeHtml(proxyPort)}}</code></span>
        </div>
        <div class="mini-stat">
          <span class="subtle">Dashboard port</span>
          <span class="value"><code>${{escapeHtml(data.dashboard_port)}}</code></span>
        </div>
        <div class="mini-stat">
          <span class="subtle">Unique clients</span>
          <span class="value">${{escapeHtml(data.unique_client_count || 0)}}</span>
        </div>
        <div class="mini-stat">
          <span class="subtle">Latest event</span>
          <span class="value" style="font-size:0.95rem;">${{escapeHtml(latest?.event_type || "None")}}</span>
        </div>
      `;
    }}

    function renderLatestEvent(event) {{
      const target = document.getElementById("latest-event");
      if (!event) {{
        target.innerHTML = `<div class="card muted">No events have been logged yet.</div>`;
        return;
      }}
      target.innerHTML = `
        <article class="card">
          <div class="card-row">
            <strong>${{escapeHtml(event.event_type)}}</strong>
            ${{decisionPill(event.decision)}}
          </div>
          <div class="subtle" style="margin-top:8px;">${{escapeHtml(event.timestamp)}}</div>
          <div style="margin-top:14px;" class="list">
            <div><span class="subtle">Trace</span><br><code>${{escapeHtml(event.trace_id)}}</code></div>
            <div><span class="subtle">Tool</span><br><code>${{escapeHtml(event.tool_name || event.mcp_method)}}</code></div>
            <div><span class="subtle">Reason</span><br>${{escapeHtml(event.reason_code)}}<div class="subtle" style="margin-top:4px;">${{escapeHtml(event.reason)}}</div></div>
            <div><span class="subtle">Client IP</span><br><code>${{escapeHtml(event.client_ip)}}</code></div>
          </div>
        </article>
      `;
    }}

    async function refreshDashboard() {{
      document.getElementById("status").textContent = "Refreshing live data...";
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
      renderMetrics(overview);
      renderDecisionChart(overview);
      renderOverviewCards(overview);
      renderTopTools(overview.top_tools || []);
      renderAlerts(alerts.alerts || []);
      renderEvents(events.events || []);
      renderScenarios(scenarios.runs || []);
      renderBlocklist(blocklist.entries || []);
      renderLatestEvent(overview.latest_event || null);
      document.getElementById("status").textContent = "Last updated " + new Date().toLocaleTimeString();
    }}

    async function runScenario(name) {{
      document.getElementById("status").textContent = `Running ${{name}} scenario...`;
      const response = await api(`/api/scenarios/${{name}}/run`, {{
        method: "POST",
        headers: {{ "Content-Type": "application/json" }},
      }});
      if (response) {{
        await refreshDashboard();
      }}
    }}

    refreshDashboard();
    setInterval(refreshDashboard, 5000);
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
        return JSONResponse({"alerts": _serialize_events(alerts_only[:max(1, min(limit, 200))])})

    @app.get("/api/blocklist")
    async def blocklist(request: Request) -> JSONResponse:
        _require_auth(request, state)
        return JSONResponse({"entries": state.blocklist_entries()})

    @app.get("/api/scenarios")
    async def scenarios(request: Request) -> JSONResponse:
        _require_auth(request, state)
        return JSONResponse({"runs": state.scenario_history})

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
