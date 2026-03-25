# MCProtector PoC — Demo Guide

End-to-end demonstration of MCProtector intercepting, evaluating, and enforcing
security policy on Model Context Protocol (MCP) requests.

---

## Prerequisites

```bash
pip install -r requirements.txt
```

---

## One-command run

```bash
make poc          # or:  ./demo.sh
```

This single command:
1. Starts the MCP upstream server on **port 9000**
2. Starts the MCProtector proxy on **port 8080**
3. Runs **Scenario A** — legitimate requests (expect ALLOW)
4. Runs **Scenario B** — policy-violating requests (expect DENY)
5. Prints a trace summary (trace IDs grouped by ALLOW / DENY)
6. Replays the first ALLOW trace and first DENY trace in human-readable form
7. Saves all structured events to **`logs/poc.jsonl`**

---

## Expected terminal output

### Services starting

```
[STEP]  Starting MCP upstream server on port 9000...
  Waiting for MCP server (pid 12345)....  ready
[STEP]  Starting MCProtector proxy on port 8080...
  Waiting for MCProtector proxy (pid 12346)....  ready
[OK]    Both services are running.
```

### Scenario A (all ALLOW)

```
============================================================
  SCENARIO A — Legitimate (policy-compliant) requests
============================================================

[Step 1] Listing available tools...
[OK] Found 3 tools: ...
[Step 2] Reading file from allowed path '/project/readme.txt'...
[OK] Tool execution result: ...
[Step 3] Writing to allowed path '/tmp/mcprotector/test.txt'...
[OK] Tool execution result: ...
[*] Scenario A completed - all requests should be ALLOWED
```

### Scenario B (all DENY)

```
============================================================
  SCENARIO B — Denied Request (Policy Violation)
============================================================

[Test 1] R2_UNSAFE_PARAMETER - Attempting to read '/etc/passwd'...
[ERROR] ...
[Test 2] R1_DISALLOWED_TOOL - Attempting to call unknown tool 'execute_command'...
[ERROR] ...
[Test 3] R3_INVALID_ARGUMENTS - Calling 'filesystem.read' without required 'path'...
[ERROR] ...
[Test 4] R2_UNSAFE_PARAMETER - Attempting to write to '/root/.bashrc'...
[ERROR] ...
[*] Scenario B completed - these requests should trigger MCProtector alerts
```

### Trace summary

```
ALLOW traces (Scenario A):
<uuid-1>  tool=tools/list            reason=REQUEST_ACCEPTED
<uuid-2>  tool=filesystem.read       reason=REQUEST_ACCEPTED
<uuid-3>  tool=filesystem.write      reason=REQUEST_ACCEPTED

DENY traces (Scenario B):
<uuid-4>  tool=filesystem.read       reason=UNSAFE_FILE_ACCESS
<uuid-5>  tool=execute_command       reason=UNSAFE_FILE_ACCESS
<uuid-6>  tool=filesystem.read       reason=INVALID_ARGUMENTS
<uuid-7>  tool=filesystem.write      reason=UNSAFE_FILE_ACCESS
```

### Trace replay (Scenario A — ALLOW)

```
── Trace replay: <uuid-2> ─────────────────────────────────
  REQUEST_RECEIVED                decision=NONE        reason=REQUEST_RECEIVED      tool=filesystem.read
  DETECTION_RULE_EVALUATED        decision=NONE        reason=REQUEST_ACCEPTED      tool=filesystem.read
  DETECTION_MODEL_EVALUATED       decision=NONE        reason=RISK_SCORE_OK         tool=filesystem.read  risk=0.30
  DECISION_MADE                   decision=ALLOW       reason=REQUEST_ACCEPTED      tool=filesystem.read
  REQUEST_FORWARDED               decision=ALLOW       reason=REQUEST_ACCEPTED      tool=filesystem.read
  RESPONSE_RETURNED               decision=ALLOW       reason=REQUEST_ACCEPTED      tool=filesystem.read  latency=3ms  upstream_status=200
```

### Trace replay (Scenario B — DENY)

```
── Trace replay: <uuid-4> ─────────────────────────────────
  REQUEST_RECEIVED                decision=NONE        reason=REQUEST_RECEIVED      tool=filesystem.read
  DETECTION_RULE_EVALUATED        decision=NONE        reason=UNSAFE_FILE_ACCESS    tool=filesystem.read
      violation  rule=R1_UNSAFE_FILE_ACCESS  detail=Path '/etc/passwd' resolves outside allowed base
  DECISION_MADE                   decision=DENY        reason=UNSAFE_FILE_ACCESS    tool=filesystem.read
  ACTION_APPLIED                  decision=DENY        reason=UNSAFE_FILE_ACCESS    tool=filesystem.read
```

---

## What the presenter should point at in the logs

| What to show | Where to look | What to say |
|---|---|---|
| Request arrives | `REQUEST_RECEIVED` event | "Every MCP request enters the pipeline here. We capture IP, method, tool name, session ID." |
| Rule evaluation | `DETECTION_RULE_EVALUATED` event | "Deterministic rules run first: R1 checks paths, R2 checks for SQL injection, R3 checks argument completeness." |
| Violations listed | `violations` array in the event | "Each violation names the rule ID and explains why the request failed. Auditors can read this without looking at code." |
| Risk score | `DETECTION_MODEL_EVALUATED` event | "A heuristic scorer adds a 0–1 risk score. Low-risk allowed paths score ≈0.3; dangerous paths score closer to 1.0." |
| Decision | `DECISION_MADE` event | "The proxy combines rule result + risk score and emits a single ALLOW or DENY. One field, unambiguous." |
| Mitigation | `ACTION_APPLIED` event | "On DENY the source IP is added to a blocklist. Subsequent requests from that IP are rejected immediately." |
| Forwarded | `REQUEST_FORWARDED` + `RESPONSE_RETURNED` | "Only ALLOW decisions reach the upstream server. Latency and upstream HTTP status are recorded." |

---

## Replay any trace

```bash
# from the trace summary printed by demo.sh, copy a trace_id, then:
python3 -m poc_logs --trace <trace_id> --file logs/poc.jsonl

# or via make:
make replay TRACE=<trace_id>
```

---

## Individual commands (manual run)

```bash
# Terminal 1 — MCP upstream server
python3 -m mcp_server.server --port 9000

# Terminal 2 — MCProtector proxy (with file logging)
LOG_MODE=console_json_and_file uvicorn proxy.app:app --host 0.0.0.0 --port 8080

# Terminal 3 — Run scenarios
python3 -m mcp_client.client scenario allowed
python3 -m mcp_client.client scenario denied

# Replay a trace
python3 -m poc_logs --trace <trace_id> --file logs/poc.jsonl
```

---

## Acceptance criteria

| Criterion | How to verify |
|---|---|
| Scenario A ends in `DECISION_MADE=ALLOW, REQUEST_FORWARDED, RESPONSE_RETURNED` | Trace replay of any ALLOW trace from `logs/poc.jsonl` |
| Scenario B ends in `DECISION_MADE=DENY, ACTION_APPLIED` | Trace replay of any DENY trace from `logs/poc.jsonl` |
| Presenter can explain decisions using logs only (no code reading) | Every decision has `reason_code`, `reason`, and `violations[]` fields in the JSONL events |

---

## Log file format

Each line in `logs/poc.jsonl` is a JSON object conforming to `schemas/poc_event.schema.json`.

Key fields for audit / explanation:

```jsonc
{
  "timestamp":    "2024-01-01T12:00:00.000Z",
  "event_type":   "DECISION_MADE",          // lifecycle stage
  "decision":     "DENY",                   // ALLOW | DENY | CHALLENGE | NONE
  "reason_code":  "UNSAFE_FILE_ACCESS",     // machine-readable reason
  "reason":       "Rule R1 matched: ...",   // human-readable reason
  "tool_name":    "filesystem.read",        // which MCP tool was called
  "trace_id":     "<uuid>",                 // links all events for one request
  "client_ip":    "10.0.0.50",
  "violations": [                           // filled by rule evaluator
    { "rule": "R1_UNSAFE_FILE_ACCESS", "detail": "..." }
  ],
  "risk_score":   0.70,                     // 0.0–1.0 heuristic score
  "latency_ms":   4.2                       // round-trip to upstream (ALLOW only)
}
```
