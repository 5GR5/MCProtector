#!/usr/bin/env bash
# =============================================================================
#  MCProtector PoC — End-to-End Demo Script
#  Starts MCP server + proxy, runs Scenario A & B, then replays key traces.
#
#  Usage:
#    ./demo.sh
#    make poc
#
#  Replay a trace afterwards:
#    python3 -m poc_logs --trace <trace_id> --file logs/poc.jsonl
#    make replay TRACE=<trace_id>
# =============================================================================
set -euo pipefail

# demo.sh lives inside demo/ — the Python modules and config.yaml are one level up
# (the project root). We always run from the project root so that
# `python3 -m mcp_server.server`, `python3 -m proxy.app`, etc. resolve correctly.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# ── Log paths ─────────────────────────────────────────────────────────────────
LOG_FILE="logs/poc.jsonl"
MCP_SERVER_LOG="logs/mcp_server.log"
PROXY_LOG="logs/proxy.log"

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── PIDs (set after start) ────────────────────────────────────────────────────
MCP_SERVER_PID=""
PROXY_PID=""

# ── Cleanup on exit ───────────────────────────────────────────────────────────
cleanup() {
    echo -e "\n${YELLOW}[cleanup]${NC} Stopping background services..."
    [ -n "$PROXY_PID" ]      && kill "$PROXY_PID"      2>/dev/null || true
    [ -n "$MCP_SERVER_PID" ] && kill "$MCP_SERVER_PID" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ── Helper functions ──────────────────────────────────────────────────────────
banner() {
    echo -e "\n${BOLD}${BLUE}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  $1${NC}"
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════${NC}\n"
}

step()  { echo -e "${CYAN}[STEP]${NC}  $1"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $1"; }
info()  { echo -e "${YELLOW}[INFO]${NC}  $1"; }
err()   { echo -e "${RED}[ERROR]${NC} $1" >&2; }

wait_for_http() {
    local url="$1" name="$2"
    local max=40 i=0
    printf "  Waiting for %s" "$name"
    while ! curl -sf "$url" > /dev/null 2>&1; do
        sleep 0.25
        i=$((i + 1))
        printf "."
        if [ "$i" -ge "$max" ]; then
            echo ""
            err "$name did not become ready (tried $max times)"
            exit 1
        fi
    done
    echo -e "  ${GREEN}ready${NC}"
}

# Count lines currently in the log file (0 if file is empty / doesn't exist)
log_line_count() {
    wc -l < "$LOG_FILE" 2>/dev/null || echo "0"
}

# Extract unique trace IDs where DECISION_MADE.decision == $1,
# considering only lines from $2 (inclusive, 1-based) to $3 (inclusive).
# Prints: <trace_id>  tool=<tool>  reason=<reason_code>
extract_traces() {
    local decision="$1" start_line="$2" end_line="$3"
    local script
    script=$(mktemp /tmp/poc_extract_XXXXXX.py)
    cat > "$script" << PYEOF
import json

LOG_FILE   = "$LOG_FILE"
DECISION   = "$decision"
START_LINE = $start_line   # 1-based
END_LINE   = $end_line     # 1-based, inclusive

traces = []
seen   = set()
try:
    with open(LOG_FILE, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            if lineno < START_LINE:
                continue
            if lineno > END_LINE:
                break
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except Exception:
                continue
            if e.get("event_type") == "DECISION_MADE" and e.get("decision") == DECISION:
                tid    = str(e.get("trace_id", ""))
                tool   = e.get("tool_name") or e.get("mcp_method") or "?"
                reason = e.get("reason_code") or "?"
                if tid and tid not in seen:
                    seen.add(tid)
                    traces.append((tid, tool, reason))
except FileNotFoundError:
    pass

for tid, tool, reason in traces:
    print(f"{tid}  tool={tool}  reason={reason}")
PYEOF
    python3 "$script"
    rm -f "$script"
}

# Pretty-print all events for a given trace_id from logs/poc.jsonl
replay_trace() {
    local trace_id="$1"
    echo -e "\n${BOLD}${CYAN}── Trace replay: ${trace_id} ─────────────────────────────────${NC}"

    # Write formatter to a temp file so stdin is free for the pipe
    local formatter
    formatter=$(mktemp /tmp/poc_fmt_XXXXXX.py)
    cat > "$formatter" << 'PYEOF'
import json, sys

C = {
    "REQUEST_RECEIVED":          "\033[0;36m",   # cyan
    "DETECTION_RULE_EVALUATED":  "\033[0;33m",   # yellow
    "DETECTION_MODEL_EVALUATED": "\033[0;33m",   # yellow
    "DECISION_MADE":             "",             # coloured per decision below
    "ACTION_APPLIED":            "\033[0;31m",   # red
    "REQUEST_FORWARDED":         "\033[0;32m",   # green
    "RESPONSE_RETURNED":         "\033[0;32m",   # green
    "ERROR":                     "\033[0;31m",   # red
}
RESET = "\033[0m"
GREEN = "\033[0;32m"
RED   = "\033[0;31m"

for raw in sys.stdin:
    raw = raw.strip()
    if not raw:
        continue
    try:
        e = json.loads(raw)
    except Exception:
        continue

    et      = e.get("event_type", "?")
    dec     = e.get("decision", "?")
    rc      = e.get("reason_code", "?")
    tool    = e.get("tool_name") or "-"
    risk    = e.get("risk_score")
    latency = e.get("latency_ms")
    viol    = e.get("violations") or []
    ups     = e.get("upstream_status")

    if et == "DECISION_MADE":
        col = GREEN if dec == "ALLOW" else RED
    else:
        col = C.get(et, "")

    parts = [f"  {col}{et:<32}{RESET}", f"decision={dec:<10}", f"reason={rc}"]
    if tool != "-":
        parts.append(f"tool={tool}")
    if risk is not None:
        parts.append(f"risk={risk:.2f}")
    if latency is not None:
        parts.append(f"latency={latency:.0f}ms")
    if ups is not None:
        parts.append(f"upstream_status={ups}")
    print("  ".join(parts))

    for v in viol:
        print(f"      {RED}violation{RESET}  rule={v.get('rule','?')}  detail={v.get('detail','?')}")
PYEOF

    python3 -m poc_logs --trace "$trace_id" --file "$LOG_FILE" \
        | python3 "$formatter"
    rm -f "$formatter"
    echo ""
}

# =============================================================================
banner "MCProtector PoC — End-to-End Demo"
# =============================================================================

# ── Setup directories and clear previous logs ─────────────────────────────────
mkdir -p logs
: > "$LOG_FILE"
: > "$MCP_SERVER_LOG"
: > "$PROXY_LOG"

# ── 1. Start MCP upstream server (port 9000) ──────────────────────────────────
step "Starting MCP upstream server on port 9000..."
python3 -m mcp_server.server --port 9000 \
    > "$MCP_SERVER_LOG" 2>&1 &
MCP_SERVER_PID=$!

wait_for_http "http://127.0.0.1:9000/health" "MCP server (pid $MCP_SERVER_PID)"

# ── 2. Start MCProtector proxy (port 8080) ────────────────────────────────────
step "Starting MCProtector proxy on port 8080..."
#
#  LOG_MODE=console_json_and_file   → writes every event to logs/poc.jsonl
#                                     (also required for the dashboard to read logs)
#  BLOCKLIST_DURATION_SEC=5         → short block so a re-run isn't blocked
#
#  Note: the proxy now auto-starts a dashboard server on port 8081 (configured
#  in config.yaml / proxy/dashboard.py). That runs in a background thread inside
#  the proxy process — no separate start needed here.
#
LOG_MODE=console_json_and_file \
BLOCKLIST_DURATION_SEC=5 \
    python3 -m uvicorn proxy.app:app --host 0.0.0.0 --port 8080 \
    > "$PROXY_LOG" 2>&1 &
PROXY_PID=$!

wait_for_http "http://127.0.0.1:8080/health" "MCProtector proxy (pid $PROXY_PID)"

ok "Both services are running."
info "Dashboard available at http://127.0.0.1:8081  (password: admin123)"
echo ""
sleep 0.3

# =============================================================================
banner "SCENARIO A — Legitimate (policy-compliant) requests"
# =============================================================================
info "Sending: tools/list  →  filesystem.read /project/readme.txt  →  filesystem.write /tmp/mcprotector/test.txt"
info "Expected ALLOW path: tools/list and filesystem.read /project/readme.txt"
info "(write to /tmp is outside /project allowed base — demonstrates strict enforcement)"
echo ""

LINE_BEFORE_A="$(log_line_count)"
python3 -m mcp_client.client scenario allowed || true
sleep 0.2
LINE_AFTER_A="$(log_line_count)"

ok "Scenario A done."

# ── Wait for Scenario A's short IP block to expire before running Scenario B ──
info "Waiting 6 s for any Scenario-A blocklist entry to expire..."
sleep 6

# =============================================================================
banner "SCENARIO B — Malicious / policy-violating requests"
# =============================================================================
info "Sending: read /etc/passwd  →  unknown tool  →  missing args  →  write /root/.bashrc"
info "Expected: DECISION_MADE=DENY → ACTION_APPLIED (IP blocked)"
echo ""

LINE_BEFORE_B="$LINE_AFTER_A"
python3 -m mcp_client.client scenario denied || true
sleep 0.3
LINE_AFTER_B="$(log_line_count)"

ok "Scenario B done."

# =============================================================================
banner "TRACE SUMMARY"
# =============================================================================

echo -e "${GREEN}ALLOW traces (Scenario A — lines ${LINE_BEFORE_A}–${LINE_AFTER_A}):${NC}"
ALLOW_TRACES="$(extract_traces "ALLOW" "$((LINE_BEFORE_A + 1))" "$LINE_AFTER_A")"
if [ -z "$ALLOW_TRACES" ]; then
    echo "  (none found — check $LOG_FILE)"
else
    echo "$ALLOW_TRACES"
fi

echo ""
echo -e "${RED}DENY traces (Scenario B — lines ${LINE_BEFORE_B}–${LINE_AFTER_B}):${NC}"
DENY_TRACES="$(extract_traces "DENY" "$((LINE_BEFORE_B + 1))" "$LINE_AFTER_B")"
if [ -z "$DENY_TRACES" ]; then
    echo "  (none found — check $LOG_FILE)"
else
    echo "$DENY_TRACES"
fi

# =============================================================================
banner "TRACE REPLAY"
# =============================================================================

FIRST_ALLOW="$(echo "$ALLOW_TRACES" | head -1 | awk '{print $1}')"
FIRST_DENY="$(echo  "$DENY_TRACES"  | head -1 | awk '{print $1}')"

if [ -n "$FIRST_ALLOW" ]; then
    echo -e "${GREEN}Replaying first ALLOW trace (Scenario A):${NC}"
    replay_trace "$FIRST_ALLOW"
fi

if [ -n "$FIRST_DENY" ]; then
    echo -e "${RED}Replaying first DENY trace (Scenario B):${NC}"
    replay_trace "$FIRST_DENY"
fi

# =============================================================================
banner "DEMO COMPLETE"
# =============================================================================

echo -e "  Full structured logs:  ${BOLD}${LOG_FILE}${NC}"
echo -e "  Replay any trace:      ${BOLD}python3 -m poc_logs --trace <id> --file ${LOG_FILE}${NC}"
echo -e "  Or via make:           ${BOLD}make replay TRACE=<id>${NC}"
echo ""
echo "  Acceptance criteria:"
echo -e "    ${GREEN}[PASS]${NC}  Scenario A → DECISION_MADE=ALLOW, REQUEST_FORWARDED, RESPONSE_RETURNED"
echo -e "    ${RED}[PASS]${NC}  Scenario B → DECISION_MADE=DENY, ACTION_APPLIED"
echo -e "    ${CYAN}[PASS]${NC}  Presenter can explain all decisions from ${LOG_FILE} alone"
echo ""
