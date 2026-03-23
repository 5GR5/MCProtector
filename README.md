
# MCProtector Proxy PoC (Local)

This package is a runnable PoC proxy that:

* receives MCP JSON-RPC requests (`POST /mcp/message`)
* normalizes them into a `NormalizedRequest`
* runs rule detection and optional model scoring
* decides ALLOW / DENY / CHALLENGE
* applies mitigation (in-memory IP blocklist)
* forwards to a local MCP server when allowed
* emits structured JSON events for every stage

---

## 🧠 Observability System

The proxy includes a  **structured observability pipeline** .

Instead of ad-hoc logs, every event:

* follows a **strict schema**
* is emitted at **well-defined lifecycle stages**
* is easy to consume by **humans, CLI tools, and dashboards**

### Event Model (`PoCEvent`)

All logs follow a shared structure.

**Core fields:**

* `timestamp`, `level`, `event_type`
* `component`, `request_id`, `trace_id`
* `client_ip`, `decision`, `reason`

**Optional groups:**

* Rules (OPA): policy results, violations
* Model: risk score, model metadata
* Actions: mitigation actions
* Performance: latency metrics

This guarantees:

* consistent logs
* predictable structure
* early validation of invalid events

---

## 📊 Dashboard-Friendly Logs

Each event is a flat JSON object:

```json
{
  "timestamp": "...",
  "event_type": "REQUEST_RECEIVED",
  "decision": "NONE",
  "tool_name": "filesystem.read",
  "latency_ms": null
}
```

Enables:

* timeline views (`timestamp`)
* request tracing (`trace_id`)
* filtering (`event_type`)
* decision tracking (`ALLOW / DENY`)
* performance analysis (`latency_ms`, `stage_latency_ms`)

---

## ⚙️ Event Emission

Events are emitted via a shared API:

```python
emitter.emit_request_received(...)
```

Benefits:

* avoids missing fields
* enforces consistent values
* simplifies maintenance

---

## 📤 Logging Outputs

* `stdout` → live JSON stream
* `logs/poc.jsonl` → persistent log storage

👉 Console = real-time debugging
👉 File = full history for analysis / replay

---

## 🔍 Trace Filtering

Focus on a single request lifecycle:

```text
trace_filter = "<trace_id>"
```

* console shows only that trace
* file still contains all events

---

## 🔄 Request Lifecycle

Each request follows a fixed flow:

1. `REQUEST_RECEIVED`
2. Rule evaluation (OPA)
3. Model scoring (risk)
4. `DECISION_MADE` (ALLOW / DENY / CHALLENGE)
5. Optional mitigation (e.g. block IP)
6. Request forwarding (if allowed)
7. `RESPONSE_RETURNED`
8. Error handling

---

## ✅ Example (Allowed)

```json
{
  "path": "/project/data/report.txt"
}
```

Flow:

* REQUEST_RECEIVED
* RULE → ALLOW
* MODEL → low risk
* DECISION → ALLOW
* REQUEST_FORWARDED
* RESPONSE_RETURNED

---

## ❌ Example (Denied)

```json
{
  "path": "/etc/passwd"
}
```

Flow:

* REQUEST_RECEIVED
* RULE → DENY (`UNSAFE_FILE_ACCESS`)
* DECISION → DENY
* ACTION → BLOCK_IP

(No forwarding, no response)

---

## 📜 Schema

Defined in:

```
schemas/poc_event.schema.json
```

Provides:

* strict contract for all events
* validation
* clear structure for dashboards and tooling

---

## 🧰 CLI (Log Exploration)

```bash
python -m poc_logs --trace <trace_id> --file logs/poc.jsonl
```

Features:

* filters by trace
* sorts by timestamp
* outputs structured JSON

Acts as a lightweight  **text-based dashboard** .

---

## ⏱️ Latency Metrics

* `stage_latency_ms` → per-stage timing
* `latency_ms` → full operation time

Used to identify bottlenecks.

---

## 🧠 Mental Model

```
Request → lifecycle stages →
each stage emits a structured event →
logs → console + file →
CLI / dashboard consume the same data
```

---

## Install

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

---

## Run (HTTP)

```bash
uvicorn proxy.app:app --host 0.0.0.0 --port 8080
```

Update `config.yaml`:

* `upstream_url: "http://127.0.0.1:9000/mcp/message"`

---

## Run with HTTPS / TLS termination (Option A)

Generate dev certificate:

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
```

Run:

```bash
uvicorn proxy.app:app --host 0.0.0.0 --port 8080 --ssl-keyfile key.pem --ssl-certfile cert.pem
```

Test:

```bash
curl -k https://localhost:8080/health
```

---

## Example Request (ALLOW path)

```bash
curl -s http://localhost:8080/mcp/message \
  -H "Content-Type: application/json" \
  -H "X-Session-Id: sess-1" \
  -H "Authorization: Bearer demo-token" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.write","arguments":{"path":"/tmp/a.txt","content":"hi"}}}'
```

You should see:

* JSON events → stdout
* human-readable summary → stderr

---

## MCP Server (Test Backend)

### Run

```bash
python -m mcp_server.server --port 9000
```

### Tools

| Tool             | Description     | Arguments            |
| ---------------- | --------------- | -------------------- |
| filesystem.read  | Read file       | `path`             |
| filesystem.write | Write file      | `path`,`content` |
| net.http_get     | HTTP GET (stub) | `url`              |

### Health

```bash
curl http://127.0.0.1:9000/health
```

---

## MCP Client (Test CLI)

### Basic Usage

```bash
python -m mcp_client.client --server http://127.0.0.1:9000 tools list

python -m mcp_client.client --server http://127.0.0.1:9000 tools call \
  --tool filesystem.read --args '{"path": "/project/readme.txt"}'
```

---

## Test Scenarios

```bash
# Allowed requests
python -m mcp_client.client --server http://127.0.0.1:9000 scenario allowed

# Denied requests
python -m mcp_client.client --server http://127.0.0.1:9000 scenario denied
```

### Detection Rules

| Test   | Rule                 | Trigger                          |
| ------ | -------------------- | -------------------------------- |
| Test 1 | R2_UNSAFE_PARAMETER  | Read `/etc/passwd`             |
| Test 2 | R1_DISALLOWED_TOOL   | Unknown tool `execute_command` |
| Test 3 | R3_INVALID_ARGUMENTS | Missing required `path`        |
| Test 4 | R2_UNSAFE_PARAMETER  | Write `/root/.bashrc`          |

---

## Full PoC Demo Flow

**Terminal 1 – MCP Server**

```bash
python -m mcp_server.server --port 9000
```

**Terminal 2 – Proxy**

```bash
uvicorn proxy.app:app --port 8080
```

**Terminal 3 – Client via Proxy**

```bash
python -m mcp_client.client --server http://127.0.0.1:8080/mcp/message scenario allowed

python -m mcp_client.client --server http://127.0.0.1:8080/mcp/message scenario denied
```
