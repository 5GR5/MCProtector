# MCProtector Proxy PoC (Local)

This package is a runnable PoC proxy that:

* receives MCP JSON-RPC requests (`POST /mcp/message`)
* serves an admin HTML dashboard on a separate port
* normalizes them into a `NormalizedRequest`
* runs rule detection and optional model scoring
* decides ALLOW / DENY / CHALLENGE
* applies mitigation (in-memory IP blocklist)
* routes multiple identified clients to multiple named MCP servers
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
* `client_id`, `client_ip`, `decision`, `reason`
* `upstream_name` for requests routed to a named MCP server

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

The proxy listens for MCP traffic on `http://127.0.0.1:8080/mcp/message`.

The admin dashboard starts automatically on `http://127.0.0.1:8081`.

The dashboard summary includes a responsive activity graph for ALLOW and DENY
decisions. The old CHALLENGED summary metric is not displayed. The
`CHALLENGE` security decision still exists in the policy engine and event
schema.

The **Topology** page at `http://127.0.0.1:8081/topology` shows observed MCP
clients, the MCProtector proxy, and configured MCP servers as a connected graph.
Use either filter to focus the graph:

* Client filter: shows the selected client, proxy, and servers used by that client.
* MCP server filter: shows the selected server, proxy, and clients routed to it.

Clicking a client or server circle applies the same filter directly from the
diagram. Relationship labels show the number of forwarded requests.

Default dashboard password:

```text
admin123
```

Override with:

```bash
DASHBOARD_ADMIN_PASSWORD=your-password uvicorn proxy.app:app --host 0.0.0.0 --port 8080
```

### Multiple MCP servers

Configure named upstream servers in `config.yaml`:

```yaml
upstreams:
  primary: "http://127.0.0.1:9000/mcp/message"
  secondary: "http://127.0.0.1:9001/mcp/message"
default_upstream: "primary"

client_routes:
  client-primary: "primary"
  client-secondary: "secondary"
```

Routing precedence:

1. `X-MCP-Server` / CLI `--target-server`
2. `client_routes` entry matching `X-Client-ID`
3. `default_upstream`

Only configured names are accepted. A request for an unknown server receives
HTTP `400` with `unknown_upstream`; clients cannot provide an arbitrary URL.

The legacy single-server setting remains supported:

```yaml
upstream_url: "http://127.0.0.1:9000/mcp/message"
```

Environment overrides:

```text
DEFAULT_UPSTREAM=primary
UPSTREAMS={"primary":"http://127.0.0.1:9000/mcp/message","secondary":"http://127.0.0.1:9001/mcp/message"}
CLIENT_ROUTES={"client-a":"primary","client-b":"secondary"}
```

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

The included server uses a threaded HTTP server, so requests from multiple
clients can be processed concurrently. Run additional instances on other
ports:

```bash
python -m mcp_server.server --port 9001
```

### Tools

| Tool             | Description      | Arguments            |
| ---------------- | ---------------- | -------------------- |
| filesystem.read  | Read file        | `path`             |
| filesystem.write | Write file       | `path`,`content` |
| net.http_get     | HTTP GET (stub)  | `url`              |
| query_db         | SQL query (stub) | `query`            |

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
  --tool filesystem.read --args '{"path": "/project/data/config.json"}'
```

When using the proxy, `--server` is the proxy URL and `--target-server` is the
configured upstream name:

```bash
python -m mcp_client.client \
  --server http://127.0.0.1:8080/mcp/message \
  --client-id client-a \
  --target-server primary \
  tools list

python -m mcp_client.client \
  --server http://127.0.0.1:8080/mcp/message \
  --client-id client-b \
  --target-server secondary \
  tools list
```

Omit `--target-server` to use `client_routes` or `default_upstream`.

---

## Test Scenarios

```bash
# Allowed requests
python -m mcp_client.client --server http://127.0.0.1:9000 scenario allowed

# Denied requests
python -m mcp_client.client --server http://127.0.0.1:9000 scenario denied
```

### Detection Rules

| Test     | Rule                 | Trigger                            |
| -------- | -------------------- | ---------------------------------- |
| Test 1   | R2_UNSAFE_PARAMETER  | Read`/etc/passwd`                |
| Test 2   | R1_DISALLOWED_TOOL   | Unknown tool`execute_command`    |
| Test 3   | R3_INVALID_ARGUMENTS | Missing required`path`           |
| Test 4   | R2_UNSAFE_PARAMETER  | Write`/root/.bashrc`             |
| SQL Test | SQL_INJECTION        | Query payload containing`OR 1=1` |

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

Dashboard:

```text
http://127.0.0.1:8081
```

**Terminal 3 – Client via Proxy**

```bash
python -m mcp_client.client --server http://127.0.0.1:8080/mcp/message scenario allowed

python -m mcp_client.client --server http://127.0.0.1:8080/mcp/message scenario denied
```

---

## Presentation Demo (Secret-file scenario)

This quick flow demonstrates reading a sensitive file (`/project/data/secrets/passwords.txt`) while the product is ON (should be blocked) and then OFF (allowed).

1. Start the MCP server (test backend):

```bash
python -m mcp_server.server --port 9000
```

2. Start the proxy and dashboard:

```bash
uvicorn proxy.app:app --host 0.0.0.0 --port 8080
```

3. Open the dashboard in your browser: http://127.0.0.1:8081 -> Tests tab. Use the "Blocked secret read" disallowed test under `filesystem.read` to run the scenario interactively.
4. Or run the automated demo script (requires `requests` installed in the environment):

```bash
python demo/run_demo.py
```

The script will:

- Log into the dashboard with the default admin password (`admin123`).
- Run the secret-file read test with the product ON (expect `DENY`).
- Toggle the product OFF and run the same test (expect `ALLOW`).

You can inspect the matching trace and events from the Tests tab or in `logs/poc.jsonl`.

---

## Verify the changes

### 1. Automated tests

```bash
python -m pytest -q
```

Expected result:

```text
42 passed
```

### 2. Start two servers and the proxy

Open three terminals:

```bash
# Terminal 1
python -m mcp_server.server --port 9000

# Terminal 2
python -m mcp_server.server --port 9001

# Terminal 3
uvicorn proxy.app:app --host 127.0.0.1 --port 8080
```

### 3. Send two clients to different servers

Open two more terminals and run:

```bash
python -m mcp_client.client \
  --server http://127.0.0.1:8080/mcp/message \
  --client-id verify-client-a \
  --target-server primary \
  tools list
```

```bash
python -m mcp_client.client \
  --server http://127.0.0.1:8080/mcp/message \
  --client-id verify-client-b \
  --target-server secondary \
  tools list
```

Both commands should return the MCP tool list. In `logs/poc.jsonl`, the events
for the two requests should contain different values:

```json
{"client_id":"verify-client-a","upstream_name":"primary"}
{"client_id":"verify-client-b","upstream_name":"secondary"}
```

### 4. Check safe rejection

```bash
python -m mcp_client.client \
  --server http://127.0.0.1:8080/mcp/message \
  --client-id verify-invalid \
  --target-server missing \
  ping
```

Expected response: `unknown_upstream`.

### 5. Check the dashboard graph

1. Open `http://127.0.0.1:8081`.
2. Log in with `admin123`.
3. Run Allowed and Denied scenarios, or use the two clients above.
4. Confirm that Request Activity shows ALLOW and DENY lines.
5. Confirm that Unique clients increases and MCP servers shows `2`.

### 6. Check the connection topology

1. Open `http://127.0.0.1:8081/topology`.
2. Confirm that client circles connect to the proxy and the proxy connects to
   `primary` and `secondary`.
3. Select a client and confirm unrelated servers disappear.
4. Reset, select an MCP server, and confirm unrelated clients disappear.
5. Resize the browser or open mobile device tools and confirm the graph changes
   to a vertical client-proxy-server layout without overlapping circles.
