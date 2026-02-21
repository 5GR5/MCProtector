# MCProtector Proxy PoC (Local)

This package is a runnable PoC proxy that:
- receives MCP JSON-RPC requests (`POST /mcp/message`)
- normalizes them into a `NormalizedRequest`
- runs rule detection and optional model scoring
- decides ALLOW / DENY / CHALLENGE
- applies mitigation (in-memory IP blocklist)
- forwards to a local MCP server when allowed
- emits structured JSON events for every stage

## Install

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Run (HTTP)

```bash
uvicorn proxy.app:app --host 0.0.0.0 --port 8080
```

Update `config.yaml` to your MCP server endpoint:
- `upstream_url: "http://127.0.0.1:9000/mcp/message"`

## Run with HTTPS / TLS termination (Option A)

Generate a dev certificate for localhost (PoC/demo only):

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
```

Run uvicorn with SSL:

```bash
uvicorn proxy.app:app --host 0.0.0.0 --port 8080 --ssl-keyfile key.pem --ssl-certfile cert.pem
```

Test:

```bash
curl -k https://localhost:8080/health
```

## Example request (ALLOW path)

```bash
curl -s http://localhost:8080/mcp/message \
  -H "Content-Type: application/json" \
  -H "X-Session-Id: sess-1" \
  -H "Authorization: Bearer demo-token" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.write","arguments":{"path":"/tmp/a.txt","content":"hi"}}}'
```

You should see JSON events printed to stdout and a concise summary printed to stderr.
