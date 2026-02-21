from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="MCP Server Stub", version="0.1")

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.post("/mcp/message")
async def mcp_message(request: Request):
    body = await request.json()
    return JSONResponse(
        content={
            "jsonrpc": "2.0",
            "id": body.get("id"),
            "result": {
                "ok": True,
                "echo_method": body.get("method"),
                "echo_tool": (body.get("params") or {}).get("name"),
            },
        }
    )