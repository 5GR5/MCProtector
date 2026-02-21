from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .config import ProxyConfig
from .mitigation import Blocklist
from .observability import EventEmitter
from .pipeline import handle_mcp_message

cfg = ProxyConfig.load()
# Logging setup
emitter = EventEmitter(log_mode=cfg.log_mode, log_file_path=cfg.log_file_path, demo_human_log=cfg.demo_human_log)
blocklist = Blocklist()

app = FastAPI(title="MCProtector PoC Proxy", version="0.1")


# Health check endpoint
@app.get("/health")
async def health():
    return {"status": "ok"}


# Main MCP message handling endpoint, sending to pipeline
@app.post("/mcp/message")
async def mcp_message(request: Request):
    body = await request.json()
    status, data, headers_out = await handle_mcp_message(request, body, cfg, emitter, blocklist)
    return JSONResponse(status_code=status, content=data, headers=headers_out)


# Shows current blocklist entries 
@app.get("/debug/blocklist")
async def debug_blocklist():
    return {"entries": blocklist.entries}
