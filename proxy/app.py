from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from observability import EventEmitter

from .config import ProxyConfig
from .dashboard import DashboardServerHandle, build_dashboard_state, start_dashboard_server, stop_dashboard_server
from .mitigation import Blocklist
from .pipeline import handle_mcp_message
from .routing import UpstreamRouter

cfg = ProxyConfig.load()

# The dashboard depends on structured file logs, so enable file output automatically
# when the dashboard is turned on.
if cfg.dashboard_enabled:
    cfg.log_mode = "console_json_and_file"

emitter = EventEmitter(
    log_mode=cfg.log_mode,
    log_file_path=cfg.log_file_path,
    demo_human_log=cfg.demo_human_log,
    trace_filter=cfg.trace_filter,
)
blocklist = Blocklist()
router = UpstreamRouter(
    cfg.upstreams or {"default": cfg.upstream_url},
    cfg.default_upstream if cfg.upstreams else "default",
    cfg.client_routes,
)
dashboard_state = build_dashboard_state(cfg, blocklist)
dashboard_handle: DashboardServerHandle | None = None

app = FastAPI(title="MCProtector PoC Proxy", version="0.1")


@app.on_event("startup")
async def startup_dashboard() -> None:
    global dashboard_handle
    if cfg.dashboard_enabled and dashboard_handle is None:
        dashboard_handle = start_dashboard_server(dashboard_state)


@app.on_event("shutdown")
async def shutdown_dashboard() -> None:
    global dashboard_handle
    stop_dashboard_server(dashboard_handle)
    dashboard_handle = None


@app.get("/health")
async def health() -> dict[str, object]:
    return {
        "status": "ok",
        "dashboard_enabled": cfg.dashboard_enabled,
        "dashboard_port": cfg.dashboard_port if cfg.dashboard_enabled else None,
        "default_upstream": router.default_upstream,
        "upstreams": list(router.upstreams),
    }


@app.post("/mcp/message")
async def mcp_message(request: Request) -> JSONResponse:
    body = await request.json()
    # Respect runtime dashboard toggle (if present) to enable/disable protection for demos
    product_enabled = getattr(dashboard_state, "product_enabled", True)
    status, data, headers_out = await handle_mcp_message(
        request,
        body,
        cfg,
        emitter,
        blocklist,
        router=router,
        product_enabled=product_enabled,
    )
    return JSONResponse(status_code=status, content=data, headers=headers_out)


@app.get("/debug/blocklist")
async def debug_blocklist() -> dict[str, object]:
    return {"entries": blocklist.entries}
