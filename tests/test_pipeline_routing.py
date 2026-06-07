from __future__ import annotations

import asyncio
from typing import Any

from fastapi import Request

from observability import EventEmitter
from proxy.config import ProxyConfig
from proxy.mitigation import Blocklist
from proxy.pipeline import handle_mcp_message
from proxy.routing import UpstreamRouter


def _request(client_id: str, target_server: str | None = None) -> Request:
    headers = [
        (b"x-client-id", client_id.encode("ascii")),
        (b"x-session-id", client_id.encode("ascii")),
        (b"x-forwarded-for", b"10.20.30.40"),
    ]
    if target_server:
        headers.append((b"x-mcp-server", target_server.encode("ascii")))
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/mcp/message",
            "raw_path": b"/mcp/message",
            "query_string": b"",
            "headers": headers,
            "client": ("127.0.0.1", 12345),
            "server": ("127.0.0.1", 8080),
        }
    )


def _body() -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "filesystem.read",
            "arguments": {"path": "/project/data/config.json"},
        },
    }


def test_pipeline_forwards_to_explicit_named_server(monkeypatch) -> None:
    forwarded_urls: list[str] = []

    async def fake_forward(url: str, body: dict, headers: dict, timeout_s: float = 10.0):
        forwarded_urls.append(url)
        return 200, {"result": {"server_url": url}}, 1.25

    monkeypatch.setattr("proxy.pipeline.forward_json", fake_forward)
    cfg = ProxyConfig(enable_model_eval=False, enable_mitigation=False)
    router = UpstreamRouter(
        {
            "primary": "http://127.0.0.1:9000/mcp/message",
            "secondary": "http://127.0.0.1:9001/mcp/message",
        },
        "primary",
    )

    status, data, headers = asyncio.run(
        handle_mcp_message(
            _request("client-a", "secondary"),
            _body(),
            cfg,
            EventEmitter(demo_human_log=False),
            Blocklist(),
            router=router,
        )
    )

    assert status == 200
    assert forwarded_urls == ["http://127.0.0.1:9001/mcp/message"]
    assert headers["x-mcp-server"] == "secondary"
    assert data["result"]["server_url"].endswith(":9001/mcp/message")


def test_pipeline_rejects_unknown_named_server(monkeypatch) -> None:
    async def fail_if_forwarded(*args, **kwargs):
        raise AssertionError("Unknown upstream must not be forwarded")

    monkeypatch.setattr("proxy.pipeline.forward_json", fail_if_forwarded)
    cfg = ProxyConfig(enable_model_eval=False, enable_mitigation=False)
    router = UpstreamRouter(
        {"primary": "http://127.0.0.1:9000/mcp/message"},
        "primary",
    )

    status, data, headers = asyncio.run(
        handle_mcp_message(
            _request("client-a", "missing"),
            _body(),
            cfg,
            EventEmitter(demo_human_log=False),
            Blocklist(),
            router=router,
        )
    )

    assert status == 400
    assert data["error"] == "unknown_upstream"
    assert "x-mcp-server" not in headers
