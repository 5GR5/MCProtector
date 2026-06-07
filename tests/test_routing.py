from __future__ import annotations

import textwrap

import pytest

from proxy.config import ProxyConfig
from proxy.routing import UpstreamRouter, UpstreamSelectionError


def test_router_uses_default_upstream() -> None:
    router = UpstreamRouter(
        {"primary": "http://localhost:9000/mcp/message", "secondary": "http://localhost:9001/mcp/message"},
        "primary",
    )

    target = router.resolve("client-a")

    assert target.name == "primary"
    assert target.url.endswith(":9000/mcp/message")


def test_router_supports_sticky_client_routes_and_explicit_override() -> None:
    router = UpstreamRouter(
        {"primary": "http://localhost:9000/mcp/message", "secondary": "http://localhost:9001/mcp/message"},
        "primary",
        {"client-b": "secondary"},
    )

    assert router.resolve("client-b").name == "secondary"
    assert router.resolve("client-b", "primary").name == "primary"


def test_router_rejects_unknown_requested_upstream() -> None:
    router = UpstreamRouter({"primary": "http://localhost:9000/mcp/message"}, "primary")

    with pytest.raises(UpstreamSelectionError, match="Unknown MCP server"):
        router.resolve("client-a", "attacker-controlled-url")


def test_legacy_upstream_url_config_remains_supported(tmp_path) -> None:
    config_path = tmp_path / "legacy.yaml"
    config_path.write_text(
        textwrap.dedent(
            """
            dashboard_enabled: false
            upstream_url: "http://127.0.0.1:9100/mcp/message"
            """
        ).strip(),
        encoding="utf-8",
    )

    cfg = ProxyConfig.load(str(config_path))

    assert cfg.default_upstream == "default"
    assert cfg.upstreams == {"default": "http://127.0.0.1:9100/mcp/message"}


def test_invalid_client_route_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown upstreams"):
        UpstreamRouter(
            {"primary": "http://localhost:9000/mcp/message"},
            "primary",
            {"client-b": "missing"},
        )
