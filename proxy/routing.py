from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


class UpstreamSelectionError(ValueError):
    """Raised when a request selects an upstream that is not configured."""


@dataclass(frozen=True)
class UpstreamTarget:
    name: str
    url: str


class UpstreamRouter:
    def __init__(
        self,
        upstreams: Mapping[str, str],
        default_upstream: str,
        client_routes: Mapping[str, str] | None = None,
    ) -> None:
        self._upstreams = {
            str(name).strip(): str(url).strip()
            for name, url in upstreams.items()
            if str(name).strip() and str(url).strip()
        }
        if not self._upstreams:
            raise ValueError("At least one upstream MCP server must be configured")
        if default_upstream not in self._upstreams:
            raise ValueError(f"Default upstream '{default_upstream}' is not configured")

        self.default_upstream = default_upstream
        self._client_routes = {
            str(client_id).strip(): str(upstream_name).strip()
            for client_id, upstream_name in (client_routes or {}).items()
            if str(client_id).strip() and str(upstream_name).strip()
        }
        unknown_routes = {
            upstream_name
            for upstream_name in self._client_routes.values()
            if upstream_name not in self._upstreams
        }
        if unknown_routes:
            names = ", ".join(sorted(unknown_routes))
            raise ValueError(f"Client routes reference unknown upstreams: {names}")

    @property
    def upstreams(self) -> dict[str, str]:
        return dict(self._upstreams)

    def resolve(self, client_id: str, requested_upstream: str | None = None) -> UpstreamTarget:
        requested = (requested_upstream or "").strip()
        if requested:
            if requested not in self._upstreams:
                raise UpstreamSelectionError(f"Unknown MCP server '{requested}'")
            selected = requested
        else:
            selected = self._client_routes.get(client_id, self.default_upstream)
        return UpstreamTarget(name=selected, url=self._upstreams[selected])
