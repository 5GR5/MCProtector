from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from observability import PoCEvent
from proxy.config import ProxyConfig
from proxy.dashboard import DashboardState, _build_activity_series, _build_topology
from proxy.mitigation import Blocklist


def _decision_event(timestamp: datetime, decision: str) -> PoCEvent:
    request_id = uuid4()
    return PoCEvent(
        timestamp=timestamp,
        level="INFO" if decision == "ALLOW" else "WARN",
        event_type="DECISION_MADE",
        component="proxy",
        request_id=request_id,
        trace_id=request_id,
        client_id="client-a",
        client_ip="10.0.0.1",
        mcp_method="tools/call",
        tool_name="filesystem.read",
        decision=decision,
        reason_code=decision,
        reason=decision,
    )


def test_activity_series_counts_only_allowed_and_denied_decisions() -> None:
    end = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    events = [
        _decision_event(end - timedelta(minutes=1), "ALLOW"),
        _decision_event(end - timedelta(minutes=2), "DENY"),
        _decision_event(end - timedelta(minutes=6), "ALLOW"),
        _decision_event(end - timedelta(minutes=3), "CHALLENGE"),
    ]

    series = _build_activity_series(events, bucket_count=3, bucket_minutes=5)

    assert len(series) == 3
    assert sum(point["allow"] for point in series) == 2
    assert sum(point["deny"] for point in series) == 1
    assert all(set(point) == {"label", "allow", "deny"} for point in series)


def _forwarded_event(
    timestamp: datetime,
    client_id: str,
    server_name: str,
) -> PoCEvent:
    request_id = uuid4()
    return PoCEvent(
        timestamp=timestamp,
        level="INFO",
        event_type="REQUEST_FORWARDED",
        component="proxy",
        request_id=request_id,
        trace_id=request_id,
        client_id=client_id,
        client_ip="10.0.0.1",
        mcp_method="tools/list",
        decision="ALLOW",
        reason_code="FORWARD",
        reason=f"Forwarding to {server_name}",
        upstream_name=server_name,
    )


def _topology_state(tmp_path, events: list[PoCEvent]) -> DashboardState:
    log_path = tmp_path / "topology.jsonl"
    log_path.write_text(
        "\n".join(event.model_dump_json(exclude_none=False) for event in events),
        encoding="utf-8",
    )
    cfg = ProxyConfig(
        log_file_path=str(log_path),
        upstreams={
            "primary": "http://127.0.0.1:9000/mcp/message",
            "secondary": "http://127.0.0.1:9001/mcp/message",
        },
        default_upstream="primary",
    )
    return DashboardState(
        cfg=cfg,
        blocklist=Blocklist(),
        proxy_url="http://127.0.0.1:8080/mcp/message",
    )


def test_topology_client_filter_keeps_only_connected_servers(tmp_path) -> None:
    now = datetime.now(timezone.utc)
    state = _topology_state(tmp_path, [
        _forwarded_event(now, "client-a", "primary"),
        _forwarded_event(now, "client-a", "primary"),
        _forwarded_event(now, "client-b", "secondary"),
    ])

    topology = _build_topology(state, client_filter="client-a")

    assert {node["id"] for node in topology["nodes"]} == {
        "proxy",
        "client:client-a",
        "server:primary",
    }
    assert topology["forwarded_request_count"] == 2
    assert topology["relationship_count"] == 1


def test_topology_server_filter_keeps_only_connected_clients(tmp_path) -> None:
    now = datetime.now(timezone.utc)
    state = _topology_state(tmp_path, [
        _forwarded_event(now, "client-a", "primary"),
        _forwarded_event(now, "client-b", "secondary"),
        _forwarded_event(now, "client-c", "secondary"),
    ])

    topology = _build_topology(state, server_filter="secondary")

    assert {node["id"] for node in topology["nodes"]} == {
        "proxy",
        "client:client-b",
        "client:client-c",
        "server:secondary",
    }
    assert topology["forwarded_request_count"] == 2
    assert topology["servers"] == ["primary", "secondary"]
