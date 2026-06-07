from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Literal
import yaml

LogMode = Literal["console_json", "console_json_and_file"]

# Configuration dataclass with YAML loading and env var overrides

@dataclass
class ProxyConfig:
    listen_host: str = "0.0.0.0"
    listen_port: int = 8080
    dashboard_enabled: bool = True
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 8081
    dashboard_admin_password: str = "admin123"
    dashboard_session_secret: str = "mcprotector-dashboard-secret"

    upstream_url: str = "http://127.0.0.1:9000/mcp/message"
    upstreams: dict[str, str] = field(default_factory=dict)
    default_upstream: str = "default"
    client_routes: dict[str, str] = field(default_factory=dict)

    enable_model_eval: bool = True
    risk_threshold: float = 0.80
    model_decision: str = "CHALLENGE"  # CHALLENGE or DENY

    enable_mitigation: bool = True
    blocklist_duration_sec: int = 120

    log_mode: LogMode = "console_json"
    log_file_path: str = "logs/poc.jsonl"
    demo_human_log: bool = True
    trace_filter: str | None = None

    @staticmethod
    def load(path: str = "config.yaml") -> "ProxyConfig":
        data: dict[str, Any] = {}
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

        cfg = ProxyConfig(**data)

        # Optional env overrides
        cfg.listen_host = os.getenv("LISTEN_HOST", cfg.listen_host)
        cfg.listen_port = int(os.getenv("LISTEN_PORT", str(cfg.listen_port)))
        cfg.dashboard_enabled = os.getenv("DASHBOARD_ENABLED", str(cfg.dashboard_enabled)).lower() in ("1", "true", "yes", "y")
        cfg.dashboard_host = os.getenv("DASHBOARD_HOST", cfg.dashboard_host)
        cfg.dashboard_port = int(os.getenv("DASHBOARD_PORT", str(cfg.dashboard_port)))
        cfg.dashboard_admin_password = os.getenv("DASHBOARD_ADMIN_PASSWORD", cfg.dashboard_admin_password)
        cfg.dashboard_session_secret = os.getenv("DASHBOARD_SESSION_SECRET", cfg.dashboard_session_secret)
        env_upstream_url = os.getenv("UPSTREAM_URL")
        if env_upstream_url:
            cfg.upstream_url = env_upstream_url
        env_upstreams = os.getenv("UPSTREAMS")
        if env_upstreams:
            parsed = yaml.safe_load(env_upstreams)
            if not isinstance(parsed, dict):
                raise ValueError("UPSTREAMS must be a YAML/JSON object of name-to-URL mappings")
            cfg.upstreams = {str(name): str(url) for name, url in parsed.items()}
        cfg.default_upstream = os.getenv("DEFAULT_UPSTREAM", cfg.default_upstream)
        env_client_routes = os.getenv("CLIENT_ROUTES")
        if env_client_routes:
            parsed = yaml.safe_load(env_client_routes)
            if not isinstance(parsed, dict):
                raise ValueError("CLIENT_ROUTES must be a YAML/JSON object of client-to-server mappings")
            cfg.client_routes = {str(client_id): str(server) for client_id, server in parsed.items()}
        cfg.enable_model_eval = os.getenv("ENABLE_MODEL_EVAL", str(cfg.enable_model_eval)).lower() in ("1", "true", "yes", "y")
        cfg.risk_threshold = float(os.getenv("RISK_THRESHOLD", str(cfg.risk_threshold)))
        cfg.model_decision = os.getenv("MODEL_DECISION", cfg.model_decision).upper()
        cfg.enable_mitigation = os.getenv("ENABLE_MITIGATION", str(cfg.enable_mitigation)).lower() in ("1", "true", "yes", "y")
        cfg.blocklist_duration_sec = int(os.getenv("BLOCKLIST_DURATION_SEC", str(cfg.blocklist_duration_sec)))
        cfg.log_mode = os.getenv("LOG_MODE", cfg.log_mode)  # type: ignore
        cfg.log_file_path = os.getenv("LOG_FILE_PATH", cfg.log_file_path)
        cfg.demo_human_log = os.getenv("DEMO_HUMAN_LOG", str(cfg.demo_human_log)).lower() in ("1", "true", "yes", "y")
        cfg.trace_filter = os.getenv("TRACE_FILTER", cfg.trace_filter)

        if not cfg.upstreams:
            cfg.upstreams = {"default": cfg.upstream_url}
            cfg.default_upstream = "default"
        elif cfg.default_upstream not in cfg.upstreams:
            raise ValueError(f"default_upstream '{cfg.default_upstream}' is not present in upstreams")
        elif env_upstream_url:
            cfg.upstreams[cfg.default_upstream] = env_upstream_url

        return cfg
