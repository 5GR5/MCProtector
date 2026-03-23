from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Literal
import yaml

LogMode = Literal["console_json", "console_json_and_file"]

# Configuration dataclass with YAML loading and env var overrides

@dataclass
class ProxyConfig:
    listen_host: str = "0.0.0.0"
    listen_port: int = 8080

    upstream_url: str = "http://127.0.0.1:9000/mcp/message"

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
        data = {}
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

        cfg = ProxyConfig(**data)

        # Optional env overrides
        cfg.upstream_url = os.getenv("UPSTREAM_URL", cfg.upstream_url)
        cfg.enable_model_eval = os.getenv("ENABLE_MODEL_EVAL", str(cfg.enable_model_eval)).lower() in ("1", "true", "yes", "y")
        cfg.risk_threshold = float(os.getenv("RISK_THRESHOLD", str(cfg.risk_threshold)))
        cfg.model_decision = os.getenv("MODEL_DECISION", cfg.model_decision).upper()
        cfg.enable_mitigation = os.getenv("ENABLE_MITIGATION", str(cfg.enable_mitigation)).lower() in ("1", "true", "yes", "y")
        cfg.blocklist_duration_sec = int(os.getenv("BLOCKLIST_DURATION_SEC", str(cfg.blocklist_duration_sec)))
        cfg.log_mode = os.getenv("LOG_MODE", cfg.log_mode)  # type: ignore
        cfg.log_file_path = os.getenv("LOG_FILE_PATH", cfg.log_file_path)
        cfg.demo_human_log = os.getenv("DEMO_HUMAN_LOG", str(cfg.demo_human_log)).lower() in ("1", "true", "yes", "y")
        cfg.trace_filter = os.getenv("TRACE_FILTER", cfg.trace_filter)

        return cfg
