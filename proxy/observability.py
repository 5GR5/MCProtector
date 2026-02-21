from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict


# Timestamp helper
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass
class EventEmitter:
    log_mode: str = "console_json"
    log_file_path: str = "logs/poc.jsonl"
    demo_human_log: bool = True

    def emit(self, event: Dict[str, Any]) -> None:
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":"))

        # JSON to stdout
        print(line, flush=True)

        # Optional human-friendly summary to stderr
        if self.demo_human_log:
            self._human_line(event)

        # Optional jsonl file
        if self.log_mode == "console_json_and_file":
            os.makedirs(os.path.dirname(self.log_file_path) or ".", exist_ok=True)
            with open(self.log_file_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

    def _human_line(self, e: Dict[str, Any]) -> None:
        et = e.get("event_type")
        tid = e.get("trace_id")
        dec = e.get("decision")
        rc = e.get("reason_code")
        rs = e.get("risk_score")
        tool = e.get("tool_name") or "-"
        meth = e.get("mcp_method") or "-"
        msg = f"[{et}] trace={tid} decision={dec} reason={rc} method={meth} tool={tool}"
        if rs is not None:
            msg += f" risk={rs}"
        print(msg, file=sys.stderr, flush=True)
