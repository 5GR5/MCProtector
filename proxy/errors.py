from __future__ import annotations

from typing import Any, Dict


def error_payload(trace_id: str, reason_code: str, reason: str) -> Dict[str, Any]:
    return {
        "error": reason_code.lower(),
        "trace_id": trace_id,
        "reason": reason,
    }
