from __future__ import annotations

import time
from typing import Dict, Tuple
import httpx


async def forward_json(
    upstream_url: str,
    body: Dict,
    headers: Dict[str, str],
    timeout_s: float = 10.0,
) -> Tuple[int, Dict, float]:
    start = time.time()
    async with httpx.AsyncClient(timeout=timeout_s) as client:
        r = await client.post(upstream_url, json=body, headers=headers)
        latency_ms = (time.time() - start) * 1000.0
        try:
            data = r.json()
        except Exception:
            data = {"raw": r.text}
        return r.status_code, data, latency_ms
