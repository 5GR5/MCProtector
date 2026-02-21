from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class Blocklist:
    # ip -> expires_at_epoch_seconds
    entries: Dict[str, float] = field(default_factory=dict)

# Check if an IP is currently blocked, with automatic cleanup of expired entries
    def is_blocked(self, ip: str) -> bool:
        self._cleanup()
        exp = self.entries.get(ip)
        return exp is not None and exp > time.time()

# Block an IP for a certain duration (in seconds)
    def block(self, ip: str, duration_sec: int) -> float:
        expires_at = time.time() + max(1, duration_sec)
        self.entries[ip] = expires_at
        return expires_at

# Get remaining block time for an IP, or None if not blocked
    def remaining_sec(self, ip: str) -> Optional[int]:
        self._cleanup()
        exp = self.entries.get(ip)
        if exp is None:
            return None
        rem = int(exp - time.time())
        return max(0, rem)

    def _cleanup(self) -> None:
        now = time.time()
        dead = [ip for ip, exp in self.entries.items() if exp <= now]
        for ip in dead:
            self.entries.pop(ip, None)
