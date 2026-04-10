from __future__ import annotations
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Set, Tuple

@dataclass
class DetectionState:
    requests_by_ip: Dict[str, Deque[float]] = field(default_factory=lambda: defaultdict(deque))
    token_ips: Dict[str, Deque[Tuple[float, str]]] = field(default_factory=lambda: defaultdict(deque))

    def add_request_for_ip(self, client_ip: str, now_ts: float) -> None:
        self.requests_by_ip[client_ip].append(now_ts)

    def count_requests_for_ip(self, client_ip: str, window_sec: int, now_ts: float) -> int:
        q = self.requests_by_ip[client_ip]
        self._trim_times(q, window_sec, now_ts)
        return len(q)

    def add_token_ip(self, token: str, client_ip: str, now_ts: float) -> None:
        self.token_ips[token].append((now_ts, client_ip))

    def unique_ips_for_token(self, token: str, window_sec: int, now_ts: float) -> Set[str]:
        q = self.token_ips[token]
        while q and (now_ts - q[0][0]) > window_sec:
            q.popleft()
        return {ip for _, ip in q}

    def evict_expired(self, now_ts: float, request_window_sec: int, token_window_sec: int) -> None:
        dead_ips = []
        for ip, q in self.requests_by_ip.items():
            self._trim_times(q, request_window_sec, now_ts)
            if not q:
                dead_ips.append(ip)
        for ip in dead_ips:
            self.requests_by_ip.pop(ip, None)

        dead_tokens = []
        for token, q in self.token_ips.items():
            while q and (now_ts - q[0][0]) > token_window_sec:
                q.popleft()
            if not q:
                dead_tokens.append(token)
        for token in dead_tokens:
            self.token_ips.pop(token, None)

    @staticmethod
    def _trim_times(q: Deque[float], window_sec: int, now_ts: float) -> None:
        while q and (now_ts - q[0]) > window_sec:
            q.popleft()
