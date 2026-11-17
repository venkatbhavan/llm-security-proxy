"""Simple in-memory sliding-window rate limiter (per client IP).

Good enough for a single-instance demo. A multi-instance production setup would
use a shared store (e.g. Redis) or the rate limiting of an API gateway / WAF.
"""
import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self, per_minute: int, per_hour: int):
        self.per_minute, self.per_hour = per_minute, per_hour
        self.hits = defaultdict(deque)
        self.lock = threading.Lock()

    def check(self, key: str) -> int:
        """Record a hit. Returns 0 if allowed, otherwise seconds until the client may retry."""
        if not self.per_minute and not self.per_hour:
            return 0
        now = time.time()
        with self.lock:
            q = self.hits[key]
            while q and now - q[0] > 3600:
                q.popleft()
            last_minute = [t for t in q if now - t <= 60]
            if self.per_minute and len(last_minute) >= self.per_minute:
                return int(60 - (now - last_minute[0])) + 1
            if self.per_hour and len(q) >= self.per_hour:
                return int(3600 - (now - q[0])) + 1
            q.append(now)
            return 0

    def reset(self):
        with self.lock:
            self.hits.clear()
