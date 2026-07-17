from __future__ import annotations

import threading
import time
from collections import deque

_buckets: dict[str, deque[float]] = {}
_lock = threading.Lock()
_calls = 0


def consume(bucket_key: str, limit: int, window_seconds: int = 60) -> bool:
    """Consume one in-process request slot using a sliding time window."""
    global _calls

    now = time.monotonic()
    cutoff = now - max(1, window_seconds)
    with _lock:
        bucket = _buckets.setdefault(bucket_key, deque())
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()
        allowed = len(bucket) < max(1, limit)
        if allowed:
            bucket.append(now)
        _calls += 1
        if _calls % 256 == 0:
            _discard_empty_buckets(now)
        return allowed


def reset() -> None:
    """Clear process-local counters during application/test lifecycle resets."""
    global _calls

    with _lock:
        _buckets.clear()
        _calls = 0


def _discard_empty_buckets(now: float) -> None:
    stale_before = now - 3600
    stale_keys = [key for key, values in _buckets.items() if not values or values[-1] <= stale_before]
    for key in stale_keys:
        _buckets.pop(key, None)
