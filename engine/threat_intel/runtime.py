"""Clock, cache and rate limiter. All injectable so tests are deterministic.

IMPORTANT: the cache and the rate limiter are PROCESS-LOCAL. With several worker processes
each has its own copy, so duplicate lookups and combined quota overruns are still possible.
Neither distributed caching nor global rate limiting is implemented. Swap in a shared
implementation of `Cache` / `RateLimiter` (e.g. Redis) before running multiple workers
against the VirusTotal public quota.
"""
from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Mapping, Optional, Protocol

from .types import Indicator, LookupResult


@dataclass
class Clock:
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)
    monotonic: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep


def cache_key(provider: str, ind: Indicator) -> str:
    """provider + indicator type + digest of the normalised value (raw value is not kept)."""
    digest = hashlib.sha256(ind.value.encode()).hexdigest()
    return f"{provider}|{ind.type.value}|{digest}"


class Cache(Protocol):
    def get(self, key: str) -> Optional[LookupResult]: ...
    def set(self, key: str, value: LookupResult, ttl_s: float) -> None: ...


class InMemoryTTLCache:
    """Bounded, thread-safe, process-local TTL cache."""

    def __init__(self, clock: Clock, max_entries: int = 2048) -> None:
        self._clock = clock
        self._max = max_entries
        self._data: "OrderedDict[str, tuple[float, LookupResult]]" = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[LookupResult]:
        with self._lock:
            item = self._data.get(key)
            if item is None:
                return None
            expires, value = item
            if self._clock.monotonic() >= expires:
                del self._data[key]
                return None
            return value

    def set(self, key: str, value: LookupResult, ttl_s: float) -> None:
        if ttl_s <= 0:
            return
        with self._lock:
            self._data[key] = (self._clock.monotonic() + ttl_s, value)
            self._data.move_to_end(key)
            while len(self._data) > self._max:
                self._data.popitem(last=False)


class RateLimiter:
    """Non-blocking sliding-window limiter, one set of windows per provider.

    `try_acquire` never sleeps: when capacity is exhausted the lookup is reported as
    NOT_CHECKED(rate_limited_locally) instead of stalling the message.
    """

    def __init__(self, clock: Clock, limits: Mapping[str, tuple]) -> None:
        self._clock = clock
        self._limits = {k: tuple(v) for k, v in limits.items()}
        self._hits: dict[str, list[deque]] = {
            k: [deque() for _ in v] for k, v in self._limits.items()
        }
        self._lock = threading.Lock()

    def try_acquire(self, provider: str) -> bool:
        windows = self._limits.get(provider)
        if not windows:
            return True
        now = self._clock.monotonic()
        with self._lock:
            queues = self._hits[provider]
            for (maximum, span), q in zip(windows, queues):
                while q and now - q[0] >= span:
                    q.popleft()
                if len(q) >= maximum:
                    return False
            for q in queues:
                q.append(now)
            return True
