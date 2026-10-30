"""In-memory Token Bucket rate limiter for IP and User access control.

Protects LLM API quota and system endpoints against brute-force, scraping,
and excessive burst traffic.
"""

from __future__ import annotations

import math
import threading
import time
from typing import Dict, Optional, Tuple
from fastapi import HTTPException, status


class TokenBucket:
    """Represents an individual token bucket for a specific key."""

    def __init__(self, capacity: float, refill_rate_per_sec: float):
        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate_per_sec)
        self.tokens = float(capacity)
        self.last_update = time.monotonic()

    def refill(self) -> None:
        """Add tokens according to elapsed monotonic time."""
        now = time.monotonic()
        elapsed = now - self.last_update
        self.last_update = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)

    def consume(self, cost: float = 1.0) -> Tuple[bool, float]:
        """Attempt to consume tokens.

        Returns:
            Tuple[bool, float]: (allowed, retry_after_seconds)
        """
        self.refill()
        if self.tokens >= cost:
            self.tokens -= cost
            return True, 0.0

        deficit = cost - self.tokens
        retry_after = deficit / self.refill_rate if self.refill_rate > 0 else 60.0
        return False, retry_after


class TokenBucketLimiter:
    """Thread-safe Token Bucket rate limiter managing multiple client identifiers."""

    def __init__(self, rate_per_minute: int = 10, capacity: Optional[int] = None):
        self.capacity = float(capacity if capacity is not None else rate_per_minute)
        self.refill_rate_per_sec = float(rate_per_minute) / 60.0
        self._buckets: Dict[str, TokenBucket] = {}
        self._lock = threading.Lock()

    def _get_bucket(self, key: str) -> TokenBucket:
        if key not in self._buckets:
            self._buckets[key] = TokenBucket(
                capacity=self.capacity,
                refill_rate_per_sec=self.refill_rate_per_sec,
            )
        return self._buckets[key]

    def is_allowed(self, key: str, cost: float = 1.0) -> Tuple[bool, float]:
        """Check whether a request under `key` is allowed.

        Returns (is_allowed, retry_after_seconds).
        """
        with self._lock:
            bucket = self._get_bucket(key)
            return bucket.consume(cost=cost)

    def check_rate_limit(self, key: str, cost: float = 1.0) -> None:
        """FastAPI-compatible check that raises HTTP 429 when rate limit is exceeded."""
        allowed, retry_after = self.is_allowed(key, cost=cost)
        if not allowed:
            retry_seconds = max(1, math.ceil(retry_after))
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Please wait before retrying.",
                headers={"Retry-After": str(retry_seconds)},
            )

    def get_remaining_tokens(self, key: str) -> float:
        """Return the current token count for a key."""
        with self._lock:
            bucket = self._get_bucket(key)
            bucket.refill()
            return max(0.0, bucket.tokens)

    def reset(self, key: Optional[str] = None) -> None:
        """Reset limits for a specific key, or clear all buckets."""
        with self._lock:
            if key is not None:
                self._buckets.pop(key, None)
            else:
                self._buckets.clear()
