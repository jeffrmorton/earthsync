"""Simple in-memory rate limiter -- no external dependencies."""

from __future__ import annotations

import time
from collections import defaultdict

from fastapi import HTTPException, Request


class RateLimiter:
    """Token bucket rate limiter keyed by client IP."""

    def __init__(self, max_requests: int, window_seconds: int):
        self._max = max_requests
        self._window = window_seconds
        self._requests: dict[str, list[float]] = defaultdict(list)

    def check(self, request: Request) -> None:
        """Raise 429 if rate limit exceeded."""
        ip = request.client.host if request.client else "unknown"
        now = time.time()
        # Prune old entries
        self._requests[ip] = [t for t in self._requests[ip] if now - t < self._window]
        if len(self._requests[ip]) >= self._max:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")
        self._requests[ip].append(now)


# Pre-configured limiters matching rate_limit.py constants
auth_limiter = RateLimiter(max_requests=20, window_seconds=900)  # 20 per 15 min
ingest_limiter = RateLimiter(max_requests=120, window_seconds=60)  # 120 per min
api_limiter = RateLimiter(max_requests=100, window_seconds=60)  # 100 per min
export_limiter = RateLimiter(max_requests=10, window_seconds=60)  # 10 per min
