"""Tests for earthsync_server.middleware.rate_limiter -- in-memory rate limiter."""

import time
from unittest.mock import MagicMock

import pytest
from earthsync_server.middleware.rate_limiter import (
    RateLimiter,
    api_limiter,
    auth_limiter,
    export_limiter,
    ingest_limiter,
)
from fastapi import HTTPException


def _mock_request(ip: str = "127.0.0.1") -> MagicMock:
    """Create a mock Request with the given client IP."""
    request = MagicMock()
    request.client.host = ip
    return request


class TestRateLimiterAllowsWithinLimit:
    def test_single_request_passes(self):
        limiter = RateLimiter(max_requests=5, window_seconds=60)
        request = _mock_request()
        limiter.check(request)  # Should not raise

    def test_requests_up_to_limit_pass(self):
        limiter = RateLimiter(max_requests=3, window_seconds=60)
        request = _mock_request()
        for _ in range(3):
            limiter.check(request)  # Should not raise

    def test_different_ips_have_separate_limits(self):
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        req_a = _mock_request("10.0.0.1")
        req_b = _mock_request("10.0.0.2")
        limiter.check(req_a)
        limiter.check(req_a)
        # IP A is at limit, but IP B should still pass
        limiter.check(req_b)


class TestRateLimiterBlocksOverLimit:
    def test_exceeding_limit_raises_429(self):
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        request = _mock_request()
        limiter.check(request)
        limiter.check(request)
        with pytest.raises(HTTPException) as exc_info:
            limiter.check(request)
        assert exc_info.value.status_code == 429
        assert "Rate limit exceeded" in exc_info.value.detail

    def test_one_ip_blocked_does_not_block_another(self):
        limiter = RateLimiter(max_requests=1, window_seconds=60)
        req_a = _mock_request("10.0.0.1")
        req_b = _mock_request("10.0.0.2")
        limiter.check(req_a)
        with pytest.raises(HTTPException):
            limiter.check(req_a)
        # IP B should still work
        limiter.check(req_b)


class TestRateLimiterResetsAfterWindow:
    def test_requests_allowed_after_window_expires(self, monkeypatch):
        limiter = RateLimiter(max_requests=2, window_seconds=10)
        request = _mock_request()

        base_time = 1000.0
        monkeypatch.setattr(time, "time", lambda: base_time)
        limiter.check(request)
        limiter.check(request)

        # Advance past the window
        monkeypatch.setattr(time, "time", lambda: base_time + 11)
        limiter.check(request)  # Should not raise -- window has expired

    def test_partial_window_expiry(self, monkeypatch):
        limiter = RateLimiter(max_requests=2, window_seconds=10)
        request = _mock_request()

        monkeypatch.setattr(time, "time", lambda: 1000.0)
        limiter.check(request)

        monkeypatch.setattr(time, "time", lambda: 1005.0)
        limiter.check(request)

        # At t=1011, first request expired but second hasn't
        monkeypatch.setattr(time, "time", lambda: 1011.0)
        limiter.check(request)  # Slot freed by expired first request


class TestRateLimiterEdgeCases:
    def test_unknown_client(self):
        """Request with no client info uses 'unknown' key."""
        limiter = RateLimiter(max_requests=1, window_seconds=60)
        request = MagicMock()
        request.client = None
        limiter.check(request)  # Should not raise


class TestPreConfiguredLimiters:
    def test_auth_limiter_config(self):
        assert auth_limiter._max == 20
        assert auth_limiter._window == 900

    def test_ingest_limiter_config(self):
        assert ingest_limiter._max == 120
        assert ingest_limiter._window == 60

    def test_api_limiter_config(self):
        assert api_limiter._max == 100
        assert api_limiter._window == 60

    def test_export_limiter_config(self):
        assert export_limiter._max == 10
        assert export_limiter._window == 60
