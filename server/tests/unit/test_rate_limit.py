"""Tests for earthsync_server.middleware.rate_limit — rate limit constants."""

from earthsync_server.middleware.rate_limit import (
    API_RATE_LIMIT,
    AUTH_RATE_LIMIT,
    EXPORT_RATE_LIMIT,
    INGEST_RATE_LIMIT,
)


class TestRateLimitConstants:
    def test_auth_rate_limit_count(self):
        assert AUTH_RATE_LIMIT[0] == 20

    def test_auth_rate_limit_period(self):
        assert AUTH_RATE_LIMIT[1] == 900

    def test_ingest_rate_limit_count(self):
        assert INGEST_RATE_LIMIT[0] == 120

    def test_ingest_rate_limit_period(self):
        assert INGEST_RATE_LIMIT[1] == 60

    def test_api_rate_limit_count(self):
        assert API_RATE_LIMIT[0] == 100

    def test_api_rate_limit_period(self):
        assert API_RATE_LIMIT[1] == 60

    def test_export_rate_limit_count(self):
        assert EXPORT_RATE_LIMIT[0] == 10

    def test_export_rate_limit_period(self):
        assert EXPORT_RATE_LIMIT[1] == 60

    def test_all_limits_are_tuples(self):
        for limit in (AUTH_RATE_LIMIT, INGEST_RATE_LIMIT, API_RATE_LIMIT, EXPORT_RATE_LIMIT):
            assert isinstance(limit, tuple)
            assert len(limit) == 2

    def test_all_counts_positive(self):
        for limit in (AUTH_RATE_LIMIT, INGEST_RATE_LIMIT, API_RATE_LIMIT, EXPORT_RATE_LIMIT):
            assert limit[0] > 0

    def test_all_periods_positive(self):
        for limit in (AUTH_RATE_LIMIT, INGEST_RATE_LIMIT, API_RATE_LIMIT, EXPORT_RATE_LIMIT):
            assert limit[1] > 0
