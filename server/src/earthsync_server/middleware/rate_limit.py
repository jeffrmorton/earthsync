"""Rate limiting configuration."""

from __future__ import annotations

# Rate limit configurations as (count, period_seconds) tuples
AUTH_RATE_LIMIT = (20, 900)  # 20 per 15 minutes
INGEST_RATE_LIMIT = (120, 60)  # 120 per minute
API_RATE_LIMIT = (100, 60)  # 100 per minute
EXPORT_RATE_LIMIT = (10, 60)  # 10 per minute
