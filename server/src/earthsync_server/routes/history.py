"""Historical data query endpoints."""

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query, Request

from earthsync_server.middleware.auth import require_jwt
from earthsync_server.middleware.rate_limiter import api_limiter

router = APIRouter()


@router.get("/hours/{hours}")
async def history_by_hours(
    hours: int,
    request: Request,
    _claims: dict = Depends(require_jwt),  # noqa: B008
) -> list:
    """Return historical spectrograms for the last N hours."""
    api_limiter.check(request)
    store = request.app.state.store
    return await store.get_spectrograms(hours=hours)


@router.get("/range")
async def history_by_range(
    request: Request,
    start_time: str = Query(...),
    end_time: str = Query(...),
    _claims: dict = Depends(require_jwt),  # noqa: B008
) -> list:
    """Return historical spectrograms for a time range."""
    api_limiter.check(request)
    store = request.app.state.store
    try:
        start_dt = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
    except ValueError:
        return []
    start_ms = start_dt.timestamp() * 1000
    end_ms = end_dt.timestamp() * 1000
    # Get all spectrograms with a generous window, then filter by range
    now = datetime.now(UTC)
    hours_back = max(1, int((now.timestamp() * 1000 - start_ms) / (3600 * 1000)) + 1)
    all_specs = await store.get_spectrograms(hours=hours_back)
    return [s for s in all_specs if start_ms <= s.get("timestamp_ms", 0) <= end_ms]


@router.get("/peaks/hours/{hours}")
async def peaks_by_hours(
    hours: int,
    request: Request,
    _claims: dict = Depends(require_jwt),  # noqa: B008
) -> list:
    """Return historical peaks for the last N hours."""
    api_limiter.check(request)
    store = request.app.state.store
    return await store.get_peaks(hours=hours)


@router.get("/peaks/range")
async def peaks_by_range(
    request: Request,
    start_time: str = Query(...),
    end_time: str = Query(...),
    _claims: dict = Depends(require_jwt),  # noqa: B008
) -> list:
    """Return historical peaks for a time range."""
    api_limiter.check(request)
    store = request.app.state.store
    try:
        start_dt = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
    except ValueError:
        return []
    start_ms = start_dt.timestamp() * 1000
    end_ms = end_dt.timestamp() * 1000
    now = datetime.now(UTC)
    hours_back = max(1, int((now.timestamp() * 1000 - start_ms) / (3600 * 1000)) + 1)
    all_peaks = await store.get_peaks(hours=hours_back)
    return [p for p in all_peaks if start_ms <= p.get("ts", 0) <= end_ms]
