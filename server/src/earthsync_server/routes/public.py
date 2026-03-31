"""Public (unauthenticated) endpoints."""

from fastapi import APIRouter, Request

router = APIRouter()


@router.get("/stations")
async def list_stations(request: Request) -> list:
    """Return list of active stations."""
    store = request.app.state.store
    return await store.get_stations()


@router.get("/stations/{station_id}/peaks")
async def station_peaks(station_id: str, request: Request) -> list:
    """Return recent peaks for a station."""
    store = request.app.state.store
    return await store.get_peaks(station_id=station_id)


@router.get("/stations/{station_id}/latest")
async def station_latest(station_id: str, request: Request) -> dict:
    """Return the latest processed data for a station."""
    store = request.app.state.store
    return await store.get_latest(station_id)


@router.get("/qbursts")
async def get_global_qbursts(request: Request, hours: int = 24) -> list:
    """Return global Q-burst events within the time window."""
    store = request.app.state.store
    return await store.get_global_qbursts(hours=hours)
