"""Detector calibration endpoints."""

from typing import Any

from fastapi import APIRouter, Body, Depends, Request

from earthsync_server.middleware.auth import require_api_key, require_jwt

router = APIRouter()


@router.put("/{station_id}/calibration")
async def update_calibration(
    station_id: str,
    request: Request,
    body: dict[str, Any] = Body(...),  # noqa: B008
    _api_key: str = Depends(require_api_key),
) -> dict:
    """Upload or update calibration data for a station."""
    store = request.app.state.store
    await store.set_calibration(station_id, body)
    return {"station_id": station_id, "status": "updated"}


@router.get("/{station_id}/calibration")
async def get_calibration(
    station_id: str,
    request: Request,
    _claims: dict = Depends(require_jwt),  # noqa: B008
) -> dict:
    """Retrieve calibration state for a station."""
    store = request.app.state.store
    result = await store.get_calibration(station_id)
    return result if result is not None else {}


@router.get("/{station_id}/quality")
async def get_quality(
    station_id: str,
    request: Request,
    _claims: dict = Depends(require_jwt),  # noqa: B008
) -> dict:
    """Return quality metrics summary for a station."""
    store = request.app.state.store
    return await store.get_quality(station_id)
