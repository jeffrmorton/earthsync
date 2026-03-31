"""Data ingestion endpoint."""

import time

from fastapi import APIRouter, Depends, HTTPException, Request, status

from earthsync_server.middleware.auth import require_api_key
from earthsync_server.middleware.rate_limiter import ingest_limiter
from earthsync_server.models import IngestRequest

router = APIRouter()


@router.post("/api/data-ingest", status_code=status.HTTP_202_ACCEPTED)
async def ingest_data(
    body: IngestRequest,
    request: Request,
    _api_key: str = Depends(require_api_key),
) -> dict:
    """Accept raw station data for processing.

    Validates that samples length is consistent with sample_rate * segment_duration (+-2).
    Stores the ingested data in the DataStore.
    """
    ingest_limiter.check(request)
    expected = body.sample_rate_hz * body.segment_duration_s
    if abs(len(body.samples) - expected) > 2:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Samples length {len(body.samples)} does not match "
                f"expected {expected} (sample_rate * segment_duration, tolerance +-2)"
            ),
        )
    store = request.app.state.store
    timestamp_ms = int(time.time() * 1000)
    record = {
        "station_id": body.station_id,
        "timestamp": body.timestamp,
        "timestamp_ms": timestamp_ms,
        "location": body.location.model_dump(),
        "sample_rate_hz": body.sample_rate_hz,
        "segment_duration_s": body.segment_duration_s,
        "num_samples": len(body.samples),
        "sensor_type": body.sensor_type,
        "metadata": body.metadata,
    }
    await store.add_spectrogram(body.station_id, record)
    return {"status": "accepted", "station_id": body.station_id}
