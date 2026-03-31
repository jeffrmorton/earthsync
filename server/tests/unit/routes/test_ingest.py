"""Tests for data ingestion endpoint."""

import pytest

API_KEY = "test-api-ingest-key"


def _valid_ingest_body(num_samples: int = 2560) -> dict:
    return {
        "station_id": "det-001",
        "timestamp": "2025-01-01T00:00:00Z",
        "location": {"lat": 37.0, "lon": -3.4},
        "samples": [0.0] * num_samples,
        "sample_rate_hz": 256,
        "segment_duration_s": 10.0,
    }


@pytest.mark.asyncio
async def test_ingest_valid(client):
    resp = await client.post(
        "/api/data-ingest",
        json=_valid_ingest_body(),
        headers={"X-API-Key": API_KEY},
    )
    assert resp.status_code == 202
    data = resp.json()
    assert data["status"] == "accepted"
    assert data["station_id"] == "det-001"


@pytest.mark.asyncio
async def test_ingest_stores_data(client, app):
    """Ingested data should be stored in the DataStore."""
    await client.post(
        "/api/data-ingest",
        json=_valid_ingest_body(),
        headers={"X-API-Key": API_KEY},
    )
    store = app.state.store
    specs = await store.get_spectrograms(station_id="det-001", hours=1)
    assert len(specs) == 1
    assert specs[0]["station_id"] == "det-001"
    assert specs[0]["sample_rate_hz"] == 256
    assert specs[0]["num_samples"] == 2560


@pytest.mark.asyncio
async def test_ingest_valid_tolerance(client):
    """Samples within +-2 of expected should be accepted."""
    resp = await client.post(
        "/api/data-ingest",
        json=_valid_ingest_body(num_samples=2562),
        headers={"X-API-Key": API_KEY},
    )
    assert resp.status_code == 202


@pytest.mark.asyncio
async def test_ingest_invalid_samples_length(client):
    resp = await client.post(
        "/api/data-ingest",
        json=_valid_ingest_body(num_samples=100),
        headers={"X-API-Key": API_KEY},
    )
    assert resp.status_code == 422
    assert "Samples length" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_ingest_missing_api_key(client):
    resp = await client.post(
        "/api/data-ingest",
        json=_valid_ingest_body(),
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_ingest_invalid_api_key(client):
    resp = await client.post(
        "/api/data-ingest",
        json=_valid_ingest_body(),
        headers={"X-API-Key": "wrong-key"},
    )
    assert resp.status_code == 403
