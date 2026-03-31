"""Tests for historical data endpoints."""

import time
from datetime import UTC, datetime, timedelta

import pytest
from jwt import encode


def _auth_header() -> dict:
    """Build a valid JWT authorization header for testing."""
    payload = {
        "sub": "testuser",
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + timedelta(hours=1),
    }
    token = encode(payload, "test-jwt-secret-key", algorithm="HS256")
    return {"Authorization": f"Bearer {token}"}


async def _seed_spectrograms(app, station_id="det-001", count=3):
    """Seed the store with spectrograms that have current timestamps."""
    store = app.state.store
    now_ms = int(time.time() * 1000)
    for i in range(count):
        await store.add_spectrogram(
            station_id,
            {
                "station_id": station_id,
                "timestamp_ms": now_ms - i * 1000,
                "location": {"lat": 37.0, "lon": -3.4},
            },
        )


async def _seed_peaks(app, station_id="det-001", count=3):
    """Seed the store with peaks that have current timestamps."""
    store = app.state.store
    now_ms = int(time.time() * 1000)
    for i in range(count):
        await store.add_peaks(station_id, now_ms - i * 1000, [{"freq": 7.83, "amp": 80.0}])


@pytest.mark.asyncio
async def test_history_by_hours_empty(client):
    resp = await client.get("/api/history/hours/24", headers=_auth_header())
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_history_by_hours_with_data(client, app):
    await _seed_spectrograms(app)
    resp = await client.get("/api/history/hours/24", headers=_auth_header())
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 3
    assert data[0]["station_id"] == "det-001"


@pytest.mark.asyncio
async def test_history_by_range(client):
    resp = await client.get(
        "/api/history/range",
        params={"start_time": "2025-01-01T00:00:00Z", "end_time": "2025-01-02T00:00:00Z"},
        headers=_auth_header(),
    )
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_peaks_by_hours_empty(client):
    resp = await client.get("/api/history/peaks/hours/12", headers=_auth_header())
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_peaks_by_hours_with_data(client, app):
    await _seed_peaks(app)
    resp = await client.get("/api/history/peaks/hours/12", headers=_auth_header())
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 3
    assert data[0]["stationId"] == "det-001"
    assert data[0]["peaks"][0]["freq"] == 7.83


@pytest.mark.asyncio
async def test_peaks_by_range(client):
    resp = await client.get(
        "/api/history/peaks/range",
        params={"start_time": "2025-01-01T00:00:00Z", "end_time": "2025-01-02T00:00:00Z"},
        headers=_auth_header(),
    )
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_history_requires_jwt(client):
    resp = await client.get("/api/history/hours/24")
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_history_invalid_jwt(client):
    resp = await client.get(
        "/api/history/hours/24",
        headers={"Authorization": "Bearer invalid-token"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_history_expired_jwt(client):
    """Expired token should return 401."""
    payload = {
        "sub": "testuser",
        "iat": datetime.now(UTC) - timedelta(hours=2),
        "exp": datetime.now(UTC) - timedelta(hours=1),
    }
    token = encode(payload, "test-jwt-secret-key", algorithm="HS256")
    resp = await client.get(
        "/api/history/hours/24",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401
    assert "expired" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_history_invalid_auth_prefix(client):
    """Non-Bearer authorization header should return 401."""
    resp = await client.get(
        "/api/history/hours/24",
        headers={"Authorization": "Basic dXNlcjpwYXNz"},
    )
    assert resp.status_code == 401
    assert "Invalid authorization" in resp.json()["detail"]
