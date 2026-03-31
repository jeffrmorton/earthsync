"""Tests for calibration endpoints."""

from datetime import UTC, datetime, timedelta

import pytest
from jwt import encode

API_KEY = "test-api-ingest-key"


def _auth_header() -> dict:
    payload = {
        "sub": "testuser",
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + timedelta(hours=1),
    }
    token = encode(payload, "test-jwt-secret-key", algorithm="HS256")
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_update_calibration(client):
    resp = await client.put(
        "/api/stations/det-001/calibration",
        json={"offset": 0.1, "gain": 1.02},
        headers={"X-API-Key": API_KEY},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["station_id"] == "det-001"
    assert data["status"] == "updated"


@pytest.mark.asyncio
async def test_update_calibration_missing_api_key(client):
    resp = await client.put(
        "/api/stations/det-001/calibration",
        json={"offset": 0.1},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_update_calibration_invalid_api_key(client):
    resp = await client.put(
        "/api/stations/det-001/calibration",
        json={"offset": 0.1},
        headers={"X-API-Key": "wrong-key"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_get_calibration_empty(client):
    resp = await client.get(
        "/api/stations/det-001/calibration",
        headers=_auth_header(),
    )
    assert resp.status_code == 200
    assert resp.json() == {}


@pytest.mark.asyncio
async def test_get_calibration_after_set(client):
    """After uploading calibration, GET should return the stored data."""
    await client.put(
        "/api/stations/det-001/calibration",
        json={"offset": 0.1, "gain": 1.02},
        headers={"X-API-Key": API_KEY},
    )
    resp = await client.get(
        "/api/stations/det-001/calibration",
        headers=_auth_header(),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["offset"] == 0.1
    assert data["gain"] == 1.02
    assert data["station_id"] == "det-001"
    assert "uploaded_at" in data


@pytest.mark.asyncio
async def test_get_calibration_requires_jwt(client):
    resp = await client.get("/api/stations/det-001/calibration")
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_get_quality_no_data(client):
    resp = await client.get(
        "/api/stations/det-001/quality",
        headers=_auth_header(),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["station_id"] == "det-001"
    assert data["status"] == "no_data"


@pytest.mark.asyncio
async def test_get_quality_requires_jwt(client):
    resp = await client.get("/api/stations/det-001/quality")
    assert resp.status_code == 422
