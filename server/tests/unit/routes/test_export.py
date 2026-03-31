"""Tests for export endpoints."""

import time
from datetime import UTC, datetime, timedelta

import pytest
from jwt import encode


def _auth_header() -> dict:
    payload = {
        "sub": "testuser",
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + timedelta(hours=1),
    }
    token = encode(payload, "test-jwt-secret-key", algorithm="HS256")
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_export_peaks_empty(client):
    resp = await client.get("/api/export/peaks", headers=_auth_header())
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_export_peaks_with_data(client, app):
    store = app.state.store
    now_ms = int(time.time() * 1000)
    await store.add_peaks("det-001", now_ms, [{"freq": 7.83, "amp": 80.0}])
    resp = await client.get("/api/export/peaks", headers=_auth_header())
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["stationId"] == "det-001"


@pytest.mark.asyncio
async def test_export_peaks_json_default(client, app):
    """Default format returns JSON with application/json content type."""
    store = app.state.store
    now_ms = int(time.time() * 1000)
    await store.add_peaks("det-001", now_ms, [{"freq": 7.83, "amp": 80.0}])
    resp = await client.get("/api/export/peaks", headers=_auth_header())
    assert resp.status_code == 200
    assert "application/json" in resp.headers["content-type"]
    data = resp.json()
    assert len(data) == 1


@pytest.mark.asyncio
async def test_export_peaks_csv_format(client, app):
    """format=csv returns CSV with correct content type and disposition."""
    store = app.state.store
    now_ms = int(time.time() * 1000)
    await store.add_peaks(
        "det-001", now_ms, [{"freq": 7.83, "amp": 80.0, "q_factor": 4.0, "snr": 12.0}]
    )
    resp = await client.get("/api/export/peaks", params={"format": "csv"}, headers=_auth_header())
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    assert "peaks.csv" in resp.headers.get("content-disposition", "")
    text = resp.text
    lines = text.strip().split("\n")
    assert lines[0].startswith("timestamp,station_id,freq_hz")
    assert len(lines) == 2  # header + 1 data row
    assert "det-001" in lines[1]


@pytest.mark.asyncio
async def test_export_peaks_csv_empty(client):
    """CSV export with no data returns header only."""
    resp = await client.get("/api/export/peaks", params={"format": "csv"}, headers=_auth_header())
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    lines = resp.text.strip().split("\n")
    assert len(lines) == 1  # header only


@pytest.mark.asyncio
async def test_export_peaks_with_params(client):
    resp = await client.get(
        "/api/export/peaks",
        params={
            "station": "det-001",
            "from": "2025-01-01T00:00:00Z",
            "to": "2025-01-02T00:00:00Z",
            "format": "csv",
        },
        headers=_auth_header(),
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_export_spectra_empty(client):
    resp = await client.get("/api/export/spectra", headers=_auth_header())
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_export_spectra_with_data(client, app):
    store = app.state.store
    now_ms = int(time.time() * 1000)
    await store.add_spectrogram(
        "det-001",
        {
            "station_id": "det-001",
            "timestamp_ms": now_ms,
            "location": {"lat": 37.0, "lon": -3.4},
        },
    )
    resp = await client.get("/api/export/spectra", headers=_auth_header())
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["station_id"] == "det-001"


@pytest.mark.asyncio
async def test_export_spectra_csv_format(client, app):
    """format=csv on spectra returns CSV with frequency-bin columns."""
    store = app.state.store
    now_ms = int(time.time() * 1000)
    await store.add_spectrogram(
        "det-001",
        {
            "station_id": "det-001",
            "timestamp_ms": now_ms,
            "spectrogram": [0.1, 0.2, 0.3],
            "location": {"lat": 37.0, "lon": -3.4},
        },
    )
    resp = await client.get("/api/export/spectra", params={"format": "csv"}, headers=_auth_header())
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    assert "spectra.csv" in resp.headers.get("content-disposition", "")
    text = resp.text
    lines = text.strip().split("\n")
    assert lines[0].startswith("timestamp,station_id,0.00Hz")
    assert len(lines) == 2  # header + 1 data row


@pytest.mark.asyncio
async def test_export_spectra_csv_empty(client):
    """CSV spectra export with no data returns header only."""
    resp = await client.get("/api/export/spectra", params={"format": "csv"}, headers=_auth_header())
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    lines = resp.text.strip().split("\n")
    assert len(lines) == 1  # header only


@pytest.mark.asyncio
async def test_export_peaks_requires_jwt(client):
    resp = await client.get("/api/export/peaks")
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_export_spectra_requires_jwt(client):
    resp = await client.get("/api/export/spectra")
    assert resp.status_code == 422
