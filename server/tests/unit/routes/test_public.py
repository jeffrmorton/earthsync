"""Tests for public (unauthenticated) endpoints."""

import time

import pytest


@pytest.mark.asyncio
async def test_list_stations_empty(client):
    resp = await client.get("/api/public/stations")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_list_stations_with_data(client, app):
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
    resp = await client.get("/api/public/stations")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["id"] == "det-001"
    assert data[0]["location"]["lat"] == 37.0


@pytest.mark.asyncio
async def test_station_peaks_empty(client):
    resp = await client.get("/api/public/stations/det-001/peaks")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_station_peaks_with_data(client, app):
    store = app.state.store
    now_ms = int(time.time() * 1000)
    await store.add_peaks("det-001", now_ms, [{"freq": 7.83, "amp": 80.0}])
    resp = await client.get("/api/public/stations/det-001/peaks")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["peaks"][0]["freq"] == 7.83


@pytest.mark.asyncio
async def test_station_latest_empty(client):
    resp = await client.get("/api/public/stations/det-001/latest")
    assert resp.status_code == 200
    assert resp.json() == {}


@pytest.mark.asyncio
async def test_station_latest_with_data(client, app):
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
    await store.add_spectrogram(
        "det-001",
        {
            "station_id": "det-001",
            "timestamp_ms": now_ms + 1000,
            "location": {"lat": 37.1, "lon": -3.5},
        },
    )
    resp = await client.get("/api/public/stations/det-001/latest")
    assert resp.status_code == 200
    data = resp.json()
    assert data["location"]["lat"] == 37.1


@pytest.mark.asyncio
async def test_get_global_qbursts_empty(client):
    resp = await client.get("/api/public/qbursts")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_get_global_qbursts_with_data(client, app):
    store = app.state.store
    now_ms = int(time.time() * 1000)
    await store.store_global_qburst(
        {
            "peak_timestamp_ms": now_ms,
            "station_ids": ["det-A", "det-B"],
            "num_stations": 2,
            "mean_amplitude": 55.0,
        }
    )
    resp = await client.get("/api/public/qbursts")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["num_stations"] == 2
    assert data[0]["station_ids"] == ["det-A", "det-B"]


@pytest.mark.asyncio
async def test_get_global_qbursts_with_hours_param(client, app):
    store = app.state.store
    now_ms = int(time.time() * 1000)
    await store.store_global_qburst(
        {
            "peak_timestamp_ms": now_ms,
            "station_ids": ["det-A"],
            "num_stations": 1,
            "mean_amplitude": 50.0,
        }
    )
    resp = await client.get("/api/public/qbursts?hours=1")
    assert resp.status_code == 200
    assert len(resp.json()) == 1
