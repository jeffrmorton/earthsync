"""End-to-end integration tests against running Docker services.

Requires: docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
Server at http://localhost:3001

Tests the full data flow:
1. Health check
2. User registration + login
3. Data ingest (synthetic SR samples)
4. History retrieval
5. Public API
6. Calibration upload
7. Export endpoints
"""

import os
import time

import httpx
import numpy as np
import pytest

BASE_URL = os.environ.get("EARTHSYNC_TEST_URL", "http://localhost:3001")
API_KEY = os.environ.get("EARTHSYNC_TEST_API_KEY", "changeme-in-production")


def _generate_test_signal(sample_rate: int = 256, duration_s: float = 10.0) -> list[float]:
    """Generate a simple test signal with SR-like peaks."""
    n = int(sample_rate * duration_s)
    t = np.arange(n) / sample_rate
    signal = np.zeros(n)
    # Add Schumann resonance modes
    for freq, amp in [(7.83, 1.0), (14.3, 0.7), (20.8, 0.5)]:
        signal += amp * np.sin(2 * np.pi * freq * t)
    # Add noise
    signal += 0.1 * np.random.default_rng(42).standard_normal(n)
    return signal.tolist()


def _unique_username() -> str:
    """Generate a unique username using current timestamp."""
    return f"testuser_{int(time.time() * 1000)}"


def _make_ingest_payload(
    station_id: str = "integ-test-det",
    sample_rate: int = 256,
    duration_s: float = 10.0,
) -> dict:
    """Build a valid IngestRequest payload."""
    return {
        "station_id": station_id,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "location": {"lat": 37.0, "lon": -3.4},
        "samples": _generate_test_signal(sample_rate, duration_s),
        "sample_rate_hz": sample_rate,
        "segment_duration_s": duration_s,
        "sensor_type": "test_coil",
        "metadata": {"integration_test": True},
    }


def _register_and_login(client: httpx.Client, username: str | None = None) -> str:
    """Register a new user and log in, returning the JWT token."""
    if username is None:
        username = _unique_username()
    password = "integration_test_password_123"

    client.post(
        f"{BASE_URL}/api/auth/register",
        json={"username": username, "password": password},
    )
    resp = client.post(
        f"{BASE_URL}/api/auth/login",
        json={"username": username, "password": password},
    )
    return resp.json()["token"]


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestHealthCheck:
    """Verify the health endpoint is reachable and returns expected data."""

    def test_health_returns_ok(self):
        with httpx.Client() as client:
            resp = client.get(f"{BASE_URL}/health")
            assert resp.status_code == 200
            body = resp.json()
            assert body["status"] == "ok"

    def test_health_version(self):
        with httpx.Client() as client:
            resp = client.get(f"{BASE_URL}/health")
            assert resp.status_code == 200
            body = resp.json()
            assert body["version"] == "0.1.1"


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestAuth:
    """Registration and login flow."""

    def test_register_user(self):
        username = _unique_username()
        with httpx.Client() as client:
            resp = client.post(
                f"{BASE_URL}/api/auth/register",
                json={"username": username, "password": "securepassword123"},
            )
            assert resp.status_code in (200, 201)
            body = resp.json()
            assert body["username"] == username

    def test_register_duplicate(self):
        username = _unique_username()
        with httpx.Client() as client:
            # First registration
            resp1 = client.post(
                f"{BASE_URL}/api/auth/register",
                json={"username": username, "password": "securepassword123"},
            )
            assert resp1.status_code in (200, 201)

            # Duplicate registration
            resp2 = client.post(
                f"{BASE_URL}/api/auth/register",
                json={"username": username, "password": "securepassword123"},
            )
            assert resp2.status_code in (400, 409)

    def test_login_success(self):
        username = _unique_username()
        password = "securepassword123"
        with httpx.Client() as client:
            client.post(
                f"{BASE_URL}/api/auth/register",
                json={"username": username, "password": password},
            )
            resp = client.post(
                f"{BASE_URL}/api/auth/login",
                json={"username": username, "password": password},
            )
            assert resp.status_code == 200
            body = resp.json()
            assert "token" in body
            assert isinstance(body["token"], str)
            assert len(body["token"]) > 0
            assert "expires_in" in body
            assert body["expires_in"] > 0

    def test_login_wrong_password(self):
        username = _unique_username()
        with httpx.Client() as client:
            client.post(
                f"{BASE_URL}/api/auth/register",
                json={"username": username, "password": "securepassword123"},
            )
            resp = client.post(
                f"{BASE_URL}/api/auth/login",
                json={"username": username, "password": "wrong_password_99"},
            )
            assert resp.status_code == 401

    def test_login_nonexistent_user(self):
        with httpx.Client() as client:
            resp = client.post(
                f"{BASE_URL}/api/auth/login",
                json={"username": "nonexistent_user_xyz_999", "password": "doesnotmatter1"},
            )
            assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Data Ingest
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDataIngest:
    """Ingest endpoint with API key authentication."""

    def test_ingest_valid_signal(self):
        payload = _make_ingest_payload()
        with httpx.Client() as client:
            resp = client.post(
                f"{BASE_URL}/api/data-ingest",
                json=payload,
                headers={"X-API-Key": API_KEY},
            )
            assert resp.status_code == 202
            body = resp.json()
            assert body["status"] == "accepted"
            assert body["station_id"] == payload["station_id"]

    def test_ingest_missing_api_key(self):
        payload = _make_ingest_payload()
        with httpx.Client() as client:
            resp = client.post(
                f"{BASE_URL}/api/data-ingest",
                json=payload,
                # No X-API-Key header
            )
            assert resp.status_code in (403, 422)

    def test_ingest_invalid_api_key(self):
        payload = _make_ingest_payload()
        with httpx.Client() as client:
            resp = client.post(
                f"{BASE_URL}/api/data-ingest",
                json=payload,
                headers={"X-API-Key": "totally-wrong-key"},
            )
            assert resp.status_code == 403

    def test_ingest_empty_samples(self):
        payload = _make_ingest_payload()
        payload["samples"] = []
        with httpx.Client() as client:
            resp = client.post(
                f"{BASE_URL}/api/data-ingest",
                json=payload,
                headers={"X-API-Key": API_KEY},
            )
            # Empty samples violates sample_rate * duration constraint
            assert resp.status_code in (400, 422)


# ---------------------------------------------------------------------------
# History (requires JWT)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestHistory:
    """History endpoints require JWT authentication."""

    def test_history_hours(self):
        with httpx.Client() as client:
            token = _register_and_login(client)
            resp = client.get(
                f"{BASE_URL}/api/history/hours/1",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == 200
            body = resp.json()
            assert isinstance(body, list)

    def test_history_peaks(self):
        with httpx.Client() as client:
            token = _register_and_login(client)
            resp = client.get(
                f"{BASE_URL}/api/history/peaks/hours/1",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == 200
            body = resp.json()
            assert isinstance(body, list)

    def test_history_no_auth(self):
        with httpx.Client() as client:
            resp = client.get(f"{BASE_URL}/api/history/hours/1")
            assert resp.status_code in (401, 422)


# ---------------------------------------------------------------------------
# Public API (no auth required)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPublicAPI:
    """Public endpoints accessible without authentication."""

    def test_stations_list(self):
        with httpx.Client() as client:
            resp = client.get(f"{BASE_URL}/api/public/stations")
            assert resp.status_code == 200
            body = resp.json()
            assert isinstance(body, list)

    def test_station_latest(self):
        with httpx.Client() as client:
            resp = client.get(f"{BASE_URL}/api/public/stations/simulator1/latest")
            assert resp.status_code == 200
            body = resp.json()
            assert isinstance(body, dict)

    def test_station_peaks(self):
        with httpx.Client() as client:
            resp = client.get(f"{BASE_URL}/api/public/stations/simulator1/peaks")
            assert resp.status_code == 200
            body = resp.json()
            assert isinstance(body, list)


# ---------------------------------------------------------------------------
# Calibration (mixed auth: API key for PUT, JWT for GET)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCalibration:
    """Calibration endpoints with mixed authentication."""

    def test_upload_calibration(self):
        with httpx.Client() as client:
            resp = client.put(
                f"{BASE_URL}/api/stations/test-det/calibration",
                json={
                    "gain": 1.05,
                    "offset": -0.02,
                    "noise_floor_uv": 0.3,
                    "last_calibrated": "2025-01-15T00:00:00Z",
                },
                headers={"X-API-Key": API_KEY},
            )
            assert resp.status_code == 200
            body = resp.json()
            assert body["station_id"] == "test-det"
            assert body["status"] == "updated"

    def test_get_calibration(self):
        with httpx.Client() as client:
            token = _register_and_login(client)
            resp = client.get(
                f"{BASE_URL}/api/stations/test-det/calibration",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == 200
            body = resp.json()
            assert isinstance(body, dict)

    def test_quality_summary(self):
        with httpx.Client() as client:
            token = _register_and_login(client)
            resp = client.get(
                f"{BASE_URL}/api/stations/test-det/quality",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == 200
            body = resp.json()
            assert isinstance(body, dict)


# ---------------------------------------------------------------------------
# Export (requires JWT)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestExport:
    """Export endpoints require JWT authentication."""

    def test_export_peaks(self):
        with httpx.Client() as client:
            token = _register_and_login(client)
            resp = client.get(
                f"{BASE_URL}/api/export/peaks",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == 200
            body = resp.json()
            assert isinstance(body, list)

    def test_export_spectra(self):
        with httpx.Client() as client:
            token = _register_and_login(client)
            resp = client.get(
                f"{BASE_URL}/api/export/spectra",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == 200
            body = resp.json()
            assert isinstance(body, list)


# ---------------------------------------------------------------------------
# Full Pipeline (multi-step flows)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestFullPipeline:
    """Multi-step flows verifying data travels through the system."""

    def test_ingest_then_history(self):
        """Ingest data via API, then query history to confirm the server accepted it."""
        with httpx.Client() as client:
            # Step 1: Ingest a valid signal
            payload = _make_ingest_payload(station_id="pipeline-test-det")
            ingest_resp = client.post(
                f"{BASE_URL}/api/data-ingest",
                json=payload,
                headers={"X-API-Key": API_KEY},
            )
            assert ingest_resp.status_code == 202
            assert ingest_resp.json()["status"] == "accepted"

            # Step 2: Register and login to get JWT
            token = _register_and_login(client)

            # Step 3: Query history
            history_resp = client.get(
                f"{BASE_URL}/api/history/hours/1",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert history_resp.status_code == 200
            assert isinstance(history_resp.json(), list)

            # Step 4: Query peaks history
            peaks_resp = client.get(
                f"{BASE_URL}/api/history/peaks/hours/1",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert peaks_resp.status_code == 200
            assert isinstance(peaks_resp.json(), list)

    def test_register_login_ingest_retrieve(self):
        """Full user lifecycle: register, login, ingest data, retrieve via multiple endpoints."""
        username = _unique_username()
        password = "full_pipeline_pass_42"

        with httpx.Client() as client:
            # Step 1: Register
            reg_resp = client.post(
                f"{BASE_URL}/api/auth/register",
                json={"username": username, "password": password},
            )
            assert reg_resp.status_code in (200, 201)
            assert reg_resp.json()["username"] == username

            # Step 2: Login
            login_resp = client.post(
                f"{BASE_URL}/api/auth/login",
                json={"username": username, "password": password},
            )
            assert login_resp.status_code == 200
            token = login_resp.json()["token"]
            assert len(token) > 0

            # Step 3: Ingest data with API key
            station_id = f"lifecycle-det-{int(time.time())}"
            payload = _make_ingest_payload(station_id=station_id)
            ingest_resp = client.post(
                f"{BASE_URL}/api/data-ingest",
                json=payload,
                headers={"X-API-Key": API_KEY},
            )
            assert ingest_resp.status_code == 202
            assert ingest_resp.json()["station_id"] == station_id

            # Step 4: Retrieve history (JWT auth)
            auth_headers = {"Authorization": f"Bearer {token}"}

            history_resp = client.get(
                f"{BASE_URL}/api/history/hours/1",
                headers=auth_headers,
            )
            assert history_resp.status_code == 200

            # Step 5: Retrieve peaks history
            peaks_resp = client.get(
                f"{BASE_URL}/api/history/peaks/hours/1",
                headers=auth_headers,
            )
            assert peaks_resp.status_code == 200

            # Step 6: Upload calibration (API key auth)
            cal_resp = client.put(
                f"{BASE_URL}/api/stations/{station_id}/calibration",
                json={"gain": 1.0, "offset": 0.0},
                headers={"X-API-Key": API_KEY},
            )
            assert cal_resp.status_code == 200
            assert cal_resp.json()["station_id"] == station_id

            # Step 7: Retrieve calibration (JWT auth)
            cal_get_resp = client.get(
                f"{BASE_URL}/api/stations/{station_id}/calibration",
                headers=auth_headers,
            )
            assert cal_get_resp.status_code == 200

            # Step 8: Quality summary (JWT auth)
            quality_resp = client.get(
                f"{BASE_URL}/api/stations/{station_id}/quality",
                headers=auth_headers,
            )
            assert quality_resp.status_code == 200

            # Step 9: Export endpoints (JWT auth)
            export_peaks_resp = client.get(
                f"{BASE_URL}/api/export/peaks",
                headers=auth_headers,
            )
            assert export_peaks_resp.status_code == 200

            export_spectra_resp = client.get(
                f"{BASE_URL}/api/export/spectra",
                headers=auth_headers,
            )
            assert export_spectra_resp.status_code == 200

            # Step 10: Public endpoints (no auth)
            stations_resp = client.get(f"{BASE_URL}/api/public/stations")
            assert stations_resp.status_code == 200

            latest_resp = client.get(
                f"{BASE_URL}/api/public/stations/{station_id}/latest",
            )
            assert latest_resp.status_code == 200
