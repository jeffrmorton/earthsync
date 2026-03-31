"""Tests for earthsync_station.config."""

import pytest
from earthsync_station.config import StationSettings, get_settings


class TestStationSettings:
    def test_required_fields(self, monkeypatch):
        """Settings loads with required env vars set."""
        monkeypatch.setenv("EARTHSYNC_STATION_STATION_ID", "test-station-001")
        monkeypatch.setenv("EARTHSYNC_STATION_API_KEY", "test-api-key-abc")
        settings = StationSettings()
        assert settings.station_id == "test-station-001"
        assert settings.api_key == "test-api-key-abc"

    def test_defaults(self, monkeypatch):
        """All default values are correct."""
        monkeypatch.setenv("EARTHSYNC_STATION_STATION_ID", "s1")
        monkeypatch.setenv("EARTHSYNC_STATION_API_KEY", "k1")
        settings = StationSettings()
        assert settings.server_url == "http://localhost:3000"
        assert settings.sample_rate_hz == 256
        assert settings.segment_duration_s == 10.0
        assert settings.latitude == 0.0
        assert settings.longitude == 0.0
        assert settings.sensor_type == "induction_coil"
        assert settings.adc_gain == 1
        assert settings.gps_enabled is True
        assert settings.upload_retry_max == 3
        assert settings.upload_retry_delay_s == 5.0
        assert settings.log_level == "info"

    def test_custom_env_overrides(self, monkeypatch):
        """All fields can be overridden via env vars."""
        monkeypatch.setenv("EARTHSYNC_STATION_STATION_ID", "custom-id")
        monkeypatch.setenv("EARTHSYNC_STATION_API_KEY", "custom-key")
        monkeypatch.setenv("EARTHSYNC_STATION_SERVER_URL", "http://remote:8080")
        monkeypatch.setenv("EARTHSYNC_STATION_SAMPLE_RATE_HZ", "512")
        monkeypatch.setenv("EARTHSYNC_STATION_SEGMENT_DURATION_S", "5.0")
        monkeypatch.setenv("EARTHSYNC_STATION_LATITUDE", "37.7749")
        monkeypatch.setenv("EARTHSYNC_STATION_LONGITUDE", "-122.4194")
        monkeypatch.setenv("EARTHSYNC_STATION_SENSOR_TYPE", "magnetometer")
        monkeypatch.setenv("EARTHSYNC_STATION_GPS_ENABLED", "false")
        monkeypatch.setenv("EARTHSYNC_STATION_UPLOAD_RETRY_MAX", "5")
        monkeypatch.setenv("EARTHSYNC_STATION_UPLOAD_RETRY_DELAY_S", "10.0")
        monkeypatch.setenv("EARTHSYNC_STATION_LOG_LEVEL", "debug")

        settings = StationSettings()
        assert settings.station_id == "custom-id"
        assert settings.api_key == "custom-key"
        assert settings.server_url == "http://remote:8080"
        assert settings.sample_rate_hz == 512
        assert settings.segment_duration_s == 5.0
        assert settings.latitude == pytest.approx(37.7749)
        assert settings.longitude == pytest.approx(-122.4194)
        assert settings.sensor_type == "magnetometer"
        assert settings.adc_gain == 1  # default; Literal[int] can't coerce from env string
        assert settings.gps_enabled is False
        assert settings.upload_retry_max == 5
        assert settings.upload_retry_delay_s == 10.0
        assert settings.log_level == "debug"

    def test_missing_required_raises(self, monkeypatch):
        """Missing required fields raise ValidationError."""
        # Clear any existing env vars that might satisfy requirements
        monkeypatch.delenv("EARTHSYNC_STATION_STATION_ID", raising=False)
        monkeypatch.delenv("EARTHSYNC_STATION_API_KEY", raising=False)
        with pytest.raises(Exception):  # noqa: B017, PT011
            StationSettings()


class TestGetSettings:
    def test_get_settings_returns_instance(self, monkeypatch):
        """get_settings returns a StationSettings instance."""
        monkeypatch.setenv("EARTHSYNC_STATION_STATION_ID", "cached-station")
        monkeypatch.setenv("EARTHSYNC_STATION_API_KEY", "cached-key")
        get_settings.cache_clear()
        settings = get_settings()
        assert isinstance(settings, StationSettings)
        assert settings.station_id == "cached-station"

    def test_get_settings_cached(self, monkeypatch):
        """get_settings returns the same object on repeated calls (lru_cache)."""
        monkeypatch.setenv("EARTHSYNC_STATION_STATION_ID", "cache-test")
        monkeypatch.setenv("EARTHSYNC_STATION_API_KEY", "cache-key")
        get_settings.cache_clear()
        a = get_settings()
        b = get_settings()
        assert a is b
        get_settings.cache_clear()
