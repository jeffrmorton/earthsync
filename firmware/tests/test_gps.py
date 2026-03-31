"""Tests for earthsync_station.gps."""

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from earthsync_station.gps import GPSD, MockGPS


class TestMockGPS:
    def test_get_time_returns_datetime(self):
        gps = MockGPS()
        t = gps.get_time()
        assert isinstance(t, datetime)
        assert t.tzinfo is not None

    def test_is_synchronized_default_true(self):
        gps = MockGPS()
        assert gps.is_synchronized() is True

    def test_is_synchronized_false(self):
        gps = MockGPS(synchronized=False)
        assert gps.is_synchronized() is False

    def test_close_no_error(self):
        gps = MockGPS()
        gps.close()  # Should not raise


class TestGPSD:
    def test_init_defaults(self):
        gpsd = GPSD()
        assert gpsd._host == "localhost"
        assert gpsd._port == 2947
        assert gpsd._session is None

    def test_init_custom(self):
        gpsd = GPSD(host="192.168.1.1", port=3000)
        assert gpsd._host == "192.168.1.1"
        assert gpsd._port == 3000

    def test_get_time_import_error(self):
        """When gps module is not installed, get_time raises RuntimeError."""
        gpsd = GPSD()
        with (
            patch.dict("sys.modules", {"gps": None}),
            pytest.raises(RuntimeError, match="gps module not available"),
        ):
            gpsd.get_time()

    def test_get_time_with_valid_fix(self):
        """When gpsd returns a valid fix, get_time returns that time."""
        mock_gps_module = MagicMock()
        mock_gps_module.WATCH_ENABLE = 1

        mock_session = MagicMock()
        mock_session.fix.time = "2026-03-28T12:00:00+00:00"

        mock_gps_module.gps.return_value = mock_session

        gpsd = GPSD()
        with patch.dict("sys.modules", {"gps": mock_gps_module}):
            t = gpsd.get_time()

        assert isinstance(t, datetime)
        assert t.year == 2026

    def test_get_time_no_fix_returns_utc_now(self):
        """When gpsd has no fix time, get_time returns datetime.now(UTC)."""
        mock_gps_module = MagicMock()
        mock_gps_module.WATCH_ENABLE = 1

        mock_session = MagicMock()
        mock_session.fix.time = None
        # Ensure hasattr check for 'time' passes but value is falsy
        mock_session.fix.time = ""

        mock_gps_module.gps.return_value = mock_session

        gpsd = GPSD()
        with patch.dict("sys.modules", {"gps": mock_gps_module}):
            t = gpsd.get_time()

        assert isinstance(t, datetime)

    def test_is_synchronized_success(self):
        """is_synchronized returns True when get_time succeeds."""
        gpsd = GPSD()
        with patch.object(gpsd, "get_time", return_value=datetime.now(UTC)):
            assert gpsd.is_synchronized() is True

    def test_is_synchronized_failure(self):
        """is_synchronized returns False when get_time raises."""
        gpsd = GPSD()
        with patch.object(gpsd, "get_time", side_effect=RuntimeError("no gps")):
            assert gpsd.is_synchronized() is False

    def test_close_with_session(self):
        """close() closes the session and sets it to None."""
        gpsd = GPSD()
        mock_session = MagicMock()
        gpsd._session = mock_session
        gpsd.close()
        mock_session.close.assert_called_once()
        assert gpsd._session is None

    def test_close_without_session(self):
        """close() with no session does not raise."""
        gpsd = GPSD()
        assert gpsd._session is None
        gpsd.close()  # Should not raise
        assert gpsd._session is None

    def test_get_time_reuses_session(self):
        """Second call to get_time reuses the existing session."""
        mock_gps_module = MagicMock()
        mock_gps_module.WATCH_ENABLE = 1

        mock_session = MagicMock()
        mock_session.fix.time = "2026-03-28T12:00:00+00:00"
        mock_gps_module.gps.return_value = mock_session

        gpsd = GPSD()
        with patch.dict("sys.modules", {"gps": mock_gps_module}):
            gpsd.get_time()
            gpsd.get_time()

        # gps.gps() should only be called once since session is reused
        mock_gps_module.gps.assert_called_once()
