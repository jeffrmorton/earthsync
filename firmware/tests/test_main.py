"""Tests for earthsync_station.main (Station class)."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
from earthsync_station.adc import MockADC
from earthsync_station.config import StationSettings
from earthsync_station.gps import MockGPS
from earthsync_station.main import Station
from earthsync_station.uploader import Uploader


@pytest.fixture
def settings(monkeypatch):
    monkeypatch.setenv("EARTHSYNC_STATION_STATION_ID", "test-station")
    monkeypatch.setenv("EARTHSYNC_STATION_API_KEY", "test-key")
    monkeypatch.setenv("EARTHSYNC_STATION_SEGMENT_DURATION_S", "0.1")
    return StationSettings()


@pytest.fixture
def adc():
    return MockADC()


@pytest.fixture
def gps():
    return MockGPS()


@pytest.fixture
def uploader():
    return MagicMock(spec=Uploader)


class TestStationInit:
    def test_init_with_config(self, adc, gps, uploader, settings):
        station = Station(adc, gps, uploader, config=settings)
        assert station._adc is adc
        assert station._gps is gps
        assert station._uploader is uploader
        assert station._settings is settings
        assert station._running is False

    def test_init_default_config(self, adc, gps, uploader, monkeypatch):
        """Station uses get_settings() when no config is passed."""
        monkeypatch.setenv("EARTHSYNC_STATION_STATION_ID", "default-cfg")
        monkeypatch.setenv("EARTHSYNC_STATION_API_KEY", "default-key")
        from earthsync_station.config import get_settings

        get_settings.cache_clear()
        station = Station(adc, gps, uploader)
        assert station._settings.station_id == "default-cfg"
        get_settings.cache_clear()


class TestStationStop:
    def test_stop_sets_running_false(self, adc, gps, uploader, settings):
        station = Station(adc, gps, uploader, config=settings)
        station._running = True
        station.stop()
        assert station._running is False

    def test_stop_closes_adc_and_gps(self, settings):
        adc = MagicMock()
        gps = MagicMock()
        uploader = MagicMock(spec=Uploader)
        station = Station(adc, gps, uploader, config=settings)
        station.stop()
        adc.close.assert_called_once()
        gps.close.assert_called_once()


class TestStationRun:
    @pytest.mark.asyncio
    async def test_run_uploads_payload(self, adc, gps, settings):
        """Station.run() reads ADC, gets GPS time, and uploads."""
        adc.configure(256, 1)
        uploader = MagicMock(spec=Uploader)
        uploader.upload = AsyncMock(return_value=True)

        station = Station(adc, gps, uploader, config=settings)

        async def stop_after_one_iteration():
            # Let the loop run one iteration then stop
            await asyncio.sleep(0.05)
            station.stop()

        task = asyncio.create_task(stop_after_one_iteration())
        await station.run()
        await task

        uploader.upload.assert_called()
        call_args = uploader.upload.call_args[0][0]
        assert call_args["station_id"] == "test-station"
        assert "samples" in call_args
        assert call_args["sample_rate_hz"] == 256
        assert "timestamp" in call_args
        assert "location" in call_args

    @pytest.mark.asyncio
    async def test_run_uses_utc_when_gps_unsynchronized(self, adc, settings):
        """When GPS is not synchronized, Station uses datetime.now(UTC)."""
        adc.configure(256, 1)
        gps = MockGPS(synchronized=False)
        uploader = MagicMock(spec=Uploader)
        uploader.upload = AsyncMock(return_value=True)

        station = Station(adc, gps, uploader, config=settings)

        async def stop_after_one_iteration():
            await asyncio.sleep(0.05)
            station.stop()

        task = asyncio.create_task(stop_after_one_iteration())
        await station.run()
        await task

        uploader.upload.assert_called()

    @pytest.mark.asyncio
    async def test_run_handles_exception(self, settings):
        """Station.run() catches and logs exceptions, continues running."""
        adc = MagicMock()
        adc.configure = MagicMock()
        adc.read_samples = MagicMock(side_effect=RuntimeError("adc error"))

        gps = MockGPS()
        uploader = MagicMock(spec=Uploader)
        uploader.upload = AsyncMock()

        station = Station(adc, gps, uploader, config=settings)

        call_count = 0

        def counting_read(n):
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                station.stop()
            raise RuntimeError("adc error")

        adc.read_samples = counting_read

        await station.run()
        # The loop should have run at least twice before stopping
        assert call_count >= 2
        # upload should never have been called since read_samples always fails
        uploader.upload.assert_not_called()
