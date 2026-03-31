"""EarthSync Station — main acquisition loop."""

import asyncio
from datetime import UTC, datetime

import structlog

from earthsync_station.adc import (
    ADS1256,
    ADS1263,
    ADCInterface,
    MockADC,
    SoundCardADC,
    SymmetricResearchADC,
)
from earthsync_station.config import StationSettings, get_settings
from earthsync_station.gps import GPSInterface
from earthsync_station.uploader import Uploader

logger = structlog.get_logger()

_ADC_FACTORIES: dict[str, type[ADCInterface]] = {
    "ads1256": ADS1256,
    "ads1263": ADS1263,
    "soundcard": SoundCardADC,
    "symmetric_research": SymmetricResearchADC,
    "mock": MockADC,
}


def create_adc(settings: StationSettings) -> ADCInterface:
    """Create ADC instance based on configuration."""
    cls = _ADC_FACTORIES.get(settings.adc_type)
    if cls is None:
        raise ValueError(
            f"Unknown ADC type: {settings.adc_type!r}. Valid: {', '.join(_ADC_FACTORIES)}"
        )
    return cls()


class Station:
    """Core acquisition loop: read ADC, timestamp via GPS, upload."""

    def __init__(
        self,
        adc: ADCInterface,
        gps: GPSInterface,
        uploader: Uploader,
        config=None,
    ):
        self._settings = config or get_settings()
        self._adc = adc
        self._gps = gps
        self._uploader = uploader
        self._running = False

    async def run(self) -> None:
        """Start the acquisition loop."""
        self._adc.configure(self._settings.sample_rate_hz, self._settings.adc_gain)
        self._running = True
        logger.info("station_started", station_id=self._settings.station_id)

        while self._running:
            try:
                n_samples = int(self._settings.sample_rate_hz * self._settings.segment_duration_s)
                samples = self._adc.read_samples(n_samples)
                timestamp = (
                    self._gps.get_time() if self._gps.is_synchronized() else datetime.now(UTC)
                )

                payload = {
                    "station_id": self._settings.station_id,
                    "timestamp": timestamp.isoformat(),
                    "location": {
                        "lat": self._settings.latitude,
                        "lon": self._settings.longitude,
                    },
                    "samples": samples.tolist(),
                    "sample_rate_hz": self._settings.sample_rate_hz,
                    "segment_duration_s": self._settings.segment_duration_s,
                    "sensor_type": self._settings.sensor_type,
                    "metadata": {"adc_gain": self._settings.adc_gain},
                }

                await self._uploader.upload(payload)
                await asyncio.sleep(self._settings.segment_duration_s)
            except Exception:
                logger.exception("acquisition_error")
                await asyncio.sleep(1.0)

    def stop(self) -> None:
        """Stop the acquisition loop and release hardware."""
        self._running = False
        self._adc.close()
        self._gps.close()
        logger.info("station_stopped")
