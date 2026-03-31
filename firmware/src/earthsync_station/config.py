"""Station configuration via environment variables."""

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings


class StationSettings(BaseSettings):
    """Configuration for an EarthSync measurement station.

    All fields are read from environment variables with the
    ``EARTHSYNC_STATION_`` prefix, e.g. ``EARTHSYNC_STATION_STATION_ID``.
    """

    model_config = {"env_prefix": "EARTHSYNC_STATION_"}

    station_id: str
    server_url: str = "http://localhost:3000"
    api_key: str
    sample_rate_hz: int = 256
    segment_duration_s: float = 10.0
    latitude: float = 0.0
    longitude: float = 0.0
    sensor_type: str = "induction_coil"
    adc_type: str = "ads1256"  # ads1256, ads1263, soundcard, symmetric_research, mock
    adc_gain: Literal[1, 2, 4, 8, 16, 32, 64] = 1
    gps_enabled: bool = True
    upload_retry_max: int = 3
    upload_retry_delay_s: float = 5.0
    log_level: str = "info"


@lru_cache
def get_settings() -> StationSettings:
    """Return cached settings singleton."""
    return StationSettings()  # type: ignore[call-arg]
