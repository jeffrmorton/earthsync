"""Simulator configuration via environment variables."""

from uuid import uuid4

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """EarthSync simulator settings.

    All values can be overridden with EARTHSYNC_SIMULATOR_<NAME> env vars.
    """

    model_config = {"env_prefix": "EARTHSYNC_SIMULATOR_"}

    station_id: str = Field(default_factory=lambda: str(uuid4()))
    station_model: str = "sierra_nevada"
    latitude: float = 37.0
    longitude: float = -3.4
    interval_ms: int = 10000
    segment_duration_s: float = 10.0
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_password: str = ""
    redis_connect_timeout_ms: int = 20000
    log_level: str = "info"
