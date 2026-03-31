"""Application configuration via environment variables."""

from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """EarthSync server settings loaded from EARTHSYNC_-prefixed env vars."""

    model_config = {"env_prefix": "EARTHSYNC_"}

    # --- Server ---
    port: int = 8000
    cors_origins: list[str] = ["http://localhost:5173"]
    jwt_secret: str  # via EARTHSYNC_JWT_SECRET
    api_ingest_key: str  # via EARTHSYNC_API_INGEST_KEY
    jwt_expiration_hours: int = 1

    # --- Redis ---
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_password: str = ""

    # --- PostgreSQL ---
    db_host: str = "localhost"
    db_port: int = 5432
    db_user: str = "earthsync"
    db_password: str  # via EARTHSYNC_DB_PASSWORD
    db_name: str = "earthsync"

    # --- DSP ---
    display_frequency_points: int = 1101
    display_frequency_max_hz: float = 55.0
    lorentzian_max_modes: int = 5
    lorentzian_max_iterations: int = 5000

    # --- Peak detection ---
    peak_smoothing_window: int = 5
    peak_prominence_factor: float = 1.5
    peak_min_distance_hz: float = 1.0
    peak_absolute_threshold: float = 0.0
    peak_tracking_freq_tolerance_hz: float = 0.5
    sr_band_filtering: bool = True

    # --- Multitaper ---
    use_multitaper: bool = False
    multitaper_nw: float = 3.0
    multitaper_n_tapers: int = 5

    # --- Quality ---
    snr_noise_halfwidth_hz: float = 2.0
    snr_exclusion_halfwidth_hz: float = 0.3
    mains_freq: list[float] = [50.0, 60.0]
    mains_ratio_threshold: float = 10.0
    clipping_threshold_fraction: float = 0.995

    # --- Retention ---
    redis_spec_retention_hours: int = 24
    redis_peak_retention_hours: int = 72
    cleanup_interval_s: int = 3600
    cross_validation_interval_s: int = 3600

    # --- Spectral ---
    spectral_buffer_size: int = 12


@lru_cache
def get_settings() -> Settings:
    """Return cached settings instance."""
    return Settings()
