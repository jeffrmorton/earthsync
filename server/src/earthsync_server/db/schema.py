"""Database schema initialization with TimescaleDB hypertables."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    import asyncpg

logger = structlog.get_logger()

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS historical_spectrograms (
    id BIGSERIAL,
    station_id VARCHAR(50) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    location_lat DOUBLE PRECISION,
    location_lon DOUBLE PRECISION,
    spectrogram_data JSONB,
    transient_detected BOOLEAN DEFAULT FALSE,
    transient_details TEXT,
    noise_floor_estimate DOUBLE PRECISION,
    quality_flags JSONB,
    algorithm_version VARCHAR(50),
    is_calibrated BOOLEAN DEFAULT FALSE,
    sample_rate_hz INTEGER,
    segment_duration_s REAL,
    native_frequency_points INTEGER,
    lorentzian_fit JSONB,
    archived_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS historical_peaks (
    id BIGSERIAL,
    station_id VARCHAR(50) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    peak_data JSONB,
    archived_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS peak_tracking_state (
    station_id VARCHAR(50) PRIMARY KEY,
    last_update TIMESTAMPTZ NOT NULL,
    state_data JSONB
);

CREATE TABLE IF NOT EXISTS station_calibration (
    station_id VARCHAR(50) PRIMARY KEY,
    calibration_data JSONB,
    uploaded_at TIMESTAMPTZ DEFAULT NOW(),
    validated BOOLEAN DEFAULT FALSE,
    validation_errors TEXT
);

CREATE TABLE IF NOT EXISTS cross_validation_results (
    id BIGSERIAL PRIMARY KEY,
    station_id VARCHAR(50) NOT NULL,
    reference_source VARCHAR(255),
    timestamp TIMESTAMPTZ NOT NULL,
    correlation DOUBLE PRECISION,
    frequency_offset DOUBLE PRECISION,
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS qburst_events (
    id BIGSERIAL PRIMARY KEY,
    peak_timestamp TIMESTAMPTZ NOT NULL,
    station_ids TEXT[],
    num_stations INTEGER NOT NULL,
    mean_amplitude DOUBLE PRECISION,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_qburst_events_time ON qburst_events (peak_timestamp);
"""

INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_hist_spec_station_time
    ON historical_spectrograms (station_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_hist_peaks_station_time
    ON historical_peaks (station_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_cross_val_station_time
    ON cross_validation_results (station_id, timestamp);
"""

HYPERTABLE_STATEMENTS = [
    # Create hypertables with 1-day chunk interval
    """SELECT create_hypertable('historical_spectrograms', 'timestamp',
        if_not_exists => TRUE, migrate_data => TRUE,
        chunk_time_interval => INTERVAL '1 day')""",
    """SELECT create_hypertable('historical_peaks', 'timestamp',
        if_not_exists => TRUE, migrate_data => TRUE,
        chunk_time_interval => INTERVAL '1 day')""",
    # Enable compression
    """ALTER TABLE historical_spectrograms SET (
        timescaledb.compress = true,
        timescaledb.compress_segmentby = 'station_id')""",
    """ALTER TABLE historical_peaks SET (
        timescaledb.compress = true,
        timescaledb.compress_segmentby = 'station_id')""",
    # Add compression policies (compress data older than 1 day)
    "SELECT add_compression_policy('historical_spectrograms', INTERVAL '1 day', if_not_exists => true)",  # noqa: E501
    "SELECT add_compression_policy('historical_peaks', INTERVAL '1 day', if_not_exists => true)",
]


async def initialize_schema(pool: asyncpg.Pool, enable_timescale: bool = True) -> None:
    """Create tables, indexes, and optionally TimescaleDB hypertables."""
    async with pool.acquire() as conn:
        await conn.execute(SCHEMA_SQL)
        logger.info("schema_tables_created")
        await conn.execute(INDEX_SQL)
        logger.info("schema_indexes_created")
        if enable_timescale:
            try:
                await conn.execute("CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;")
                for stmt in HYPERTABLE_STATEMENTS:
                    try:
                        await conn.execute(stmt)
                    except Exception as e:
                        logger.warning("hypertable_statement_skipped", error=str(e))
                logger.info("timescaledb_configured")
            except Exception:
                logger.warning("timescaledb_not_available_using_plain_postgres")
