"""Tests for earthsync_server.db.schema — TimescaleDB schema initialization."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from earthsync_server.db.schema import (
    HYPERTABLE_STATEMENTS,
    INDEX_SQL,
    SCHEMA_SQL,
    initialize_schema,
)


class _AsyncCtx:
    """Minimal async context manager wrapping a mock connection."""

    def __init__(self, conn):
        self._conn = conn

    async def __aenter__(self):
        return self._conn

    async def __aexit__(self, *args):
        pass


@pytest.fixture
def mock_conn():
    conn = AsyncMock()
    conn.execute = AsyncMock()
    return conn


@pytest.fixture
def mock_pool(mock_conn):
    pool = MagicMock()
    pool.acquire.return_value = _AsyncCtx(mock_conn)
    return pool


class TestSchemaSQL:
    def test_schema_sql_contains_users_table(self):
        assert "CREATE TABLE IF NOT EXISTS users" in SCHEMA_SQL

    def test_schema_sql_contains_historical_spectrograms(self):
        assert "CREATE TABLE IF NOT EXISTS historical_spectrograms" in SCHEMA_SQL

    def test_schema_sql_contains_historical_peaks(self):
        assert "CREATE TABLE IF NOT EXISTS historical_peaks" in SCHEMA_SQL

    def test_schema_sql_contains_peak_tracking_state(self):
        assert "CREATE TABLE IF NOT EXISTS peak_tracking_state" in SCHEMA_SQL

    def test_schema_sql_contains_station_calibration(self):
        assert "CREATE TABLE IF NOT EXISTS station_calibration" in SCHEMA_SQL

    def test_schema_sql_contains_cross_validation_results(self):
        assert "CREATE TABLE IF NOT EXISTS cross_validation_results" in SCHEMA_SQL

    def test_schema_sql_contains_qburst_events_table(self):
        assert "CREATE TABLE IF NOT EXISTS qburst_events" in SCHEMA_SQL

    def test_schema_sql_qburst_events_has_peak_timestamp(self):
        assert "peak_timestamp TIMESTAMPTZ NOT NULL" in SCHEMA_SQL

    def test_schema_sql_qburst_events_has_station_ids(self):
        assert "station_ids TEXT[]" in SCHEMA_SQL

    def test_schema_sql_qburst_events_has_num_stations(self):
        assert "num_stations INTEGER NOT NULL" in SCHEMA_SQL

    def test_schema_sql_qburst_events_has_mean_amplitude(self):
        assert "mean_amplitude DOUBLE PRECISION" in SCHEMA_SQL

    def test_schema_sql_qburst_events_index(self):
        assert "idx_qburst_events_time" in SCHEMA_SQL


class TestIndexSQL:
    def test_index_sql_contains_spectrogram_index(self):
        assert "idx_hist_spec_station_time" in INDEX_SQL

    def test_index_sql_contains_peaks_index(self):
        assert "idx_hist_peaks_station_time" in INDEX_SQL

    def test_index_sql_contains_cross_val_index(self):
        assert "idx_cross_val_station_time" in INDEX_SQL


class TestHypertableStatements:
    def test_hypertable_statements_is_list(self):
        assert isinstance(HYPERTABLE_STATEMENTS, list)

    def test_hypertable_statements_count(self):
        assert len(HYPERTABLE_STATEMENTS) == 6

    def test_hypertable_spectrograms_create(self):
        stmt = HYPERTABLE_STATEMENTS[0]
        assert "historical_spectrograms" in stmt
        assert "create_hypertable" in stmt
        assert "chunk_time_interval" in stmt

    def test_hypertable_peaks_create(self):
        stmt = HYPERTABLE_STATEMENTS[1]
        assert "historical_peaks" in stmt
        assert "create_hypertable" in stmt
        assert "chunk_time_interval" in stmt

    def test_compression_enabled_spectrograms(self):
        stmt = HYPERTABLE_STATEMENTS[2]
        assert "historical_spectrograms" in stmt
        assert "timescaledb.compress" in stmt
        assert "compress_segmentby" in stmt

    def test_compression_enabled_peaks(self):
        stmt = HYPERTABLE_STATEMENTS[3]
        assert "historical_peaks" in stmt
        assert "timescaledb.compress" in stmt
        assert "compress_segmentby" in stmt

    def test_compression_policy_spectrograms(self):
        stmt = HYPERTABLE_STATEMENTS[4]
        assert "add_compression_policy" in stmt
        assert "historical_spectrograms" in stmt

    def test_compression_policy_peaks(self):
        stmt = HYPERTABLE_STATEMENTS[5]
        assert "add_compression_policy" in stmt
        assert "historical_peaks" in stmt


class TestInitializeSchema:
    async def test_creates_tables_and_indexes(self, mock_pool, mock_conn):
        await initialize_schema(mock_pool, enable_timescale=False)
        calls = [c.args[0] for c in mock_conn.execute.call_args_list]
        assert calls[0] == SCHEMA_SQL
        assert calls[1] == INDEX_SQL

    async def test_with_timescale_enabled(self, mock_pool, mock_conn):
        await initialize_schema(mock_pool, enable_timescale=True)
        calls = [c.args[0] for c in mock_conn.execute.call_args_list]
        assert calls[0] == SCHEMA_SQL
        assert calls[1] == INDEX_SQL
        assert "CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;" in calls[2]
        # 6 individual hypertable statements follow
        for i, stmt in enumerate(HYPERTABLE_STATEMENTS):
            assert calls[3 + i] == stmt

    async def test_timescale_default_enabled(self, mock_pool, mock_conn):
        await initialize_schema(mock_pool)
        # 2 (schema+index) + 1 (extension) + 6 (hypertable stmts) = 9
        assert mock_conn.execute.call_count == 9

    async def test_timescale_disabled_skips_hypertables(self, mock_pool, mock_conn):
        await initialize_schema(mock_pool, enable_timescale=False)
        assert mock_conn.execute.call_count == 2

    async def test_timescale_failure_falls_back(self, mock_pool, mock_conn):
        """When TimescaleDB is not installed, logs warning and continues."""
        original_execute = mock_conn.execute

        async def side_effect(sql):
            if "CREATE EXTENSION" in sql:
                raise RuntimeError("TimescaleDB not available")
            return await original_execute(sql)

        mock_conn.execute = AsyncMock(side_effect=side_effect)
        with patch("earthsync_server.db.schema.logger") as mock_logger:
            await initialize_schema(mock_pool, enable_timescale=True)
            mock_logger.warning.assert_called_once_with(
                "timescaledb_not_available_using_plain_postgres"
            )

    async def test_individual_hypertable_statement_failure_skips(self, mock_pool, mock_conn):
        """If a single hypertable statement fails, it logs warning and continues."""
        call_idx = 0

        async def side_effect(sql):
            nonlocal call_idx
            call_idx += 1
            # Fail on the compression statement (4th hypertable stmt = call index 6)
            if "timescaledb.compress" in sql and "historical_spectrograms" in sql:
                raise RuntimeError("Compression not supported")

        mock_conn.execute = AsyncMock(side_effect=side_effect)
        with patch("earthsync_server.db.schema.logger") as mock_logger:
            await initialize_schema(mock_pool, enable_timescale=True)
            # Should have logged the skipped statement warning
            warning_calls = [
                c
                for c in mock_logger.warning.call_args_list
                if c.args[0] == "hypertable_statement_skipped"
            ]
            assert len(warning_calls) >= 1
            mock_logger.info.assert_any_call("timescaledb_configured")
