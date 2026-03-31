"""Tests for the in-memory MemoryStore and DatabaseStore Q-burst methods."""

import time
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
from earthsync_server.db.store import DatabaseStore, MemoryStore


@pytest.fixture
def store():
    return MemoryStore()


class TestUserOperations:
    @pytest.mark.asyncio
    async def test_create_user_success(self, store):
        assert await store.create_user("alice", "hash123") is True

    @pytest.mark.asyncio
    async def test_create_user_duplicate(self, store):
        await store.create_user("alice", "hash123")
        assert await store.create_user("alice", "hash456") is False

    @pytest.mark.asyncio
    async def test_get_user_exists(self, store):
        await store.create_user("alice", "hash123")
        assert await store.get_user("alice") == "hash123"

    @pytest.mark.asyncio
    async def test_get_user_not_exists(self, store):
        assert await store.get_user("nobody") is None


class TestSpectrogramOperations:
    @pytest.mark.asyncio
    async def test_add_get_spectrograms(self, store):
        now_ms = int(time.time() * 1000)
        await store.add_spectrogram(
            "det-001",
            {
                "station_id": "det-001",
                "timestamp_ms": now_ms,
                "location": {"lat": 37.0, "lon": -3.4},
            },
        )
        results = await store.get_spectrograms(station_id="det-001", hours=1)
        assert len(results) == 1
        assert results[0]["station_id"] == "det-001"

    @pytest.mark.asyncio
    async def test_get_spectrograms_all_stations(self, store):
        now_ms = int(time.time() * 1000)
        await store.add_spectrogram("det-001", {"timestamp_ms": now_ms})
        await store.add_spectrogram("det-002", {"timestamp_ms": now_ms})
        results = await store.get_spectrograms(hours=1)
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_get_spectrograms_filters_old(self, store):
        old_ms = int(time.time() * 1000) - 2 * 3600 * 1000  # 2 hours ago
        await store.add_spectrogram("det-001", {"timestamp_ms": old_ms})
        results = await store.get_spectrograms(station_id="det-001", hours=1)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_spectrogram_cap_1000(self, store):
        for i in range(1010):
            await store.add_spectrogram("det-001", {"timestamp_ms": i, "index": i})
        assert len(store._spectrograms["det-001"]) == 1000
        # Should keep the most recent
        assert store._spectrograms["det-001"][-1]["index"] == 1009


class TestPeakOperations:
    @pytest.mark.asyncio
    async def test_add_get_peaks(self, store):
        now_ms = int(time.time() * 1000)
        await store.add_peaks("det-001", now_ms, [{"freq": 7.83, "amp": 80.0}])
        results = await store.get_peaks(station_id="det-001", hours=1)
        assert len(results) == 1
        assert results[0]["stationId"] == "det-001"
        assert results[0]["peaks"][0]["freq"] == 7.83

    @pytest.mark.asyncio
    async def test_get_peaks_all_stations(self, store):
        now_ms = int(time.time() * 1000)
        await store.add_peaks("det-001", now_ms, [{"freq": 7.83}])
        await store.add_peaks("det-002", now_ms, [{"freq": 14.3}])
        results = await store.get_peaks(hours=1)
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_get_peaks_filters_old(self, store):
        old_ms = int(time.time() * 1000) - 2 * 3600 * 1000
        await store.add_peaks("det-001", old_ms, [{"freq": 7.83}])
        results = await store.get_peaks(station_id="det-001", hours=1)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_peaks_cap_1000(self, store):
        for i in range(1010):
            await store.add_peaks("det-001", i, [{"freq": 7.83}])
        assert len(store._peaks["det-001"]) == 1000


class TestCalibrationOperations:
    @pytest.mark.asyncio
    async def test_set_get_calibration(self, store):
        await store.set_calibration("det-001", {"offset": 0.1, "gain": 1.02})
        result = await store.get_calibration("det-001")
        assert result is not None
        assert result["offset"] == 0.1
        assert result["gain"] == 1.02
        assert result["station_id"] == "det-001"
        assert "uploaded_at" in result

    @pytest.mark.asyncio
    async def test_get_calibration_not_found(self, store):
        assert await store.get_calibration("det-999") is None


class TestQualityOperations:
    @pytest.mark.asyncio
    async def test_get_quality_no_data(self, store):
        result = await store.get_quality("det-001")
        assert result["station_id"] == "det-001"
        assert result["status"] == "no_data"


class TestStationOperations:
    @pytest.mark.asyncio
    async def test_get_stations_empty(self, store):
        assert await store.get_stations() == []

    @pytest.mark.asyncio
    async def test_get_stations(self, store):
        now_ms = int(time.time() * 1000)
        await store.add_spectrogram(
            "det-001",
            {
                "timestamp_ms": now_ms,
                "location": {"lat": 37.0, "lon": -3.4},
            },
        )
        stations = await store.get_stations()
        assert len(stations) == 1
        assert stations[0]["id"] == "det-001"
        assert stations[0]["location"]["lat"] == 37.0


class TestLatestOperations:
    @pytest.mark.asyncio
    async def test_get_latest_empty(self, store):
        assert await store.get_latest("det-001") == {}

    @pytest.mark.asyncio
    async def test_get_latest(self, store):
        now_ms = int(time.time() * 1000)
        await store.add_spectrogram("det-001", {"timestamp_ms": now_ms, "value": "first"})
        await store.add_spectrogram("det-001", {"timestamp_ms": now_ms + 1000, "value": "second"})
        result = await store.get_latest("det-001")
        assert result["value"] == "second"


class TestCrossValidationOperations:
    @pytest.mark.asyncio
    async def test_store_cross_validation(self, store):
        result = {"matched": 5, "total": 8, "correlation": 0.95, "mean_offset": 0.1}
        await store.store_cross_validation("det-001", result)
        assert len(store._cross_validations) == 1
        assert store._cross_validations[0]["station_id"] == "det-001"
        assert store._cross_validations[0]["correlation"] == 0.95
        assert store._cross_validations[0]["matched"] == 5
        assert "timestamp_ms" in store._cross_validations[0]

    @pytest.mark.asyncio
    async def test_store_cross_validation_multiple(self, store):
        await store.store_cross_validation("det-001", {"matched": 3, "total": 8})
        await store.store_cross_validation("det-002", {"matched": 5, "total": 8})
        assert len(store._cross_validations) == 2

    @pytest.mark.asyncio
    async def test_clear_removes_cross_validations(self, store):
        await store.store_cross_validation("det-001", {"matched": 3, "total": 8})
        assert len(store._cross_validations) == 1
        await store.clear()
        assert len(store._cross_validations) == 0


class TestClear:
    @pytest.mark.asyncio
    async def test_clear(self, store):
        await store.create_user("alice", "hash")
        await store.add_spectrogram("det-001", {"timestamp_ms": 1})
        await store.add_peaks("det-001", 1, [{"freq": 7.83}])
        await store.set_calibration("det-001", {"offset": 0.1})
        await store.clear()
        assert await store.get_user("alice") is None
        assert await store.get_spectrograms() == []
        assert await store.get_peaks() == []
        assert await store.get_calibration("det-001") is None
        assert await store.get_stations() == []

    @pytest.mark.asyncio
    async def test_clear_removes_qbursts(self, store):
        await store.record_qburst("det-A", 1000, 50.0)
        await store.store_global_qburst({"peak_timestamp_ms": 2000})
        assert len(store._qbursts) == 2
        await store.clear()
        assert len(store._qbursts) == 0


class TestMemoryStoreQBurst:
    """Tests for MemoryStore Q-burst operations."""

    @pytest.mark.asyncio
    async def test_record_qburst(self, store):
        await store.record_qburst("det-A", 1000, 50.0)
        assert len(store._qbursts) == 1
        assert store._qbursts[0]["station_id"] == "det-A"
        assert store._qbursts[0]["timestamp_ms"] == 1000
        assert store._qbursts[0]["amplitude"] == 50.0

    @pytest.mark.asyncio
    async def test_record_qburst_multiple(self, store):
        await store.record_qburst("det-A", 1000, 50.0)
        await store.record_qburst("det-B", 2000, 60.0)
        assert len(store._qbursts) == 2

    @pytest.mark.asyncio
    async def test_store_global_qburst(self, store):
        event = {
            "peak_timestamp_ms": 1000,
            "station_ids": ["det-A", "det-B"],
            "num_stations": 2,
            "mean_amplitude": 55.0,
        }
        await store.store_global_qburst(event)
        assert len(store._qbursts) == 1
        assert store._qbursts[0]["peak_timestamp_ms"] == 1000

    @pytest.mark.asyncio
    async def test_get_global_qbursts_recent(self, store):
        now_ms = int(time.time() * 1000)
        event = {
            "peak_timestamp_ms": now_ms,
            "station_ids": ["det-A", "det-B"],
            "num_stations": 2,
            "mean_amplitude": 55.0,
        }
        await store.store_global_qburst(event)
        results = await store.get_global_qbursts(hours=24)
        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_get_global_qbursts_filters_old(self, store):
        old_ms = int(time.time() * 1000) - 25 * 3600 * 1000  # 25 hours ago
        event = {
            "peak_timestamp_ms": old_ms,
            "station_ids": ["det-A", "det-B"],
            "num_stations": 2,
            "mean_amplitude": 55.0,
        }
        await store.store_global_qburst(event)
        results = await store.get_global_qbursts(hours=24)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_get_global_qbursts_individual_records(self, store):
        """Individual Q-burst records with timestamp_ms are also returned."""
        now_ms = int(time.time() * 1000)
        await store.record_qburst("det-A", now_ms, 50.0)
        results = await store.get_global_qbursts(hours=24)
        assert len(results) == 1


class TestDatabaseStoreQBurst:
    """Tests for DatabaseStore Q-burst operations using mocked pool."""

    @pytest.mark.asyncio
    async def test_record_qburst_is_noop(self):
        """record_qburst on DatabaseStore is intentionally a no-op."""
        pool = MagicMock()
        db_store = DatabaseStore(pool)
        await db_store.record_qburst("det-A", 1000, 50.0)

    @pytest.mark.asyncio
    async def test_get_global_qbursts(self):
        pool = MagicMock()
        ts = datetime(2026, 3, 28, 12, 0, 0, tzinfo=UTC)
        row = {
            "peak_timestamp": ts,
            "station_ids": ["det-A", "det-B"],
            "num_stations": 2,
            "mean_amplitude": 55.0,
        }
        pool.fetch = AsyncMock(return_value=[row])
        db_store = DatabaseStore(pool)
        results = await db_store.get_global_qbursts(hours=24)
        assert len(results) == 1
        assert results[0]["peak_timestamp_ms"] == int(ts.timestamp() * 1000)
        assert results[0]["station_ids"] == ["det-A", "det-B"]
        assert results[0]["num_stations"] == 2
        assert results[0]["mean_amplitude"] == 55.0
        pool.fetch.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_global_qbursts_empty(self):
        pool = MagicMock()
        pool.fetch = AsyncMock(return_value=[])
        db_store = DatabaseStore(pool)
        results = await db_store.get_global_qbursts(hours=1)
        assert results == []

    @pytest.mark.asyncio
    async def test_store_global_qburst(self):
        pool = MagicMock()
        pool.execute = AsyncMock()
        db_store = DatabaseStore(pool)
        event = {
            "peak_timestamp_ms": 1711627200000,
            "station_ids": ["det-A", "det-B"],
            "num_stations": 2,
            "mean_amplitude": 55.0,
        }
        await db_store.store_global_qburst(event)
        pool.execute.assert_called_once()
        call_args = pool.execute.call_args
        assert "INSERT INTO qburst_events" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_store_cross_validation(self):
        pool = MagicMock()
        pool.execute = AsyncMock()
        db_store = DatabaseStore(pool)
        result = {"matched": 5, "total": 8, "correlation": 0.95, "mean_offset": 0.1}
        await db_store.store_cross_validation("det-001", result)
        pool.execute.assert_called_once()
        call_args = pool.execute.call_args
        assert "INSERT INTO cross_validation_results" in call_args[0][0]
        assert call_args[0][1] == "det-001"
        assert call_args[0][2] == "schumann_fundamentals"
        assert call_args[0][3] == 0.95
        assert call_args[0][4] == 0.1
        assert "matched 5/8" in call_args[0][5]

    @pytest.mark.asyncio
    async def test_clear_includes_qburst_events(self):
        pool = MagicMock()
        pool.execute = AsyncMock()
        db_store = DatabaseStore(pool)
        await db_store.clear()
        assert pool.execute.call_count == 6
        all_sqls = [c[0][0] for c in pool.execute.call_args_list]
        assert any("qburst_events" in sql for sql in all_sqls)
        assert any("cross_validation_results" in sql for sql in all_sqls)
