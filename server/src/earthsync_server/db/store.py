"""Data store abstraction -- in-memory for tests, asyncpg for production."""

from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import UTC

import asyncpg
import structlog

logger = structlog.get_logger()


class BaseStore(ABC):
    """Abstract data store interface used by route handlers."""

    @abstractmethod
    async def get_user(self, username: str) -> str | None: ...

    @abstractmethod
    async def create_user(self, username: str, password_hash: str) -> bool: ...

    @abstractmethod
    async def add_spectrogram(self, station_id: str, record: dict) -> None: ...

    @abstractmethod
    async def get_spectrograms(
        self, station_id: str | None = None, hours: int = 1
    ) -> list[dict]: ...

    @abstractmethod
    async def add_peaks(self, station_id: str, timestamp_ms: int, peaks: list[dict]) -> None: ...

    @abstractmethod
    async def get_peaks(self, station_id: str | None = None, hours: int = 1) -> list[dict]: ...

    @abstractmethod
    async def set_calibration(self, station_id: str, data: dict) -> None: ...

    @abstractmethod
    async def get_calibration(self, station_id: str) -> dict | None: ...

    @abstractmethod
    async def get_quality(self, station_id: str) -> dict: ...

    @abstractmethod
    async def get_stations(self) -> list[dict]: ...

    @abstractmethod
    async def get_latest(self, station_id: str) -> dict: ...

    @abstractmethod
    async def trim_old(self, spec_cutoff_ms: float, peak_cutoff_ms: float) -> int: ...

    @abstractmethod
    async def record_qburst(self, station_id: str, timestamp_ms: int, amplitude: float) -> None: ...

    @abstractmethod
    async def get_global_qbursts(self, hours: int = 24) -> list[dict]: ...

    @abstractmethod
    async def store_global_qburst(self, event: dict) -> None: ...

    @abstractmethod
    async def store_cross_validation(self, station_id: str, result: dict) -> None: ...

    @abstractmethod
    async def clear(self) -> None: ...


class MemoryStore(BaseStore):
    """In-memory store for unit tests. Same interface as DatabaseStore."""

    def __init__(self) -> None:
        self._users: dict[str, str] = {}  # username -> password_hash
        self._spectrograms: dict[str, list[dict]] = defaultdict(list)
        self._peaks: dict[str, list[dict]] = defaultdict(list)
        self._calibrations: dict[str, dict] = {}
        self._quality: dict[str, dict] = {}
        self._qbursts: list[dict] = []
        self._cross_validations: list[dict] = []

    async def get_user(self, username: str) -> str | None:
        """Get password hash for username, or None if not found."""
        return self._users.get(username)

    async def create_user(self, username: str, password_hash: str) -> bool:
        """Create user. Returns False if username exists."""
        if username in self._users:
            return False
        self._users[username] = password_hash
        return True

    async def add_spectrogram(self, station_id: str, record: dict) -> None:
        """Add a processed spectrogram record."""
        self._spectrograms[station_id].append(record)
        if len(self._spectrograms[station_id]) > 1000:
            self._spectrograms[station_id] = self._spectrograms[station_id][-1000:]

    async def get_spectrograms(self, station_id: str | None = None, hours: int = 1) -> list[dict]:
        """Get spectrograms within time window."""
        cutoff = time.time() * 1000 - hours * 3600 * 1000
        sources = [station_id] if station_id else list(self._spectrograms.keys())
        return [
            r
            for did in sources
            for r in self._spectrograms.get(did, [])
            if r.get("timestamp_ms", 0) >= cutoff
        ]

    async def add_peaks(self, station_id: str, timestamp_ms: int, peaks: list[dict]) -> None:
        """Add detected peaks for a station at a timestamp."""
        self._peaks[station_id].append({"ts": timestamp_ms, "peaks": peaks})
        if len(self._peaks[station_id]) > 1000:
            self._peaks[station_id] = self._peaks[station_id][-1000:]

    async def get_peaks(self, station_id: str | None = None, hours: int = 1) -> list[dict]:
        """Get peaks within time window."""
        cutoff = time.time() * 1000 - hours * 3600 * 1000
        sources = [station_id] if station_id else list(self._peaks.keys())
        return [
            {"stationId": did, **r}
            for did in sources
            for r in self._peaks.get(did, [])
            if r.get("ts", 0) >= cutoff
        ]

    async def set_calibration(self, station_id: str, data: dict) -> None:
        self._calibrations[station_id] = {
            **data,
            "station_id": station_id,
            "uploaded_at": time.time(),
        }

    async def get_calibration(self, station_id: str) -> dict | None:
        return self._calibrations.get(station_id)

    async def get_quality(self, station_id: str) -> dict:
        return self._quality.get(station_id, {"station_id": station_id, "status": "no_data"})

    async def get_stations(self) -> list[dict]:
        """Get all known station IDs with their latest locations."""
        stations = []
        for did in set(list(self._spectrograms.keys()) + list(self._peaks.keys())):
            specs = self._spectrograms.get(did, [])
            latest = specs[-1] if specs else {}
            stations.append(
                {
                    "id": did,
                    "location": latest.get("location", {"lat": 0, "lon": 0}),
                    "last_update": latest.get("timestamp_ms", 0),
                }
            )
        return stations

    async def get_latest(self, station_id: str) -> dict:
        """Get latest spectrogram for a station."""
        specs = self._spectrograms.get(station_id, [])
        return specs[-1] if specs else {}

    async def trim_old(self, spec_cutoff_ms: float, peak_cutoff_ms: float) -> int:
        """Remove records older than the cutoff timestamps. Returns count trimmed."""
        trimmed = 0
        for did in list(self._spectrograms):
            before = len(self._spectrograms[did])
            self._spectrograms[did] = [
                r for r in self._spectrograms[did] if r.get("timestamp_ms", 0) >= spec_cutoff_ms
            ]
            trimmed += before - len(self._spectrograms[did])
        for did in list(self._peaks):
            before = len(self._peaks[did])
            self._peaks[did] = [r for r in self._peaks[did] if r.get("ts", 0) >= peak_cutoff_ms]
            trimmed += before - len(self._peaks[did])
        return trimmed

    async def record_qburst(self, station_id: str, timestamp_ms: int, amplitude: float) -> None:
        """Record an individual Q-burst detection."""
        self._qbursts.append(
            {
                "station_id": station_id,
                "timestamp_ms": timestamp_ms,
                "amplitude": amplitude,
            }
        )

    async def get_global_qbursts(self, hours: int = 24) -> list[dict]:
        """Get global Q-burst events within time window."""
        cutoff = time.time() * 1000 - hours * 3600 * 1000
        return [
            q
            for q in self._qbursts
            if q.get("peak_timestamp_ms", q.get("timestamp_ms", 0)) >= cutoff
        ]

    async def store_global_qburst(self, event: dict) -> None:
        """Store a correlated global Q-burst event."""
        self._qbursts.append(event)

    async def store_cross_validation(self, station_id: str, result: dict) -> None:
        """Store a cross-validation result."""
        self._cross_validations.append(
            {"station_id": station_id, **result, "timestamp_ms": time.time() * 1000}
        )

    async def clear(self) -> None:
        """Clear all data (for testing)."""
        self._users.clear()
        self._spectrograms.clear()
        self._peaks.clear()
        self._calibrations.clear()
        self._quality.clear()
        self._qbursts.clear()
        self._cross_validations.clear()


# Keep backward-compat alias so nothing breaks during migration
DataStore = MemoryStore


class DatabaseStore(BaseStore):
    """Production store backed by TimescaleDB via asyncpg."""

    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def get_user(self, username: str) -> str | None:
        row = await self._pool.fetchrow(
            "SELECT password_hash FROM users WHERE username = $1", username
        )
        return row["password_hash"] if row else None

    async def create_user(self, username: str, password_hash: str) -> bool:
        try:
            await self._pool.execute(
                "INSERT INTO users (username, password_hash) VALUES ($1, $2)",
                username,
                password_hash,
            )
            return True  # noqa: TRY300
        except asyncpg.UniqueViolationError:
            return False

    async def add_spectrogram(self, station_id: str, record: dict) -> None:
        await self._pool.execute(
            """INSERT INTO historical_spectrograms
               (station_id, timestamp, location_lat, location_lon, spectrogram_data,
                algorithm_version, sample_rate_hz)
               VALUES ($1, to_timestamp($2::double precision / 1000.0),
                       $3, $4, $5, $6, $7)""",
            station_id,
            float(record.get("timestamp_ms", time.time() * 1000)),
            record.get("location", {}).get("lat", 0.0),
            record.get("location", {}).get("lon", 0.0),
            json.dumps(record),
            record.get("algorithm_version", "0.1.1"),
            record.get("sample_rate_hz"),
        )

    async def get_spectrograms(self, station_id: str | None = None, hours: int = 1) -> list[dict]:
        if station_id:
            rows = await self._pool.fetch(
                """SELECT spectrogram_data FROM historical_spectrograms
                   WHERE station_id = $1 AND timestamp > NOW() - $2 * INTERVAL '1 hour'
                   ORDER BY timestamp DESC LIMIT 1000""",
                station_id,
                hours,
            )
        else:
            rows = await self._pool.fetch(
                """SELECT spectrogram_data FROM historical_spectrograms
                   WHERE timestamp > NOW() - $1 * INTERVAL '1 hour'
                   ORDER BY timestamp DESC LIMIT 1000""",
                hours,
            )
        return [json.loads(row["spectrogram_data"]) for row in rows]

    async def add_peaks(self, station_id: str, timestamp_ms: int, peaks: list[dict]) -> None:
        await self._pool.execute(
            """INSERT INTO historical_peaks (station_id, timestamp, peak_data)
               VALUES ($1, to_timestamp($2::double precision / 1000.0), $3)""",
            station_id,
            float(timestamp_ms),
            json.dumps(peaks),
        )

    async def get_peaks(self, station_id: str | None = None, hours: int = 1) -> list[dict]:
        if station_id:
            rows = await self._pool.fetch(
                """SELECT station_id,
                          extract(epoch from timestamp) * 1000 as ts,
                          peak_data
                   FROM historical_peaks
                   WHERE station_id = $1 AND timestamp > NOW() - $2 * INTERVAL '1 hour'
                   ORDER BY timestamp DESC LIMIT 1000""",
                station_id,
                hours,
            )
        else:
            rows = await self._pool.fetch(
                """SELECT station_id,
                          extract(epoch from timestamp) * 1000 as ts,
                          peak_data
                   FROM historical_peaks
                   WHERE timestamp > NOW() - $1 * INTERVAL '1 hour'
                   ORDER BY timestamp DESC LIMIT 1000""",
                hours,
            )
        return [
            {
                "stationId": r["station_id"],
                "ts": int(r["ts"]),
                "peaks": json.loads(r["peak_data"]),
            }
            for r in rows
        ]

    async def set_calibration(self, station_id: str, data: dict) -> None:
        await self._pool.execute(
            """INSERT INTO station_calibration (station_id, calibration_data)
               VALUES ($1, $2)
               ON CONFLICT (station_id)
               DO UPDATE SET calibration_data = $2, uploaded_at = NOW()""",
            station_id,
            json.dumps(data),
        )

    async def get_calibration(self, station_id: str) -> dict | None:
        row = await self._pool.fetchrow(
            "SELECT calibration_data FROM station_calibration WHERE station_id = $1",
            station_id,
        )
        return json.loads(row["calibration_data"]) if row else None

    async def get_quality(self, station_id: str) -> dict:
        row = await self._pool.fetchrow(
            """SELECT spectrogram_data FROM historical_spectrograms
               WHERE station_id = $1 ORDER BY timestamp DESC LIMIT 1""",
            station_id,
        )
        if not row:
            return {"station_id": station_id, "status": "no_data"}
        data = json.loads(row["spectrogram_data"])
        return data.get("quality", {"station_id": station_id, "status": "ok"})

    async def get_stations(self) -> list[dict]:
        rows = await self._pool.fetch(
            """SELECT DISTINCT ON (station_id) station_id,
                      location_lat, location_lon,
                      extract(epoch from timestamp) * 1000 as last_update
               FROM historical_spectrograms
               ORDER BY station_id, timestamp DESC"""
        )
        return [
            {
                "id": r["station_id"],
                "location": {"lat": r["location_lat"], "lon": r["location_lon"]},
                "last_update": int(r["last_update"]),
            }
            for r in rows
        ]

    async def get_latest(self, station_id: str) -> dict:
        row = await self._pool.fetchrow(
            """SELECT spectrogram_data FROM historical_spectrograms
               WHERE station_id = $1 ORDER BY timestamp DESC LIMIT 1""",
            station_id,
        )
        return json.loads(row["spectrogram_data"]) if row else {}

    async def trim_old(self, spec_cutoff_ms: float, peak_cutoff_ms: float) -> int:
        r1 = await self._pool.execute(
            "DELETE FROM historical_spectrograms WHERE timestamp < to_timestamp($1 / 1000.0)",
            spec_cutoff_ms,
        )
        r2 = await self._pool.execute(
            "DELETE FROM historical_peaks WHERE timestamp < to_timestamp($1 / 1000.0)",
            peak_cutoff_ms,
        )
        c1 = int(r1.split()[-1]) if r1 else 0
        c2 = int(r2.split()[-1]) if r2 else 0
        return c1 + c2

    async def record_qburst(self, station_id: str, timestamp_ms: int, amplitude: float) -> None:
        """Individual Q-burst tracking (stored in memory via correlator, not in DB)."""

    async def get_global_qbursts(self, hours: int = 24) -> list[dict]:
        """Get global Q-burst events from the database."""
        rows = await self._pool.fetch(
            """SELECT peak_timestamp, station_ids, num_stations, mean_amplitude
               FROM qburst_events
               WHERE peak_timestamp > NOW() - $1 * INTERVAL '1 hour'
               ORDER BY peak_timestamp DESC LIMIT 100""",
            hours,
        )
        return [
            {
                "peak_timestamp_ms": int(r["peak_timestamp"].timestamp() * 1000),
                "station_ids": list(r["station_ids"]),
                "num_stations": r["num_stations"],
                "mean_amplitude": r["mean_amplitude"],
            }
            for r in rows
        ]

    async def store_global_qburst(self, event: dict) -> None:
        """Store a correlated global Q-burst event."""
        from datetime import datetime  # noqa: PLC0415

        ts = datetime.fromtimestamp(event["peak_timestamp_ms"] / 1000, tz=UTC)
        sql = (
            "INSERT INTO qburst_events"
            " (peak_timestamp, station_ids, num_stations, mean_amplitude)"
            " VALUES ($1, $2, $3, $4)"
        )
        await self._pool.execute(
            sql,
            ts,
            event["station_ids"],
            event["num_stations"],
            event["mean_amplitude"],
        )

    async def store_cross_validation(self, station_id: str, result: dict) -> None:
        """Store a cross-validation result in the database."""
        await self._pool.execute(
            """INSERT INTO cross_validation_results
               (station_id, reference_source, timestamp, correlation, frequency_offset, notes)
               VALUES ($1, $2, NOW(), $3, $4, $5)""",
            station_id,
            "schumann_fundamentals",
            result.get("correlation", 0.0),
            result.get("mean_offset", 0.0),
            f"matched {result.get('matched', 0)}/{result.get('total', 0)}",
        )

    async def clear(self) -> None:
        await self._pool.execute("DELETE FROM historical_spectrograms")
        await self._pool.execute("DELETE FROM historical_peaks")
        await self._pool.execute("DELETE FROM station_calibration")
        await self._pool.execute("DELETE FROM users")
        await self._pool.execute("DELETE FROM qburst_events")
        await self._pool.execute("DELETE FROM cross_validation_results")
