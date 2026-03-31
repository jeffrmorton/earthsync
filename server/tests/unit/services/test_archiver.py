"""Tests for the Archiver background service."""

from __future__ import annotations

import time

import pytest
from earthsync_server.db.store import MemoryStore
from earthsync_server.services.archiver import Archiver


class TestArchiverInit:
    def test_default_retention(self):
        store = MemoryStore()
        archiver = Archiver(store)
        assert archiver._retention_spec == 24
        assert archiver._retention_peak == 72

    def test_custom_retention(self):
        store = MemoryStore()
        archiver = Archiver(store, retention_hours_spec=48, retention_hours_peak=168)
        assert archiver._retention_spec == 48
        assert archiver._retention_peak == 168

    def test_initial_archive_count_zero(self):
        store = MemoryStore()
        archiver = Archiver(store)
        assert archiver.total_archived == 0


class TestArchiveCycle:
    @pytest.mark.asyncio
    async def test_no_data_returns_zero(self):
        store = MemoryStore()
        archiver = Archiver(store)
        result = await archiver.archive_cycle()
        assert result == 0

    @pytest.mark.asyncio
    async def test_trims_old_spectrograms(self):
        store = MemoryStore()
        # Add old record (2 days ago)
        old_ts = time.time() * 1000 - 48 * 3600 * 1000
        await store.add_spectrogram("det1", {"timestamp_ms": old_ts, "data": "old"})
        # Add recent record
        await store.add_spectrogram("det1", {"timestamp_ms": time.time() * 1000, "data": "new"})

        archiver = Archiver(store, retention_hours_spec=24)
        trimmed = await archiver.archive_cycle()
        assert trimmed == 1
        assert len(store._spectrograms["det1"]) == 1

    @pytest.mark.asyncio
    async def test_trims_old_peaks(self):
        store = MemoryStore()
        old_ts = int(time.time() * 1000 - 96 * 3600 * 1000)
        await store.add_peaks("det1", old_ts, [{"freq": 7.83}])
        await store.add_peaks("det1", int(time.time() * 1000), [{"freq": 14.3}])

        archiver = Archiver(store, retention_hours_peak=72)
        trimmed = await archiver.archive_cycle()
        assert trimmed == 1

    @pytest.mark.asyncio
    async def test_total_archived_accumulates(self):
        store = MemoryStore()
        old_ts = time.time() * 1000 - 48 * 3600 * 1000
        await store.add_spectrogram("det1", {"timestamp_ms": old_ts})

        archiver = Archiver(store, retention_hours_spec=24)
        await archiver.archive_cycle()
        assert archiver.total_archived == 1
        # Second cycle: nothing to trim
        await archiver.archive_cycle()
        assert archiver.total_archived == 1

    @pytest.mark.asyncio
    async def test_keeps_recent_data(self):
        store = MemoryStore()
        now_ms = time.time() * 1000
        await store.add_spectrogram("det1", {"timestamp_ms": now_ms, "data": "keep"})

        archiver = Archiver(store, retention_hours_spec=24)
        trimmed = await archiver.archive_cycle()
        assert trimmed == 0
        assert len(store._spectrograms["det1"]) == 1
