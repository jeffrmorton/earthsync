"""Background archival -- enforces data retention policies.

Trims store entries older than the configured retention window.
In production the store is backed by TimescaleDB; for tests
it uses the in-memory MemoryStore.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from earthsync_server.db.store import BaseStore

logger = structlog.get_logger()


class Archiver:
    """Enforces data retention by trimming old entries from the store."""

    def __init__(
        self,
        store: BaseStore,
        retention_hours_spec: int = 24,
        retention_hours_peak: int = 72,
    ):
        self._store = store
        self._retention_spec = retention_hours_spec
        self._retention_peak = retention_hours_peak
        self._archive_count = 0

    async def archive_cycle(self) -> int:
        """Run one archival cycle. Returns number of records trimmed."""
        now_ms = time.time() * 1000
        spec_cutoff = now_ms - self._retention_spec * 3600 * 1000
        peak_cutoff = now_ms - self._retention_peak * 3600 * 1000

        trimmed = await self._store.trim_old(spec_cutoff, peak_cutoff)
        self._archive_count += trimmed

        logger.info(
            "archive_cycle_complete",
            trimmed=trimmed,
            retention_spec_h=self._retention_spec,
            retention_peak_h=self._retention_peak,
        )
        return trimmed

    @property
    def total_archived(self) -> int:
        return self._archive_count
