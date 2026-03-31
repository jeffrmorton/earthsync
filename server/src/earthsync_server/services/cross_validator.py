"""Background cross-validation against known SR fundamentals."""

from __future__ import annotations

import structlog

from earthsync_server.constants import SCHUMANN_FREQUENCIES
from earthsync_server.dsp.cross_validation import compare_to_fundamentals

logger = structlog.get_logger()


class CrossValidator:
    """Periodically validates detected peaks against known SR fundamentals."""

    def __init__(self, correlation_threshold: float = 0.8):
        self._threshold = correlation_threshold
        self._last_result: dict | None = None

    def validate_peaks(self, detected_peaks: list) -> dict:
        """Compare detected peaks to known fundamentals."""
        result = compare_to_fundamentals(detected_peaks, SCHUMANN_FREQUENCIES)
        self._last_result = result
        logger.info(
            "cross_validation",
            matched=result["matched"],
            total=result["total"],
            correlation=round(result["correlation"], 3),
        )
        return result

    @property
    def last_result(self) -> dict | None:
        return self._last_result
