"""Tests for the CrossValidator background service."""

from __future__ import annotations

from earthsync_server.constants import SCHUMANN_FREQUENCIES
from earthsync_server.models import DetectedPeak
from earthsync_server.services.cross_validator import CrossValidator


class TestCrossValidatorInit:
    """Tests for CrossValidator initialization."""

    def test_default_threshold(self):
        cv = CrossValidator()
        assert cv._threshold == 0.8

    def test_custom_threshold(self):
        cv = CrossValidator(correlation_threshold=0.9)
        assert cv._threshold == 0.9

    def test_last_result_initially_none(self):
        cv = CrossValidator()
        assert cv.last_result is None


class TestValidatePeaks:
    """Tests for the validate_peaks method."""

    def test_perfect_match(self):
        cv = CrossValidator()
        peaks = [DetectedPeak(freq=f, amp=1.0) for f in SCHUMANN_FREQUENCIES]
        result = cv.validate_peaks(peaks)
        assert result["matched"] == len(SCHUMANN_FREQUENCIES)
        assert result["total"] == len(SCHUMANN_FREQUENCIES)
        assert result["correlation"] > 0.99

    def test_no_peaks(self):
        cv = CrossValidator()
        result = cv.validate_peaks([])
        assert result["matched"] == 0
        assert result["total"] == len(SCHUMANN_FREQUENCIES)
        assert result["correlation"] == 0.0

    def test_partial_match(self):
        cv = CrossValidator()
        # Only first three modes
        peaks = [DetectedPeak(freq=f, amp=1.0) for f in SCHUMANN_FREQUENCIES[:3]]
        result = cv.validate_peaks(peaks)
        assert result["matched"] == 3
        assert result["total"] == len(SCHUMANN_FREQUENCIES)

    def test_shifted_peaks(self):
        cv = CrossValidator()
        # Peaks shifted by 0.5 Hz (still within default 2 Hz tolerance)
        peaks = [DetectedPeak(freq=f + 0.5, amp=1.0) for f in SCHUMANN_FREQUENCIES]
        result = cv.validate_peaks(peaks)
        assert result["matched"] == len(SCHUMANN_FREQUENCIES)
        assert result["mean_offset"] > 0

    def test_result_has_expected_keys(self):
        cv = CrossValidator()
        peaks = [DetectedPeak(freq=7.83, amp=1.0)]
        result = cv.validate_peaks(peaks)
        assert "matched" in result
        assert "total" in result
        assert "offsets" in result
        assert "correlation" in result
        assert "mean_offset" in result


class TestLastResult:
    """Tests for the last_result property."""

    def test_last_result_updates_after_validate(self):
        cv = CrossValidator()
        peaks = [DetectedPeak(freq=7.83, amp=1.0)]
        result = cv.validate_peaks(peaks)
        assert cv.last_result is result

    def test_last_result_reflects_latest_call(self):
        cv = CrossValidator()
        peaks1 = [DetectedPeak(freq=7.83, amp=1.0)]
        peaks2 = [DetectedPeak(freq=7.83, amp=1.0), DetectedPeak(freq=14.3, amp=1.0)]
        cv.validate_peaks(peaks1)
        result2 = cv.validate_peaks(peaks2)
        assert cv.last_result is result2
        assert cv.last_result["matched"] == 2
