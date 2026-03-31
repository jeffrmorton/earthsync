"""Tests for cross-validation against known Schumann Resonance fundamentals."""

from unittest.mock import patch

import numpy as np
import pytest
from earthsync_server.constants import SCHUMANN_FREQUENCIES
from earthsync_server.dsp.cross_validation import compare_to_fundamentals, pearson_correlation
from earthsync_server.models import DetectedPeak

# --- pearson_correlation tests ---


class TestPearsonCorrelation:
    """Tests for pearson_correlation."""

    def test_pearson_identical(self):
        """Identical arrays should have correlation 1.0."""
        a = np.array([1.0, 2.0, 3.0, 4.0, 5.0])
        result = pearson_correlation(a, a)
        assert result == pytest.approx(1.0)

    def test_pearson_anticorrelated(self):
        """Negated array should have correlation -1.0."""
        a = np.array([1.0, 2.0, 3.0, 4.0, 5.0])
        b = -a
        result = pearson_correlation(a, b)
        assert result == pytest.approx(-1.0)

    def test_pearson_uncorrelated(self):
        """Random arrays should have correlation near 0."""
        rng = np.random.default_rng(42)
        a = rng.normal(0, 1, 10000)
        b = rng.normal(0, 1, 10000)
        result = pearson_correlation(a, b)
        assert abs(result) < 0.05

    def test_pearson_short_array(self):
        """Array with fewer than 2 elements should return 0.0."""
        a = np.array([1.0])
        b = np.array([2.0])
        result = pearson_correlation(a, b)
        assert result == 0.0

    def test_pearson_constant(self):
        """Constant array should return 0.0."""
        a = np.array([5.0, 5.0, 5.0, 5.0])
        b = np.array([1.0, 2.0, 3.0, 4.0])
        result = pearson_correlation(a, b)
        assert result == 0.0

    def test_pearson_empty(self):
        """Empty arrays should return 0.0."""
        a = np.array([])
        b = np.array([])
        result = pearson_correlation(a, b)
        assert result == 0.0

    def test_pearson_nan_from_corrcoef(self):
        """Arrays that produce NaN from corrcoef should return 0.0."""
        # Both constant but different values - std check catches this,
        # but we also test the NaN guard by mocking corrcoef
        a = np.array([1.0, 2.0, 3.0])
        b = np.array([4.0, 5.0, 6.0])
        mock_return = np.array([[1.0, np.nan], [np.nan, 1.0]])
        with patch(
            "earthsync_server.dsp.cross_validation.np.corrcoef",
            return_value=mock_return,
        ):
            result = pearson_correlation(a, b)
        assert result == 0.0

    def test_pearson_linear_relationship(self):
        """Linearly related arrays should have correlation 1.0."""
        a = np.array([1.0, 2.0, 3.0, 4.0])
        b = 2.0 * a + 10.0
        result = pearson_correlation(a, b)
        assert result == pytest.approx(1.0)


# --- compare_to_fundamentals tests ---


class TestCompareToFundamentals:
    """Tests for compare_to_fundamentals."""

    def test_compare_perfect_match(self):
        """Peaks at exact fundamentals should all match."""
        peaks = [DetectedPeak(freq=f, amp=1.0) for f in SCHUMANN_FREQUENCIES]
        result = compare_to_fundamentals(peaks)
        assert result["matched"] == len(SCHUMANN_FREQUENCIES)
        assert result["total"] == len(SCHUMANN_FREQUENCIES)
        assert result["correlation"] == pytest.approx(1.0)
        assert all(o == pytest.approx(0.0) for o in result["offsets"])

    def test_compare_offset_match(self):
        """Peaks offset by 0.1 Hz should still match within tolerance."""
        peaks = [DetectedPeak(freq=f + 0.1, amp=1.0) for f in SCHUMANN_FREQUENCIES]
        result = compare_to_fundamentals(peaks)
        assert result["matched"] == len(SCHUMANN_FREQUENCIES)
        assert all(o == pytest.approx(0.1) for o in result["offsets"])
        assert result["mean_offset"] == pytest.approx(0.1)

    def test_compare_missing_peaks(self):
        """Only matching a subset should report correct count."""
        peaks = [DetectedPeak(freq=f, amp=1.0) for f in SCHUMANN_FREQUENCIES[:3]]
        result = compare_to_fundamentals(peaks)
        assert result["matched"] == 3
        assert result["total"] == len(SCHUMANN_FREQUENCIES)

    def test_compare_beyond_tolerance(self):
        """Peaks far from fundamentals should not match."""
        # Offset by 100 Hz to guarantee no overlap with any SR fundamental
        peaks = [DetectedPeak(freq=f + 100.0, amp=1.0) for f in SCHUMANN_FREQUENCIES]
        result = compare_to_fundamentals(peaks, tolerance_hz=2.0)
        assert result["matched"] == 0

    def test_compare_empty_peaks(self):
        """No detected peaks should yield 0 matches."""
        result = compare_to_fundamentals([])
        assert result["matched"] == 0
        assert result["total"] == len(SCHUMANN_FREQUENCIES)
        assert result["offsets"] == []
        assert result["correlation"] == 0.0
        assert result["mean_offset"] == 0.0

    def test_compare_with_float_peaks(self):
        """Plain float values should work as peak frequencies."""
        peaks = list(SCHUMANN_FREQUENCIES)
        result = compare_to_fundamentals(peaks)
        assert result["matched"] == len(SCHUMANN_FREQUENCIES)

    def test_compare_custom_expected_freqs(self):
        """Custom expected frequencies should be used."""
        expected = (7.83, 14.3, 20.8)
        peaks = [DetectedPeak(freq=f, amp=1.0) for f in expected]
        result = compare_to_fundamentals(peaks, expected_freqs=expected)
        assert result["matched"] == 3
        assert result["total"] == 3

    def test_compare_custom_tolerance(self):
        """Custom tolerance should control matching window."""
        peaks = [DetectedPeak(freq=f + 1.5, amp=1.0) for f in SCHUMANN_FREQUENCIES]
        # Should not match with tolerance=1.0
        result_tight = compare_to_fundamentals(peaks, tolerance_hz=1.0)
        # Should match with tolerance=2.0
        result_loose = compare_to_fundamentals(peaks, tolerance_hz=2.0)
        assert result_tight["matched"] == 0
        assert result_loose["matched"] == len(SCHUMANN_FREQUENCIES)

    def test_compare_correlation_for_subset(self):
        """Correlation with partial matches should still be high."""
        peaks = [DetectedPeak(freq=f, amp=1.0) for f in SCHUMANN_FREQUENCIES[:4]]
        result = compare_to_fundamentals(peaks)
        assert result["matched"] == 4
        assert result["correlation"] == pytest.approx(1.0)

    def test_compare_mean_offset_zero_for_exact(self):
        """Exact matches should have mean offset of 0."""
        peaks = [DetectedPeak(freq=f, amp=1.0) for f in SCHUMANN_FREQUENCIES]
        result = compare_to_fundamentals(peaks)
        assert result["mean_offset"] == pytest.approx(0.0)
