"""Tests for time-domain and spectral quality validation."""

import numpy as np
import pytest
from earthsync_server.dsp.quality import detect_qburst, validate_spectrum, validate_time_domain

# --- validate_time_domain tests ---


class TestValidateTimeDomain:
    """Tests for validate_time_domain."""

    def test_valid_samples_usable(self):
        """Clean data should be usable with no flags."""
        rng = np.random.default_rng(42)
        samples = rng.normal(0, 1, 2560)
        result = validate_time_domain(samples, sample_rate_hz=256, segment_duration_s=10.0)
        assert result.is_usable is True
        assert result.flags == []

    def test_length_mismatch(self):
        """Wrong length should produce length_mismatch flag."""
        samples = np.zeros(100)
        result = validate_time_domain(samples, sample_rate_hz=256, segment_duration_s=10.0)
        assert "length_mismatch" in result.flags

    def test_contains_nan(self):
        """NaN in samples should produce contains_nan flag."""
        samples = np.ones(2560)
        samples[10] = np.nan
        result = validate_time_domain(samples, sample_rate_hz=256, segment_duration_s=10.0)
        assert "contains_nan" in result.flags

    def test_contains_infinity(self):
        """Inf in samples should produce contains_infinity flag."""
        samples = np.ones(2560)
        samples[10] = np.inf
        result = validate_time_domain(samples, sample_rate_hz=256, segment_duration_s=10.0)
        assert "contains_infinity" in result.flags

    def test_excessive_invalid(self):
        """More than 1% NaN should produce excessive_invalid and is_usable=False."""
        samples = np.ones(2560)
        # Set 2% to NaN (>1% threshold)
        samples[:52] = np.nan
        result = validate_time_domain(samples, sample_rate_hz=256, segment_duration_s=10.0)
        assert "excessive_invalid" in result.flags
        assert "contains_nan" in result.flags
        assert result.is_usable is False

    def test_flatline(self):
        """Constant array should produce flatline flag and is_usable=False."""
        samples = np.full(2560, 5.0)
        result = validate_time_domain(samples, sample_rate_hz=256, segment_duration_s=10.0)
        assert "flatline" in result.flags
        assert result.is_usable is False

    def test_clipping(self):
        """Many samples at extremes should produce clipping flag."""
        rng = np.random.default_rng(42)
        samples = rng.normal(0, 1, 2560)
        smin, smax = samples.min(), samples.max()
        # Force >1% but <=10% of samples to the extremes
        n_clip = int(0.05 * len(samples))
        samples[: n_clip // 2] = smin
        samples[n_clip // 2 : n_clip] = smax
        result = validate_time_domain(samples, sample_rate_hz=256, segment_duration_s=10.0)
        assert "clipping" in result.flags

    def test_saturation(self):
        """More than 10% clipped should produce saturated flag and is_usable=False."""
        rng = np.random.default_rng(42)
        samples = rng.normal(0, 1, 2560)
        smin, smax = samples.min(), samples.max()
        # Force >10% of samples to extremes
        n_sat = int(0.15 * len(samples))
        samples[: n_sat // 2] = smin
        samples[n_sat // 2 : n_sat] = smax
        result = validate_time_domain(samples, sample_rate_hz=256, segment_duration_s=10.0)
        assert "saturated" in result.flags
        assert result.is_usable is False

    def test_multiple_flags(self):
        """Signal with multiple issues should have all relevant flags."""
        samples = np.full(2560, 3.0)
        samples[0] = np.nan
        result = validate_time_domain(samples, sample_rate_hz=256, segment_duration_s=10.0)
        assert "contains_nan" in result.flags
        assert "flatline" in result.flags

    def test_empty_samples(self):
        """Empty array should produce length_mismatch and is_usable=False."""
        samples = np.array([])
        result = validate_time_domain(samples, sample_rate_hz=256, segment_duration_s=10.0)
        assert "length_mismatch" in result.flags
        assert result.is_usable is False

    def test_length_within_tolerance(self):
        """Length within 2 samples of expected should not flag."""
        # Expected: 256 * 10 = 2560, so 2558 is within tolerance
        rng = np.random.default_rng(42)
        samples = rng.normal(0, 1, 2558)
        result = validate_time_domain(samples, sample_rate_hz=256, segment_duration_s=10.0)
        assert "length_mismatch" not in result.flags

    def test_single_nan_not_excessive(self):
        """A single NaN in a large array should not be excessive."""
        rng = np.random.default_rng(42)
        samples = rng.normal(0, 1, 2560)
        samples[500] = np.nan
        result = validate_time_domain(samples, sample_rate_hz=256, segment_duration_s=10.0)
        assert "contains_nan" in result.flags
        assert "excessive_invalid" not in result.flags
        assert result.is_usable is True


# --- validate_spectrum tests ---


class TestValidateSpectrum:
    """Tests for validate_spectrum."""

    def test_spectrum_clean(self):
        """Normal PSD should produce no flags."""
        rng = np.random.default_rng(42)
        freqs = np.linspace(0, 128, 1000)
        psd = rng.uniform(0.5, 1.5, 1000)
        result = validate_spectrum(psd, freqs)
        assert result == []

    def test_spectrum_mains_50hz(self):
        """Strong 50 Hz peak should produce mains_contamination."""
        freqs = np.linspace(0, 128, 1000)
        psd = np.ones(1000)
        # Inject a large spike at 50 Hz
        idx_50 = int(np.argmin(np.abs(freqs - 50.0)))
        psd[idx_50] = 100.0
        result = validate_spectrum(psd, freqs)
        assert "mains_contamination" in result

    def test_spectrum_mains_60hz(self):
        """Strong 60 Hz peak should produce mains_contamination."""
        freqs = np.linspace(0, 128, 1000)
        psd = np.ones(1000)
        idx_60 = int(np.argmin(np.abs(freqs - 60.0)))
        psd[idx_60] = 100.0
        result = validate_spectrum(psd, freqs)
        assert "mains_contamination" in result

    def test_spectrum_dead_channel(self):
        """All-zero PSD should produce dead_channel flag."""
        freqs = np.linspace(0, 128, 1000)
        psd = np.zeros(1000)
        result = validate_spectrum(psd, freqs)
        assert "dead_channel" in result

    def test_spectrum_custom_mains(self):
        """Custom mains frequency list should be respected."""
        freqs = np.linspace(0, 128, 1000)
        psd = np.ones(1000)
        # Spike at 25 Hz (custom mains)
        idx_25 = int(np.argmin(np.abs(freqs - 25.0)))
        psd[idx_25] = 100.0
        result = validate_spectrum(psd, freqs, mains_freqs=[25.0])
        assert "mains_contamination" in result

    def test_spectrum_mains_below_threshold(self):
        """Mains peak below threshold should not flag."""
        freqs = np.linspace(0, 128, 1000)
        psd = np.ones(1000)
        # Small spike at 50 Hz (below 10x median)
        idx_50 = int(np.argmin(np.abs(freqs - 50.0)))
        psd[idx_50] = 5.0
        result = validate_spectrum(psd, freqs)
        assert "mains_contamination" not in result

    def test_spectrum_dead_channel_no_mains_flag(self):
        """Dead channel should not also flag mains contamination."""
        freqs = np.linspace(0, 128, 1000)
        psd = np.zeros(1000)
        result = validate_spectrum(psd, freqs)
        assert result == ["dead_channel"]


# --- detect_qburst tests ---


class TestDetectQBurst:
    """Tests for detect_qburst."""

    def test_qburst_detected(self):
        """Spike exceeding 10x baseline should be detected."""
        rng = np.random.default_rng(42)
        sample_rate = 1000
        duration_s = 1.0
        n = int(sample_rate * duration_s)
        samples = rng.normal(0, 1, n)
        # Inject a large burst in one window (50ms = 50 samples)
        samples[200:250] = 50.0
        result = detect_qburst(samples, sample_rate)
        assert result.detected is True

    def test_qburst_not_detected(self):
        """Normal signal should not trigger detection."""
        rng = np.random.default_rng(42)
        sample_rate = 1000
        samples = rng.normal(0, 1, 1000)
        result = detect_qburst(samples, sample_rate)
        assert result.detected is False

    def test_qburst_peak_amplitude(self):
        """Peak amplitude should reflect the burst RMS."""
        rng = np.random.default_rng(42)
        sample_rate = 1000
        samples = rng.normal(0, 0.1, 1000)
        # Inject burst: constant 100.0 for one window
        samples[100:150] = 100.0
        result = detect_qburst(samples, sample_rate)
        assert result.detected is True
        assert result.peak_amplitude is not None
        assert result.peak_amplitude > 90.0

    def test_qburst_duration(self):
        """Duration should reflect number of burst windows * 50ms."""
        rng = np.random.default_rng(42)
        sample_rate = 1000
        samples = rng.normal(0, 0.1, 1000)
        # Inject burst across 2 windows (100ms)
        samples[100:200] = 100.0
        result = detect_qburst(samples, sample_rate)
        assert result.detected is True
        assert result.duration_ms is not None
        assert result.duration_ms == pytest.approx(100.0)

    def test_qburst_short_signal(self):
        """Fewer than 3 windows should return not detected."""
        sample_rate = 1000
        # 2 windows = 100 samples, need <3 windows = <150 samples
        samples = np.ones(100)
        result = detect_qburst(samples, sample_rate)
        assert result.detected is False

    def test_qburst_custom_threshold(self):
        """Custom threshold should be respected."""
        rng = np.random.default_rng(42)
        sample_rate = 1000
        samples = rng.normal(0, 1, 1000)
        # Inject moderate burst
        samples[200:250] = 8.0
        # Should not be detected at threshold=10
        result_high = detect_qburst(samples, sample_rate, threshold=20.0)
        # Should be detected at threshold=3
        result_low = detect_qburst(samples, sample_rate, threshold=3.0)
        assert result_high.detected is False
        assert result_low.detected is True

    def test_qburst_zero_signal(self):
        """All-zero signal should return not detected (median RMS = 0)."""
        sample_rate = 1000
        samples = np.zeros(1000)
        result = detect_qburst(samples, sample_rate)
        assert result.detected is False

    def test_qburst_none_fields_when_not_detected(self):
        """When not detected, peak_amplitude and duration_ms should be None."""
        rng = np.random.default_rng(42)
        sample_rate = 1000
        samples = rng.normal(0, 1, 1000)
        result = detect_qburst(samples, sample_rate)
        assert result.detected is False
        assert result.peak_amplitude is None
        assert result.duration_ms is None

    def test_qburst_zero_window_size(self):
        """Very low sample rate where window_size rounds to 0."""
        samples = np.ones(10)
        result = detect_qburst(samples, sample_rate_hz=1)  # 0.05 * 1 = 0 window
        assert result.detected is False


class TestValidateSpectrumEdgeCases:
    def test_empty_freqs_with_nonzero_psd(self):
        """Empty frequency array with non-zero PSD skips mains check."""
        # Non-zero PSD avoids dead_channel early return, but empty freqs
        result = validate_spectrum(np.array([1.0]), np.array([]))
        assert "mains_contamination" not in result

    def test_empty_freqs_and_psd(self):
        """Completely empty arrays should flag dead_channel."""
        result = validate_spectrum(np.array([0.0]), np.array([0.0]))
        assert "dead_channel" in result
