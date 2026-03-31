"""Tests for peak detection DSP module."""

import numpy as np
from earthsync_server.dsp.peaks import (
    compute_fwhm,
    detect_peaks,
    filter_to_sr_bands,
    parabolic_interpolation,
    smooth_spectrum,
)
from earthsync_server.models import DetectedPeak


def _make_freqs(n: int = 1000, fs: float = 100.0) -> np.ndarray:
    """Create a frequency array for testing (0 to fs/2)."""
    return np.linspace(0.0, fs / 2.0, n)


def _make_sine_psd(
    freqs: np.ndarray,
    peak_freq: float,
    amplitude: float = 100.0,
    width: float = 0.5,
) -> np.ndarray:
    """Create a Lorentzian-like peak in PSD at peak_freq."""
    return amplitude / (1.0 + ((freqs - peak_freq) / width) ** 2)


def _make_multi_peak_psd(
    freqs: np.ndarray,
    peak_freqs: list[float],
    amplitude: float = 100.0,
    width: float = 0.5,
) -> np.ndarray:
    """Create PSD with multiple Lorentzian peaks."""
    psd = np.ones_like(freqs) * 0.1  # low noise floor
    for pf in peak_freqs:
        psd += _make_sine_psd(freqs, pf, amplitude, width)
    return psd


class TestDetectPeaks:
    """Tests for detect_peaks()."""

    def test_detect_peaks_pure_sine(self):
        """Single Lorentzian peak at 7.83 Hz should produce one detected peak."""
        freqs = _make_freqs(1000, 100.0)
        psd = _make_sine_psd(freqs, 7.83, amplitude=100.0, width=0.5)

        peaks = detect_peaks(psd, freqs, absolute_threshold=0.5)

        assert len(peaks) == 1
        assert abs(peaks[0].freq - 7.83) < 0.2

    def test_detect_peaks_multiple(self):
        """Three peaks at SR frequencies 7.83, 14.3, 20.8 Hz."""
        freqs = _make_freqs(2000, 100.0)
        psd = _make_multi_peak_psd(freqs, [7.83, 14.3, 20.8], amplitude=100.0, width=0.5)

        peaks = detect_peaks(psd, freqs, absolute_threshold=0.5)

        assert len(peaks) >= 3
        detected_freqs = [p.freq for p in peaks]
        for expected in [7.83, 14.3, 20.8]:
            assert any(abs(f - expected) < 0.5 for f in detected_freqs), (
                f"Expected peak near {expected} Hz, got {detected_freqs}"
            )

    def test_detect_peaks_min_distance(self):
        """Peaks closer than min_distance_hz are filtered."""
        freqs = _make_freqs(2000, 100.0)
        # Two peaks only 0.3 Hz apart
        psd = _make_multi_peak_psd(freqs, [10.0, 10.3], amplitude=100.0, width=0.2)

        peaks = detect_peaks(psd, freqs, min_distance_hz=2.0, absolute_threshold=0.5)

        # With 2 Hz min distance, at most one peak should survive
        assert len(peaks) <= 1

    def test_detect_peaks_threshold(self):
        """Peaks below absolute threshold are filtered out."""
        freqs = _make_freqs(1000, 100.0)
        psd = _make_sine_psd(freqs, 10.0, amplitude=5.0, width=0.5)

        peaks = detect_peaks(psd, freqs, absolute_threshold=200.0)

        assert len(peaks) == 0

    def test_detect_peaks_empty_psd(self):
        """Empty arrays return empty list."""
        assert detect_peaks(np.array([]), np.array([])) == []

    def test_detect_peaks_short_psd(self):
        """PSD with fewer than 3 points returns empty list."""
        assert detect_peaks(np.array([1.0, 2.0]), np.array([0.0, 1.0])) == []

    def test_detect_peaks_q_factor(self):
        """Detected peaks should have reasonable Q-factor values."""
        freqs = _make_freqs(2000, 100.0)
        # Sharp peak should yield higher Q
        psd = _make_sine_psd(freqs, 14.3, amplitude=200.0, width=0.3)

        peaks = detect_peaks(psd, freqs, absolute_threshold=0.5)

        assert len(peaks) >= 1
        peak = peaks[0]
        # Q-factor should be positive and reasonable for SR
        if peak.q_factor is not None:
            assert peak.q_factor > 0.0

    def test_detect_peaks_sorted_by_freq(self):
        """Results should be sorted by frequency."""
        freqs = _make_freqs(2000, 100.0)
        psd = _make_multi_peak_psd(freqs, [20.8, 7.83, 14.3], amplitude=100.0, width=0.5)

        peaks = detect_peaks(psd, freqs, absolute_threshold=0.5)

        for i in range(len(peaks) - 1):
            assert peaks[i].freq <= peaks[i + 1].freq


class TestSmoothSpectrum:
    """Tests for smooth_spectrum()."""

    def test_smooth_spectrum_reduces_noise(self):
        """Smoothing should reduce noise variance."""
        rng = np.random.default_rng(42)
        noisy = 50.0 + rng.normal(0, 5, 500)

        smoothed = smooth_spectrum(noisy, window_size=11)

        assert np.var(smoothed) < np.var(noisy)

    def test_smooth_spectrum_small_window(self):
        """Window=1 returns input unchanged."""
        psd = np.array([1.0, 3.0, 2.0, 5.0, 4.0])
        result = smooth_spectrum(psd, window_size=1)
        np.testing.assert_array_equal(result, psd)

    def test_smooth_spectrum_large_window(self):
        """Window >= len(psd) returns input copy."""
        psd = np.array([1.0, 2.0, 3.0])
        result = smooth_spectrum(psd, window_size=10)
        np.testing.assert_array_equal(result, psd)

    def test_smooth_spectrum_negative_window(self):
        """Negative window size treated as 1 (returns copy)."""
        psd = np.array([1.0, 2.0, 3.0])
        result = smooth_spectrum(psd, window_size=-1)
        np.testing.assert_array_equal(result, psd)

    def test_smooth_spectrum_preserves_length(self):
        """Output length matches input length."""
        psd = np.ones(100)
        result = smooth_spectrum(psd, window_size=7)
        assert len(result) == len(psd)


class TestParabolicInterpolation:
    """Tests for parabolic_interpolation()."""

    def test_parabolic_interpolation_center(self):
        """Symmetric peak should yield no shift from center bin."""
        psd = np.array([1.0, 5.0, 10.0, 5.0, 1.0])
        idx, amp = parabolic_interpolation(psd, 2)

        assert abs(idx - 2.0) < 1e-10
        assert amp >= 10.0 - 1e-10

    def test_parabolic_interpolation_offset(self):
        """Asymmetric neighbors should shift the interpolated index."""
        psd = np.array([1.0, 8.0, 10.0, 6.0, 1.0])
        idx, _ = parabolic_interpolation(psd, 2)

        # Higher left neighbor pulls the peak slightly left
        assert idx < 2.0

    def test_parabolic_interpolation_edge_first(self):
        """First bin returns uninterpolated values."""
        psd = np.array([10.0, 5.0, 1.0])
        idx, amp = parabolic_interpolation(psd, 0)

        assert idx == 0.0
        assert amp == 10.0

    def test_parabolic_interpolation_edge_last(self):
        """Last bin returns uninterpolated values."""
        psd = np.array([1.0, 5.0, 10.0])
        idx, amp = parabolic_interpolation(psd, 2)

        assert idx == 2.0
        assert amp == 10.0

    def test_parabolic_interpolation_flat(self):
        """Three equal values: denominator ~ 0, returns center."""
        psd = np.array([1.0, 5.0, 5.0, 5.0, 1.0])
        idx, amp = parabolic_interpolation(psd, 2)

        assert abs(idx - 2.0) < 1e-10
        assert abs(amp - 5.0) < 1e-10


class TestComputeFwhm:
    """Tests for compute_fwhm()."""

    def test_compute_fwhm_known_width(self):
        """Lorentzian with known half-width should yield correct FWHM."""
        gamma = 1.0  # half-width at half-maximum
        freqs = np.linspace(0.0, 50.0, 5000)
        center = 20.0
        psd = 100.0 / (1.0 + ((freqs - center) / gamma) ** 2)

        peak_idx = np.argmax(psd)
        fwhm = compute_fwhm(psd, freqs, peak_idx)

        assert fwhm is not None
        # FWHM of Lorentzian = 2 * gamma
        assert abs(fwhm - 2.0 * gamma) < 0.1

    def test_compute_fwhm_none_on_edge(self):
        """Peak at spectrum edge where half-max crossing is missing returns None."""
        freqs = np.linspace(0.0, 5.0, 100)
        # Peak right at the start, monotonically decreasing - no left crossing
        psd = 100.0 / (1.0 + ((freqs - 0.0) / 0.5) ** 2)

        fwhm = compute_fwhm(psd, freqs, 0)

        assert fwhm is None

    def test_compute_fwhm_short_psd(self):
        """PSD with fewer than 3 points returns None."""
        assert compute_fwhm(np.array([1.0, 2.0]), np.array([0.0, 1.0]), 1) is None

    def test_compute_fwhm_negative_index(self):
        """Negative peak index returns None."""
        freqs = np.linspace(0.0, 10.0, 100)
        psd = np.ones(100)
        assert compute_fwhm(psd, freqs, -1) is None

    def test_compute_fwhm_q_factor_consistency(self):
        """FWHM and Q-factor should be consistent: Q = f_center / FWHM."""
        gamma = 2.0
        center = 14.3
        freqs = np.linspace(0.0, 50.0, 5000)
        psd = 100.0 / (1.0 + ((freqs - center) / gamma) ** 2)

        peak_idx = np.argmax(psd)
        fwhm = compute_fwhm(psd, freqs, peak_idx)

        assert fwhm is not None
        q = center / fwhm
        expected_q = center / (2.0 * gamma)
        assert abs(q - expected_q) < 0.3

    def test_compute_fwhm_minimum_floor(self):
        """FWHM is floored at 2x frequency resolution to prevent unrealistic Q."""
        # Very narrow peak: natural FWHM much smaller than resolution
        freqs = np.linspace(0.0, 50.0, 500)  # coarse: resolution = 0.1 Hz
        freq_res = freqs[1] - freqs[0]
        center = 20.0
        # Extremely narrow peak: gamma = 0.01 Hz, natural FWHM = 0.02 Hz
        gamma = 0.01
        psd = 100.0 / (1.0 + ((freqs - center) / gamma) ** 2)

        peak_idx = np.argmax(psd)
        fwhm = compute_fwhm(psd, freqs, peak_idx)

        assert fwhm is not None
        # FWHM should be at least 2x frequency resolution
        assert fwhm >= freq_res * 2.0
        # Resulting Q should be bounded: Q = 20.0 / fwhm <= 20.0 / (2 * 0.1) = 100
        q = center / fwhm
        assert q <= center / (freq_res * 2.0)

    def test_compute_fwhm_floor_does_not_inflate_wide_peaks(self):
        """The FWHM floor does not affect peaks that are already wide."""
        freqs = np.linspace(0.0, 50.0, 5000)  # fine resolution
        freq_res = freqs[1] - freqs[0]
        center = 14.3
        gamma = 2.0  # natural FWHM = 4.0 Hz, well above 2*freq_res
        psd = 100.0 / (1.0 + ((freqs - center) / gamma) ** 2)

        peak_idx = np.argmax(psd)
        fwhm = compute_fwhm(psd, freqs, peak_idx)

        assert fwhm is not None
        # FWHM should be close to the natural value, not inflated by the floor
        assert abs(fwhm - 2.0 * gamma) < 0.2
        assert fwhm > freq_res * 2.0  # well above the floor


class TestFilterToSrBands:
    """Tests for filter_to_sr_bands()."""

    def test_filter_to_sr_bands_one_per_band(self):
        """3 peaks in mode 1 range keeps only the strongest."""
        peaks = [
            DetectedPeak(freq=7.0, amp=10.0),
            DetectedPeak(freq=7.83, amp=50.0),
            DetectedPeak(freq=8.5, amp=30.0),
        ]
        result = filter_to_sr_bands(peaks)

        assert len(result) == 1
        assert result[0].freq == 7.83
        assert result[0].amp == 50.0

    def test_filter_to_sr_bands_selects_strongest(self):
        """Peaks at 7.5, 7.83, 8.0 keeps 7.83 (highest amp)."""
        peaks = [
            DetectedPeak(freq=7.5, amp=20.0),
            DetectedPeak(freq=7.83, amp=80.0),
            DetectedPeak(freq=8.0, amp=40.0),
        ]
        result = filter_to_sr_bands(peaks)

        assert len(result) == 1
        assert result[0].freq == 7.83

    def test_filter_to_sr_bands_empty_band(self):
        """No peak in mode 3 results in mode 3 absent from output."""
        # Only place peaks in mode 1 and mode 2
        peaks = [
            DetectedPeak(freq=7.83, amp=50.0),
            DetectedPeak(freq=14.3, amp=40.0),
        ]
        result = filter_to_sr_bands(peaks)

        assert len(result) == 2
        result_freqs = [p.freq for p in result]
        # Mode 3 center is 20.8, no peak near there
        assert not any(18.5 <= f <= 23.5 for f in result_freqs)

    def test_filter_to_sr_bands_empty_input(self):
        """Empty list returns empty result."""
        result = filter_to_sr_bands([])

        assert result == []

    def test_filter_to_sr_bands_all_bands(self):
        """8 peaks, one per band, all returned."""
        peaks = [
            DetectedPeak(freq=7.83, amp=80.0),
            DetectedPeak(freq=14.3, amp=75.0),
            DetectedPeak(freq=20.8, amp=70.0),
            DetectedPeak(freq=27.3, amp=68.0),
            DetectedPeak(freq=33.8, amp=65.0),
            DetectedPeak(freq=39.0, amp=62.0),
            DetectedPeak(freq=45.0, amp=58.0),
            DetectedPeak(freq=51.0, amp=55.0),
        ]
        result = filter_to_sr_bands(peaks)

        assert len(result) == 8

    def test_filter_to_sr_bands_custom_ranges(self):
        """Custom mode_ranges override defaults."""
        custom_ranges = {
            "Custom Band": {"min": 5.0, "max": 10.0},
        }
        peaks = [
            DetectedPeak(freq=7.0, amp=30.0),
            DetectedPeak(freq=14.3, amp=40.0),  # outside custom band
        ]
        result = filter_to_sr_bands(peaks, mode_ranges=custom_ranges)

        assert len(result) == 1
        assert result[0].freq == 7.0

    def test_filter_to_sr_bands_outside_all_bands(self):
        """Peak outside all bands is discarded."""
        peaks = [
            DetectedPeak(freq=3.0, amp=100.0),  # below all bands
            DetectedPeak(freq=55.0, amp=100.0),  # above all bands
        ]
        result = filter_to_sr_bands(peaks)

        assert len(result) == 0


class TestDetectPeaksWithSrFiltering:
    """Tests for detect_peaks with sr_band_filtering parameter."""

    def test_detect_peaks_with_sr_filtering(self):
        """With sr_band_filtering=True, at most 8 peaks returned."""
        freqs = _make_freqs(4000, 200.0)
        # Create peaks at many frequencies including all SR modes
        peak_freqs = [7.83, 14.3, 20.8, 27.3, 33.8, 39.0, 45.0, 51.0, 5.0, 55.0]
        psd = _make_multi_peak_psd(freqs, peak_freqs, amplitude=100.0, width=0.3)

        peaks = detect_peaks(psd, freqs, absolute_threshold=0.5, sr_band_filtering=True)

        assert len(peaks) <= 8

    def test_detect_peaks_without_sr_filtering(self):
        """With sr_band_filtering=False, more peaks may be returned."""
        freqs = _make_freqs(4000, 200.0)
        # Create peaks both inside and outside SR bands
        peak_freqs = [7.83, 14.3, 20.8, 27.3, 33.8, 39.0, 45.0, 51.0, 5.0, 55.0, 60.0]
        psd = _make_multi_peak_psd(freqs, peak_freqs, amplitude=100.0, width=0.3)

        peaks_filtered = detect_peaks(psd, freqs, absolute_threshold=0.5, sr_band_filtering=True)
        peaks_unfiltered = detect_peaks(psd, freqs, absolute_threshold=0.5, sr_band_filtering=False)

        # Unfiltered should have at least as many peaks
        assert len(peaks_unfiltered) >= len(peaks_filtered)
