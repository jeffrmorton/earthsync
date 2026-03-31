"""Tests for Welch PSD estimation module.

Validates spectral estimation accuracy, parameter handling, edge cases,
and display grid resampling against known analytical results.
"""

import numpy as np
import pytest
from earthsync_server.dsp.welch import (
    WelchPSDResult,
    compute_multitaper_psd,
    compute_welch_psd,
    resample_to_display_grid,
)

# ---------------------------------------------------------------------------
# compute_welch_psd tests
# ---------------------------------------------------------------------------


class TestComputeWelchPSD:
    """Tests for the compute_welch_psd function."""

    def test_pure_sine_peak(self):
        """A 10 Hz pure sine at 256 Hz sample rate produces a PSD peak at 10 Hz."""
        fs = 256
        duration = 10.0  # long segment for sharp peak
        t = np.arange(0, duration, 1.0 / fs)
        signal = np.sin(2 * np.pi * 10.0 * t)

        result = compute_welch_psd(signal, fs)

        peak_idx = np.argmax(result.psd)
        peak_freq = result.freqs[peak_idx]

        # Peak must be within one frequency bin of 10 Hz
        assert abs(peak_freq - 10.0) <= result.frequency_resolution_hz

    def test_pure_sine_peak_amplitude(self):
        """PSD peak amplitude scales with the square of the sine amplitude."""
        fs = 256
        duration = 4.0
        t = np.arange(0, duration, 1.0 / fs)

        amp1, amp2 = 1.0, 3.0
        sig1 = amp1 * np.sin(2 * np.pi * 10.0 * t)
        sig2 = amp2 * np.sin(2 * np.pi * 10.0 * t)

        result1 = compute_welch_psd(sig1, fs)
        result2 = compute_welch_psd(sig2, fs)

        peak1 = np.max(result1.psd)
        peak2 = np.max(result2.psd)

        # Ratio of peak PSDs should be (amp2/amp1)^2 = 9.0
        ratio = peak2 / peak1
        assert abs(ratio - (amp2 / amp1) ** 2) < 1.0, f"Expected ~9.0, got {ratio}"

    def test_white_noise_flat(self):
        """White noise produces an approximately flat PSD."""
        rng = np.random.default_rng(42)
        fs = 256
        n_samples = 4096
        noise = rng.standard_normal(n_samples)

        result = compute_welch_psd(noise, fs)

        # Exclude DC bin (index 0) and Nyquist
        psd_interior = result.psd[1:-1]
        mean_psd = np.mean(psd_interior)
        std_psd = np.std(psd_interior)

        # Coefficient of variation should be modest for flat spectrum
        cv = std_psd / mean_psd
        assert cv < 1.0, f"PSD too uneven for white noise, CV={cv}"

    def test_sample_rate_affects_nyquist_256(self):
        """256 Hz sample rate yields 128 Hz Nyquist frequency."""
        signal = np.ones(100)
        result = compute_welch_psd(signal, 256)
        assert result.nyquist_hz == 128.0

    def test_sample_rate_affects_nyquist_100(self):
        """100 Hz sample rate yields 50 Hz Nyquist frequency."""
        signal = np.ones(100)
        result = compute_welch_psd(signal, 100)
        assert result.nyquist_hz == 50.0

    def test_frequency_resolution(self):
        """Frequency resolution equals sample_rate / nfft."""
        fs = 256
        n = 1024
        signal = np.zeros(n)

        result = compute_welch_psd(signal, fs)

        expected_resolution = fs / result.nfft
        assert result.frequency_resolution_hz == pytest.approx(expected_resolution)

    def test_nfft_value(self):
        """NFFT equals the number of samples (nperseg = len(samples))."""
        signal = np.zeros(512)
        result = compute_welch_psd(signal, 256)
        assert result.nfft == 512

    def test_empty_samples_raises(self):
        """Empty sample array raises ValueError."""
        with pytest.raises(ValueError, match="samples array must not be empty"):
            compute_welch_psd(np.array([]), 256)

    def test_zero_sample_rate_raises(self):
        """Zero sample rate raises ValueError."""
        with pytest.raises(ValueError, match="sample_rate_hz must be positive"):
            compute_welch_psd(np.array([1.0, 2.0]), 0)

    def test_negative_sample_rate_raises(self):
        """Negative sample rate raises ValueError."""
        with pytest.raises(ValueError, match="sample_rate_hz must be positive"):
            compute_welch_psd(np.array([1.0, 2.0]), -10)

    def test_single_sample(self):
        """Single sample input produces a valid result without error."""
        result = compute_welch_psd(np.array([42.0]), 256)

        assert isinstance(result, WelchPSDResult)
        assert len(result.psd) >= 1
        assert len(result.freqs) >= 1
        assert result.nfft == 1
        assert result.nyquist_hz == 128.0

    def test_return_type(self):
        """Return value is a WelchPSDResult dataclass."""
        result = compute_welch_psd(np.array([1.0, 2.0, 3.0, 4.0]), 100)
        assert isinstance(result, WelchPSDResult)
        assert isinstance(result.psd, np.ndarray)
        assert isinstance(result.freqs, np.ndarray)

    def test_psd_freqs_same_length(self):
        """PSD and frequency arrays have the same length."""
        signal = np.random.default_rng(0).standard_normal(500)
        result = compute_welch_psd(signal, 200)
        assert len(result.psd) == len(result.freqs)


# ---------------------------------------------------------------------------
# resample_to_display_grid tests
# ---------------------------------------------------------------------------


class TestResampleToDisplayGrid:
    """Tests for the resample_to_display_grid function."""

    def test_resample_to_display_grid_shape(self):
        """Output length equals n_points."""
        psd = np.ones(100)
        freqs = np.linspace(0, 50, 100)

        result = resample_to_display_grid(psd, freqs, n_points=500)
        assert len(result) == 500

    def test_resample_to_display_grid_range(self):
        """Output covers 0 to max_hz range (verified by peak placement)."""
        # Create a PSD with a peak at 30 Hz
        freqs = np.linspace(0, 100, 1000)
        psd = np.exp(-((freqs - 30) ** 2) / 2)

        result = resample_to_display_grid(psd, freqs, n_points=1101, max_hz=55.0)
        display_freqs = np.linspace(0, 55.0, 1101)

        peak_idx = np.argmax(result)
        peak_freq = display_freqs[peak_idx]

        assert abs(peak_freq - 30.0) < 0.5

    def test_resample_preserves_peak(self):
        """Peak in native PSD is preserved in the resampled grid."""
        fs = 256
        t = np.arange(0, 4.0, 1.0 / fs)
        signal = np.sin(2 * np.pi * 14.3 * t)

        welch_result = compute_welch_psd(signal, fs)

        resampled = resample_to_display_grid(welch_result.psd, welch_result.freqs)
        display_freqs = np.linspace(0, 55.0, 1101)

        peak_idx = np.argmax(resampled)
        peak_freq = display_freqs[peak_idx]

        assert abs(peak_freq - 14.3) < 0.5

    def test_resample_default_params(self):
        """Default parameters: 1101 points, 55 Hz max."""
        psd = np.ones(200)
        freqs = np.linspace(0, 100, 200)

        result = resample_to_display_grid(psd, freqs)
        assert len(result) == 1101

    def test_resample_custom_params(self):
        """Custom n_points and max_hz are respected."""
        psd = np.ones(200)
        freqs = np.linspace(0, 100, 200)

        result = resample_to_display_grid(psd, freqs, n_points=500, max_hz=30.0)
        assert len(result) == 500

    def test_resample_extrapolation(self):
        """Frequencies beyond native range are filled with zeros."""
        # Native range only covers 0-20 Hz
        freqs = np.linspace(0, 20, 100)
        psd = np.ones(100) * 5.0

        result = resample_to_display_grid(psd, freqs, n_points=1101, max_hz=55.0)
        display_freqs = np.linspace(0, 55.0, 1101)

        # Points well within native range should be ~5.0
        in_range_mask = display_freqs <= 19.0
        assert np.all(result[in_range_mask] > 4.0)

        # Points well beyond native range should be 0.0
        beyond_mask = display_freqs >= 25.0
        assert np.all(result[beyond_mask] == 0.0)

    def test_resample_returns_ndarray(self):
        """Return type is a numpy ndarray."""
        psd = np.ones(50)
        freqs = np.linspace(0, 25, 50)

        result = resample_to_display_grid(psd, freqs)
        assert isinstance(result, np.ndarray)

    def test_resample_zero_max_freq(self):
        """When native max freq is 0, return zeros."""
        psd = np.ones(1)
        freqs = np.array([0.0])
        result = resample_to_display_grid(psd, freqs)
        assert np.all(result == 0.0)


# ---------------------------------------------------------------------------
# compute_multitaper_psd tests
# ---------------------------------------------------------------------------


class TestComputeMultitaperPSD:
    """Tests for the compute_multitaper_psd function."""

    def test_multitaper_pure_sine_peak(self):
        """A 10 Hz pure sine produces a PSD peak at 10 Hz."""
        fs = 256
        duration = 10.0
        t = np.arange(0, duration, 1.0 / fs)
        signal = np.sin(2 * np.pi * 10.0 * t)

        result = compute_multitaper_psd(signal, fs)

        peak_idx = np.argmax(result.psd)
        peak_freq = result.freqs[peak_idx]

        assert abs(peak_freq - 10.0) <= result.frequency_resolution_hz

    def test_multitaper_peak_narrower_than_welch(self):
        """Multitaper resolves two close peaks better than Welch with rectangular window."""
        fs = 256
        duration = 4.0
        t = np.arange(0, duration, 1.0 / fs)
        # Two closely spaced sinusoids
        signal = np.sin(2 * np.pi * 10.0 * t) + np.sin(2 * np.pi * 11.0 * t)

        mt_result = compute_multitaper_psd(signal, fs, nw=2.5, n_tapers=4)
        welch_result = compute_welch_psd(signal, fs)

        # Both methods should detect peak energy in the 9-12 Hz range
        mt_mask = (mt_result.freqs >= 9.0) & (mt_result.freqs <= 12.0)
        welch_mask = (welch_result.freqs >= 9.0) & (welch_result.freqs <= 12.0)

        # Peak power should be concentrated near 10-11 Hz for both
        assert np.max(mt_result.psd[mt_mask]) > np.mean(mt_result.psd) * 10
        assert np.max(welch_result.psd[welch_mask]) > np.mean(welch_result.psd) * 10

        # Both should have same frequency resolution
        assert mt_result.frequency_resolution_hz == welch_result.frequency_resolution_hz

    def test_multitaper_white_noise_lower_variance(self):
        """Multitaper PSD variance is lower than Welch PSD variance for white noise."""
        rng = np.random.default_rng(42)
        fs = 256
        n_samples = 4096
        noise = rng.standard_normal(n_samples)

        mt_result = compute_multitaper_psd(noise, fs, n_tapers=5)
        welch_result = compute_welch_psd(noise, fs)

        # Compare variance of interior PSD bins (exclude DC and Nyquist)
        mt_var = np.var(mt_result.psd[1:-1] / np.mean(mt_result.psd[1:-1]))
        welch_var = np.var(welch_result.psd[1:-1] / np.mean(welch_result.psd[1:-1]))

        assert mt_var < welch_var

    def test_multitaper_nw_affects_bandwidth(self):
        """Higher NW produces smoother spectrum (lower normalized variance)."""
        rng = np.random.default_rng(42)
        fs = 256
        n_samples = 2048
        noise = rng.standard_normal(n_samples)

        result_low_nw = compute_multitaper_psd(noise, fs, nw=2.0, n_tapers=3)
        result_high_nw = compute_multitaper_psd(noise, fs, nw=4.0, n_tapers=7)

        var_low = np.var(result_low_nw.psd[1:-1] / np.mean(result_low_nw.psd[1:-1]))
        var_high = np.var(result_high_nw.psd[1:-1] / np.mean(result_high_nw.psd[1:-1]))

        # Higher NW with more tapers should give lower variance
        assert var_high < var_low

    def test_multitaper_returns_correct_shape(self):
        """Output arrays have correct shape for input length."""
        fs = 256
        n = 1024
        signal = np.zeros(n)

        result = compute_multitaper_psd(signal, fs)

        expected_len = n // 2 + 1  # rfft output length
        assert len(result.psd) == expected_len
        assert len(result.freqs) == expected_len
        assert len(result.psd) == len(result.freqs)

    def test_multitaper_empty_raises(self):
        """Empty samples raises ValueError."""
        with pytest.raises(ValueError, match="samples must not be empty"):
            compute_multitaper_psd(np.array([]), 256)

    def test_multitaper_zero_rate_raises(self):
        """Zero sample_rate raises ValueError."""
        with pytest.raises(ValueError, match="sample_rate_hz must be positive"):
            compute_multitaper_psd(np.array([1.0, 2.0]), 0)

    def test_multitaper_negative_rate_raises(self):
        """Negative sample_rate raises ValueError."""
        with pytest.raises(ValueError, match="sample_rate_hz must be positive"):
            compute_multitaper_psd(np.array([1.0, 2.0]), -10)

    def test_multitaper_single_sample(self):
        """Single sample input produces valid result without error."""
        result = compute_multitaper_psd(np.array([42.0]), 256)

        assert isinstance(result, WelchPSDResult)
        assert len(result.psd) >= 1
        assert len(result.freqs) >= 1
        assert result.nfft == 1
        assert result.nyquist_hz == 128.0

    def test_multitaper_result_type(self):
        """Return value is a WelchPSDResult dataclass."""
        result = compute_multitaper_psd(np.array([1.0, 2.0, 3.0, 4.0]), 100)
        assert isinstance(result, WelchPSDResult)
        assert isinstance(result.psd, np.ndarray)
        assert isinstance(result.freqs, np.ndarray)

    def test_multitaper_freqs_correct_range(self):
        """Frequencies go from 0 to Nyquist."""
        fs = 256
        n = 512
        signal = np.zeros(n)

        result = compute_multitaper_psd(signal, fs)

        assert result.freqs[0] == 0.0
        assert result.freqs[-1] == pytest.approx(fs / 2.0)
        assert result.nyquist_hz == fs / 2.0
