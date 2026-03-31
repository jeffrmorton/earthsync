"""Tests for peak analysis — SNR, noise floor, uncertainties."""

import numpy as np
from earthsync_server.constants import SCHUMANN_FREQUENCIES
from earthsync_server.dsp.peak_analysis import (
    compute_snr,
    compute_uncertainties,
    estimate_noise_floor,
)
from earthsync_server.models import DetectedPeak


class TestComputeSNR:
    def test_known_ratio(self):
        """Signal 100x noise -> 20 dB."""
        freqs = np.linspace(0, 50, 1000)
        psd = np.ones(1000)  # Flat noise
        snr = compute_snr(25.0, 100.0, psd, freqs)
        assert abs(snr - 20.0) < 0.5

    def test_high_peak(self):
        freqs = np.linspace(0, 50, 500)
        psd = np.ones(500) * 0.1
        snr = compute_snr(25.0, 1000.0, psd, freqs)
        assert snr > 30.0

    def test_weak_peak(self):
        freqs = np.linspace(0, 50, 500)
        psd = np.ones(500) * 10.0
        snr = compute_snr(25.0, 12.0, psd, freqs)
        assert snr < 3.0

    def test_edge_frequency(self):
        """Peak near edge of spectrum still computes."""
        freqs = np.linspace(0, 50, 500)
        psd = np.ones(500)
        snr = compute_snr(1.0, 10.0, psd, freqs)
        assert snr > 0.0

    def test_zero_noise_returns_zero(self):
        freqs = np.linspace(0, 50, 500)
        psd = np.zeros(500)
        snr = compute_snr(25.0, 10.0, psd, freqs)
        assert snr == 0.0

    def test_zero_peak_amp_returns_zero(self):
        freqs = np.linspace(0, 50, 500)
        psd = np.ones(500)
        snr = compute_snr(25.0, 0.0, psd, freqs)
        assert snr == 0.0

    def test_empty_annular_returns_zero(self):
        """Spectrum too narrow for annular region."""
        freqs = np.array([25.0])
        psd = np.array([1.0])
        snr = compute_snr(25.0, 10.0, psd, freqs)
        assert snr == 0.0


class TestEstimateNoiseFloor:
    def test_white_noise(self):
        rng = np.random.default_rng(42)
        freqs = np.linspace(0, 55, 1101)
        psd = rng.exponential(1.0, 1101)
        nf = estimate_noise_floor(psd, freqs)
        assert nf.median > 0.0
        assert nf.std > 0.0

    def test_excludes_sr_frequencies(self):
        freqs = np.linspace(0, 55, 1101)
        psd = np.ones(1101)
        # Add huge spikes at SR frequencies
        for sf in SCHUMANN_FREQUENCIES:
            idx = int(sf * 1101 / 55)
            if idx < 1101:
                psd[max(0, idx - 5) : idx + 5] = 1000.0
        nf = estimate_noise_floor(psd, freqs)
        assert nf.median < 10.0  # Spikes excluded

    def test_empty_after_exclusion(self):
        """All bins excluded → zero noise floor."""
        freqs = np.array([7.83, 14.3])
        psd = np.array([1.0, 1.0])
        nf = estimate_noise_floor(psd, freqs)
        assert nf.median == 0.0
        assert nf.std == 0.0

    def test_no_exclusion_uses_all(self):
        freqs = np.linspace(0, 55, 100)
        psd = np.ones(100) * 5.0
        nf = estimate_noise_floor(psd, freqs, exclusion_freqs=())
        assert abs(nf.median - 5.0) < 0.01


class TestComputeUncertainties:
    def test_with_variance(self):
        peak = DetectedPeak(freq=7.83, amp=10.0)
        variances = np.ones(100) * 0.25  # variance = 0.25 → std = 0.5
        result = compute_uncertainties(peak, variances, freq_resolution_hz=0.1)
        assert result.amp_err is not None
        assert abs(result.amp_err - 0.5) < 0.01
        assert result.freq_err is not None
        assert result.freq_err > 0.0

    def test_without_variance(self):
        peak = DetectedPeak(freq=7.83, amp=10.0)
        result = compute_uncertainties(peak, None, freq_resolution_hz=0.1)
        assert result is peak  # Same object, unchanged

    def test_zero_freq_resolution(self):
        peak = DetectedPeak(freq=7.83, amp=10.0)
        variances = np.ones(100) * 0.25
        result = compute_uncertainties(peak, variances, freq_resolution_hz=0.0)
        assert result is peak

    def test_zero_variance_at_peak(self):
        peak = DetectedPeak(freq=0.5, amp=10.0)
        variances = np.zeros(100)
        result = compute_uncertainties(peak, variances, freq_resolution_hz=0.1)
        assert result is peak

    def test_freq_err_proportional_to_variance(self):
        peak = DetectedPeak(freq=5.0, amp=10.0)
        var_low = np.ones(100) * 0.01
        var_high = np.ones(100) * 1.0
        result_low = compute_uncertainties(peak, var_low, freq_resolution_hz=0.1)
        result_high = compute_uncertainties(peak, var_high, freq_resolution_hz=0.1)
        assert result_high.freq_err > result_low.freq_err  # type: ignore[operator]

    def test_zero_peak_amp(self):
        peak = DetectedPeak(freq=5.0, amp=0.0)
        variances = np.ones(100) * 0.25
        result = compute_uncertainties(peak, variances, freq_resolution_hz=0.1)
        assert result.freq_err == 0.0

    def test_preserves_other_fields(self):
        peak = DetectedPeak(freq=7.83, amp=10.0, q_factor=4.0, snr=15.0, q_err=0.5)
        variances = np.ones(100) * 0.25
        result = compute_uncertainties(peak, variances, freq_resolution_hz=0.1)
        assert result.q_factor == 4.0
        assert result.snr == 15.0
        assert result.q_err == 0.5
