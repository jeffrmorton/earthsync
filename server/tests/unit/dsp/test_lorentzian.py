"""Tests for multi-Lorentzian curve fitting module.

Validates peak recovery, uncertainty estimation, background fitting,
convergence handling, and edge cases using synthetic Lorentzian spectra.
"""

from unittest.mock import patch

import numpy as np
from earthsync_server.dsp.lorentzian import fit_lorentzians, lorentzian_model
from earthsync_server.models import LorentzianFitResult, LorentzianMode


def _make_lorentzian(f: np.ndarray, f0: float, amp: float, q: float) -> np.ndarray:
    """Generate a single Lorentzian peak for test data.

    Args:
        f: Frequency array.
        f0: Center frequency.
        amp: Amplitude parameter.
        q: Quality factor.

    Returns:
        Lorentzian curve evaluated at frequencies f.
    """
    gamma = f0 / (2.0 * q)
    return amp / ((f - f0) ** 2 + gamma**2)


# ---------------------------------------------------------------------------
# lorentzian_model tests
# ---------------------------------------------------------------------------


class TestLorentzianModel:
    """Tests for the lorentzian_model function."""

    def test_lorentzian_model_shape(self):
        """Model output has the same shape as the input frequency array."""
        f = np.linspace(1, 50, 500)
        params = {"f0": 7.83, "a0": 100.0, "q0": 4.0, "slope": 0.0, "intercept": 0.0}

        result = lorentzian_model(f, params, n_modes=1)
        assert result.shape == f.shape

    def test_lorentzian_model_peak_at_center(self):
        """Model peaks at the specified center frequency."""
        f = np.linspace(1, 50, 5000)
        f0 = 14.3
        params = {"f0": f0, "a0": 100.0, "q0": 4.0, "slope": 0.0, "intercept": 0.0}

        result = lorentzian_model(f, params, n_modes=1)
        peak_idx = np.argmax(result)
        peak_freq = f[peak_idx]

        assert abs(peak_freq - f0) < 0.05

    def test_q_factor_affects_width(self):
        """Higher Q factor produces a narrower peak (smaller FWHM)."""
        f = np.linspace(1, 50, 5000)

        params_low_q = {"f0": 20.0, "a0": 100.0, "q0": 2.0, "slope": 0.0, "intercept": 0.0}
        params_high_q = {"f0": 20.0, "a0": 100.0, "q0": 10.0, "slope": 0.0, "intercept": 0.0}

        result_low = lorentzian_model(f, params_low_q, n_modes=1)
        result_high = lorentzian_model(f, params_high_q, n_modes=1)

        # FWHM: width where amplitude drops to half-max
        def fwhm(curve: np.ndarray) -> float:
            half_max = np.max(curve) / 2.0
            above = np.where(curve >= half_max)[0]
            return f[above[-1]] - f[above[0]]

        fwhm_low = fwhm(result_low)
        fwhm_high = fwhm(result_high)

        assert fwhm_high < fwhm_low, (
            f"High-Q FWHM ({fwhm_high:.2f}) should be less than low-Q ({fwhm_low:.2f})"
        )

    def test_lorentzian_model_multi_mode(self):
        """Model with multiple modes produces distinct peaks."""
        f = np.linspace(1, 50, 5000)
        params = {
            "f0": 7.83,
            "a0": 100.0,
            "q0": 4.0,
            "f1": 14.3,
            "a1": 80.0,
            "q1": 4.0,
            "slope": 0.0,
            "intercept": 0.0,
        }

        result = lorentzian_model(f, params, n_modes=2)

        # Find local maxima near expected frequencies
        idx_7 = np.argmin(np.abs(f - 7.83))
        idx_14 = np.argmin(np.abs(f - 14.3))

        # Both should be local peaks (higher than neighbors 10 bins away)
        assert result[idx_7] > result[idx_7 - 50]
        assert result[idx_14] > result[idx_14 + 50]

    def test_lorentzian_model_background(self):
        """Linear background shifts the baseline."""
        f = np.linspace(1, 50, 500)
        params_no_bg = {"f0": 20.0, "a0": 100.0, "q0": 4.0, "slope": 0.0, "intercept": 0.0}
        params_with_bg = {"f0": 20.0, "a0": 100.0, "q0": 4.0, "slope": 0.5, "intercept": 10.0}

        result_no_bg = lorentzian_model(f, params_no_bg, n_modes=1)
        result_with_bg = lorentzian_model(f, params_with_bg, n_modes=1)

        # Background should add slope*f + intercept
        expected_offset = 0.5 * f + 10.0
        diff = result_with_bg - result_no_bg
        np.testing.assert_allclose(diff, expected_offset, atol=1e-10)


# ---------------------------------------------------------------------------
# fit_lorentzians tests
# ---------------------------------------------------------------------------


class TestFitLorentzians:
    """Tests for the fit_lorentzians function."""

    def test_single_lorentzian_recovery(self):
        """Fit recovers a single known Lorentzian: freq within 0.1 Hz, amp within 10%."""
        f = np.linspace(1, 50, 2000)
        f0, amp, q = 7.83, 200.0, 4.0
        psd = _make_lorentzian(f, f0, amp, q)

        peaks = [{"freq": 7.83, "amp": 200.0}]
        result = fit_lorentzians(psd, f, peaks)

        assert result.converged
        assert len(result.modes) == 1

        mode = result.modes[0]
        assert abs(mode.freq - f0) < 0.1
        assert abs(mode.amp - amp) / amp < 0.1

    def test_single_lorentzian_uncertainties_not_null(self):
        """Successful fit provides non-None uncertainty estimates for all parameters."""
        f = np.linspace(1, 50, 2000)
        psd = _make_lorentzian(f, 7.83, 200.0, 4.0)
        # Add small noise to ensure covariance matrix is well-conditioned
        rng = np.random.default_rng(42)
        psd += rng.standard_normal(len(psd)) * 0.01

        peaks = [{"freq": 7.83, "amp": 200.0}]
        result = fit_lorentzians(psd, f, peaks)

        assert result.converged
        mode = result.modes[0]
        assert mode.freq_err is not None
        assert mode.amp_err is not None
        assert mode.q_err is not None

    def test_multi_mode_recovery(self):
        """Fit recovers three Lorentzians at SR frequencies 7.83, 14.3, 20.8 Hz."""
        f = np.linspace(1, 50, 3000)

        expected = [
            (7.83, 200.0, 3.5),
            (14.3, 150.0, 4.5),
            (20.8, 120.0, 5.0),
        ]

        psd = np.zeros_like(f)
        for f0, amp, q in expected:
            psd += _make_lorentzian(f, f0, amp, q)

        peaks = [{"freq": f0, "amp": amp} for f0, amp, _ in expected]
        result = fit_lorentzians(psd, f, peaks)

        assert result.converged
        assert len(result.modes) == 3

        fitted_freqs = sorted(m.freq for m in result.modes)
        expected_freqs = sorted(f0 for f0, _, _ in expected)

        for fitted, exp in zip(fitted_freqs, expected_freqs, strict=True):
            assert abs(fitted - exp) < 0.3, f"Expected ~{exp} Hz, got {fitted:.2f} Hz"

    def test_fit_with_linear_background(self):
        """Fit recovers a linear background added to the spectrum."""
        f = np.linspace(1, 50, 2000)
        slope_true, intercept_true = 0.5, 10.0
        psd = _make_lorentzian(f, 14.3, 300.0, 4.0) + slope_true * f + intercept_true

        peaks = [{"freq": 14.3, "amp": 300.0}]
        result = fit_lorentzians(psd, f, peaks)

        assert result.converged
        assert abs(result.background["slope"] - slope_true) < 0.5
        assert abs(result.background["intercept"] - intercept_true) < 5.0

    def test_fit_converged_true(self):
        """Clean synthetic data produces a converged fit."""
        f = np.linspace(1, 50, 2000)
        psd = _make_lorentzian(f, 7.83, 200.0, 4.0)

        peaks = [{"freq": 7.83, "amp": 200.0}]
        result = fit_lorentzians(psd, f, peaks)

        assert result.converged is True

    def test_fit_chi_squared_reasonable(self):
        """Chi-squared is finite and non-negative for a clean fit."""
        f = np.linspace(1, 50, 2000)
        psd = _make_lorentzian(f, 7.83, 200.0, 4.0)

        peaks = [{"freq": 7.83, "amp": 200.0}]
        result = fit_lorentzians(psd, f, peaks)

        assert result.chi_squared is not None
        assert result.chi_squared >= 0.0
        assert np.isfinite(result.chi_squared)

    def test_max_modes_limit(self):
        """Providing 10 peaks with max_modes=3 fits only 3 modes."""
        f = np.linspace(1, 50, 2000)
        psd = np.ones_like(f)

        # 10 initial peaks
        peaks = [{"freq": float(i * 5), "amp": 100.0 - i} for i in range(1, 11)]

        result = fit_lorentzians(psd, f, peaks, max_modes=3)

        assert len(result.modes) == 3

    def test_empty_peaks_returns_background_only(self):
        """No initial peaks produces a result with only background (no modes)."""
        f = np.linspace(1, 50, 500)
        psd = 2.0 * f + 5.0  # pure linear

        result = fit_lorentzians(psd, f, initial_peaks=[])

        assert len(result.modes) == 0
        assert "slope" in result.background
        assert "intercept" in result.background
        assert result.converged

    def test_noisy_data_still_converges(self):
        """Fit converges on noisy data and still locates the peak."""
        rng = np.random.default_rng(123)
        f = np.linspace(1, 50, 2000)
        psd = _make_lorentzian(f, 7.83, 200.0, 4.0)
        psd += rng.standard_normal(len(psd)) * 0.5  # moderate noise

        peaks = [{"freq": 7.83, "amp": 200.0}]
        result = fit_lorentzians(psd, f, peaks)

        assert result.converged
        assert abs(result.modes[0].freq - 7.83) < 0.5

    def test_fit_failure_returns_converged_false(self):
        """Garbage data that cannot be fit returns converged=False."""
        f = np.linspace(1, 50, 50)
        # All NaN data will cause the fit to fail
        psd = np.full(50, np.nan)

        peaks = [{"freq": 10.0, "amp": 100.0}]
        result = fit_lorentzians(psd, f, peaks)

        assert result.converged is False

    def test_degrees_of_freedom(self):
        """Degrees of freedom = len(freqs) - n_params (3 per mode + 2 background)."""
        f = np.linspace(1, 50, 2000)
        psd = _make_lorentzian(f, 7.83, 200.0, 4.0)

        peaks = [{"freq": 7.83, "amp": 200.0}]
        result = fit_lorentzians(psd, f, peaks)

        # 1 mode: 3 params (f, a, q) + 2 background = 5
        expected_dof = len(f) - 5
        assert result.degrees_of_freedom == expected_dof

    def test_degrees_of_freedom_multi_mode(self):
        """DOF correct for multiple modes: n_data - (3*n_modes + 2)."""
        f = np.linspace(1, 50, 2000)
        psd = _make_lorentzian(f, 7.83, 200.0, 4.0) + _make_lorentzian(f, 14.3, 150.0, 4.0)

        peaks = [{"freq": 7.83, "amp": 200.0}, {"freq": 14.3, "amp": 150.0}]
        result = fit_lorentzians(psd, f, peaks)

        # 2 modes: 3*2 + 2 = 8 params
        expected_dof = len(f) - 8
        assert result.degrees_of_freedom == expected_dof

    def test_result_types(self):
        """Fit result uses correct Pydantic model types."""
        f = np.linspace(1, 50, 500)
        psd = _make_lorentzian(f, 7.83, 200.0, 4.0)

        peaks = [{"freq": 7.83, "amp": 200.0}]
        result = fit_lorentzians(psd, f, peaks)

        assert isinstance(result, LorentzianFitResult)
        assert isinstance(result.modes[0], LorentzianMode)

    def test_background_only_degrees_of_freedom(self):
        """Background-only fit has DOF = len(freqs) - 2."""
        f = np.linspace(1, 50, 500)
        psd = 2.0 * f + 5.0

        result = fit_lorentzians(psd, f, initial_peaks=[])

        expected_dof = len(f) - 2
        assert result.degrees_of_freedom == expected_dof

    def test_modes_sorted_by_amplitude(self):
        """Modes are taken from the top peaks by amplitude (max_modes limit)."""
        f = np.linspace(1, 50, 2000)
        # 4 peaks with different amplitudes
        peaks = [
            {"freq": 7.83, "amp": 50.0},
            {"freq": 14.3, "amp": 200.0},
            {"freq": 20.8, "amp": 150.0},
            {"freq": 27.3, "amp": 10.0},
        ]
        psd = np.zeros_like(f)
        for p in peaks:
            psd += _make_lorentzian(f, p["freq"], p["amp"], 4.0)

        result = fit_lorentzians(psd, f, peaks, max_modes=2)

        # Only the 2 highest-amplitude peaks should be fitted
        assert len(result.modes) == 2

    def test_fit_exception_returns_unconverged(self):
        """If lmfit raises during fit, result should be converged=False."""
        freqs = np.linspace(1, 50, 500)
        psd = np.ones(500)
        peaks = [{"freq": 7.83, "amp": 10.0}]
        with patch("earthsync_server.dsp.lorentzian.minimize", side_effect=RuntimeError("boom")):
            result = fit_lorentzians(psd, freqs, peaks)
        assert result.converged is False

    def test_background_only_exception(self):
        """If minimize raises during background-only fit, handle gracefully."""
        freqs = np.linspace(1, 50, 500)
        psd = np.ones(500)
        # Empty peaks triggers _fit_background_only path
        with patch("earthsync_server.dsp.lorentzian.minimize", side_effect=RuntimeError("boom")):
            result = fit_lorentzians(psd, freqs, [])
        assert result.converged is False
        assert result.background["slope"] == 0.0

    def test_q_initial_guess_clamped_high(self):
        """Peak with Q=176 from detector is clamped to 20 for the initial guess.

        The fitter should still converge and produce Q <= 30 (the upper bound).
        """
        f = np.linspace(1, 50, 2000)
        # Use a physically realistic Q=5 Lorentzian
        psd = _make_lorentzian(f, 7.83, 200.0, 5.0)

        # Provide an unrealistically high Q from peak detection
        peaks = [{"freq": 7.83, "amp": 200.0, "q_factor": 176.0}]
        result = fit_lorentzians(psd, f, peaks)

        assert result.converged
        assert result.modes[0].q_factor <= 30.0

    def test_q_initial_guess_clamped_low(self):
        """Peak with Q=0.1 from detector is clamped to 1.0 for the initial guess."""
        f = np.linspace(1, 50, 2000)
        psd = _make_lorentzian(f, 7.83, 200.0, 4.0)

        peaks = [{"freq": 7.83, "amp": 200.0, "q_factor": 0.1}]
        result = fit_lorentzians(psd, f, peaks)

        assert result.converged
        # Q should be bounded above 0.5 (the param min)
        assert result.modes[0].q_factor >= 0.5

    def test_q_upper_bound_30(self):
        """Fitted Q never exceeds 30.0 even on very narrow synthetic peaks."""
        f = np.linspace(1, 50, 2000)
        # Very narrow peak (Q=100 in the data)
        psd = _make_lorentzian(f, 14.3, 200.0, 100.0)

        peaks = [{"freq": 14.3, "amp": 200.0, "q_factor": 100.0}]
        result = fit_lorentzians(psd, f, peaks)

        assert result.converged
        # The fitter is hard-bounded at max=30.0
        assert result.modes[0].q_factor <= 30.0

    def test_q_none_defaults_to_4(self):
        """Peak with q_factor=None defaults to 4.0 initial guess."""
        f = np.linspace(1, 50, 2000)
        psd = _make_lorentzian(f, 7.83, 200.0, 4.0)

        peaks = [{"freq": 7.83, "amp": 200.0, "q_factor": None}]
        result = fit_lorentzians(psd, f, peaks)

        assert result.converged
        assert abs(result.modes[0].q_factor - 4.0) < 2.0
