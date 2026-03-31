"""Multi-Lorentzian curve fitting for Schumann Resonance peak extraction.

Fits a sum of Lorentzian functions plus linear background to PSD data
using the Levenberg-Marquardt algorithm via lmfit. The Lorentzian model
matches the theoretical spectral shape of SR modes in the Earth-ionosphere
cavity.

Model: S(f) = sum_i [A_i / ((f - f_i)^2 + (f_i / (2*Q_i))^2)] + slope*f + intercept

lmfit automatically computes parameter uncertainties from the covariance
matrix (Hessian inverse), providing freq_err, amp_err, q_err per mode.

References:
    Sentman, D.D. (1995). "Schumann Resonances." In Handbook of
    Atmospheric Electrodynamics, Vol. 1.
"""

import numpy as np
from lmfit import Parameters, minimize

from earthsync_server.models import LorentzianFitResult, LorentzianMode


def lorentzian_model(f: np.ndarray, params: dict, n_modes: int) -> np.ndarray:
    """Evaluate the multi-Lorentzian plus linear background model.

    Computes:
        S(f) = sum_{i=0}^{n_modes-1} [A_i / ((f - f_i)^2 + gamma_i^2)] + slope*f + intercept

    where gamma_i = f_i / (2 * Q_i) is the half-width at half-maximum.

    Args:
        f: Frequency array (Hz) at which to evaluate the model.
        params: Dictionary (or lmfit Parameters) with keys:
            f0, a0, q0, f1, a1, q1, ..., slope, intercept.
        n_modes: Number of Lorentzian components.

    Returns:
        Model evaluated at each frequency in f.
    """
    model = np.zeros_like(f, dtype=float)

    for i in range(n_modes):
        fi = float(params[f"f{i}"])
        ai = float(params[f"a{i}"])
        qi = float(params[f"q{i}"])

        # Half-width at half-maximum: gamma = f_center / (2 * Q)
        gamma = fi / (2.0 * qi)
        model += ai / ((f - fi) ** 2 + gamma**2)

    model += float(params["slope"]) * f + float(params["intercept"])

    return model


def _residuals(params: Parameters, f: np.ndarray, data: np.ndarray, n_modes: int) -> np.ndarray:
    """Compute residuals (data - model) for lmfit minimization.

    Args:
        params: lmfit Parameters object.
        f: Frequency array.
        data: Observed PSD values.
        n_modes: Number of Lorentzian components.

    Returns:
        Residual array (data - model).
    """
    return data - lorentzian_model(f, params, n_modes)


def fit_lorentzians(
    psd: np.ndarray,
    freqs: np.ndarray,
    initial_peaks: list,
    max_modes: int = 8,
    max_iterations: int = 5000,
) -> LorentzianFitResult:
    """Fit multi-Lorentzian model to PSD data.

    Takes initial peak estimates (from peak detection), builds an lmfit
    parameter set with bounded constraints, and runs Levenberg-Marquardt
    optimization. Parameter uncertainties are extracted from the covariance
    matrix computed by lmfit.

    Args:
        psd: Power spectral density values.
        freqs: Corresponding frequency array (Hz).
        initial_peaks: List of dicts with 'freq' and 'amp' keys from
            peak detection. Sorted by amplitude; top max_modes are used.
        max_modes: Maximum number of Lorentzian components to fit.
            Default 8 (all SR modes).
        max_iterations: Maximum Levenberg-Marquardt iterations. Default 5000.

    Returns:
        LorentzianFitResult with fitted modes, background parameters,
        chi-squared statistic, degrees of freedom, and convergence flag.
    """
    # Handle empty peaks: fit background only
    if len(initial_peaks) == 0:
        return _fit_background_only(psd, freqs, max_iterations)

    # Take top max_modes peaks by amplitude
    sorted_peaks = sorted(initial_peaks, key=lambda p: p["amp"], reverse=True)
    peaks_to_fit = sorted_peaks[:max_modes]
    n_modes = len(peaks_to_fit)

    # Build lmfit Parameters with bounds
    params = Parameters()

    for i, peak in enumerate(peaks_to_fit):
        freq_init = peak["freq"]
        amp_init = peak["amp"]
        q_init = peak.get("q_factor", 4.0) or 4.0
        q_init = max(1.0, min(q_init, 20.0))  # Clamp to realistic SR range (Q=3-10)

        # Frequency: initial +/- 2 Hz
        params.add(
            f"f{i}",
            value=freq_init,
            min=max(0.1, freq_init - 2.0),
            max=freq_init + 2.0,
        )
        # Amplitude: must be positive
        params.add(f"a{i}", value=amp_init, min=1e-10)
        # Q factor: use detected Q as initial, bound to physically realistic SR range
        params.add(f"q{i}", value=q_init, min=0.5, max=30.0)

    # Linear background
    params.add("slope", value=0.0)
    params.add("intercept", value=float(np.median(psd)))

    # Run Levenberg-Marquardt fit
    try:
        result = minimize(
            _residuals,
            params,
            args=(freqs, psd, n_modes),
            method="leastsq",
            max_nfev=max_iterations,
        )
    except Exception:
        # Fit failed entirely -- return unconverged result
        return _make_failed_result(n_modes, peaks_to_fit, len(freqs))

    converged = result.success

    # Extract fitted modes with uncertainties
    modes = []
    for i in range(n_modes):
        freq_val = float(result.params[f"f{i}"].value)
        amp_val = float(result.params[f"a{i}"].value)
        q_val = float(result.params[f"q{i}"].value)

        freq_err = result.params[f"f{i}"].stderr
        amp_err = result.params[f"a{i}"].stderr
        q_err = result.params[f"q{i}"].stderr

        # stderr is None when covariance matrix could not be estimated
        freq_err = float(freq_err) if freq_err is not None else None
        amp_err = float(amp_err) if amp_err is not None else None
        q_err = float(q_err) if q_err is not None else None

        modes.append(
            LorentzianMode(
                freq=freq_val,
                amp=amp_val,
                q_factor=q_val,
                freq_err=freq_err,
                amp_err=amp_err,
                q_err=q_err,
            )
        )

    background = {
        "slope": float(result.params["slope"].value),
        "intercept": float(result.params["intercept"].value),
    }

    # Degrees of freedom = n_data - n_params
    n_params = 3 * n_modes + 2  # 3 per mode (f, a, q) + slope + intercept
    dof = len(freqs) - n_params

    # Reduced chi-squared normalized by data variance
    # This gives values near 1.0 for a good fit
    chi_squared = None
    if dof > 0 and result.residual is not None:
        data_variance = float(np.var(psd)) if np.var(psd) > 0 else 1.0
        chi_squared = float(np.sum(result.residual**2) / (dof * data_variance))

    return LorentzianFitResult(
        modes=modes,
        background=background,
        chi_squared=chi_squared,
        degrees_of_freedom=dof,
        converged=converged,
    )


def _fit_background_only(
    psd: np.ndarray, freqs: np.ndarray, max_iterations: int
) -> LorentzianFitResult:
    """Fit a linear background model when no peaks are provided.

    Args:
        psd: Power spectral density values.
        freqs: Corresponding frequency array (Hz).
        max_iterations: Maximum iterations for the fit.

    Returns:
        LorentzianFitResult with empty modes list and fitted background.
    """
    params = Parameters()
    params.add("slope", value=0.0)
    params.add("intercept", value=float(np.median(psd)))

    def bg_residuals(params: Parameters, f: np.ndarray, data: np.ndarray) -> np.ndarray:
        model = float(params["slope"]) * f + float(params["intercept"])
        return data - model

    try:
        result = minimize(
            bg_residuals,
            params,
            args=(freqs, psd),
            method="leastsq",
            max_nfev=max_iterations,
        )
        background = {
            "slope": float(result.params["slope"].value),
            "intercept": float(result.params["intercept"].value),
        }
        converged = result.success
    except Exception:
        background = {"slope": 0.0, "intercept": float(np.median(psd))}
        converged = False

    dof = len(freqs) - 2  # 2 background params

    return LorentzianFitResult(
        modes=[],
        background=background,
        chi_squared=None,
        degrees_of_freedom=dof,
        converged=converged,
    )


def _make_failed_result(n_modes: int, peaks: list, n_freqs: int) -> LorentzianFitResult:
    """Construct an unconverged result when the fit fails entirely.

    Uses the initial peak values as-is with None uncertainties.

    Args:
        n_modes: Number of modes attempted.
        peaks: Initial peak list (dicts with 'freq', 'amp').
        n_freqs: Length of the frequency array.

    Returns:
        LorentzianFitResult with converged=False.
    """
    modes = [
        LorentzianMode(
            freq=peak["freq"],
            amp=peak["amp"],
            q_factor=4.0,
            freq_err=None,
            amp_err=None,
            q_err=None,
        )
        for peak in peaks[:n_modes]
    ]

    n_params = 3 * n_modes + 2
    dof = n_freqs - n_params

    return LorentzianFitResult(
        modes=modes,
        background={"slope": 0.0, "intercept": 0.0},
        chi_squared=None,
        degrees_of_freedom=dof,
        converged=False,
    )
