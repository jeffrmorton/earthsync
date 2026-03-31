"""Welch Power Spectral Density estimation.

Computes one-sided PSD using scipy.signal.welch with Hann windowing,
and resamples to a fixed display grid for frontend visualization.

References:
    Welch, P.D. (1967). "The use of fast Fourier transform for the
    estimation of power spectra." IEEE Trans. Audio Electroacoustics.

    Sierra Nevada SR observatory uses Welch PSD with Hann windows
    as the standard spectral estimation method.
"""

from dataclasses import dataclass

import numpy as np
from scipy.signal import welch
from scipy.signal.windows import dpss


@dataclass
class WelchPSDResult:
    """Result container for Welch PSD estimation.

    Attributes:
        psd: One-sided power spectral density array (V^2/Hz).
        freqs: Corresponding frequency bin centers (Hz).
        nfft: Number of FFT points used (equals nperseg).
        frequency_resolution_hz: Spacing between frequency bins (Hz).
        nyquist_hz: Nyquist frequency, sample_rate_hz / 2.
    """

    psd: np.ndarray
    freqs: np.ndarray
    nfft: int
    frequency_resolution_hz: float
    nyquist_hz: float


def compute_welch_psd(samples: np.ndarray, sample_rate_hz: int) -> WelchPSDResult:
    """Compute one-sided Welch PSD with Hann windowing.

    Uses the full sample array as a single segment (nperseg = len(samples))
    with no overlap, which gives the highest frequency resolution possible
    for the given data length.

    Args:
        samples: Time-domain signal array. Must not be empty.
        sample_rate_hz: Sampling frequency in Hz. Must be > 0.

    Returns:
        WelchPSDResult with PSD, frequencies, and metadata.

    Raises:
        ValueError: If samples is empty or sample_rate_hz <= 0.
    """
    if len(samples) == 0:
        msg = "samples array must not be empty"
        raise ValueError(msg)
    if sample_rate_hz <= 0:
        msg = f"sample_rate_hz must be positive, got {sample_rate_hz}"
        raise ValueError(msg)

    nperseg = len(samples)

    freqs, psd = welch(
        samples,
        fs=sample_rate_hz,
        window="hann",
        nperseg=nperseg,
        noverlap=0,
        scaling="density",
    )

    nfft = nperseg
    frequency_resolution_hz = sample_rate_hz / nfft
    nyquist_hz = sample_rate_hz / 2.0

    return WelchPSDResult(
        psd=psd,
        freqs=freqs,
        nfft=nfft,
        frequency_resolution_hz=frequency_resolution_hz,
        nyquist_hz=nyquist_hz,
    )


def compute_multitaper_psd(
    samples: np.ndarray,
    sample_rate_hz: int,
    nw: float = 3.0,
    n_tapers: int = 5,
) -> WelchPSDResult:
    """Multitaper PSD using DPSS (Slepian) tapers.

    Provides lower spectral leakage and variance compared to single-window
    Welch estimation. Standard for precision spectral analysis.

    References:
        Thomson, D.J. (1982). "Spectrum estimation and harmonic analysis."
        Proceedings of the IEEE, 70(9), 1055-1096.

    Args:
        samples: Time-domain signal array.
        sample_rate_hz: Sampling frequency in Hz.
        nw: Time-bandwidth product (controls frequency resolution vs. leakage).
        n_tapers: Number of DPSS tapers to use (typically 2*nw - 1).

    Returns:
        WelchPSDResult with multitaper PSD estimate.

    Raises:
        ValueError: If samples is empty or sample_rate_hz <= 0.
    """
    if len(samples) == 0:
        raise ValueError("samples must not be empty")
    if sample_rate_hz <= 0:
        raise ValueError("sample_rate_hz must be positive")

    n = len(samples)
    # Clamp NW: dpss requires NW < n/2
    effective_nw = min(nw, max((n - 1) / 2.0, 0.5))
    # Clamp n_tapers: Kmax must be > 0 and < n for dpss
    effective_tapers = min(n_tapers, max(n - 1, 1))
    tapers, eigenvalues = dpss(n, NW=effective_nw, Kmax=effective_tapers, return_ratios=True)

    # Handle single-taper case: dpss returns 1-D arrays when Kmax=1
    if effective_tapers == 1:
        tapers = tapers.reshape(1, n)
        eigenvalues = np.atleast_1d(eigenvalues)

    freqs = np.fft.rfftfreq(n, d=1.0 / sample_rate_hz)
    psd_sum = np.zeros(len(freqs))

    for taper, weight in zip(tapers, eigenvalues, strict=True):
        windowed = samples * taper
        fft_vals = np.fft.rfft(windowed)
        psd_sum += weight * np.abs(fft_vals) ** 2

    psd = psd_sum / (sample_rate_hz * eigenvalues.sum())
    # One-sided scaling (double non-DC, non-Nyquist bins)
    if len(psd) > 2:
        psd[1:-1] *= 2

    return WelchPSDResult(
        psd=psd,
        freqs=freqs,
        nfft=n,
        frequency_resolution_hz=sample_rate_hz / n,
        nyquist_hz=sample_rate_hz / 2.0,
    )


def resample_to_display_grid(
    psd: np.ndarray,
    freqs: np.ndarray,
    n_points: int = 1101,
    max_hz: float = 55.0,
) -> np.ndarray:
    """Resample PSD to a uniform frequency grid for frontend display.

    Creates a linearly-spaced frequency grid from 0 to max_hz and
    interpolates the native PSD onto it. Frequencies beyond the native
    range are filled with zeros (no extrapolation of spectral content).

    Args:
        psd: Power spectral density values from Welch estimation.
        freqs: Corresponding frequency bin centers (Hz).
        n_points: Number of points in the output grid. Default 1101.
        max_hz: Maximum frequency of the display grid (Hz). Default 55.0.

    Returns:
        Numpy array of length n_points with interpolated PSD values.
    """
    display_freqs = np.linspace(0.0, max_hz, n_points)

    # Determine the native frequency coverage
    native_max = freqs[-1] if len(freqs) > 0 else 0.0

    # Interpolate within native range, zero-fill beyond
    if native_max <= 0.0:
        return np.zeros(n_points)

    return np.interp(display_freqs, freqs, psd, left=0.0, right=0.0)
