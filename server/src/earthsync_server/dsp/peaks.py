"""Peak detection for Schumann Resonance spectra.

Detects spectral peaks using scipy.signal.find_peaks with prominence-based
filtering, minimum frequency spacing, and sub-bin accuracy via parabolic
interpolation.
"""

from __future__ import annotations

import numpy as np
from scipy.signal import find_peaks

from earthsync_server.constants import SCHUMANN_MODE_RANGES
from earthsync_server.models import DetectedPeak


def smooth_spectrum(psd: np.ndarray, window_size: int = 5) -> np.ndarray:
    """Apply Hann window convolution for smoothing.

    Args:
        psd: Power spectral density array.
        window_size: Size of the Hann smoothing window. Must be >= 1.

    Returns:
        Smoothed PSD array of the same length as input.
    """
    window_size = max(window_size, 1)

    if window_size >= len(psd) or window_size == 1:
        return psd.copy()

    window = np.hanning(window_size)
    window = window / window.sum()

    return np.convolve(psd, window, mode="same")


def parabolic_interpolation(psd: np.ndarray, peak_idx: int) -> tuple[float, float]:
    """3-point parabolic interpolation around a peak index.

    Fits a parabola through the peak and its two neighbors to find the
    true peak location with sub-bin accuracy.

    Args:
        psd: Power spectral density array.
        peak_idx: Index of the detected peak bin.

    Returns:
        Tuple of (interpolated_index, interpolated_amplitude).
    """
    if peak_idx <= 0 or peak_idx >= len(psd) - 1:
        return (float(peak_idx), float(psd[peak_idx]))

    alpha = float(psd[peak_idx - 1])
    beta = float(psd[peak_idx])
    gamma = float(psd[peak_idx + 1])

    denominator = alpha - 2.0 * beta + gamma
    if abs(denominator) < 1e-15:
        return (float(peak_idx), beta)

    p = 0.5 * (alpha - gamma) / denominator
    interpolated_idx = float(peak_idx) + p
    interpolated_amp = beta - 0.25 * (alpha - gamma) * p

    return (interpolated_idx, interpolated_amp)


def compute_fwhm(psd: np.ndarray, freqs: np.ndarray, peak_idx: int) -> float | None:
    """Find full width at half maximum of a spectral peak.

    Locates the half-maximum points on both sides of the peak using
    linear interpolation between bins.

    Args:
        psd: Power spectral density array.
        freqs: Corresponding frequency array (Hz).
        peak_idx: Index of the peak bin.

    Returns:
        FWHM in Hz, or None if half-max crossing not found on both sides.
    """
    if len(psd) < 3 or peak_idx < 0 or peak_idx >= len(psd):
        return None

    half_max = float(psd[peak_idx]) / 2.0

    # Search left
    left_freq = None
    for i in range(peak_idx, 0, -1):
        if psd[i - 1] <= half_max:
            # Linear interpolation between bins i-1 and i
            frac = (half_max - psd[i - 1]) / (psd[i] - psd[i - 1]) if psd[i] != psd[i - 1] else 0.0
            left_freq = freqs[i - 1] + frac * (freqs[i] - freqs[i - 1])
            break

    # Search right
    right_freq = None
    for i in range(peak_idx, len(psd) - 1):
        if psd[i + 1] <= half_max:
            frac = (half_max - psd[i + 1]) / (psd[i] - psd[i + 1]) if psd[i] != psd[i + 1] else 0.0
            right_freq = freqs[i + 1] - frac * (freqs[i + 1] - freqs[i])
            break

    if left_freq is None or right_freq is None:
        return None

    fwhm = right_freq - left_freq
    if fwhm <= 0.0:
        return None

    # Cap minimum FWHM to 2x frequency resolution to avoid unrealistically
    # high Q-factors (Q > 50) on narrow simulator peaks.  Real Schumann
    # Resonance modes have Q = 3-10 (Sentman 1995).
    freq_resolution = float(freqs[1] - freqs[0]) if len(freqs) > 1 else 1.0
    min_fwhm = freq_resolution * 2.0
    return max(fwhm, min_fwhm)


def filter_to_sr_bands(
    peaks: list[DetectedPeak],
    mode_ranges: dict[str, dict[str, float]] | None = None,
) -> list[DetectedPeak]:
    """Keep only the strongest peak per SR frequency band.

    For each of the 8 canonical Schumann Resonance mode bands,
    selects the highest-amplitude peak. Peaks outside all bands
    are discarded.

    Args:
        peaks: Detected peaks to filter.
        mode_ranges: Frequency band definitions. Defaults to SCHUMANN_MODE_RANGES.

    Returns:
        Filtered list with at most one peak per SR mode band.
    """
    if mode_ranges is None:
        mode_ranges = SCHUMANN_MODE_RANGES
    filtered = []
    for band_range in mode_ranges.values():
        candidates = [p for p in peaks if band_range["min"] <= p.freq <= band_range["max"]]
        if candidates:
            filtered.append(max(candidates, key=lambda p: p.amp))
    return filtered


def detect_peaks(  # noqa: PLR0913
    psd: np.ndarray,
    freqs: np.ndarray,
    smoothing_window: int = 5,
    prominence_factor: float = 1.5,
    min_distance_hz: float = 1.0,
    absolute_threshold: float = 0.0,
    sr_band_filtering: bool = True,
) -> list[DetectedPeak]:
    """Detect spectral peaks in a Schumann Resonance PSD.

    Smooths the PSD, finds peaks using scipy prominence-based detection,
    applies parabolic interpolation for sub-bin accuracy, and computes
    Q-factors from FWHM estimates.

    Args:
        psd: Power spectral density array.
        freqs: Corresponding frequency array (Hz).
        smoothing_window: Hann smoothing window size.
        prominence_factor: Prominence threshold as a multiple of std(smoothed).
        min_distance_hz: Minimum distance between peaks in Hz.
        absolute_threshold: Minimum peak amplitude to accept.
        sr_band_filtering: If True, keep only the strongest peak per SR band.

    Returns:
        List of DetectedPeak objects sorted by frequency.
    """
    if len(psd) == 0 or len(freqs) == 0:
        return []

    if len(psd) < 3:
        return []

    smoothed = smooth_spectrum(psd, smoothing_window)

    freq_resolution = float(freqs[1] - freqs[0]) if len(freqs) > 1 else 1.0
    min_distance_bins = max(1, int(min_distance_hz / freq_resolution))

    prominence = prominence_factor * np.std(smoothed)

    peak_indices, _ = find_peaks(
        smoothed,
        prominence=prominence,
        distance=min_distance_bins,
    )

    results: list[DetectedPeak] = []
    for idx in peak_indices:
        interp_idx, interp_amp = parabolic_interpolation(smoothed, int(idx))

        if interp_amp < absolute_threshold:
            continue

        # Convert interpolated index to frequency
        interp_freq = float(freqs[0]) + interp_idx * freq_resolution

        # Compute Q-factor from FWHM
        fwhm = compute_fwhm(smoothed, freqs, int(idx))
        q_factor: float | None = None
        if fwhm is not None and fwhm > 0.0:
            q_factor = interp_freq / fwhm

        results.append(
            DetectedPeak(
                freq=interp_freq,
                amp=interp_amp,
                q_factor=q_factor,
            )
        )

    results.sort(key=lambda p: p.freq)

    if sr_band_filtering:
        results = filter_to_sr_bands(results)

    return results
