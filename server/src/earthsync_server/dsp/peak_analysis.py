"""Peak analysis -- SNR computation, noise floor estimation, uncertainties.

All functions are pure with no side effects.

References:
    Noise floor estimation uses MAD (Median Absolute Deviation) which is
    robust to outliers. MAD * 1.4826 ~ sigma for Gaussian distributions.
"""

from __future__ import annotations

import math

import numpy as np

from earthsync_server.constants import MAD_TO_SIGMA, SCHUMANN_FREQUENCIES
from earthsync_server.models import DetectedPeak, NoiseFloor


def compute_snr(  # noqa: PLR0913
    peak_freq: float,
    peak_amp: float,
    psd: np.ndarray,
    freqs: np.ndarray,
    noise_halfwidth_hz: float = 2.0,
    exclusion_halfwidth_hz: float = 0.3,
) -> float:
    """Compute signal-to-noise ratio for a single peak.

    Defines an annular noise region around the peak frequency, excluding
    the immediate peak vicinity, and computes SNR in decibels.

    Args:
        peak_freq: Frequency of the peak (Hz).
        peak_amp: Amplitude of the peak.
        psd: Power spectral density array.
        freqs: Corresponding frequency array (Hz).
        noise_halfwidth_hz: Half-width of the noise estimation window (Hz).
        exclusion_halfwidth_hz: Half-width of the peak exclusion zone (Hz).

    Returns:
        SNR in decibels (dB). Returns 0.0 if noise level is non-positive
        or annular region is empty.
    """
    noise_mask = (freqs >= peak_freq - noise_halfwidth_hz) & (
        freqs <= peak_freq + noise_halfwidth_hz
    )
    exclusion_mask = (freqs >= peak_freq - exclusion_halfwidth_hz) & (
        freqs <= peak_freq + exclusion_halfwidth_hz
    )
    annular_mask = noise_mask & ~exclusion_mask

    annular_values = psd[annular_mask]

    if len(annular_values) == 0:
        return 0.0

    noise_level = float(np.median(annular_values))

    if noise_level <= 0.0:
        return 0.0

    if peak_amp <= 0.0:
        return 0.0

    return 10.0 * math.log10(peak_amp / noise_level)


def estimate_noise_floor(
    psd: np.ndarray,
    freqs: np.ndarray,
    exclusion_freqs: tuple[float, ...] = SCHUMANN_FREQUENCIES,
    exclusion_halfwidth_hz: float = 1.5,
) -> NoiseFloor:
    """Estimate the noise floor of a PSD using MAD-based robust statistics.

    Excludes bins near known Schumann Resonance frequencies to avoid
    biasing the noise estimate with signal content.

    Args:
        psd: Power spectral density array.
        freqs: Corresponding frequency array (Hz).
        exclusion_freqs: Frequencies to exclude from noise estimate.
        exclusion_halfwidth_hz: Half-width of exclusion zones (Hz).

    Returns:
        NoiseFloor with median and MAD-scaled standard deviation.
    """
    mask = np.ones(len(freqs), dtype=bool)

    for ef in exclusion_freqs:
        mask &= ~((freqs >= ef - exclusion_halfwidth_hz) & (freqs <= ef + exclusion_halfwidth_hz))

    noise_bins = psd[mask]

    if len(noise_bins) == 0:
        return NoiseFloor(median=0.0, std=0.0)

    median_val = float(np.median(noise_bins))
    mad = float(np.median(np.abs(noise_bins - median_val)))
    std_val = mad * MAD_TO_SIGMA

    return NoiseFloor(median=median_val, std=std_val)


def compute_uncertainties(
    peak: DetectedPeak,
    spectral_variances: np.ndarray | None,
    freq_resolution_hz: float,
) -> DetectedPeak:
    """Compute frequency and amplitude uncertainties for a detected peak.

    Uses spectral variance at the peak bin to estimate errors via
    parabolic interpolation error propagation.

    Args:
        peak: The detected peak to augment with uncertainties.
        spectral_variances: Variance array matching PSD bins, or None.
        freq_resolution_hz: Frequency resolution of the PSD (Hz).

    Returns:
        New DetectedPeak with freq_err and amp_err filled in, or
        the original peak unchanged if spectral_variances is None.
    """
    if spectral_variances is None:
        return peak

    if freq_resolution_hz <= 0.0:
        return peak

    # Find the nearest bin to the peak frequency
    peak_bin = round(peak.freq / freq_resolution_hz)
    peak_bin = max(0, min(peak_bin, len(spectral_variances) - 1))

    variance_at_peak = float(spectral_variances[peak_bin])

    if variance_at_peak <= 0.0:
        return peak

    amp_err = math.sqrt(variance_at_peak)

    # Frequency uncertainty from parabolic interpolation error propagation:
    # delta_f ~ freq_resolution * sqrt(variance) / peak_amplitude
    freq_err = freq_resolution_hz * amp_err / peak.amp if peak.amp > 0.0 else 0.0

    return DetectedPeak(
        freq=peak.freq,
        amp=peak.amp,
        q_factor=peak.q_factor,
        freq_err=freq_err,
        amp_err=amp_err,
        q_err=peak.q_err,
        snr=peak.snr,
    )
