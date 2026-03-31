"""Time-domain and spectral quality validation.

Validates incoming time-domain samples for common acquisition errors
(clipping, flatline, NaN/Inf) and detects Q-burst transients.
Also validates computed PSD for mains contamination.

References:
    Q-burst detection: amplitude >10x background, with sliding-window
    RMS exceeding threshold x running median (Nickolaenko & Hayakawa, 2002).
"""

from __future__ import annotations

import numpy as np

from earthsync_server.models import QBurstResult, TimeDomainQuality


def validate_time_domain(
    samples: np.ndarray,
    sample_rate_hz: int,
    segment_duration_s: float,
) -> TimeDomainQuality:
    """Validate time-domain samples for common acquisition errors.

    Checks for length mismatches, NaN/Inf values, flatline signals,
    clipping, and saturation. Returns a quality assessment with flags
    indicating any issues found.

    Args:
        samples: Raw time-domain signal array.
        sample_rate_hz: Sampling frequency in Hz.
        segment_duration_s: Expected segment duration in seconds.

    Returns:
        TimeDomainQuality with is_usable flag and list of issue flags.
    """
    flags: list[str] = []
    n = len(samples)
    expected = sample_rate_hz * segment_duration_s

    # Length check
    if abs(n - expected) > 2:
        flags.append("length_mismatch")

    if n == 0:
        return TimeDomainQuality(is_usable=False, flags=flags)

    nan_mask = np.isnan(samples)
    inf_mask = np.isinf(samples)

    # NaN check
    if np.any(nan_mask):
        flags.append("contains_nan")

    # Inf check
    if np.any(inf_mask):
        flags.append("contains_infinity")

    # Excessive invalid (>1% NaN+Inf)
    invalid_count = int(np.sum(nan_mask) + np.sum(inf_mask))
    if invalid_count / n > 0.01:
        flags.append("excessive_invalid")

    # For flatline and clipping checks, work only with finite values
    finite_samples = samples[np.isfinite(samples)]

    # Flatline check
    is_flatline = False
    if len(finite_samples) > 0 and np.std(finite_samples) < 1e-10:
        flags.append("flatline")
        is_flatline = True

    # Clipping and saturation checks
    is_saturated = False
    if len(finite_samples) > 1:
        smin = float(np.min(finite_samples))
        smax = float(np.max(finite_samples))
        value_range = smax - smin

        if value_range > 0:
            margin = 0.005 * value_range
            low_threshold = smin + margin
            high_threshold = smax - margin
            clipped = int(
                np.sum(finite_samples <= low_threshold) + np.sum(finite_samples >= high_threshold)
            )
            clipped_fraction = clipped / n

            if clipped_fraction > 0.01:
                flags.append("clipping")

            if clipped_fraction > 0.10:
                flags.append("saturated")
                is_saturated = True

    is_usable = not (is_flatline or is_saturated or "excessive_invalid" in flags)

    return TimeDomainQuality(is_usable=is_usable, flags=flags)


def validate_spectrum(
    psd: np.ndarray,
    freqs: np.ndarray,
    mains_freqs: list[float] | None = None,
    mains_ratio_threshold: float = 10.0,
) -> list[str]:
    """Validate a computed PSD for mains contamination and dead channels.

    Args:
        psd: Power spectral density array.
        freqs: Corresponding frequency bin centers (Hz).
        mains_freqs: Frequencies to check for mains contamination.
            Defaults to [50.0, 60.0].
        mains_ratio_threshold: Ratio of mains energy to median PSD
            above which contamination is flagged.

    Returns:
        List of flag strings indicating quality issues.
    """
    flags: list[str] = []

    if mains_freqs is None:
        mains_freqs = [50.0, 60.0]

    # Dead channel check
    if np.all(psd == 0):
        flags.append("dead_channel")
        return flags

    median_psd = float(np.median(psd))

    for mf in mains_freqs:
        # Find the closest frequency bin to the mains frequency
        if len(freqs) == 0:
            continue
        idx = int(np.argmin(np.abs(freqs - mf)))
        if median_psd > 0 and psd[idx] > mains_ratio_threshold * median_psd:
            flags.append("mains_contamination")
            break

    return flags


def detect_qburst(
    samples: np.ndarray,
    sample_rate_hz: int,
    threshold: float = 10.0,
) -> QBurstResult:
    """Detect Q-burst transients in time-domain signal.

    Divides the signal into 50ms windows and compares each window's
    RMS to the median RMS across all windows. A Q-burst is detected
    when any window's RMS exceeds threshold times the median.

    Args:
        samples: Raw time-domain signal array.
        sample_rate_hz: Sampling frequency in Hz.
        threshold: RMS ratio above median to trigger detection.

    Returns:
        QBurstResult indicating whether a Q-burst was detected,
        with peak amplitude and duration if so.
    """
    window_size = int(sample_rate_hz * 0.05)

    if window_size == 0:
        return QBurstResult(detected=False)

    n_windows = len(samples) // window_size

    if n_windows < 3:
        return QBurstResult(detected=False)

    # Compute RMS for each window
    rms_values = np.empty(n_windows)
    for i in range(n_windows):
        start = i * window_size
        end = start + window_size
        window = samples[start:end]
        rms_values[i] = float(np.sqrt(np.mean(window**2)))

    median_rms = float(np.median(rms_values))

    if median_rms == 0:
        return QBurstResult(detected=False)

    burst_mask = rms_values > threshold * median_rms
    burst_count = int(np.sum(burst_mask))

    if burst_count > 0:
        peak_amplitude = float(np.max(rms_values[burst_mask]))
        duration_ms = float(burst_count * 50)
        return QBurstResult(
            detected=True,
            peak_amplitude=peak_amplitude,
            duration_ms=duration_ms,
        )

    return QBurstResult(detected=False)
