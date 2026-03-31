"""Cross-validation against known Schumann Resonance fundamentals.

Computes correlation between detected peak frequencies and the
known fundamental frequencies to assess measurement quality.

References:
    Schumann, W.O. (1952). "Uber die strahlungslosen Eigenschwingungen
    einer leitenden Kugel, die von einer Luftschicht und einer
    Ionospharenhuelle umgeben ist."
"""

from __future__ import annotations

import numpy as np

from earthsync_server.constants import SCHUMANN_FREQUENCIES


def pearson_correlation(a: np.ndarray, b: np.ndarray) -> float:
    """Compute the Pearson correlation coefficient between two arrays.

    Args:
        a: First array of values.
        b: Second array of values (same length as a).

    Returns:
        Pearson correlation coefficient in [-1, 1], or 0.0 for
        degenerate cases (length < 2 or constant arrays).
    """
    if len(a) < 2 or len(b) < 2:
        return 0.0

    if np.std(a) == 0.0 or np.std(b) == 0.0:
        return 0.0

    corr = np.corrcoef(a, b)[0, 1]

    # Handle NaN from corrcoef (e.g. all identical values)
    if np.isnan(corr):
        return 0.0

    return float(corr)


def compare_to_fundamentals(
    detected_peaks: list,
    expected_freqs: tuple[float, ...] = SCHUMANN_FREQUENCIES,
    tolerance_hz: float = 2.0,
) -> dict:
    """Compare detected peak frequencies against known SR fundamentals.

    For each expected frequency, finds the closest detected peak within
    the tolerance window. Computes match statistics and correlation
    between matched pairs.

    Args:
        detected_peaks: List of objects with a .freq attribute (e.g.
            DetectedPeak instances) or floats.
        expected_freqs: Tuple of expected fundamental frequencies (Hz).
        tolerance_hz: Maximum allowed offset to consider a match (Hz).

    Returns:
        Dictionary with keys:
            matched: Number of expected frequencies matched.
            total: Total number of expected frequencies.
            offsets: List of (detected - expected) offsets for matches.
            correlation: Pearson correlation of matched pairs.
            mean_offset: Mean absolute offset of matched pairs.
    """
    # Extract frequencies from peak objects or treat as floats
    peak_freqs: list[float] = []
    for p in detected_peaks:
        if hasattr(p, "freq"):
            peak_freqs.append(float(p.freq))
        else:
            peak_freqs.append(float(p))

    matched_detected: list[float] = []
    matched_expected: list[float] = []
    offsets: list[float] = []

    for ef in expected_freqs:
        if not peak_freqs:
            continue

        # Find closest detected peak
        distances = [abs(pf - ef) for pf in peak_freqs]
        min_idx = int(np.argmin(distances))
        min_dist = distances[min_idx]

        if min_dist <= tolerance_hz:
            matched_detected.append(peak_freqs[min_idx])
            matched_expected.append(ef)
            offsets.append(peak_freqs[min_idx] - ef)

    matched_count = len(offsets)
    total = len(expected_freqs)

    correlation = pearson_correlation(
        np.array(matched_detected),
        np.array(matched_expected),
    )

    mean_offset = float(np.mean(np.abs(offsets))) if offsets else 0.0

    return {
        "matched": matched_count,
        "total": total,
        "offsets": offsets,
        "correlation": correlation,
        "mean_offset": mean_offset,
    }
