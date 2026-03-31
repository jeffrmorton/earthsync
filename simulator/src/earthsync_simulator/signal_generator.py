"""Time-domain Schumann Resonance signal synthesis.

All public functions are pure (no side effects) and accept an optional
``numpy.random.Generator`` for reproducibility.
"""

from __future__ import annotations

import math
from typing import TYPE_CHECKING, Any

import numpy as np

if TYPE_CHECKING:
    from earthsync_simulator.profiles import StationProfile

# Canonical Schumann Resonance mode centre frequencies (Hz).
SCHUMANN_FREQUENCIES: tuple[float, ...] = (7.83, 14.3, 20.8, 27.3, 33.8, 39.0, 45.0, 51.0)


# ---------------------------------------------------------------------------
# Biquad bandpass filter
# ---------------------------------------------------------------------------


def biquad_bandpass_coeffs(
    center_freq: float,
    q: float,
    sample_rate: float,
) -> tuple[float, float, float, float, float, float]:
    """Compute biquad bandpass filter coefficients.

    Returns ``(b0, b1, b2, a0, a1, a2)`` using the standard IIR biquad
    bandpass design (constant-0-dB-peak-gain variant).
    """
    w0 = 2.0 * math.pi * center_freq / sample_rate
    sin_w0 = math.sin(w0)
    cos_w0 = math.cos(w0)
    alpha = sin_w0 / (2.0 * q)

    b0 = alpha
    b1 = 0.0
    b2 = -alpha
    a0 = 1.0 + alpha
    a1 = -2.0 * cos_w0
    a2 = 1.0 - alpha

    return (b0, b1, b2, a0, a1, a2)


def apply_biquad(
    samples: np.ndarray,
    coeffs: tuple[float, float, float, float, float, float],
    state: tuple[float, float, float, float] | None = None,
) -> tuple[np.ndarray, tuple[float, float, float, float]]:
    """Apply a biquad filter described by *coeffs* to *samples*.

    *state* is ``(x1, x2, y1, y2)`` — the two previous input and output
    values.  Pass ``None`` for zero-initialised state.

    Returns ``(filtered, new_state)``.
    """
    b0, b1, b2, a0, a1, a2 = coeffs
    # Normalise by a0
    b0 /= a0
    b1 /= a0
    b2 /= a0
    a1 /= a0
    a2 /= a0

    if state is None:
        x1 = x2 = y1 = y2 = 0.0
    else:
        x1, x2, y1, y2 = state

    out = np.empty_like(samples, dtype=np.float64)
    for i in range(len(samples)):
        x0 = float(samples[i])
        y0 = b0 * x0 + b1 * x1 + b2 * x2 - a1 * y1 - a2 * y2
        out[i] = y0
        x2, x1 = x1, x0
        y2, y1 = y1, y0

    return out, (x1, x2, y1, y2)


# ---------------------------------------------------------------------------
# Noise generators
# ---------------------------------------------------------------------------


def generate_pink_noise(
    n: int,
    rng: np.random.Generator | None = None,
) -> np.ndarray:
    """Generate *n* samples of pink (1/f) noise via Voss-McCartney.

    Uses 16 rows of random values updated at staggered intervals to
    approximate a -10 dB/decade spectral slope.
    """
    if rng is None:
        rng = np.random.default_rng()

    num_rows = 16
    # Running sum of each row
    rows = rng.standard_normal(num_rows)
    running_sum = float(np.sum(rows))

    out = np.empty(n, dtype=np.float64)
    max_key = (1 << num_rows) - 1

    for i in range(n):
        # Determine which row to update via trailing-zero count
        idx = i & max_key
        if idx == 0:  # noqa: SIM108
            # Update row 0 (always)
            row_idx = 0
        else:
            # Trailing zeros of idx give the row to update
            row_idx = int(np.log2(idx & -idx)) % num_rows
        running_sum -= float(rows[row_idx])
        rows[row_idx] = rng.standard_normal()
        running_sum += float(rows[row_idx])
        out[i] = running_sum + rng.standard_normal()

    # Normalise to unit variance
    std = out.std()
    if std > 0:
        out /= std
    return out


# ---------------------------------------------------------------------------
# Main signal generator
# ---------------------------------------------------------------------------


def generate_sr_time_domain(  # noqa: PLR0915
    profile: StationProfile,
    segment_duration_s: float,
    diurnal_phase: float = 0.0,
    rng: np.random.Generator | None = None,
) -> dict[str, Any]:
    """Synthesise a time-domain Schumann Resonance signal.

    Parameters
    ----------
    profile:
        Observatory station profile.
    segment_duration_s:
        Length of the segment in seconds.
    diurnal_phase:
        Fraction of the 24-h day (0.0 -- 1.0) used for diurnal amplitude
        modulation.
    rng:
        Optional random generator for reproducibility.

    Returns
    -------
    dict
        ``samples`` (numpy 1-D array), ``sample_rate_hz``, ``segment_duration_s``,
        and ``metadata`` sub-dict.
    """
    if rng is None:
        rng = np.random.default_rng()

    sr = profile.sample_rate_hz
    n_samples = int(sr * segment_duration_s)
    t = np.arange(n_samples) / sr

    # Diurnal amplitude modulation factor
    diurnal_factor = 1.0 + 0.4 * math.sin(2.0 * math.pi * diurnal_phase)

    # Q-burst injection: 0.5 % probability per call
    inject_qburst = rng.random() < 0.005
    qburst_decay_time = float(rng.uniform(0.1, 0.5)) if inject_qburst else 0.0
    qburst_start_sample = int(rng.integers(0, max(1, n_samples // 2))) if inject_qburst else 0

    signal = np.zeros(n_samples, dtype=np.float64)
    metadata_modes: list[dict[str, Any]] = []

    # Diurnal Q-factor modulation
    q_modulation = 1.0 + profile.q_modulation_depth * math.sin(2 * math.pi * diurnal_phase)

    # Correlated mode amplitudes
    amps = np.array(
        [
            profile.amplitudes[i] if i < len(profile.amplitudes) else 50.0
            for i in range(len(SCHUMANN_FREQUENCIES))
        ]
    )
    if profile.mode_correlation > 0:
        # Build covariance matrix with inter-mode correlation
        std_devs = amps * 0.1  # 10% standard deviation
        corr_matrix = profile.mode_correlation * np.ones((len(amps), len(amps))) + (
            1 - profile.mode_correlation
        ) * np.eye(len(amps))
        cov_matrix = np.outer(std_devs, std_devs) * corr_matrix
        amp_draw = rng.multivariate_normal(amps, cov_matrix)
        amp_draw = np.maximum(amp_draw, amps * 0.5)  # Floor at 50% of nominal
    else:
        amp_draw = amps

    for mode_idx, freq in enumerate(SCHUMANN_FREQUENCIES):
        if freq >= sr / 2.0:
            # Skip modes above Nyquist
            continue

        amp = float(amp_draw[mode_idx])
        q = profile.q_factors[mode_idx] if mode_idx < len(profile.q_factors) else 4.0

        # Apply diurnal Q modulation
        q_effective = q * q_modulation

        # Scale amplitude to a reasonable signal level (normalise to 0-1 range)
        amp_scaled = amp / 100.0

        # --- Deterministic component: 30 % ---
        phase_offset = float(rng.uniform(0, 2 * math.pi))
        deterministic = 0.3 * amp_scaled * np.sin(2.0 * math.pi * freq * t + phase_offset)

        # --- Stochastic component: 70 % ---
        white = rng.standard_normal(n_samples)
        coeffs = biquad_bandpass_coeffs(freq, q_effective, sr)
        filtered, _ = apply_biquad(white, coeffs)
        # Normalise filtered noise to unit variance then scale
        filt_std = filtered.std()
        if filt_std > 0:
            filtered /= filt_std
        stochastic = 0.7 * amp_scaled * filtered

        mode_signal = (deterministic + stochastic) * diurnal_factor

        # Harmonic injection: add 2nd harmonic if below Nyquist
        if profile.harmonic_amplitude > 0 and 2 * freq < sr / 2:
            harmonic_coeffs = biquad_bandpass_coeffs(2 * freq, q_effective * 0.8, sr)
            harmonic_noise = rng.standard_normal(n_samples)
            harmonic_filtered, _ = apply_biquad(harmonic_noise, harmonic_coeffs)
            signal += profile.harmonic_amplitude * amp_scaled * diurnal_factor * harmonic_filtered

        # Q-burst injection on modes 0 and 1 (damped oscillation)
        if inject_qburst and mode_idx in (0, 1):
            qburst_amp = 10.0 * amp_scaled * diurnal_factor
            burst_len = n_samples - qburst_start_sample
            if burst_len > 0:
                tau = float(rng.uniform(0.1, 0.5))
                burst_freq = freq
                burst_signal = (
                    qburst_amp
                    * np.exp(-np.arange(burst_len) / (tau * sr))
                    * np.sin(2 * np.pi * burst_freq * np.arange(burst_len) / sr)
                )
                mode_signal[qburst_start_sample:] += burst_signal

        signal += mode_signal
        metadata_modes.append(
            {
                "mode": mode_idx,
                "frequency_hz": freq,
                "amplitude": amp,
                "q_factor": q,
            }
        )

    # Pink noise floor
    pink = generate_pink_noise(n_samples, rng=rng)
    signal += profile.pink_noise_level * pink

    # White noise floor
    signal += profile.white_noise_level * rng.standard_normal(n_samples)

    # Mains harmonic contamination
    for h in range(1, profile.mains_harmonics + 1):
        mains_freq_h = profile.mains_freq_hz * h
        if mains_freq_h < sr / 2:
            mains_amp = profile.mains_amplitude / h  # Decreasing amplitude per harmonic
            signal += mains_amp * np.sin(2 * np.pi * mains_freq_h * t)

    return {
        "samples": signal,
        "sample_rate_hz": sr,
        "segment_duration_s": segment_duration_s,
        "metadata": {
            "modes": metadata_modes,
            "diurnal_phase": diurnal_phase,
            "diurnal_factor": diurnal_factor,
            "qburst_injected": inject_qburst,
            "qburst_decay_time_s": qburst_decay_time,
            "profile_model": profile.model,
        },
    }
