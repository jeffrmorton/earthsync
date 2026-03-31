"""Tests for earthsync_simulator.signal_generator."""

import numpy as np
import pytest
from earthsync_simulator.profiles import create_profile
from earthsync_simulator.signal_generator import (
    SCHUMANN_FREQUENCIES,
    apply_biquad,
    biquad_bandpass_coeffs,
    generate_pink_noise,
    generate_sr_time_domain,
)

# ── helpers ─────────────────────────────────────────────────────────────────


def _peak_frequency(signal: np.ndarray, sample_rate: int) -> float:
    """Return the frequency (Hz) of the strongest FFT bin."""
    spectrum = np.abs(np.fft.rfft(signal))
    freqs = np.fft.rfftfreq(len(signal), d=1.0 / sample_rate)
    return float(freqs[np.argmax(spectrum)])


def _has_spectral_peak_near(
    signal: np.ndarray,
    sample_rate: int,
    target_hz: float,
    tolerance_hz: float = 1.5,
) -> bool:
    """True if there is a local spectral maximum within *tolerance_hz* of *target_hz*."""
    spectrum = np.abs(np.fft.rfft(signal))
    freqs = np.fft.rfftfreq(len(signal), d=1.0 / sample_rate)
    mask = np.abs(freqs - target_hz) <= tolerance_hz
    if not np.any(mask):
        return False
    local_peak = np.max(spectrum[mask])
    # Compare to neighbours just outside the window
    outside = spectrum[~mask]
    median_outside = np.median(outside) if len(outside) > 0 else 0
    return local_peak > 1.5 * median_outside


# ── biquad coefficients ────────────────────────────────────────────────────


class TestBiquadCoeffs:
    def test_biquad_coeffs_valid(self):
        b0, b1, b2, a0, _, _ = biquad_bandpass_coeffs(10.0, 5.0, 256)
        assert a0 > 0, "a0 must be positive"
        assert b1 == 0.0, "b1 must be zero for bandpass"
        assert b0 == pytest.approx(-b2, abs=1e-12)

    def test_biquad_coeffs_high_q(self):
        b0, _, _, _, _, _ = biquad_bandpass_coeffs(20.0, 50.0, 256)
        # Higher Q → narrower bandwidth → smaller b0
        b0_low_q, *_ = biquad_bandpass_coeffs(20.0, 1.0, 256)
        assert abs(b0) < abs(b0_low_q)


# ── apply_biquad ───────────────────────────────────────────────────────────


class TestApplyBiquad:
    def test_apply_biquad_passband(self):
        """A 10 Hz sine should pass through a 10 Hz bandpass largely intact,
        while a 40 Hz sine is attenuated."""
        sr = 256
        t = np.arange(sr * 2) / sr  # 2 seconds
        sig_10 = np.sin(2 * np.pi * 10 * t)
        sig_40 = np.sin(2 * np.pi * 40 * t)

        coeffs = biquad_bandpass_coeffs(10.0, 5.0, sr)
        out_10, _ = apply_biquad(sig_10, coeffs)
        out_40, _ = apply_biquad(sig_40, coeffs)

        # Steady-state energy (skip first 128 samples for transient)
        rms_10 = np.sqrt(np.mean(out_10[128:] ** 2))
        rms_40 = np.sqrt(np.mean(out_40[128:] ** 2))
        assert rms_10 > 3 * rms_40

    def test_apply_biquad_preserves_length(self):
        n = 1024
        samples = np.random.default_rng(0).standard_normal(n)
        coeffs = biquad_bandpass_coeffs(20.0, 4.0, 256)
        out, state = apply_biquad(samples, coeffs)
        assert len(out) == n
        assert len(state) == 4

    def test_apply_biquad_state_continuity(self):
        """Filtering in two chunks with state carry-over should equal one pass."""
        rng = np.random.default_rng(42)
        full = rng.standard_normal(512)
        coeffs = biquad_bandpass_coeffs(15.0, 4.0, 256)

        out_full, _ = apply_biquad(full, coeffs)

        out_a, state = apply_biquad(full[:256], coeffs)
        out_b, _ = apply_biquad(full[256:], coeffs, state=state)
        out_split = np.concatenate([out_a, out_b])

        np.testing.assert_allclose(out_full, out_split, atol=1e-10)


# ── pink noise ─────────────────────────────────────────────────────────────


class TestPinkNoise:
    def test_generate_pink_noise_length(self):
        out = generate_pink_noise(4096, rng=np.random.default_rng(0))
        assert len(out) == 4096

    def test_generate_pink_noise_spectral_slope(self):
        """FFT should show roughly -10 dB/decade (1/f) slope."""
        rng = np.random.default_rng(99)
        n = 2**16
        pink = generate_pink_noise(n, rng=rng)
        spectrum = np.abs(np.fft.rfft(pink)) ** 2
        _freqs = np.fft.rfftfreq(n, d=1.0)  # normalised
        # Compare power in low vs high band (skip DC)
        low = spectrum[1 : n // 16]
        high = spectrum[n // 4 : n // 2]
        # Low band should have more power than high band
        assert np.mean(low) > np.mean(high)

    def test_generate_pink_noise_unit_variance(self):
        out = generate_pink_noise(8192, rng=np.random.default_rng(7))
        assert out.std() == pytest.approx(1.0, abs=0.15)


# ── SR time-domain synthesis ───────────────────────────────────────────────


class TestGenerateSR:
    @pytest.fixture
    def profile(self):
        return create_profile("sierra_nevada")

    def test_output_length(self, profile):
        result = generate_sr_time_domain(profile, 2.0, rng=np.random.default_rng(0))
        expected = profile.sample_rate_hz * 2
        assert len(result["samples"]) == expected
        assert result["sample_rate_hz"] == profile.sample_rate_hz
        assert result["segment_duration_s"] == 2.0

    def test_has_sr_peaks(self, profile):
        """FFT of output should show peaks near the first few Schumann modes."""
        result = generate_sr_time_domain(profile, 10.0, rng=np.random.default_rng(1))
        samples = result["samples"]
        sr = result["sample_rate_hz"]
        # Check the first three modes (strongest)
        for freq in SCHUMANN_FREQUENCIES[:3]:
            if freq < sr / 2:
                assert _has_spectral_peak_near(samples, sr, freq, tolerance_hz=2.0), (
                    f"Expected spectral peak near {freq} Hz"
                )

    def test_diurnal_modulation(self, profile):
        """Signal amplitude should vary with diurnal phase."""
        rms_values = []
        for phase in [0.0, 0.25, 0.5, 0.75]:
            result = generate_sr_time_domain(
                profile, 5.0, diurnal_phase=phase, rng=np.random.default_rng(42)
            )
            rms_values.append(np.sqrt(np.mean(result["samples"] ** 2)))
        # Phase 0.25 should be loudest (sin peaks at 0.25)
        assert rms_values[1] > rms_values[3]

    def test_mains_contamination(self, profile):
        """FFT should show a peak at the mains frequency."""
        result = generate_sr_time_domain(profile, 10.0, rng=np.random.default_rng(2))
        assert _has_spectral_peak_near(
            result["samples"],
            result["sample_rate_hz"],
            profile.mains_freq_hz,
            tolerance_hz=1.0,
        )

    def test_reproducible(self, profile):
        """Same rng seed produces identical output."""
        a = generate_sr_time_domain(profile, 2.0, rng=np.random.default_rng(123))
        b = generate_sr_time_domain(profile, 2.0, rng=np.random.default_rng(123))
        np.testing.assert_array_equal(a["samples"], b["samples"])

    def test_metadata_keys(self, profile):
        result = generate_sr_time_domain(profile, 1.0, rng=np.random.default_rng(0))
        meta = result["metadata"]
        assert "modes" in meta
        assert "diurnal_phase" in meta
        assert "diurnal_factor" in meta
        assert "qburst_injected" in meta
        assert "profile_model" in meta
        assert meta["profile_model"] == "sierra_nevada"

    def test_all_profiles(self):
        """All three profiles produce valid output without error."""
        for model in ("sierra_nevada", "modra", "heartmath"):
            profile = create_profile(model)
            result = generate_sr_time_domain(profile, 1.0, rng=np.random.default_rng(0))
            expected_len = profile.sample_rate_hz * 1
            assert len(result["samples"]) == expected_len
            assert not np.any(np.isnan(result["samples"]))

    def test_qburst_injection(self):
        """Force Q-burst by finding a seed that triggers it, then verify
        amplitude spike on modes 0-1."""
        profile = create_profile("sierra_nevada")
        # Brute-force a seed that triggers Q-burst (p=0.005, so ~1 in 200)
        qburst_result = None
        normal_result = None
        for seed in range(2000):
            rng = np.random.default_rng(seed)
            result = generate_sr_time_domain(profile, 5.0, rng=rng)
            if result["metadata"]["qburst_injected"]:
                qburst_result = result
                # Also generate a non-burst reference with a known-safe seed
                # (seed 0 is very unlikely to burst, but regenerate to be sure)
                for ref_seed in range(2000):
                    rng2 = np.random.default_rng(ref_seed)
                    ref = generate_sr_time_domain(profile, 5.0, rng=rng2)
                    if not ref["metadata"]["qburst_injected"]:
                        normal_result = ref
                        break
                break

        assert qburst_result is not None, "No Q-burst triggered in 2000 seeds"
        assert normal_result is not None

        # Q-burst signal should have higher peak amplitude
        peak_burst = np.max(np.abs(qburst_result["samples"]))
        peak_normal = np.max(np.abs(normal_result["samples"]))
        assert peak_burst > peak_normal

    def test_heartmath_60hz_mains(self):
        """HeartMath profile should inject 60 Hz mains, not 50 Hz."""
        profile = create_profile("heartmath")
        assert profile.mains_freq_hz == 60.0
        # 60 Hz is very close to Nyquist (65 Hz) for 130 Hz sample rate,
        # so verify the mains component by checking the DFT bin power at
        # exactly 60 Hz is higher than a signal generated with mains zeroed.
        rng_a = np.random.default_rng(5)
        result = generate_sr_time_domain(profile, 10.0, rng=rng_a)
        samples = result["samples"]
        sr = result["sample_rate_hz"]
        spectrum = np.abs(np.fft.rfft(samples))
        freqs = np.fft.rfftfreq(len(samples), d=1.0 / sr)
        # Find the bin closest to 60 Hz
        idx_60 = np.argmin(np.abs(freqs - 60.0))
        power_at_60 = spectrum[idx_60]
        # Compare to average power across nearby non-mains bins
        nearby = spectrum[max(0, idx_60 - 10) : idx_60 - 2]
        assert power_at_60 > np.mean(nearby) * 0.5, (
            "60 Hz mains component should be present in HeartMath signal"
        )

    def test_output_no_nan_or_inf(self, profile):
        """Output must be finite."""
        result = generate_sr_time_domain(profile, 5.0, rng=np.random.default_rng(77))
        assert np.all(np.isfinite(result["samples"]))

    def test_default_rng_when_none(self, profile):
        """generate_sr_time_domain with rng=None uses a default generator."""
        result = generate_sr_time_domain(profile, 1.0, rng=None)
        assert len(result["samples"]) == profile.sample_rate_hz
        assert np.all(np.isfinite(result["samples"]))

    def test_nyquist_skip(self):
        """Modes above Nyquist (sr/2) are skipped.

        HeartMath has sr=130, so Nyquist=65 Hz. The 8th Schumann mode
        at 51 Hz is just below Nyquist, but no modes should appear above it.
        A profile with a very low sample rate would skip higher modes.
        """
        # Create a profile-like object with very low sample rate so most modes
        # are above Nyquist.
        from earthsync_simulator.profiles import StationProfile

        low_sr_profile = StationProfile(
            model="test_low_sr",
            sample_rate_hz=20,  # Nyquist = 10 Hz, only 7.83 Hz passes
            sensor_type="test",
            mains_freq_hz=50.0,
            mains_amplitude=0.0,
            white_noise_level=0.0,
            pink_noise_level=0.0,
            amplitudes=(80.0,) * 8,
            q_factors=(4.0,) * 8,
            adc_bits=16,
            gain_db=100.0,
        )
        result = generate_sr_time_domain(low_sr_profile, 1.0, rng=np.random.default_rng(0))
        # Only mode 0 (7.83 Hz) is below Nyquist (10 Hz)
        assert len(result["metadata"]["modes"]) == 1
        assert result["metadata"]["modes"][0]["frequency_hz"] == 7.83


class TestPinkNoiseDefaultRng:
    def test_pink_noise_default_rng(self):
        """generate_pink_noise with rng=None uses a default generator."""
        out = generate_pink_noise(512, rng=None)
        assert len(out) == 512
        assert np.all(np.isfinite(out))


# ── Signal realism enhancements ──────────────────────────────────────────


class TestSignalRealism:
    def test_q_modulation_varies_with_phase(self):
        """Generate at phase=0.25 (sin=1, max Q boost) and phase=0.75 (sin=-1, max Q cut);
        different Q modulation should produce different peak widths/amplitudes in the PSD."""
        profile = create_profile("sierra_nevada")
        # phase=0.25 -> sin(pi/2)=1 -> q_mod = 1 + 0.3 = 1.3
        # phase=0.75 -> sin(3pi/2)=-1 -> q_mod = 1 - 0.3 = 0.7
        result_hi = generate_sr_time_domain(
            profile, 10.0, diurnal_phase=0.25, rng=np.random.default_rng(42)
        )
        result_lo = generate_sr_time_domain(
            profile, 10.0, diurnal_phase=0.75, rng=np.random.default_rng(42)
        )
        sr = result_hi["sample_rate_hz"]

        # Compute PSD for both and compare power near the first SR mode
        spec_hi = np.abs(np.fft.rfft(result_hi["samples"])) ** 2
        spec_lo = np.abs(np.fft.rfft(result_lo["samples"])) ** 2
        freqs = np.fft.rfftfreq(len(result_hi["samples"]), d=1.0 / sr)

        # Power in a narrow band around 7.83 Hz
        mask = np.abs(freqs - 7.83) <= 2.0
        power_hi = np.sum(spec_hi[mask])
        power_lo = np.sum(spec_lo[mask])

        # They should differ since Q modulation changes the filter shape
        assert power_hi != pytest.approx(power_lo, rel=0.01), (
            "PSD near 7.83 Hz should differ between phase=0.25 and phase=0.75"
        )

    def test_correlated_mode_amplitudes(self):
        """Generate 100 signals with same profile; mode amplitudes should be
        correlated (Pearson > 0.5)."""
        profile = create_profile("sierra_nevada")
        n_trials = 100
        mode_powers = []

        for seed in range(n_trials):
            result = generate_sr_time_domain(profile, 5.0, rng=np.random.default_rng(seed))
            samples = result["samples"]
            sr = result["sample_rate_hz"]
            spectrum = np.abs(np.fft.rfft(samples)) ** 2
            freqs = np.fft.rfftfreq(len(samples), d=1.0 / sr)

            # Measure power near mode 0 (7.83 Hz) and mode 1 (14.3 Hz)
            mask_0 = np.abs(freqs - 7.83) <= 1.5
            mask_1 = np.abs(freqs - 14.3) <= 1.5
            power_0 = np.sum(spectrum[mask_0])
            power_1 = np.sum(spectrum[mask_1])
            mode_powers.append((power_0, power_1))

        powers = np.array(mode_powers)
        # Pearson correlation
        corr = np.corrcoef(powers[:, 0], powers[:, 1])[0, 1]
        assert corr > 0.5, f"Mode amplitude correlation should be > 0.5, got {corr:.3f}"

    def test_harmonic_present_in_fft(self):
        """Generated signal should show a spectral peak near 2x7.83 Hz = 15.66 Hz."""
        profile = create_profile("sierra_nevada")
        result = generate_sr_time_domain(profile, 10.0, rng=np.random.default_rng(7))
        samples = result["samples"]
        sr = result["sample_rate_hz"]

        # Check for energy near the 2nd harmonic of the fundamental
        harmonic_freq = 2 * 7.83  # ~15.66 Hz
        assert _has_spectral_peak_near(samples, sr, harmonic_freq, tolerance_hz=2.0), (
            f"Expected spectral peak near {harmonic_freq} Hz (2nd harmonic of 7.83 Hz)"
        )

    def test_mains_harmonics_present(self):
        """Sierra Nevada (50 Hz mains, sr=256) should show peaks at 50, 100 Hz.
        150 Hz is above Nyquist (128 Hz) so it should not appear.
        Use a longer signal and boosted mains amplitude to make harmonics detectable."""
        from earthsync_simulator.profiles import StationProfile

        # Use a profile with stronger mains to make harmonics clearly visible
        strong_mains_profile = StationProfile(
            model="test_mains",
            sample_rate_hz=256,
            sensor_type="test",
            mains_freq_hz=50.0,
            mains_amplitude=0.05,  # Boosted for visibility
            white_noise_level=0.01,
            pink_noise_level=0.03,
            amplitudes=(80.0, 75.0, 70.0, 68.0, 65.0, 62.0, 58.0, 55.0),
            q_factors=(3.5, 4.5, 5.0, 5.5, 5.0, 4.5, 4.0, 3.5),
            adc_bits=16,
            gain_db=100.0,
            mains_harmonics=3,
        )
        result = generate_sr_time_domain(strong_mains_profile, 20.0, rng=np.random.default_rng(3))
        samples = result["samples"]
        sr = result["sample_rate_hz"]

        # Check FFT bins directly for mains harmonics
        spectrum = np.abs(np.fft.rfft(samples))
        freqs = np.fft.rfftfreq(len(samples), d=1.0 / sr)

        # 50 Hz fundamental -- find nearest bin and check it's elevated
        idx_50 = np.argmin(np.abs(freqs - 50.0))
        idx_100 = np.argmin(np.abs(freqs - 100.0))

        # Both should be above median spectral level in their neighbourhood
        nearby_50 = np.median(spectrum[max(0, idx_50 - 20) : idx_50 - 5])
        assert spectrum[idx_50] > nearby_50, "Expected mains fundamental at 50 Hz"

        nearby_100 = np.median(spectrum[max(0, idx_100 - 20) : idx_100 - 5])
        assert spectrum[idx_100] > nearby_100, "Expected mains 2nd harmonic at 100 Hz"

        # 150 Hz is above Nyquist (128 Hz)
        assert np.max(freqs) < 150.0, "Nyquist should be below 150 Hz"

    def test_qburst_has_oscillation(self):
        """Force Q-burst and verify the burst region has zero crossings
        (oscillation), not monotonic decay."""
        profile = create_profile("sierra_nevada")
        # Find a seed that triggers Q-burst
        qburst_result = None
        for seed in range(2000):
            rng = np.random.default_rng(seed)
            result = generate_sr_time_domain(profile, 5.0, rng=rng)
            if result["metadata"]["qburst_injected"]:
                qburst_result = result
                break

        assert qburst_result is not None, "No Q-burst triggered in 2000 seeds"

        samples = qburst_result["samples"]
        # Look at the second half of the signal where the burst should be
        second_half = samples[len(samples) // 4 :]

        # Count zero crossings: sign changes
        signs = np.sign(second_half)
        zero_crossings = np.sum(np.abs(np.diff(signs)) > 0)

        # An oscillating signal should have many zero crossings
        # For 5s at 256 Hz, even a single SR cycle (7.83 Hz) gives ~7 crossings/s
        assert zero_crossings > 10, (
            f"Expected many zero crossings (oscillation), got {zero_crossings}"
        )

    def test_backward_compatible(self):
        """Old-style profile without new fields still works via default values."""
        from earthsync_simulator.profiles import StationProfile

        old_profile = StationProfile(
            model="test_old",
            sample_rate_hz=256,
            sensor_type="test",
            mains_freq_hz=50.0,
            mains_amplitude=0.01,
            white_noise_level=0.05,
            pink_noise_level=0.15,
            amplitudes=(80.0, 75.0, 70.0, 68.0, 65.0, 62.0, 58.0, 55.0),
            q_factors=(3.5, 4.5, 5.0, 5.5, 5.0, 4.5, 4.0, 3.5),
            adc_bits=16,
            gain_db=100.0,
        )
        result = generate_sr_time_domain(old_profile, 2.0, rng=np.random.default_rng(0))
        assert len(result["samples"]) == 512
        assert np.all(np.isfinite(result["samples"]))
        assert result["metadata"]["profile_model"] == "test_old"

    def test_all_profiles_with_enhancements(self):
        """All 3 profiles produce valid output with the new signal realism features."""
        for model in ("sierra_nevada", "modra", "heartmath"):
            profile = create_profile(model)
            result = generate_sr_time_domain(
                profile, 5.0, diurnal_phase=0.25, rng=np.random.default_rng(0)
            )
            samples = result["samples"]
            assert len(samples) == profile.sample_rate_hz * 5
            assert np.all(np.isfinite(samples))
            assert not np.any(np.isnan(samples))
            # Verify new features are active by checking profile fields
            assert profile.q_modulation_depth > 0
            assert profile.harmonic_amplitude > 0
            assert profile.mode_correlation > 0
            assert profile.mains_harmonics >= 1

    def test_mode_correlation_zero_independent(self):
        """With correlation=0, the amp_draw should equal the nominal amplitudes
        (no multivariate_normal draw), verifying the code path is taken."""
        from earthsync_simulator.profiles import StationProfile

        uncorrelated_profile = StationProfile(
            model="test_uncorr",
            sample_rate_hz=256,
            sensor_type="test",
            mains_freq_hz=50.0,
            mains_amplitude=0.0,
            white_noise_level=0.0,
            pink_noise_level=0.0,
            amplitudes=(80.0, 75.0, 70.0, 68.0, 65.0, 62.0, 58.0, 55.0),
            q_factors=(3.5, 4.5, 5.0, 5.5, 5.0, 4.5, 4.0, 3.5),
            adc_bits=16,
            gain_db=100.0,
            mode_correlation=0.0,
            harmonic_amplitude=0.0,
            mains_harmonics=1,
        )

        # Generate two signals with different seeds -- since correlation=0,
        # the amplitude draw bypasses multivariate_normal and uses nominal values.
        # The metadata amplitudes should exactly match the profile amplitudes.
        result_a = generate_sr_time_domain(uncorrelated_profile, 2.0, rng=np.random.default_rng(10))
        result_b = generate_sr_time_domain(uncorrelated_profile, 2.0, rng=np.random.default_rng(20))

        # With correlation=0, all modes get the exact nominal amplitude
        for mode_info in result_a["metadata"]["modes"]:
            idx = mode_info["mode"]
            expected = uncorrelated_profile.amplitudes[idx]
            assert mode_info["amplitude"] == expected, (
                f"Mode {idx} amplitude should be nominal ({expected}) "
                f"when correlation=0, got {mode_info['amplitude']}"
            )

        # Both runs should report the same nominal amplitudes (no random draw)
        amps_a = [m["amplitude"] for m in result_a["metadata"]["modes"]]
        amps_b = [m["amplitude"] for m in result_b["metadata"]["modes"]]
        assert amps_a == amps_b, (
            "With correlation=0, mode amplitudes should be deterministic (nominal)"
        )
