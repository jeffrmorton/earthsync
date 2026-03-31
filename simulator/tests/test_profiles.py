"""Tests for earthsync_simulator.profiles."""

import pytest
from earthsync_simulator.profiles import StationProfile, create_profile


class TestProfiles:
    def test_sierra_nevada_profile(self):
        p = create_profile("sierra_nevada")
        assert isinstance(p, StationProfile)
        assert p.sample_rate_hz == 256
        assert p.sensor_type == "magnetic_ns"
        assert p.mains_freq_hz == 50.0
        assert p.adc_bits == 16
        assert p.gain_db == 100.0

    def test_modra_profile(self):
        p = create_profile("modra")
        assert p.sample_rate_hz == 200
        assert p.sensor_type == "electric_ball"
        assert p.mains_freq_hz == 50.0
        assert p.adc_bits == 16
        assert p.gain_db == 80.0

    def test_heartmath_profile(self):
        p = create_profile("heartmath")
        assert p.sample_rate_hz == 130
        assert p.sensor_type == "magnetic_induction"
        assert p.mains_freq_hz == 60.0
        assert p.adc_bits == 24
        assert p.gain_db == 120.0

    def test_unknown_model_raises(self):
        with pytest.raises(ValueError, match="nonexistent"):
            create_profile("nonexistent")

    def test_all_profiles_have_8_modes(self):
        for model in ("sierra_nevada", "modra", "heartmath"):
            p = create_profile(model)
            assert len(p.amplitudes) == 8, f"{model} amplitudes length != 8"
            assert len(p.q_factors) == 8, f"{model} q_factors length != 8"

    def test_profiles_are_frozen(self):
        p = create_profile("sierra_nevada")
        with pytest.raises(AttributeError):
            p.sample_rate_hz = 999  # type: ignore[misc]

    def test_profile_model_name_matches_key(self):
        for model in ("sierra_nevada", "modra", "heartmath"):
            p = create_profile(model)
            assert p.model == model

    def test_profiles_have_new_fields(self):
        """All 3 profiles have the new signal realism fields."""
        for model in ("sierra_nevada", "modra", "heartmath"):
            p = create_profile(model)
            assert hasattr(p, "q_modulation_depth")
            assert hasattr(p, "harmonic_amplitude")
            assert hasattr(p, "mode_correlation")
            assert hasattr(p, "mains_harmonics")
            assert isinstance(p.q_modulation_depth, float)
            assert isinstance(p.harmonic_amplitude, float)
            assert isinstance(p.mode_correlation, float)
            assert isinstance(p.mains_harmonics, int)

    def test_profiles_new_field_values(self):
        """Verify each profile has its specific new-field values."""
        sn = create_profile("sierra_nevada")
        assert sn.q_modulation_depth == 0.3
        assert sn.harmonic_amplitude == 0.15
        assert sn.mode_correlation == 0.7
        assert sn.mains_harmonics == 3

        mo = create_profile("modra")
        assert mo.q_modulation_depth == 0.25
        assert mo.harmonic_amplitude == 0.12
        assert mo.mode_correlation == 0.6
        assert mo.mains_harmonics == 3

        hm = create_profile("heartmath")
        assert hm.q_modulation_depth == 0.35
        assert hm.harmonic_amplitude == 0.18
        assert hm.mode_correlation == 0.8
        assert hm.mains_harmonics == 3

    def test_default_values_backward_compatible(self):
        """StationProfile with only original args gets correct defaults for new fields."""
        p = StationProfile(
            model="test_compat",
            sample_rate_hz=256,
            sensor_type="test",
            mains_freq_hz=50.0,
            mains_amplitude=0.01,
            white_noise_level=0.05,
            pink_noise_level=0.15,
            amplitudes=(80.0,) * 8,
            q_factors=(4.0,) * 8,
            adc_bits=16,
            gain_db=100.0,
        )
        assert p.q_modulation_depth == 0.3
        assert p.harmonic_amplitude == 0.15
        assert p.mode_correlation == 0.7
        assert p.mains_harmonics == 3
