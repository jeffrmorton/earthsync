"""Observatory station profiles for Schumann Resonance simulation."""

from dataclasses import dataclass


@dataclass(frozen=True)
class StationProfile:
    """Hardware characteristics of an SR observatory station."""

    model: str
    sample_rate_hz: int
    sensor_type: str
    mains_freq_hz: float
    mains_amplitude: float
    white_noise_level: float
    pink_noise_level: float
    amplitudes: tuple[float, ...]
    q_factors: tuple[float, ...]
    adc_bits: int
    gain_db: float
    q_modulation_depth: float = 0.3
    harmonic_amplitude: float = 0.15
    mode_correlation: float = 0.7
    mains_harmonics: int = 3


_PROFILES: dict[str, StationProfile] = {
    "sierra_nevada": StationProfile(
        model="sierra_nevada",
        sample_rate_hz=256,
        sensor_type="magnetic_ns",
        mains_freq_hz=50.0,
        mains_amplitude=0.008,
        white_noise_level=0.05,
        pink_noise_level=0.15,
        amplitudes=(80.0, 75.0, 70.0, 68.0, 65.0, 62.0, 58.0, 55.0),
        q_factors=(3.5, 4.5, 5.0, 5.5, 5.0, 4.5, 4.0, 3.5),
        adc_bits=16,
        gain_db=100.0,
        q_modulation_depth=0.3,
        harmonic_amplitude=0.15,
        mode_correlation=0.7,
        mains_harmonics=3,
    ),
    "modra": StationProfile(
        model="modra",
        sample_rate_hz=200,
        sensor_type="electric_ball",
        mains_freq_hz=50.0,
        mains_amplitude=0.006,
        white_noise_level=0.08,
        pink_noise_level=0.20,
        amplitudes=(60.0, 55.0, 50.0, 48.0, 45.0, 42.0, 38.0, 35.0),
        q_factors=(3.0, 4.0, 4.5, 5.0, 4.5, 4.0, 3.5, 3.0),
        adc_bits=16,
        gain_db=80.0,
        q_modulation_depth=0.25,
        harmonic_amplitude=0.12,
        mode_correlation=0.6,
        mains_harmonics=3,
    ),
    "heartmath": StationProfile(
        model="heartmath",
        sample_rate_hz=130,
        sensor_type="magnetic_induction",
        mains_freq_hz=60.0,
        mains_amplitude=0.005,
        white_noise_level=0.03,
        pink_noise_level=0.10,
        amplitudes=(90.0, 85.0, 80.0, 78.0, 75.0, 72.0, 68.0, 65.0),
        q_factors=(4.0, 5.0, 5.5, 6.0, 5.5, 5.0, 4.5, 4.0),
        adc_bits=24,
        gain_db=120.0,
        q_modulation_depth=0.35,
        harmonic_amplitude=0.18,
        mode_correlation=0.8,
        mains_harmonics=3,
    ),
}


def create_profile(model: str) -> StationProfile:
    """Return the station profile for *model*.

    Raises ``ValueError`` if *model* is not one of the known observatory types.
    """
    try:
        return _PROFILES[model]
    except KeyError:
        valid = ", ".join(sorted(_PROFILES))
        raise ValueError(f"Unknown station model {model!r}. Valid models: {valid}") from None
