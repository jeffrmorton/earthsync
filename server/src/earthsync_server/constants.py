"""Scientific constants for Schumann Resonance processing."""

SCHUMANN_FREQUENCIES: tuple[float, ...] = (7.83, 14.3, 20.8, 27.3, 33.8, 39.0, 45.0, 51.0)
DEFAULT_Q_FACTORS: tuple[float, ...] = (3.5, 4.5, 5.0, 5.5, 5.0, 4.5, 4.0, 3.5)
DEFAULT_AMPLITUDES: tuple[float, ...] = (80.0, 75.0, 70.0, 68.0, 65.0, 62.0, 58.0, 55.0)

ALGORITHM_VERSION = "0.1.1"
DISPLAY_FREQUENCY_POINTS = 1101
DISPLAY_FREQUENCY_MAX_HZ = 55.0
MAD_TO_SIGMA = 1.4826

SCHUMANN_MODE_RANGES: dict[str, dict[str, float]] = {
    "Mode 1 (7.83 Hz)": {"min": 6.5, "max": 9.5},
    "Mode 2 (14.3 Hz)": {"min": 12.5, "max": 16.5},
    "Mode 3 (20.8 Hz)": {"min": 18.5, "max": 23.5},
    "Mode 4 (27.3 Hz)": {"min": 24.5, "max": 30.5},
    "Mode 5 (33.8 Hz)": {"min": 31.5, "max": 36.5},
    "Mode 6 (39.0 Hz)": {"min": 36.5, "max": 41.5},
    "Mode 7 (45.0 Hz)": {"min": 42.5, "max": 47.5},
    "Mode 8 (51.0 Hz)": {"min": 48.5, "max": 53.5},
}
