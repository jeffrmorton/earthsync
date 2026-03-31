"""Tests for StreamProcessor — the 14-step DSP pipeline."""

from __future__ import annotations

import numpy as np
import pytest
from earthsync_server.config import Settings
from earthsync_server.constants import ALGORITHM_VERSION, SCHUMANN_FREQUENCIES
from earthsync_server.models import WSPayload
from earthsync_server.services.qburst_correlator import QBurstCorrelator
from earthsync_server.services.stream_processor import StreamProcessor


def _make_settings(**overrides) -> Settings:
    """Create Settings with required env vars stubbed."""
    defaults = {
        "jwt_secret": "test-secret",
        "api_ingest_key": "test-key",
        "db_password": "test-pw",
    }
    defaults.update(overrides)
    return Settings(**defaults)


def _make_sr_signal(
    sample_rate_hz: int = 256,
    duration_s: float = 10.0,
    freqs: tuple[float, ...] = SCHUMANN_FREQUENCIES,
    amplitudes: tuple[float, ...] | None = None,
    noise_level: float = 0.5,
) -> np.ndarray:
    """Generate a synthetic SR signal with known peaks for testing."""
    if amplitudes is None:
        amplitudes = (10.0, 8.0, 7.0, 6.0, 5.5, 5.0, 4.5, 4.0)
    n_samples = int(sample_rate_hz * duration_s)
    t = np.arange(n_samples) / sample_rate_hz
    signal = np.random.default_rng(42).normal(0.0, noise_level, n_samples)
    for freq, amp in zip(freqs, amplitudes, strict=True):
        signal += amp * np.sin(2 * np.pi * freq * t)
    return signal


def _make_message(  # noqa: PLR0913
    station_id: str = "det-001",
    sample_rate_hz: int = 256,
    duration_s: float = 10.0,
    samples: np.ndarray | None = None,
    timestamp: str = "2026-03-28T12:00:00Z",
    location: dict | None = None,
) -> dict:
    """Build a Redis stream message dict."""
    if samples is None:
        samples = _make_sr_signal(sample_rate_hz, duration_s)
    if location is None:
        location = {"lat": 37.0, "lon": -3.4}
    return {
        "station_id": station_id,
        "samples": samples.tolist(),
        "sample_rate_hz": sample_rate_hz,
        "segment_duration_s": duration_s,
        "location": location,
        "timestamp": timestamp,
    }


class TestProcessValidSegment:
    """Tests for successful pipeline processing."""

    def test_returns_ws_payload(self):
        settings = _make_settings()
        proc = StreamProcessor(settings)
        msg = _make_message()
        result = proc.process_segment(msg)
        assert isinstance(result, WSPayload)

    def test_payload_has_station_id(self):
        settings = _make_settings()
        proc = StreamProcessor(settings)
        msg = _make_message(station_id="sierra-nevada-01")
        result = proc.process_segment(msg)
        assert result is not None
        assert result.station_id == "sierra-nevada-01"

    def test_payload_has_timestamp(self):
        settings = _make_settings()
        proc = StreamProcessor(settings)
        msg = _make_message(timestamp="2026-03-28T15:00:00Z")
        result = proc.process_segment(msg)
        assert result is not None
        assert result.timestamp == "2026-03-28T15:00:00Z"

    def test_payload_has_location(self):
        settings = _make_settings()
        proc = StreamProcessor(settings)
        msg = _make_message(location={"lat": 48.15, "lon": 17.1})
        result = proc.process_segment(msg)
        assert result is not None
        assert result.location.lat == pytest.approx(48.15)
        assert result.location.lon == pytest.approx(17.1)

    def test_payload_has_algorithm_version(self):
        settings = _make_settings()
        proc = StreamProcessor(settings)
        msg = _make_message()
        result = proc.process_segment(msg)
        assert result is not None
        assert result.algorithm_version == ALGORITHM_VERSION

    def test_payload_has_calibration_status(self):
        settings = _make_settings()
        proc = StreamProcessor(settings)
        msg = _make_message()
        result = proc.process_segment(msg)
        assert result is not None
        assert result.calibration_status == "uncalibrated"

    def test_payload_has_sample_rate(self):
        settings = _make_settings()
        proc = StreamProcessor(settings)
        msg = _make_message(sample_rate_hz=512)
        result = proc.process_segment(msg)
        assert result is not None
        assert result.sample_rate_hz == 512

    def test_payload_has_frequency_resolution(self):
        settings = _make_settings()
        proc = StreamProcessor(settings)
        msg = _make_message()
        result = proc.process_segment(msg)
        assert result is not None
        assert result.frequency_resolution_hz is not None
        assert result.frequency_resolution_hz > 0

    def test_payload_has_noise_floor(self):
        settings = _make_settings()
        proc = StreamProcessor(settings)
        msg = _make_message()
        result = proc.process_segment(msg)
        assert result is not None
        assert result.noise_floor is not None
        assert result.noise_floor.median >= 0
        assert result.noise_floor.std >= 0

    def test_payload_has_quality_flags_list(self):
        settings = _make_settings()
        proc = StreamProcessor(settings)
        msg = _make_message()
        result = proc.process_segment(msg)
        assert result is not None
        assert isinstance(result.quality_flags, list)

    def test_payload_lorentzian_fit_present(self):
        settings = _make_settings()
        proc = StreamProcessor(settings)
        msg = _make_message()
        result = proc.process_segment(msg)
        assert result is not None
        assert result.lorentzian_fit is not None

    def test_payload_detected_peaks_list(self):
        settings = _make_settings()
        proc = StreamProcessor(settings)
        msg = _make_message()
        result = proc.process_segment(msg)
        assert result is not None
        assert isinstance(result.detected_peaks, list)

    def test_payload_transient_info(self):
        settings = _make_settings()
        proc = StreamProcessor(settings)
        msg = _make_message()
        result = proc.process_segment(msg)
        assert result is not None
        assert result.transient_info is not None
        assert result.transient_info.type in ("none", "broadband", "narrowband", "error")


class TestProcessUnusableSegment:
    """Tests for segments that should be rejected."""

    def test_flatline_returns_none(self):
        settings = _make_settings()
        proc = StreamProcessor(settings)
        flatline = np.zeros(2560)
        msg = _make_message(samples=flatline)
        result = proc.process_segment(msg)
        assert result is None

    def test_empty_samples_returns_none(self):
        settings = _make_settings()
        proc = StreamProcessor(settings)
        msg = _make_message(samples=np.array([]))
        result = proc.process_segment(msg)
        assert result is None

    def test_all_nan_returns_none(self):
        settings = _make_settings()
        proc = StreamProcessor(settings)
        nans = np.full(2560, np.nan)
        msg = _make_message(samples=nans)
        result = proc.process_segment(msg)
        assert result is None


class TestQBurstDetection:
    """Tests for Q-burst transient detection."""

    def test_qburst_detected(self):
        settings = _make_settings()
        proc = StreamProcessor(settings)
        rng = np.random.default_rng(42)
        samples = rng.normal(0.0, 1.0, 2560)
        # Inject a massive spike in the middle
        samples[1200:1250] = 200.0
        msg = _make_message(samples=samples)
        result = proc.process_segment(msg)
        assert result is not None
        assert result.transient_info.type == "broadband"
        assert result.transient_info.details is not None
        assert "Q-burst" in result.transient_info.details

    def test_no_qburst_in_clean_signal(self):
        settings = _make_settings()
        proc = StreamProcessor(settings)
        msg = _make_message()
        result = proc.process_segment(msg)
        assert result is not None
        assert result.transient_info.type == "none"


class TestPeakTracking:
    """Tests for peak tracking across consecutive segments."""

    def test_first_segment_peaks_are_new(self):
        settings = _make_settings()
        proc = StreamProcessor(settings)
        msg = _make_message()
        result = proc.process_segment(msg)
        assert result is not None
        for peak in result.detected_peaks:
            assert peak.track_status == "new"

    def test_second_segment_peaks_continue(self):
        settings = _make_settings()
        proc = StreamProcessor(settings)
        # Use same signal twice for same station
        samples = _make_sr_signal()
        msg1 = _make_message(station_id="det-track", samples=samples)
        msg2 = _make_message(station_id="det-track", samples=samples)
        result1 = proc.process_segment(msg1)
        result2 = proc.process_segment(msg2)
        assert result1 is not None
        assert result2 is not None
        if len(result2.detected_peaks) > 0:
            continuing = [p for p in result2.detected_peaks if p.track_status == "continuing"]
            assert len(continuing) > 0

    def test_different_stations_independent(self):
        settings = _make_settings()
        proc = StreamProcessor(settings)
        samples = _make_sr_signal()
        msg_a = _make_message(station_id="det-A", samples=samples)
        msg_b = _make_message(station_id="det-B", samples=samples)
        result_a = proc.process_segment(msg_a)
        result_b = proc.process_segment(msg_b)
        assert result_a is not None
        assert result_b is not None
        # All peaks for det-B should be "new" since it is a different station
        for peak in result_b.detected_peaks:
            assert peak.track_status == "new"


class TestSpectralBuffer:
    """Tests for the per-station spectral buffer."""

    def test_buffer_accumulates(self):
        settings = _make_settings(spectral_buffer_size=3)
        proc = StreamProcessor(settings)
        for _i in range(3):
            msg = _make_message(station_id="det-buf")
            proc.process_segment(msg)
        assert "det-buf" in proc._spectral_buffers
        assert len(proc._spectral_buffers["det-buf"]) == 3

    def test_buffer_evicts_oldest(self):
        settings = _make_settings(spectral_buffer_size=2)
        proc = StreamProcessor(settings)
        for _i in range(5):
            msg = _make_message(station_id="det-evict")
            proc.process_segment(msg)
        assert len(proc._spectral_buffers["det-evict"]) == 2


class TestMissingFields:
    """Tests for graceful handling of missing message fields."""

    def test_missing_station_id_uses_default(self):
        settings = _make_settings()
        proc = StreamProcessor(settings)
        samples = _make_sr_signal()
        msg = {"samples": samples.tolist(), "sample_rate_hz": 256, "segment_duration_s": 10.0}
        result = proc.process_segment(msg)
        assert result is not None
        assert result.station_id == "unknown"

    def test_missing_location_uses_zeros(self):
        settings = _make_settings()
        proc = StreamProcessor(settings)
        samples = _make_sr_signal()
        msg = {
            "station_id": "det-no-loc",
            "samples": samples.tolist(),
            "sample_rate_hz": 256,
            "segment_duration_s": 10.0,
        }
        result = proc.process_segment(msg)
        assert result is not None
        assert result.location.lat == 0.0
        assert result.location.lon == 0.0

    def test_missing_timestamp_uses_empty(self):
        settings = _make_settings()
        proc = StreamProcessor(settings)
        samples = _make_sr_signal()
        msg = {
            "station_id": "det-no-ts",
            "samples": samples.tolist(),
            "sample_rate_hz": 256,
            "segment_duration_s": 10.0,
        }
        result = proc.process_segment(msg)
        assert result is not None
        assert result.timestamp == ""


class TestDisplaySpectrum:
    """Tests for display grid resampling."""

    def test_display_spectrum_length_default(self):
        settings = _make_settings()
        proc = StreamProcessor(settings)
        msg = _make_message()
        result = proc.process_segment(msg)
        assert result is not None
        assert len(result.spectrogram) == 1101

    def test_display_spectrum_length_custom(self):
        settings = _make_settings(display_frequency_points=500)
        proc = StreamProcessor(settings)
        msg = _make_message()
        result = proc.process_segment(msg)
        assert result is not None
        assert len(result.spectrogram) == 500

    def test_display_spectrum_all_finite(self):
        settings = _make_settings()
        proc = StreamProcessor(settings)
        msg = _make_message()
        result = proc.process_segment(msg)
        assert result is not None
        assert all(np.isfinite(v) for v in result.spectrogram)


class TestCorrelatorIntegration:
    """Tests for Q-burst correlator integration in the stream processor."""

    def test_correlator_receives_qburst(self):
        """When a Q-burst is detected and correlator is set, it records the burst."""
        settings = _make_settings()
        correlator = QBurstCorrelator()
        proc = StreamProcessor(settings, correlator=correlator)
        rng = np.random.default_rng(42)
        samples = rng.normal(0.0, 1.0, 2560)
        samples[1200:1250] = 200.0
        msg = _make_message(samples=samples)
        result = proc.process_segment(msg)
        assert result is not None
        assert result.transient_info.type == "broadband"
        assert correlator.buffer_size == 1

    def test_no_correlator_recording_without_qburst(self):
        """Clean signal does not record in the correlator."""
        settings = _make_settings()
        correlator = QBurstCorrelator()
        proc = StreamProcessor(settings, correlator=correlator)
        msg = _make_message()
        result = proc.process_segment(msg)
        assert result is not None
        assert correlator.buffer_size == 0

    def test_no_correlator_is_fine(self):
        """Processor works without correlator (None)."""
        settings = _make_settings()
        proc = StreamProcessor(settings, correlator=None)
        rng = np.random.default_rng(42)
        samples = rng.normal(0.0, 1.0, 2560)
        samples[1200:1250] = 200.0
        msg = _make_message(samples=samples)
        result = proc.process_segment(msg)
        assert result is not None
        assert result.transient_info.type == "broadband"

    def test_default_correlator_is_none(self):
        """StreamProcessor defaults to no correlator."""
        settings = _make_settings()
        proc = StreamProcessor(settings)
        assert proc._correlator is None
