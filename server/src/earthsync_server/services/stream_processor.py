"""Redis stream consumer — 14-step DSP pipeline."""

from __future__ import annotations

from typing import TYPE_CHECKING

import numpy as np
import structlog

from earthsync_server.constants import ALGORITHM_VERSION

if TYPE_CHECKING:
    from earthsync_server.config import Settings
from earthsync_server.dsp.lorentzian import fit_lorentzians
from earthsync_server.dsp.peak_analysis import compute_snr, estimate_noise_floor
from earthsync_server.dsp.peak_tracking import track_peaks
from earthsync_server.dsp.peaks import detect_peaks
from earthsync_server.dsp.quality import detect_qburst, validate_spectrum, validate_time_domain
from earthsync_server.dsp.welch import (
    compute_multitaper_psd,
    compute_welch_psd,
    resample_to_display_grid,
)
from earthsync_server.models import Location, TransientInfo, WSPayload

logger = structlog.get_logger()


class StreamProcessor:
    """Processes time-domain segments through the full DSP pipeline."""

    def __init__(self, settings: Settings, correlator: object | None = None):
        self._settings = settings
        self._tracking_state: dict[str, list[dict]] = {}  # station_id -> peak state
        self._spectral_buffers: dict[str, list[np.ndarray]] = {}  # station_id -> ring buffer
        self._correlator = correlator

    @property
    def tracked_stations(self) -> dict[str, list[dict]]:
        """Current peak tracking state per station (read-only copy)."""
        return dict(self._tracking_state)

    def process_segment(self, message: dict) -> WSPayload | None:
        """Process a single time-domain segment through the 14-step pipeline.

        Returns WSPayload for broadcast, or None if segment is unusable.
        """
        # Step 1: Parse message
        # Accept both camelCase (simulator) and snake_case (ingest API)
        station_id = message.get("station_id") or message.get("stationId") or "unknown"
        samples = np.array(message.get("samples", []), dtype=np.float64)
        sample_rate_hz = int(message.get("sample_rate_hz") or message.get("sampleRateHz") or 256)
        segment_duration_s = float(
            message.get("segment_duration_s") or message.get("segmentDurationS") or 10.0
        )
        location = message.get("location", {"lat": 0.0, "lon": 0.0})
        timestamp = message.get("timestamp", "")
        timestamp_ms = (
            int(message.get("timestamp", 0))
            if isinstance(message.get("timestamp"), (int, float))
            else 0
        )

        # Step 2: Validate time-domain
        td_quality = validate_time_domain(samples, sample_rate_hz, segment_duration_s)
        if not td_quality.is_usable:
            logger.warning("segment_unusable", station_id=station_id, flags=td_quality.flags)
            return None

        # Step 3: Detect Q-burst
        qburst = detect_qburst(samples, sample_rate_hz)

        # Step 3b: Record Q-burst in correlator for inter-station analysis
        if qburst.detected and self._correlator is not None:
            self._correlator.record(station_id, timestamp_ms, qburst.peak_amplitude or 0.0)

        # Step 4: Compute PSD (Welch or multitaper)
        if self._settings.use_multitaper:
            welch = compute_multitaper_psd(
                samples,
                sample_rate_hz,
                nw=self._settings.multitaper_nw,
                n_tapers=self._settings.multitaper_n_tapers,
            )
        else:
            welch = compute_welch_psd(samples, sample_rate_hz)

        # Step 5: Validate spectrum
        spectral_flags = validate_spectrum(
            welch.psd,
            welch.freqs,
            mains_freqs=self._settings.mains_freq,
            mains_ratio_threshold=self._settings.mains_ratio_threshold,
        )

        # Step 6: Detect peaks
        detected = detect_peaks(
            welch.psd,
            welch.freqs,
            smoothing_window=self._settings.peak_smoothing_window,
            prominence_factor=self._settings.peak_prominence_factor,
            min_distance_hz=self._settings.peak_min_distance_hz,
            sr_band_filtering=self._settings.sr_band_filtering,
        )

        # Step 7: Fit Lorentzians
        initial_peaks = [{"freq": p.freq, "amp": p.amp, "q_factor": p.q_factor} for p in detected]
        fit_result = fit_lorentzians(
            welch.psd,
            welch.freqs,
            initial_peaks,
            max_modes=self._settings.lorentzian_max_modes,
        )

        # Step 8: Update spectral buffer
        buf = self._spectral_buffers.setdefault(station_id, [])
        buf.append(welch.psd)
        if len(buf) > self._settings.spectral_buffer_size:
            buf.pop(0)

        # Step 9-10: Compute SNR per peak
        for peak in detected:
            peak.snr = compute_snr(peak.freq, peak.amp, welch.psd, welch.freqs)

        # Step 11: Track peaks
        prev_state = self._tracking_state.get(station_id, [])
        tracked, new_state = track_peaks(
            prev_state,
            detected,
            timestamp_ms,
            freq_tolerance_hz=self._settings.peak_tracking_freq_tolerance_hz,
        )
        self._tracking_state[station_id] = new_state

        # Step 12: Estimate noise floor
        noise_floor = estimate_noise_floor(welch.psd, welch.freqs)

        # Step 13: Resample to display grid
        display_spectrum = resample_to_display_grid(
            welch.psd,
            welch.freqs,
            n_points=self._settings.display_frequency_points,
            max_hz=self._settings.display_frequency_max_hz,
        )

        # Step 14: Build payload
        transient_type = "none"
        transient_details = None
        if qburst.detected:
            transient_type = "broadband"
            transient_details = (
                f"Q-burst: {qburst.peak_amplitude:.2f} peak, {qburst.duration_ms:.0f}ms"
            )

        all_flags = list(td_quality.flags) + spectral_flags

        return WSPayload(
            station_id=station_id,
            timestamp=str(timestamp),
            location=Location(lat=location.get("lat", 0.0), lon=location.get("lon", 0.0)),
            spectrogram=display_spectrum.tolist(),
            lorentzian_fit=fit_result,
            detected_peaks=tracked,
            transient_info=TransientInfo(type=transient_type, details=transient_details),
            noise_floor=noise_floor,
            quality_flags=all_flags,
            algorithm_version=ALGORITHM_VERSION,
            calibration_status="uncalibrated",
            sample_rate_hz=sample_rate_hz,
            frequency_resolution_hz=welch.frequency_resolution_hz,
        )
