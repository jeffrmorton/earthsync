"""Tests for peak tracking — UUID continuity across time."""

from earthsync_server.dsp.peak_tracking import track_peaks
from earthsync_server.models import DetectedPeak


def _peak(freq: float, amp: float = 1.0) -> DetectedPeak:
    return DetectedPeak(freq=freq, amp=amp)


class TestTrackPeaks:
    def test_all_new_when_no_previous(self):
        peaks = [_peak(7.83), _peak(14.3)]
        tracked, _ = track_peaks([], peaks, timestamp_ms=1000)
        assert len(tracked) == 2
        assert all(t.track_status == "new" for t in tracked)
        assert all(len(t.track_id) == 36 for t in tracked)  # UUID format

    def test_continuing_when_same_freq(self):
        prev = [{"id": "abc-123", "freq": 7.83, "amp": 1.0, "last_ts": 500}]
        peaks = [_peak(7.83)]
        tracked, _ = track_peaks(prev, peaks, timestamp_ms=1000)
        assert tracked[0].track_status == "continuing"
        assert tracked[0].track_id == "abc-123"

    def test_new_when_freq_beyond_tolerance(self):
        prev = [{"id": "abc-123", "freq": 7.83, "amp": 1.0, "last_ts": 500}]
        peaks = [_peak(14.3)]
        tracked, _ = track_peaks(prev, peaks, timestamp_ms=1000, freq_tolerance_hz=0.5)
        assert tracked[0].track_status == "new"
        assert tracked[0].track_id != "abc-123"

    def test_mixed_new_and_continuing(self):
        prev = [{"id": "id-1", "freq": 7.83, "amp": 1.0, "last_ts": 500}]
        peaks = [_peak(7.83), _peak(14.3)]
        tracked, _ = track_peaks(prev, peaks, timestamp_ms=1000)
        statuses = {t.freq: t.track_status for t in tracked}
        assert statuses[7.83] == "continuing"
        assert statuses[14.3] == "new"

    def test_tolerance_boundary_included(self):
        prev = [{"id": "id-1", "freq": 7.83, "amp": 1.0, "last_ts": 500}]
        peaks = [_peak(8.33)]  # 7.83 + 0.5 = exactly at tolerance
        tracked, _ = track_peaks(prev, peaks, timestamp_ms=1000, freq_tolerance_hz=0.5)
        assert tracked[0].track_status == "continuing"

    def test_tolerance_boundary_excluded(self):
        prev = [{"id": "id-1", "freq": 7.83, "amp": 1.0, "last_ts": 500}]
        peaks = [_peak(8.34)]  # 0.51 Hz offset, beyond 0.5 tolerance
        tracked, _ = track_peaks(prev, peaks, timestamp_ms=1000, freq_tolerance_hz=0.5)
        assert tracked[0].track_status == "new"

    def test_empty_current_peaks(self):
        prev = [{"id": "id-1", "freq": 7.83, "amp": 1.0, "last_ts": 500}]
        tracked, state = track_peaks(prev, [], timestamp_ms=1000)
        assert tracked == []
        assert state == []

    def test_state_format(self):
        peaks = [_peak(7.83, amp=2.5)]
        _, state = track_peaks([], peaks, timestamp_ms=42000)
        assert len(state) == 1
        assert state[0]["freq"] == 7.83
        assert state[0]["amp"] == 2.5
        assert state[0]["last_ts"] == 42000
        assert "id" in state[0]

    def test_closest_match_wins(self):
        prev = [
            {"id": "id-far", "freq": 7.50, "amp": 1.0, "last_ts": 500},
            {"id": "id-close", "freq": 7.80, "amp": 1.0, "last_ts": 500},
        ]
        peaks = [_peak(7.83)]
        tracked, _ = track_peaks(prev, peaks, timestamp_ms=1000)
        assert tracked[0].track_id == "id-close"

    def test_each_prev_claimed_once(self):
        prev = [{"id": "id-1", "freq": 10.0, "amp": 1.0, "last_ts": 500}]
        peaks = [_peak(10.0), _peak(10.2)]
        tracked, _ = track_peaks(prev, peaks, timestamp_ms=1000)
        ids = [t.track_id for t in tracked]
        assert ids[0] == "id-1"  # First peak claims it
        assert ids[1] != "id-1"  # Second gets new UUID

    def test_preserves_peak_fields(self):
        peaks = [DetectedPeak(freq=7.83, amp=2.0, q_factor=4.0, snr=15.0)]
        tracked, _ = track_peaks([], peaks, timestamp_ms=1000)
        assert tracked[0].freq == 7.83
        assert tracked[0].amp == 2.0
        assert tracked[0].q_factor == 4.0
        assert tracked[0].snr == 15.0
