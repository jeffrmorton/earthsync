"""Tests for QBurstCorrelator -- inter-station Q-burst correlation service."""

from __future__ import annotations

import pytest
from earthsync_server.services.qburst_correlator import QBurstCorrelator


class TestRecord:
    def test_record_single_qburst(self):
        """Recording one burst gives buffer_size = 1."""
        c = QBurstCorrelator()
        c.record("det-A", 1000, 50.0)
        assert c.buffer_size == 1

    def test_record_multiple_stations(self):
        """Buffer has entries for each station."""
        c = QBurstCorrelator()
        c.record("det-A", 1000, 50.0)
        c.record("det-B", 1100, 60.0)
        c.record("det-A", 2000, 55.0)
        assert c.buffer_size == 3
        assert len(c._buffer["det-A"]) == 2
        assert len(c._buffer["det-B"]) == 1


class TestNoGlobalEvent:
    def test_no_global_event_single_station(self):
        """One station alone cannot produce a global event."""
        c = QBurstCorrelator()
        c.record("det-A", 1000, 50.0)
        c.record("det-A", 2000, 55.0)
        assert c.check_global_events() == []

    def test_no_global_event_outside_window(self):
        """Two stations with timestamps 5s apart (default window 2s) produce no event."""
        c = QBurstCorrelator(time_window_ms=2000)
        c.record("det-A", 1000, 50.0)
        c.record("det-B", 6000, 60.0)
        assert c.check_global_events() == []

    def test_no_global_event_empty_buffer(self):
        """Empty buffer returns no events."""
        c = QBurstCorrelator()
        assert c.check_global_events() == []


class TestGlobalEvent:
    def test_global_event_two_stations(self):
        """Two stations within 1s window produce 1 global event."""
        c = QBurstCorrelator(time_window_ms=2000)
        c.record("det-A", 1000, 50.0)
        c.record("det-B", 1500, 60.0)
        events = c.check_global_events()
        assert len(events) == 1
        assert events[0]["num_stations"] == 2

    def test_global_event_three_stations(self):
        """Three stations within window produce event with num_stations=3."""
        c = QBurstCorrelator(time_window_ms=2000)
        c.record("det-A", 1000, 50.0)
        c.record("det-B", 1500, 60.0)
        c.record("det-C", 1800, 70.0)
        events = c.check_global_events()
        assert len(events) == 1
        assert events[0]["num_stations"] == 3

    def test_event_mean_amplitude(self):
        """Mean amplitude is correctly averaged across matching stations."""
        c = QBurstCorrelator(time_window_ms=2000)
        c.record("det-A", 1000, 40.0)
        c.record("det-B", 1500, 60.0)
        events = c.check_global_events()
        assert len(events) == 1
        assert events[0]["mean_amplitude"] == pytest.approx(50.0)

    def test_event_station_ids_sorted(self):
        """Detector IDs are returned in alphabetical order."""
        c = QBurstCorrelator(time_window_ms=2000)
        c.record("det-C", 1000, 50.0)
        c.record("det-A", 1200, 60.0)
        events = c.check_global_events()
        assert len(events) == 1
        assert events[0]["station_ids"] == ["det-A", "det-C"]

    def test_event_has_peak_timestamp_ms(self):
        """Global event contains peak_timestamp_ms from the initiating burst."""
        c = QBurstCorrelator(time_window_ms=2000)
        c.record("det-A", 1000, 50.0)
        c.record("det-B", 1500, 60.0)
        events = c.check_global_events()
        assert events[0]["peak_timestamp_ms"] == 1000


class TestClearBuffer:
    def test_clear_buffer(self):
        """Buffer is empty after clear."""
        c = QBurstCorrelator()
        c.record("det-A", 1000, 50.0)
        c.record("det-B", 1500, 60.0)
        assert c.buffer_size == 2
        c.clear_buffer()
        assert c.buffer_size == 0
        assert c._buffer == {}


class TestMinStationsConfigurable:
    def test_min_stations_3_requires_3(self):
        """With min_stations=3, two stations are not enough."""
        c = QBurstCorrelator(time_window_ms=2000, min_stations=3)
        c.record("det-A", 1000, 50.0)
        c.record("det-B", 1500, 60.0)
        assert c.check_global_events() == []

    def test_min_stations_3_with_3_stations(self):
        """With min_stations=3, three stations within window produce event."""
        c = QBurstCorrelator(time_window_ms=2000, min_stations=3)
        c.record("det-A", 1000, 50.0)
        c.record("det-B", 1500, 60.0)
        c.record("det-C", 1800, 70.0)
        events = c.check_global_events()
        assert len(events) == 1
        assert events[0]["num_stations"] == 3


class TestUsedTimestamps:
    def test_used_timestamps_not_double_counted(self):
        """Same burst timestamp is not reused in multiple events."""
        c = QBurstCorrelator(time_window_ms=500)
        # Two clusters: [1000, 1200] and [5000, 5100]
        c.record("det-A", 1000, 50.0)
        c.record("det-B", 1200, 60.0)
        c.record("det-A", 5000, 70.0)
        c.record("det-B", 5100, 80.0)
        events = c.check_global_events()
        assert len(events) == 2
        # Each event should use different timestamps
        ts_set = {e["peak_timestamp_ms"] for e in events}
        assert 1000 in ts_set
        assert 5000 in ts_set


class TestBufferSizeProperty:
    def test_buffer_size_property(self):
        """buffer_size returns total count across all stations."""
        c = QBurstCorrelator()
        assert c.buffer_size == 0
        c.record("det-A", 1000, 50.0)
        assert c.buffer_size == 1
        c.record("det-B", 1500, 60.0)
        assert c.buffer_size == 2
        c.record("det-A", 2000, 55.0)
        assert c.buffer_size == 3


class TestTimeWindowMs:
    def test_custom_time_window(self):
        """A narrow window rejects bursts that would match with default window."""
        c = QBurstCorrelator(time_window_ms=100)
        c.record("det-A", 1000, 50.0)
        c.record("det-B", 1500, 60.0)  # 500ms apart > 100ms window
        assert c.check_global_events() == []

    def test_exact_boundary_within_window(self):
        """Bursts exactly at the window boundary are still matched."""
        c = QBurstCorrelator(time_window_ms=500)
        c.record("det-A", 1000, 50.0)
        c.record("det-B", 1500, 60.0)  # exactly 500ms apart
        events = c.check_global_events()
        assert len(events) == 1
