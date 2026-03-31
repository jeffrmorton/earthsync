"""Inter-station Q-burst correlation service.

Detects global Schumann Resonance transient events (Q-bursts caused by
lightning superstrokes) by correlating transient detection timestamps
across multiple stations within a configurable time window.

References:
    Nickolaenko, A.P. & Hayakawa, M. (2002). Resonances in the
    Earth-Ionosphere Cavity. Kluwer Academic.
"""

from __future__ import annotations

import structlog

logger = structlog.get_logger()


class QBurstCorrelator:
    """Correlates Q-burst detections across stations to identify global events."""

    def __init__(self, time_window_ms: int = 2000, min_stations: int = 2):
        self._window = time_window_ms
        self._min = min_stations
        self._buffer: dict[str, list[tuple[int, float]]] = {}

    def record(self, station_id: str, timestamp_ms: int, amplitude: float) -> None:
        """Record a Q-burst detection from a station."""
        self._buffer.setdefault(station_id, []).append((timestamp_ms, amplitude))

    def check_global_events(self) -> list[dict]:
        """Find timestamps where min_stations+ detected Q-burst within +/-window.

        Returns list of global event dicts with peak_timestamp_ms,
        station_ids, num_stations, mean_amplitude.
        """
        if len(self._buffer) < self._min:
            return []

        # Flatten all bursts with station info
        all_bursts: list[tuple[int, str, float]] = []
        for did, bursts in self._buffer.items():
            for ts, amp in bursts:
                all_bursts.append((ts, did, amp))
        all_bursts.sort()

        events = []
        used_timestamps: set[int] = set()

        for ts, did, amp in all_bursts:
            if ts in used_timestamps:
                continue
            # Find all bursts from OTHER stations within window
            matches = [
                (ts2, did2, amp2)
                for ts2, did2, amp2 in all_bursts
                if abs(ts2 - ts) <= self._window and did2 != did and ts2 not in used_timestamps
            ]
            unique_dids = {did2 for _, did2, _ in matches}
            if len(unique_dids) >= self._min - 1:  # -1 because initiator counts
                all_dids = [did, *list(unique_dids)]
                amps_list = [amp]
                for _, d, a in matches:
                    if d in unique_dids:
                        amps_list.append(a)

                events.append(
                    {
                        "peak_timestamp_ms": ts,
                        "station_ids": sorted(all_dids),
                        "num_stations": len(all_dids),
                        "mean_amplitude": sum(amps_list) / len(amps_list),
                    }
                )
                # Mark as used
                used_timestamps.add(ts)
                for ts2, did2, _ in matches:
                    if did2 in unique_dids:
                        used_timestamps.add(ts2)

        return events

    def clear_buffer(self) -> None:
        """Clear the burst buffer after processing."""
        self._buffer.clear()

    @property
    def buffer_size(self) -> int:
        """Total number of burst entries across all stations."""
        return sum(len(v) for v in self._buffer.values())
