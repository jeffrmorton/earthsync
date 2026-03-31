"""Peak tracking across time -- UUID assignment for continuity.

Pure function: takes previous state and current peaks, returns
tracked peaks with persistent UUIDs and new state.
"""

from __future__ import annotations

import uuid

from earthsync_server.models import DetectedPeak, TrackedPeak


def track_peaks(
    previous_state: list[dict],
    current_peaks: list[DetectedPeak],
    timestamp_ms: int,
    freq_tolerance_hz: float = 0.5,
) -> tuple[list[TrackedPeak], list[dict]]:
    """Match current peaks to previous state for temporal continuity.

    For each current peak, finds the closest match in the previous state
    within the frequency tolerance. Matched peaks reuse their UUID and
    get status "continuing"; unmatched peaks receive a new UUID and
    status "new".

    Args:
        previous_state: List of dicts with keys {id, freq, amp, last_ts}.
        current_peaks: Currently detected peaks.
        timestamp_ms: Current timestamp in milliseconds.
        freq_tolerance_hz: Maximum frequency difference for a match (Hz).

    Returns:
        Tuple of (tracked_peaks, new_state) where new_state has the same
        dict format as previous_state.
    """
    tracked: list[TrackedPeak] = []
    new_state: list[dict] = []

    # Track which previous-state entries have been claimed
    claimed: set[int] = set()

    for peak in current_peaks:
        best_idx: int | None = None
        best_dist = float("inf")

        for i, prev in enumerate(previous_state):
            if i in claimed:
                continue
            dist = abs(peak.freq - prev["freq"])
            if dist <= freq_tolerance_hz and dist < best_dist:
                best_dist = dist
                best_idx = i

        if best_idx is not None:
            claimed.add(best_idx)
            track_id = previous_state[best_idx]["id"]
            status = "continuing"
        else:
            track_id = str(uuid.uuid4())
            status = "new"

        tracked.append(
            TrackedPeak(
                freq=peak.freq,
                amp=peak.amp,
                q_factor=peak.q_factor,
                freq_err=peak.freq_err,
                amp_err=peak.amp_err,
                q_err=peak.q_err,
                snr=peak.snr,
                track_status=status,
                track_id=track_id,
            )
        )

        new_state.append(
            {
                "id": track_id,
                "freq": peak.freq,
                "amp": peak.amp,
                "last_ts": timestamp_ms,
            }
        )

    return tracked, new_state
