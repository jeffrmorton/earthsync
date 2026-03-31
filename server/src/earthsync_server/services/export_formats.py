"""Data export in standard geophysics formats."""

from __future__ import annotations

import csv
import io
import json


def export_peaks_csv(peaks: list[dict]) -> str:
    """Export peaks as CSV string.

    Args:
        peaks: List of peak records from the data store. Each record has
            'ts' (timestamp), 'stationId', and 'peaks' (list of peak dicts
            with 'freq', 'amp', 'q_factor', 'snr').

    Returns:
        CSV-formatted string with header row and one row per individual peak.
    """
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp", "station_id", "freq_hz", "amplitude", "q_factor", "snr_db"])
    for record in peaks:
        ts = record.get("ts", 0)
        station = record.get("stationId", "unknown")
        for peak in record.get("peaks", []):
            writer.writerow(
                [
                    ts,
                    station,
                    f"{peak.get('freq', 0):.4f}",
                    f"{peak.get('amp', 0):.6f}",
                    f"{peak.get('q_factor', '')}" if peak.get("q_factor") else "",
                    f"{peak.get('snr', ''):.1f}" if peak.get("snr") else "",
                ]
            )
    return output.getvalue()


def export_spectra_csv(spectrograms: list[dict]) -> str:
    """Export spectrograms as CSV (one row per time step, columns = frequency bins).

    Args:
        spectrograms: List of spectrogram records from the data store.
            Each record has 'timestamp_ms', 'station_id', and 'spectrogram'
            (list of float values).

    Returns:
        CSV-formatted string with frequency-bin columns.
    """
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp", "station_id", *[f"{i * 0.05:.2f}Hz" for i in range(1101)]])
    for record in spectrograms:
        ts = record.get("timestamp_ms", 0)
        station = record.get("station_id", "unknown")
        spectrum = record.get("spectrogram", [])
        writer.writerow([ts, station, *[f"{v:.6f}" for v in spectrum]])
    return output.getvalue()


def export_peaks_json(peaks: list[dict]) -> str:
    """Export peaks as formatted JSON.

    Args:
        peaks: List of peak records from the data store.

    Returns:
        Pretty-printed JSON string.
    """
    return json.dumps(peaks, indent=2, default=str)
