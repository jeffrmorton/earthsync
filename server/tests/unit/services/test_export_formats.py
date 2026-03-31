"""Tests for data export format utilities."""

from __future__ import annotations

import csv
import io
import json

from earthsync_server.services.export_formats import (
    export_peaks_csv,
    export_peaks_json,
    export_spectra_csv,
)


class TestExportPeaksCsv:
    """Tests for export_peaks_csv()."""

    def test_csv_header_row(self):
        """CSV output starts with the expected header row."""
        result = export_peaks_csv([])
        reader = csv.reader(io.StringIO(result))
        header = next(reader)
        assert header == ["timestamp", "station_id", "freq_hz", "amplitude", "q_factor", "snr_db"]

    def test_csv_empty_data_header_only(self):
        """Empty peaks list produces header-only CSV (no data rows)."""
        result = export_peaks_csv([])
        lines = result.strip().split("\n")
        assert len(lines) == 1  # header only

    def test_csv_single_peak(self):
        """Single peak record produces correct CSV row."""
        peaks = [
            {
                "ts": 1700000000000,
                "stationId": "sierra-01",
                "peaks": [{"freq": 7.83, "amp": 80.5, "q_factor": 4.2, "snr": 12.5}],
            }
        ]
        result = export_peaks_csv(peaks)
        reader = csv.reader(io.StringIO(result))
        next(reader)  # skip header
        row = next(reader)
        assert row[0] == "1700000000000"
        assert row[1] == "sierra-01"
        assert row[2] == "7.8300"
        assert row[3] == "80.500000"
        assert row[4] == "4.2"
        assert row[5] == "12.5"

    def test_csv_multiple_peaks_per_record(self):
        """Multiple peaks in a single record produce multiple CSV rows."""
        peaks = [
            {
                "ts": 1700000000000,
                "stationId": "sierra-01",
                "peaks": [
                    {"freq": 7.83, "amp": 80.0, "q_factor": 4.0, "snr": 12.0},
                    {"freq": 14.3, "amp": 60.0, "q_factor": 5.0, "snr": 10.0},
                ],
            }
        ]
        result = export_peaks_csv(peaks)
        reader = csv.reader(io.StringIO(result))
        next(reader)  # skip header
        rows = list(reader)
        assert len(rows) == 2
        assert rows[0][2] == "7.8300"
        assert rows[1][2] == "14.3000"

    def test_csv_missing_q_factor(self):
        """Peak without q_factor produces empty q_factor field."""
        peaks = [
            {
                "ts": 1700000000000,
                "stationId": "test-01",
                "peaks": [{"freq": 7.83, "amp": 80.0}],
            }
        ]
        result = export_peaks_csv(peaks)
        reader = csv.reader(io.StringIO(result))
        next(reader)  # skip header
        row = next(reader)
        assert row[4] == ""  # q_factor
        assert row[5] == ""  # snr

    def test_csv_missing_snr(self):
        """Peak with q_factor but no snr produces empty snr field."""
        peaks = [
            {
                "ts": 1700000000000,
                "stationId": "test-01",
                "peaks": [{"freq": 7.83, "amp": 80.0, "q_factor": 4.0}],
            }
        ]
        result = export_peaks_csv(peaks)
        reader = csv.reader(io.StringIO(result))
        next(reader)  # skip header
        row = next(reader)
        assert row[4] == "4.0"
        assert row[5] == ""

    def test_csv_multiple_records(self):
        """Multiple peak records from different stations produce correct rows."""
        peaks = [
            {
                "ts": 1700000000000,
                "stationId": "sierra-01",
                "peaks": [{"freq": 7.83, "amp": 80.0, "q_factor": 4.0, "snr": 12.0}],
            },
            {
                "ts": 1700000001000,
                "stationId": "modra-01",
                "peaks": [{"freq": 14.3, "amp": 60.0, "q_factor": 5.0, "snr": 10.0}],
            },
        ]
        result = export_peaks_csv(peaks)
        reader = csv.reader(io.StringIO(result))
        next(reader)  # skip header
        rows = list(reader)
        assert len(rows) == 2
        assert rows[0][1] == "sierra-01"
        assert rows[1][1] == "modra-01"

    def test_csv_record_without_peaks_key(self):
        """Record with no 'peaks' key produces no data rows for that record."""
        peaks = [{"ts": 1700000000000, "stationId": "test-01"}]
        result = export_peaks_csv(peaks)
        lines = result.strip().split("\n")
        assert len(lines) == 1  # header only

    def test_csv_defaults_for_missing_fields(self):
        """Missing ts and stationId default to 0 and 'unknown'."""
        peaks = [{"peaks": [{"freq": 7.83, "amp": 80.0}]}]
        result = export_peaks_csv(peaks)
        reader = csv.reader(io.StringIO(result))
        next(reader)  # skip header
        row = next(reader)
        assert row[0] == "0"
        assert row[1] == "unknown"


class TestExportSpectraCsv:
    """Tests for export_spectra_csv()."""

    def test_spectra_csv_header(self):
        """Spectra CSV header has timestamp, station_id, and 1101 frequency columns."""
        result = export_spectra_csv([])
        reader = csv.reader(io.StringIO(result))
        header = next(reader)
        assert header[0] == "timestamp"
        assert header[1] == "station_id"
        assert len(header) == 1103  # 2 metadata + 1101 freq bins
        assert header[2] == "0.00Hz"
        assert header[-1] == "55.00Hz"

    def test_spectra_csv_empty_data(self):
        """Empty spectrogram list produces header-only CSV."""
        result = export_spectra_csv([])
        lines = result.strip().split("\n")
        assert len(lines) == 1

    def test_spectra_csv_single_record(self):
        """Single spectrogram record produces one data row."""
        spectrum = [float(i) * 0.001 for i in range(1101)]
        spectrograms = [
            {
                "timestamp_ms": 1700000000000,
                "station_id": "sierra-01",
                "spectrogram": spectrum,
            }
        ]
        result = export_spectra_csv(spectrograms)
        reader = csv.reader(io.StringIO(result))
        next(reader)  # skip header
        row = next(reader)
        assert row[0] == "1700000000000"
        assert row[1] == "sierra-01"
        assert len(row) == 1103
        assert row[2] == "0.000000"

    def test_spectra_csv_defaults_for_missing_fields(self):
        """Missing timestamp_ms and station_id default to 0 and 'unknown'."""
        spectrograms = [{"spectrogram": [1.0, 2.0]}]
        result = export_spectra_csv(spectrograms)
        reader = csv.reader(io.StringIO(result))
        next(reader)  # skip header
        row = next(reader)
        assert row[0] == "0"
        assert row[1] == "unknown"

    def test_spectra_csv_empty_spectrogram(self):
        """Record with empty spectrogram produces row with metadata only."""
        spectrograms = [{"timestamp_ms": 1700000000000, "station_id": "test-01", "spectrogram": []}]
        result = export_spectra_csv(spectrograms)
        reader = csv.reader(io.StringIO(result))
        next(reader)  # skip header
        row = next(reader)
        assert row[0] == "1700000000000"
        assert row[1] == "test-01"
        assert len(row) == 2  # no spectrum values


class TestExportPeaksJson:
    """Tests for export_peaks_json()."""

    def test_json_empty(self):
        """Empty peaks list produces '[]'."""
        result = export_peaks_json([])
        assert json.loads(result) == []

    def test_json_single_peak(self):
        """Single peak record round-trips through JSON."""
        peaks = [
            {
                "ts": 1700000000000,
                "stationId": "sierra-01",
                "peaks": [{"freq": 7.83, "amp": 80.0}],
            }
        ]
        result = export_peaks_json(peaks)
        parsed = json.loads(result)
        assert len(parsed) == 1
        assert parsed[0]["stationId"] == "sierra-01"
        assert parsed[0]["peaks"][0]["freq"] == 7.83

    def test_json_formatted(self):
        """JSON output is pretty-printed (indented)."""
        peaks = [{"ts": 1, "peaks": []}]
        result = export_peaks_json(peaks)
        assert "\n" in result  # indented output has newlines

    def test_json_preserves_types(self):
        """JSON output preserves int, float, string, None types."""
        peaks = [
            {
                "ts": 1700000000000,
                "stationId": "test",
                "peaks": [{"freq": 7.83, "amp": 80.0, "q_factor": None}],
            }
        ]
        result = export_peaks_json(peaks)
        parsed = json.loads(result)
        assert isinstance(parsed[0]["ts"], int)
        assert isinstance(parsed[0]["peaks"][0]["freq"], float)
        assert parsed[0]["peaks"][0]["q_factor"] is None
