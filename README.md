# EarthSync Project (v1.1.8)

## Overview
EarthSync simulates, distributes, ingests, and visualizes time-series geospatial data, modeling Schumann Resonances (SR). It features a React client, Node.js backend (API/WebSocket/Ingest), Node.js detectors, Redis, PostgreSQL, and Prometheus/Grafana monitoring.

**Version 1.1.8** introduces enhanced server-side peak detection (smoothing, prominence, configurable parameters), client-side visualization of historical peak trends (Frequency, Amplitude, Q-Factor), improved error feedback, and minor globe enhancements.

## API Documentation
See `server/openapi.yaml` (v1.1.8) for the OpenAPI 3.0 specification. No major API *endpoint* changes from v1.1.7, but the underlying peak detection is improved.

## Features (v1.1.8)
-   **Real-time 3D Visualization**: Plotly.js surface plot showing processed (downsampled) spectrogram data.
-   **Server-Side Analysis**:
    -   **Enhanced Peak Detection**: Now uses smoothing, prominence checks, minimum distance filtering, and absolute thresholding on **raw** data for more robust peak finding. Configurable via `server/.env`.
    -   Q-Factor estimation with interpolation.
    -   Detected peaks (Freq, Amp, Q-Factor) sent via WebSocket and stored historically.
    -   Placeholders for future peak tracking and transient detection logic.
-   **Data Ingest API**: Secure `/data-ingest` endpoint accepts batches of **raw** external sensor data (5501 points per spectrum).
-   **Responsive Chart & Globe**:
    -   Interactive spectrogram visualization.
    -   Globe shows detector locations; point color varies subtly with recent average peak amplitude. Tooltips show latest peak details.
-   **Historical Data & Visualization**:
    -   Retrieve downsampled spectrogram data via `/history/:hours`.
    -   Retrieve detected peak data (Freq, Amp, Q-Factor, Timestamp) via `/history/peaks/:hours`.
    -   **New:** Client displays 2D line charts of historical peak Frequency, Amplitude, and Q-Factor vs. Time for the selected detector.
    -   Data cached in Redis (Spectrograms in Lists, Peaks in Sorted Sets).
-   **Multi-Detector Support**: Simulators run by default; augment/replace via the ingest API.
-   **User Authentication**: JWT-based registration/login.
-   **Encrypted WebSockets**: Real-time data (downsampled spectrogram + peaks) streaming (AES-256-CBC).
-   **Stateless Server (Keys)**: User encryption keys stored in Redis.
-   **Client Controls & Persistence**: Settings persist in `localStorage`.
-   **Improved Feedback**: Loading indicators, WS status, more specific Snackbar alerts.
-   **Backend Improvements**: Input validation, centralized error handling.
-   **Configurable Logging & Peak Detection**: Via `.env` files.
-   **Monitoring**: Prometheus & Grafana dashboard includes ingest, peak detection, and Redis metrics.
-   **CI/CD**: GitHub Actions workflow builds and tests core features.
-   **Dockerized**: Full stack defined in `docker-compose.yml`.

## Prerequisites
-   Docker & Docker Compose (v2 recommended)
-   Git
-   Bash-compatible Shell
-   Recommended: `sudo sysctl vm.overcommit_memory=1` on host for Redis.

## Installation
1.  `git clone <repository-url>` or save the setup script and run it (`./setup_earthsync.sh`).
2.  `cd earthsync`
3.  **(IMPORTANT)** If upgrading, clean up old volumes: `docker compose down -v`
4.  Review `.env` files (especially `server/.env` for `API_INGEST_KEY` and peak detection parameters).
5.  `docker compose up --build -d`

## Usage
-   **Client**: `http://localhost:3001` (Register/Login, view real-time or historical data, including new peak charts in historical mode).
-   **API**: `http://localhost:3000`
-   **Data Ingest**: `POST http://localhost:3000/data-ingest` (Requires `X-API-Key` header and valid JSON body - see `openapi.yaml`).
-   **Prometheus**: `http://localhost:9090`
-   **Grafana**: `http://localhost:3002` (Anonymous Viewer access)
-   **Logs**: `docker compose logs -f <service_name>`

## Stopping
-   `docker compose down`
-   `docker compose down -v` (**Deletes all data**)

## Configuration
-   Managed via `.env` files and `docker-compose.yml`.
-   Set `API_INGEST_KEY` in `server/.env`.
-   Adjust peak detection parameters in `server/.env`:
    -   `PEAK_SMOOTHING_WINDOW`: Points for moving average (odd integer, default 5).
    -   `PEAK_PROMINENCE_FACTOR`: Sensitivity relative to local noise (float > 0, default 1.5).
    -   `PEAK_MIN_DISTANCE_HZ`: Minimum frequency separation between peaks (float > 0, default 1.0).
    -   `PEAK_ABSOLUTE_THRESHOLD`: Minimum amplitude for a peak candidate (float >= 0, default 1.0).

## Monitoring Details
-   Grafana Dashboard updated to reflect metrics accurately.

## Adding More Simulated Detectors
(Same as before - involves updating `docker-compose.yml`, optionally `prometheus.yml`, Grafana queries, and `redis-exporter` config).

## Troubleshooting
-   **No Peaks Detected/Too Many Peaks:** Adjust peak detection parameters in `server/.env` and restart the server (`docker compose restart server`). Check server logs for peak detection details.
-   **Data Ingest Issues:** Check server logs for API key/validation errors (esp. spectrogram length - must be 5501). Check request headers and JSON payload.
-   **Historical Peak Charts Empty:** Ensure historical data exists (`docker compose exec redis redis-cli -a <password> SCAN 0 MATCH peaks:*`, `ZCARD peaks:<id>`). Check browser console for errors. Verify detector selection.
-   **Build Failures**: Check Docker daemon, Dockerfile syntax, `npm install` logs. Use `docker compose build --no-cache <service_name>`.
-   **Connection Issues**: Check `docker compose ps`, logs, `.env` files, port conflicts.
-   **Service Unhealthy**: Check logs, test healthcheck command.
-   **Redis `overcommit_memory`**: Apply `vm.overcommit_memory=1` or disable saves.
-   **No Data/Flat Chart**: Check browser console (F12). Check server/detector logs. Check Redis (`XLEN spectrogram_stream`, `XRANGE spectrogram_stream - + COUNT 10`, `SCAN 0 MATCH userkey:*`, `SCAN 0 MATCH spectrogram_history:*`).
-   **WebSocket Issues**: Check WS Status indicator. Check browser/server logs. Check JWT/key TTLs.
-   **Grafana Issues**: Run `docker compose down -v` first. Check logs.
-   **Settings Not Persisted**: Clear browser localStorage.

## License
MIT License. See [LICENSE](LICENSE) file.
