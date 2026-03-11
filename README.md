# EarthSync Project (v1.1.29)

## Overview
EarthSync simulates, distributes, ingests, and visualizes time-series geospatial data, modeling Schumann Resonances (SR). It features a React **frontend** (v1.1.11), Node.js **backend** (v1.1.29, API/WebSocket/Ingest), Node.js **detectors**, Redis, PostgreSQL, and Prometheus/Grafana monitoring. All 10 services are orchestrated via Docker Compose.

**Version 1.1.29** includes enhanced server-side peak detection (smoothing, prominence, parabolic interpolation), peak tracking with persistent UUIDs, broadband/narrowband transient detection, Redis-to-PostgreSQL archival, client-side visualization of historical peak trends (Frequency, Amplitude, Q-Factor), and improved error feedback.

## API Documentation
See `backend/openapi.yaml` for the OpenAPI 3.0 specification. Routes are mounted with prefixes: auth at `/api/auth`, history at `/api/history`, ingest at `/api/data-ingest`, misc at `/`.

## Features (v1.1.29)
-   **Real-time 3D Visualization**: Plotly.js surface plot showing processed (downsampled) spectrogram data.
-   **Server-Side Analysis**:
    -   **Enhanced Peak Detection**: Smoothing, prominence checks, minimum distance filtering, absolute thresholding, and parabolic interpolation for sub-bin precision on **raw** data. Configurable via `backend/.env`.
    -   Q-Factor estimation via FWHM.
    -   **Peak Tracking**: Persistent UUID-based peak tracking across time steps with frequency tolerance matching. State persisted in PostgreSQL.
    -   **Transient Detection**: Broadband (global amplitude spike) and narrowband (localized frequency spike) transient detection using median baseline from recent Redis history.
    -   Detected peaks (Freq, Amp, Q-Factor, trackId, trackStatus) and transient info sent via WebSocket and stored historically.
-   **Data Ingest API**: Secure `POST /api/data-ingest` endpoint accepts batches of **raw** external sensor data (5501 points per spectrum). Requires `X-API-Key` header.
-   **Responsive Chart & Globe**:
    -   Interactive spectrogram visualization (2D heatmap and 3D surface).
    -   Globe shows detector locations; point color varies subtly with recent average peak amplitude. Tooltips show latest peak details.
-   **Historical Data & Visualization**:
    -   Retrieve downsampled spectrogram data via `GET /api/history/hours/:hours` or `/api/history/range`.
    -   Retrieve detected peak data (Freq, Amp, Q-Factor, trackId, trackStatus) via `GET /api/history/peaks/hours/:hours` or `/api/history/peaks/range`.
    -   Frontend displays 2D line charts of historical peak Frequency, Amplitude, and Q-Factor vs. Time grouped by Schumann mode with track segmentation.
    -   Data cached in Redis (Spectrograms in Lists, Peaks in Sorted Sets), archived to PostgreSQL.
-   **Data Archival**: Background archiver periodically moves old data from Redis to PostgreSQL to manage Redis memory.
-   **Multi-Detector Support**: 3 simulators (NYC, London, Sydney) run by default; augment/replace via the ingest API.
-   **User Authentication**: JWT-based registration (`POST /api/auth/register`) and login (`POST /api/auth/login`).
-   **Encrypted WebSockets**: Real-time data (downsampled spectrogram + peaks + transient info) streaming (AES-256-CBC per-user encryption).
-   **Stateless Server (Keys)**: User encryption keys stored in Redis with 1-hour TTL.
-   **Client Controls & Persistence**: Settings persist in `localStorage`.
-   **Improved Feedback**: Loading indicators, WS status, transient pulse animation, more specific Snackbar alerts.
-   **Backend Improvements**: Input validation, centralized error handling, graceful shutdown.
-   **Configurable Logging, Peak Detection & Transient Detection**: Via `.env` files.
-   **Monitoring**: Prometheus & Grafana dashboard includes ingest, peak detection, transient detection, archival, and Redis metrics.
-   **CI/CD**: GitHub Actions workflow builds and tests core features.
-   **Dockerized**: Full stack (10 services) defined in `docker-compose.yml` with health checks and resource limits.

## Prerequisites
-   Docker & Docker Compose (v2 recommended)
-   Git
-   Bash-compatible Shell
-   Recommended: `sudo sysctl vm.overcommit_memory=1` on host for Redis.

## Installation
1.  `git clone <repository-url>` or save the setup script and run it (`./setup_earthsync.sh`).
2.  `cd earthsync`
3.  **(IMPORTANT)** If upgrading, clean up old volumes: `docker compose down -v`
4.  Review `.env` files (especially `backend/.env` for `API_INGEST_KEY` and peak detection parameters).
5.  `docker compose up --build -d` (core services only)
6.  With monitoring: `docker compose --profile monitoring up --build -d`

## Usage
-   **Frontend**: `http://localhost:3080` (Register/Login, view real-time or historical data, including peak charts in historical mode).
-   **API / Data Ingest**: Not exposed on host; accessible only within the Docker network. Use the frontend or `docker compose exec` for direct access.
-   **Grafana**: `http://localhost:3082` (Anonymous Viewer access, monitoring profile only)
-   **Logs**: `docker compose logs -f <service_name>` (e.g. `backend`, `frontend`)

## Stopping
-   `docker compose down` (core services)
-   `docker compose --profile monitoring down` (includes monitoring)
-   `docker compose --profile monitoring down -v` (**Deletes all data**)

## Configuration
-   Managed via `.env` files and `docker-compose.yml`.
-   Set `API_INGEST_KEY` in `backend/.env`.
-   **Peak detection** parameters in `backend/.env`:
    -   `PEAK_SMOOTHING_WINDOW`: Points for moving average (odd integer, default 5).
    -   `PEAK_PROMINENCE_FACTOR`: Sensitivity relative to local noise (float > 0, default 1.5).
    -   `PEAK_MIN_DISTANCE_HZ`: Minimum frequency separation between peaks (float > 0, default 1.0).
    -   `PEAK_ABSOLUTE_THRESHOLD`: Minimum amplitude for a peak candidate (float >= 0, default 1.0).
    -   `PEAK_TRACKING_FREQ_TOLERANCE_HZ`: Hz tolerance for tracking same peak (float, default 0.5).
-   **Transient detection** parameters in `backend/.env`:
    -   `TRANSIENT_HISTORY_LOOKBACK`: Number of recent spectra for baseline (int, default 5).
    -   `TRANSIENT_BROADBAND_FACTOR`: Multiplier for broadband threshold (float, default 3.0).
    -   `TRANSIENT_BROADBAND_THRESHOLD_PCT`: Min percentage of bins above threshold (float, default 0.10).
    -   `TRANSIENT_NARROWBAND_FACTOR`: Multiplier for narrowband threshold (float, default 5.0).
    -   `TRANSIENT_NARROWBAND_IGNORE_HZ`: Hz range around known SR peaks to ignore (float, default 1.5).
-   **Data retention** in `backend/.env`:
    -   `REDIS_SPEC_RETENTION_HOURS`: Hours to keep spectrograms in Redis before archiving (default 24).
    -   `REDIS_PEAK_RETENTION_HOURS`: Hours to keep peaks in Redis before archiving (default 72).
    -   `CLEANUP_INTERVAL_MS`: Archival task interval in milliseconds (default 3600000).

## Monitoring Details
-   **Profile**: Monitoring services (`prometheus`, `redis-exporter`, `grafana`) use the `monitoring` profile. Start with `docker compose --profile monitoring up -d`.
-   Grafana Dashboard includes HTTP request rate, latency (P95), WebSocket connections, Redis key counts, spectrogram history length, peak detection rate, data ingest rate, and peak history size.

## Adding More Simulated Detectors
(Same as before - involves updating `docker-compose.yml`, optionally `prometheus.yml`, Grafana queries, and `redis-exporter` config).

## Troubleshooting
-   **WebSocket Timeout in CI/Locally:** If the WS test fails with a timeout:
    -   Check backend logs (`docker compose logs backend`) for errors during stream processing or WS broadcasting, especially around peak detection and key retrieval. Look for "WS send skip" messages.
    -   Temporarily increase `LOG_LEVEL` to `debug` in `backend/.env` and restart (`docker compose restart backend`) for more detail.
    -   Ensure Redis is healthy (`docker compose ps`).
    -   Try increasing `WS_MESSAGE_TIMEOUT` in the `integration.test.js` file further if the server appears slow under load (now defaults to 25000ms).
-   **No Peaks Detected/Too Many Peaks:** Adjust peak detection parameters in `backend/.env` and restart the backend (`docker compose restart backend`). Check backend logs for peak detection details.
-   **Data Ingest Issues:** Check backend logs for API key/validation errors (esp. spectrogram length - must be 5501). Check request headers and JSON payload.
-   **Historical Peak Charts Empty:** Ensure historical data exists (`docker compose exec redis redis-cli -a <password> SCAN 0 MATCH peaks:*`, `ZCARD peaks:<id>`). Check browser console for errors. Verify detector selection.
-   **Build Failures**: Check Docker daemon, Dockerfile syntax, `npm install` logs. Use `docker compose build --no-cache <service_name>`.
-   **Connection Issues**: Check `docker compose ps`, logs, `.env` files, port conflicts.
-   **Service Unhealthy**: Check logs, test healthcheck command.
-   **Redis `overcommit_memory`**: Apply `vm.overcommit_memory=1` or disable saves.
-   **No Data/Flat Chart**: Check browser console (F12). Check backend/detector logs. Check Redis (`XLEN spectrogram_stream`, `XRANGE spectrogram_stream - + COUNT 10`, `SCAN 0 MATCH userkey:*`, `SCAN 0 MATCH spectrogram_history:*`).
-   **Grafana Issues**: Run `docker compose down -v` first. Check logs.
-   **Settings Not Persisted**: Clear browser localStorage.

## License
MIT License. See [LICENSE](LICENSE) file.
