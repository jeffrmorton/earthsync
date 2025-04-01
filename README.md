# EarthSync Project (v1.1.8)

## Overview
EarthSync simulates, distributes, ingests, and visualizes time-series geospatial data, specifically modeling Schumann Resonances (SR). It features a React client, Node.js backend (API/WebSocket/Ingest), Node.js detectors, Redis, PostgreSQL, and Prometheus/Grafana monitoring.

**Version 1.1.8 Enhancements:**
-   **Enhanced Peak Detection:** Server uses smoothing, prominence, minimum distance, and absolute threshold criteria (configurable via `.env`) for more robust peak identification on raw data. Q-Factor estimation uses interpolation.
-   **Historical Peak Visualization:** Client displays historical peak trends (Freq, Amp, Q-Factor) as 2D charts when in historical mode.
-   **Globe Enhancement:** Client globe points subtly change color based on recent average peak amplitude.
-   **Improved Client Feedback:** More specific error messages in the UI.

## API Documentation
See `server/openapi.yaml` for the OpenAPI 3.0 specification (v1.1.8).

## Features
-   Real-time 3D Spectrogram Visualization (Downsampled Data).
-   Server-Side Analysis: Enhanced Peak detection (Freq, Amp, Q-Factor) on **raw** data.
-   Data Ingest API: Secure `/data-ingest` endpoint for batches of **raw** sensor data (5501 points/spectrum).
-   Responsive Chart & Globe: Interactive components with peak info tooltips.
-   Multi-Detector Support: Simulation + Ingest.
-   User Authentication (JWT).
-   Encrypted WebSockets (AES-256-CBC).
-   Stateless Server (Redis for keys).
-   Historical Data API:
    -   `/history/:hours`: Downsampled spectrograms.
    -   `/history/peaks/:hours`: Detected peak history (Freq, Amp, Q-Factor, Timestamp).
-   Enhanced Simulation: Diurnal variations, randomized parameters.
-   Client Controls & Persistence: Settings saved in `localStorage`.
-   Improved Feedback & Error Reporting.
-   Configurable Logging & Peak Detection.
-   Monitoring: Prometheus & Grafana dashboard.
-   CI/CD: GitHub Actions workflow.
-   Dockerized: Full stack via `docker-compose.yml`.

## Prerequisites
-   Docker & Docker Compose (v2 recommended)
-   Git
-   Bash-compatible Shell
-   Optional Host Tweak: `sudo sysctl vm.overcommit_memory=1` (for Redis background saves)

## Installation
1.  `git clone <repository-url>` or save the setup script and run it (`./setup_earthsync.sh`).
2.  `cd earthsync`
3.  **(IMPORTANT)** If upgrading, clean up old volumes: `docker compose down -v`
4.  Review `.env` files (especially `server/.env` for `API_INGEST_KEY` and peak detection params).
5.  `docker compose up --build -d`

## Usage
-   **Client**: `http://localhost:3001`
-   **API**: `http://localhost:3000`
-   **Data Ingest**: `POST http://localhost:3000/data-ingest` (Requires `X-API-Key` header and valid JSON body - see `openapi.yaml`).
    ```bash
    # Example using curl (replace YOUR_API_KEY, send batch of 1)
    curl -X POST http://localhost:3000/data-ingest \
      -H "Content-Type: application/json" \
      -H "X-API-Key: YOUR_API_KEY" \
      -d '{
            "detectorId": "my_sensor_01",
            "location": {"lat": 50.0, "lon": 10.0},
            "spectrograms": [ [<5501 raw amplitude values here>] ]
          }'
    ```
-   **Prometheus**: `http://localhost:9090`
-   **Grafana**: `http://localhost:3002` (Anonymous Viewer access)
-   **Logs**: `docker compose logs -f <service_name>`

## Stopping
-   `docker compose down`
-   `docker compose down -v` (**Deletes all data**)

## Configuration
-   Managed via `.env` files and `docker-compose.yml`.
-   **Server (`server/.env`):**
    -   `API_INGEST_KEY`: **Set a secure key for production.**
    -   `PEAK_SMOOTHING_WINDOW`: Points for moving average (odd integer, default 5).
    -   `PEAK_PROMINENCE_FACTOR`: Factor of noise level for prominence (default 1.5).
    -   `PEAK_MIN_DISTANCE_HZ`: Min frequency separation between peaks (default 1.0).
    -   `PEAK_ABSOLUTE_THRESHOLD`: Minimum amplitude for a peak candidate (default 1.0).
-   Other env vars control ports, credentials, logging, etc.

## Monitoring Details
-   Grafana Dashboard includes panels for system health, API/WS stats, Redis usage, and data flow metrics (ingest, peaks detected).

## Adding More Simulated Detectors
(Same process as v1.1.7 - see previous README section if needed).

## Troubleshooting
-   **Data Ingest Issues:** Check server logs (`docker compose logs server`) for API key/validation errors (esp. spectrogram length - must be 5501). Ensure `Content-Type: application/json`, correct `X-API-Key`, and valid JSON payload (`spectrograms` array).
-   **Peak Detection Issues:** Check server logs. Check `peaks_detected_total` metric in Grafana. Adjust peak detection params in `server/.env` and restart (`docker compose up -d --build server`). Check client sidebar/tooltips/historical charts. Check Redis (`SCAN 0 MATCH peaks:*`, `ZCARD peaks:<id>`, `ZRANGE peaks:<id> 0 -1 WITHSCORES`).
-   **Build Failures**: Check Docker daemon status, Dockerfile syntax, `npm install` logs. Use `docker compose build --no-cache <service_name>`.
-   **Connection Issues**: Check `docker compose ps`, logs, `.env` files, host port conflicts.
-   **Service Unhealthy**: Check service logs, test healthcheck command manually inside container (`docker compose exec <service_name> <healthcheck_cmd>`).
-   **Redis `overcommit_memory`**: Apply `vm.overcommit_memory=1` or disable saves in Redis config (not default here).
-   **No Data/Flat Chart**: Check browser console (F12). Check server/detector logs. Check Redis stream (`XLEN spectrogram_stream`, `XRANGE spectrogram_stream - + COUNT 10`) and other keys (`SCAN 0 MATCH userkey:*`, `SCAN 0 MATCH spectrogram_history:*`).
-   **WebSocket Issues**: Check WS Status indicator in client UI. Check browser/server logs. Check JWT/key TTLs. Check network policies/firewalls.
-   **Grafana Issues**: Try `docker compose down -v && docker compose up -d --build`. Check Grafana logs (`docker compose logs grafana`).
-   **Settings Not Persisted**: Clear browser localStorage for the client's origin (`http://localhost:3001`).

## License
MIT License. See [LICENSE](LICENSE) file.
