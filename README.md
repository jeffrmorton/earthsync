# EarthSync Project

## Overview
EarthSync simulates and visualizes Schumann Resonance data in 3D from multiple virtual detectors. It features a React client, Node.js backend (API/WebSocket), Node.js detectors, Redis (caching/messaging/key storage), PostgreSQL user storage, and Prometheus/Grafana monitoring. This version includes enhanced simulation, input validation, error handling, improved UI feedback, state persistence, and a stateless server architecture (regarding user keys).

## API Documentation
See `server/openapi.yaml` for the OpenAPI 3.0 specification. Use tools like Swagger UI or Postman to interact with the API at `http://localhost:3000`.

## Features
-   **Real-time 3D Visualization**: Plotly.js surface plot (Frequency: 0-55 Hz, Time, Amplitude).
-   **Responsive Full-Screen Chart**: Adapts to window size. Plotly controls enabled.
-   **Sidebar Globe**: `react-globe.gl` showing detector locations (Red=Active, Blue=Idle, Grey=Historical). Clickable points select detector. Width matches sidebar.
-   **Multi-Detector Support**: Default: `detector1` (NYC), `detector2` (London), `detector3` (Sydney). Easily extendable.
-   **User Authentication**: JWT-based registration/login.
-   **Encrypted WebSockets**: Real-time data streaming (AES-256-CBC). Key exchange required (key stored in Redis with TTL). Status indicator in UI. Stable connection with reconnect logic.
-   **Stateless Server (Keys)**: User encryption keys are stored in Redis, not server memory, allowing for horizontal scaling behind a load balancer.
-   **Historical Data**: Retrieve data (1-72h), cached in Redis (5min TTL). Filter by detector.
-   **Enhanced Simulation**: Includes diurnal amplitude variations and randomized peak sharpness/noise.
-   **Client Controls & Persistence**: Real-time/Historical toggle, Detector selection, Time window (30-600s), Color scale, Normalization, Theme toggle, Sidebar toggle, Logout. Most settings (except mode/hours) persist in `localStorage`.
-   **Improved Feedback**: Loading indicators (top bar, plot area) for data fetching/transitions, WebSocket connection status display, Snackbar alerts for errors.
-   **Backend Improvements**: Input validation (`express-validator`) on API endpoints, centralized error handling.
-   **Configurable Logging**: Set log levels via `.env` (defaults: `info` for server/detectors, `warn` for monitoring).
-   **Monitoring**: Prometheus & Grafana dashboard showing HTTP metrics, WS connections, Redis list lengths, and stored user key count.
-   **CI/CD**: GitHub Actions workflow builds, tests (API, WS, simulation), and cleans up.
-   **Dockerized**: Full stack defined in `docker-compose.yml` with healthchecks. Uses `npm install` for easier builds.

## Prerequisites
-   Docker & Docker Compose (v2 recommended for `docker compose` syntax)
-   Git
-   Bash-compatible Shell
-   Recommended: `sudo sysctl vm.overcommit_memory=1` on host for Redis stability.

## Installation
1.  `git clone <repository-url>` or save the setup script and run it (`./setup_earthsync.sh`).
2.  `cd earthsync`
3.  **(IMPORTANT)** If you ran previous versions of this script, clean up old volumes to prevent potential conflicts (especially with Grafana):
    `docker compose down -v`
4.  `docker compose up --build -d` (Use `docker-compose` if `docker compose` command is not available)

## Usage
-   **Client**: `http://localhost:3001` (Register/Login)
-   **API**: `http://localhost:3000` (See `openapi.yaml`)
-   **Prometheus**: `http://localhost:9090`
-   **Grafana**: `http://localhost:3002` (Anonymous viewing enabled. Login as admin/admin for editing if needed, unless defaults changed).
-   **Logs**: `docker compose logs -f <service_name>` (e.g., `server`, `detector1`)

## Stopping
-   `docker compose down` (Stop & remove containers)
-   `docker compose down -v` (Stop, remove containers & volumes - **Deletes all data**)

## Configuration
Managed via `.env` files (client, server, detector) and `docker-compose.yml` environment variables. Key storage is now in Redis (prefix `userkey:`, TTL matches JWT expiry). Grafana anonymous access is set to `Viewer`.

## Monitoring Details
-   **Prometheus**: Scrapes `server:3000/metrics` and `redis-exporter:9121/metrics`.
-   **Grafana Dashboard ("EarthSync Monitoring Dashboard")**:
    -   HTTP Request Rate & Latency (P95)
    -   Active WebSocket Connections
    -   Redis History List Length (per detector)
    -   Stored User Encryption Keys (Count)

## Adding More Detectors
1.  Duplicate a detector service (e.g., `detector3` -> `detector4`) in `docker-compose.yml`.
2.  Assign a unique `DETECTOR_ID` and desired `LATITUDE`, `LONGITUDE` in its `environment` section.
3.  Add the new history key (e.g., `spectrogram_history:detector4`) to `REDIS_EXPORTER_CHECK_SINGLE_KEYS` under the `redis-exporter` service.
4.  Update the Grafana dashboard JSON (`grafana/provisioning/dashboards/earthsync-dashboard.json`) query for "Redis Spectrogram History Length" to include the new key pattern (`key=~"spectrogram_history:detector.*"` should pick it up automatically), or add a new panel.
5.  Restart: `docker compose up -d --build --force-recreate`

## Troubleshooting
-   **Build Failures**: Check Docker daemon, Dockerfile syntax, `npm install` logs. Check network connectivity or `package.json` validity. Use `docker compose build --no-cache <service_name>`.
-   **Connection Issues**: Check `docker compose ps`, service logs (`docker compose logs ...`), `.env` files, port conflicts. Ensure services can reach Redis/Postgres by their service names.
-   **Service Unhealthy**: Check logs, test healthcheck command manually (`docker exec ...`).
-   **Redis `overcommit_memory`**: Apply `vm.overcommit_memory=1` on host or disable Redis saves.
-   **No Data/Flat Chart**: Check browser console (F12) for JS errors. Check `updateSpectrogram` logic. Verify server logs for stream processing errors or Redis key fetch errors. Check detector logs. Check Redis (`docker exec <redis_id> redis-cli -a password XLEN spectrogram_stream`, `XRANGE spectrogram_stream - + COUNT 1`, `SCAN 0 MATCH userkey:*`, `SCAN 0 MATCH spectrogram_history:*`).
-   **WebSocket Issues**: Check WS Status indicator. Check browser console/server logs for errors. If WS connects/disconnects, check `useEffect` dependencies and key retrieval logic. Ensure JWT/key TTLs match.
-   **Grafana Issues**:
    -   **Dashboard Not Loading/Provisioning Errors:** Run `docker compose down -v` then `docker compose up --build -d` to ensure a clean Grafana volume. Check Grafana logs (`docker compose logs grafana`). The `No available receivers` warning is expected. The `Could not make user admin ... userID=0` error *should* be resolved by setting the anonymous role to Viewer, but cleaning the volume is the best first step if it persists.
    -   **Metrics Not Showing:** Check Prometheus UI (`/targets`), ensure metric names match dashboard queries. Check Redis Exporter config in `docker-compose.yml`.
-   **Settings Not Persisted**: Clear browser localStorage for `localhost:3001`. Check console for `localStorage` errors.

## License
MIT License. See [LICENSE](LICENSE) file.
