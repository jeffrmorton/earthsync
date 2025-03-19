# EarthSync Project

## Overview
EarthSync is a web application that visualizes Schumann Resonance data in 3D from multiple detectors worldwide. It features a client interface with a perfectly placed full-screen 3D chart spanning 0-55 Hz accurately, a globe at the bottom of the sidebar showing detector locations, a server for API and WebSocket connections, detectors generating synthetic data with geospatial metadata, and monitoring with Prometheus and Grafana.

## API Documentation
The server API is documented using OpenAPI 3.0. See `server/openapi.yaml` for the full specification. Import it into tools like Swagger UI to explore endpoints.

## Features
- Real-time 3D visualization of Schumann Resonance with labeled axes (Frequency: 0-55 Hz, Time, Amplitude).
- Full-screen 3D chart that adjusts to window size, with a yellow line highlighting the last active detector’s data, perfectly centered and unobstructed.
- Globe at the bottom of the sidebar (200x200 pixels) displaying detector locations (red when active within 5 seconds, blue when idle) with hoverable location tooltips.
- Multi-detector support with unique IDs (e.g., `detector1`, `detector2`, `detector3`).
- User authentication (register/login).
- Historical data retrieval with server-side caching (5-minute TTL) and detector filtering by ID.
- Adjustable time windows, color scales, and normalization.
- Configurable log levels via environment variables (default: `info` for detectors/server, `warn` for others).
- Monitoring with Prometheus and Grafana (HTTP requests, WebSocket connections, Redis queue length for all detectors).
- CI/CD pipeline with GitHub Actions.
- Dockerized deployment with healthchecks.
- HTTP support for development (HTTPS can be enabled with certificates).
- Performance optimizations: server-side downsampling (default factor 5), client-side throttle (1000ms).
- Aesthetic enhancements: detailed night Earth texture and glow effect on active detectors.

## Prerequisites
- Docker
- Docker Compose
- GitHub account for CI/CD
- Bash-compatible shell (Linux/macOS; on Windows, use Git Bash or WSL2)
- Host configuration: Enable memory overcommit for Redis stability (`sudo sysctl vm.overcommit_memory=1` or edit `/etc/sysctl.conf` and reboot)

## Installation
1. Clone or download the repository.
2. Navigate to the project directory: `cd earthsync`
3. Combine the setup scripts: `cat part1.sh part2.sh part3.sh part4.sh > setup_earthsync.sh && chmod +x setup_earthsync.sh`
4. Run the setup script: `./setup_earthsync.sh`
5. Start the application: `docker-compose up --build`

## Usage
- **Client Interface**: Open `http://localhost:3001`, log in or register, and view the interface. The left sidebar contains controls and a globe at the bottom showing detector locations. The main area displays a full-screen 3D spectrogram plot with accurate 0-55 Hz frequency range. Use the sidebar to switch between real-time and historical data, select a detector by ID, adjust settings, or toggle themes. The client connects to `http://localhost:3000` for API and WebSocket data.
- **Prometheus Metrics**: Access at `http://localhost:9090` for raw metrics.
- **Grafana Dashboard**: Access at `http://localhost:3002` (anonymous access enabled with Admin role). The "EarthSync Server Metrics" dashboard shows HTTP request rates, WebSocket connections, and Redis queue lengths for all detectors.
- **Logs**: View service logs with `docker-compose logs <service_name>` (e.g., `server`, `detector1`). Detectors and server use `info` level for detailed output; others use `warn`.

## Stopping the Application
- Stop and remove containers: `docker-compose down`
- Stop and remove containers with volumes (reset data): `docker-compose down -v`

## Environment Variables
Edit `.env` files in `client`, `server`, and `detector` directories:
- `REACT_APP_API_BASE_URL` (client): API endpoint (default: `http://localhost:3000`)
- `REACT_APP_WS_URL` (client): WebSocket endpoint (default: `ws://localhost:3000`)
- `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`: Redis connection details
- `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`: PostgreSQL details
- `JWT_SECRET`: JWT secret (set in `docker-compose.yml`)
- `DETECTOR_INTERVAL`: Data generation interval (ms, default: 5000)
- `DETECTOR_BATCH_SIZE`: Spectrograms per batch (default: 2)
- `DETECTOR_ID`: Unique detector identifier (e.g., `detector1`)
- `LATITUDE`, `LONGITUDE`: Detector GPS coordinates (e.g., 40.7128, -74.0060 for New York)
- `LOG_LEVEL`: Log level (e.g., `info` for detectors/server, `warn` for others)
- `REDIS_EXPORTER_LOG_LEVEL`: Log level for Redis Exporter (default: `warn`)
- `GF_LOG_LEVEL`: Log level for Grafana (default: `warn`)
- `CLEANUP_INTERVAL_MS`: Redis history cleanup interval (ms, default: 3600000)
- `DOWNSAMPLE_FACTOR`: Spectrogram downsampling factor (default: 5)

## Resource Limits
Docker Compose sets the following limits (adjust in `docker-compose.yml`):
- **redis**: 0.5 CPU, 512MB RAM
- **redis-exporter**: 0.2 CPU, 128MB RAM
- **postgres**: 0.5 CPU, 512MB RAM
- **server**: 1.0 CPU, 1GB RAM
- **detector1, detector2, detector3**: 0.5 CPU, 256MB RAM each
- **client**: 0.5 CPU, 256MB RAM
- **prometheus**: 0.5 CPU, 256MB RAM
- **grafana**: 0.5 CPU, 256MB RAM

## Monitoring
- **Prometheus**: Scrapes metrics from `http://server:3000/metrics` and `http://redis-exporter:9121`. Access at `http://localhost:9090`. Logs are set to `warn` level via `--log.level=warn`.
- **Grafana**: Uses Prometheus as a data source, displaying:
  - **HTTP Requests Rate**: Requests per second by method, route, and status.
  - **WebSocket Connections**: Active connections over time.
  - **Redis Spectrogram History Length**: Length of `spectrogram_history:detector1`, `detector2`, and `detector3` queues.
  Logs are set to `warn` level via `GF_LOG_LEVEL=warn`.
- **Redis Exporter**: Runs on port 9121, exposing metrics for all detector history keys. Verify at `http://localhost:9121/metrics`. Logs are set to `warn` level.

## Adding More Detectors
To add detectors:
1. Duplicate a detector service in `docker-compose.yml` (e.g., `detector4`).
2. Set unique `DETECTOR_ID`, `LATITUDE`, and `LONGITUDE` in the `environment` section.
3. Update `REDIS_EXPORTER_CHECK_SINGLE_KEYS` in `redis-exporter` to include the new key (e.g., `spectrogram_history:detector4`).
4. Restart with `docker-compose up -d --build`.

## Troubleshooting
- **Build fails**: Ensure Docker and Docker Compose are running (`docker --version`, `docker-compose --version`).
- **Connection issues**: Check ports (3000, 3001, 6379, 5432, 9121, 9090, 3002) and `.env` consistency.
- **Service unhealthy**: Inspect logs (`docker-compose logs <service>`). For Redis, test with `docker exec -it earthsync-redis-1 redis-cli -a password ping`.
- **Redis overcommit warning**: Enable `vm.overcommit_memory=1` on the host (`sudo sysctl vm.overcommit_memory=1`) or uncomment `--save ""` in Redis `command` to disable saves (less reliable).
- **Grafana network errors**: Update/plugin check failures are disabled with `GF_CHECK_FOR_UPDATES=false`. Ensure outbound HTTPS is allowed if re-enabling.
- **Grafana user admin error**: Anonymous access is enabled with Admin role; access `http://localhost:3002` without login.
- **Silent detectors/server**: Logs are set to `info`; check for Redis/Postgres connection errors (`docker-compose logs server detector1`).
- **Redis-Exporter latency error**: Fixed with Redis 7; verify metrics at `http://localhost:9121/metrics`.
- **Chart not resizing**: Verify `flex: 1` and `height: '100%'` in the `Plotly` `Box`. Check browser DevTools for CSS overrides.
- **Globe not at bottom**: Adjust `flexGrow: 1` on the upper `Box` or add `mt: 'auto'` to the globe’s `Box`.
- **Data issues**: Check console logs for `zData`, `displayData`, and `xLabels`. Ensure `spectrogramData` contains valid arrays spanning 0-55 Hz.
- **Historical data missing**: Check Redis for detector-specific keys (`docker exec -it earthsync-redis-1 redis-cli -a password keys spectrogram_history:*`).
- **WebSocket disconnects**: Review server logs for stream errors and detector logs for publishing issues.
- **Test failures**: If history test fails on detector count, ensure all detectors are pre-populated with data in the test. Verify Redis keys and server logs.

## CI/CD with GitHub Actions
The `build-and-test.yml` workflow:
- Builds all Docker images on push/PR to `main`.
- Tests API endpoints, WebSocket connectivity, multi-detector data, and frequency range (0-55 Hz) integrity.
- Cleans up resources afterward.

## License
MIT License (see LICENSE file for details).
