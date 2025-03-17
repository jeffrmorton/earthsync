# EarthSync Project

## Overview
EarthSync is a web application that visualizes Schumann Resonance data in 3D using real-time spectrogram data. It includes a client interface, a server for handling API and WebSocket connections, a detector to generate synthetic data, and monitoring with Prometheus and Grafana.

## API Documentation
The server API is documented using OpenAPI 3.0. See `server/openapi.yaml` for the full specification. You can view it with tools like Swagger UI by importing the file.

## Features
- Real-time 3D visualization of Schumann Resonance with labeled axes (Frequency, Time, Amplitude).
- User authentication (register/login).
- Historical data retrieval with server-side caching (5-minute TTL).
- Adjustable time windows, color scales, and normalization.
- Configurable log levels via environment variables.
- Monitoring with Prometheus and Grafana (HTTP requests, WebSocket connections, Redis queue length).
- CI/CD pipeline with GitHub Actions.
- Dockerized deployment with healthchecks.
- HTTP support for development (HTTPS can be enabled with proper certificates).
- Performance optimizations: server-side downsampling (configurable factor, default 5) and caching for historical data.

## Prerequisites
- Docker
- Docker Compose
- GitHub account for CI/CD
- Bash-compatible shell (Linux/macOS; on Windows, use Git Bash or WSL2)

## Installation
1. Clone or download the repository.
2. Navigate to the project directory: `cd earthsync`
3. Combine the setup scripts: `cat part1.sh part2.sh > setup_earthsync.sh && chmod +x setup_earthsync.sh`
4. Run the setup script: `./setup_earthsync.sh`
5. Start the application: `docker-compose up --build`

## Usage
- **Client Interface**: Open `http://localhost:3001` in your browser, log in or register with a username and password, and use the interface to switch between real-time and historical data, adjust settings, and toggle themes. The client uses `http://localhost:3000` as the API and WebSocket endpoint.
- **Prometheus Metrics**: Access at `http://localhost:9090` to view raw metrics scraped from the server and Redis exporter.
- **Grafana Dashboard**: Access at `http://localhost:3002` (default login: admin/admin). The "EarthSync Server Metrics" dashboard is pre-configured and loaded automatically with Prometheus as the data source, displaying:
  - **HTTP Requests Rate**: Rate of HTTP requests per second, broken down by method, route, and status.
  - **WebSocket Connections**: Number of active WebSocket connections over time.
  - **Redis Spectrogram History Length**: Length of the `spectrogram_history` list in Redis.
- **Logs**: Check service logs with `docker-compose logs <service_name>` (e.g., `docker-compose logs server`).

## Stopping the Application
- Stop and remove containers: `docker-compose down`
- Stop and remove containers with volumes (reset data): `docker-compose down -v`

## Environment Variables
Edit `.env` files in `client`, `server`, and `detector` directories to configure:
- `REACT_APP_API_BASE_URL` (client): API endpoint (default: `http://localhost:3000`)
- `REACT_APP_WS_URL` (client): WebSocket endpoint (default: `ws://localhost:3000`)
- `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`: Redis connection details
- `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`: PostgreSQL details
- `JWT_SECRET`: Secret for JWT authentication (set in `docker-compose.yml`)
- `DETECTOR_INTERVAL`: Interval for detector data generation (ms, default: 5000)
- `DETECTOR_BATCH_SIZE`: Number of spectrograms per batch (default: 2)
- `LOG_LEVEL`: Log level (e.g., `error`, `warn`, `info`, `debug`, default: `info`)
- `CLEANUP_INTERVAL_MS`: Server cleanup interval for Redis history (ms, default: 3600000)
- `DOWNSAMPLE_FACTOR`: Factor for server-side spectrogram downsampling (default: 5, reducing 5501 points to ~1100)

## Resource Limits
Docker Compose sets the following resource limits (adjust in `docker-compose.yml` as needed):
- **redis**: 0.5 CPU, 512MB RAM
- **redis-exporter**: 0.2 CPU, 128MB RAM
- **postgres**: 0.5 CPU, 512MB RAM
- **server**: 1.0 CPU, 1GB RAM
- **detector**: 0.5 CPU, 256MB RAM
- **client**: 0.5 CPU, 256MB RAM
- **prometheus**: 0.5 CPU, 256MB RAM
- **grafana**: 0.5 CPU, 256MB RAM

## Monitoring
- **Prometheus**: Scrapes metrics from `http://server:3000/metrics` (server) and `http://redis-exporter:9121` (Redis). Access at `http://localhost:9090`.
- **Grafana**: Uses Prometheus as a data source via provisioning. The "EarthSync Server Metrics" dashboard is pre-configured, showing:
  - HTTP request rates and WebSocket connections from the server.
  - Redis `spectrogram_history` length via the `redis_key_size` metric from the Redis exporter.
- **Redis Exporter**: Runs on port 9121, exposing Redis metrics. Use `REDIS_EXPORTER_CHECK_SINGLE_KEYS=spectrogram_history` to monitor the history list length and `REDIS_EXPORTER_DEBUG=true` for verbose logging. Verify metrics at `http://localhost:9121/metrics`.

## Troubleshooting
- **Build fails**: Ensure Docker and Docker Compose are installed and running. Check `docker --version` and `docker-compose --version`.
- **Connection issues**: Verify ports (3000, 3001, 6379, 5432, 9121, 9090, 3002) are free and `.env` settings match. On Windows/WSL2, use `localhost` if container names don’t resolve.
- **Service unhealthy**: Check logs (`docker-compose logs <service>`) for errors. For `redis-exporter`, ensure Redis is accessible (`docker exec -it earthsync-redis-1 redis-cli -a password ping` should return "PONG").
- **Log level not applied**: Ensure `LOG_LEVEL` is set correctly in `.env` files and restart containers.
- **Graph not rendering**: Check client logs (`docker-compose logs client`) for WebSocket messages and spectrogram data. Ensure `spectrogram_stream` has data (`docker exec -it earthsync-redis-1 redis-cli -a password xlen spectrogram_stream`).
- **Historical data error**: Verify Redis history (`docker exec -it earthsync-redis-1 redis-cli -a password lrange spectrogram_history 0 -1`) contains valid JSON with `spectrogram` arrays.
- **WebSocket disconnects**: Inspect server logs (`docker-compose logs server`) for stream read errors and detector logs (`docker-compose logs detector`) for publishing issues.
- **Grafana "No Data"**: 
  - Ensure the Redis exporter is running (`docker-compose ps redis-exporter`).
  - Check Prometheus targets (`http://localhost:9090/targets`) for `redis-exporter:9121` (should be "UP").
  - Verify the metric `redis_key_size{key="spectrogram_history"}` exists:
    - Visit `http://localhost:9121/metrics` and search for `redis_key_size`.
    - In Prometheus (`http://localhost:9090/graph`), query `redis_key_size{key="spectrogram_history"}`.
  - If missing, check Redis exporter logs (`docker-compose logs redis-exporter`) for errors. Confirm `spectrogram_history` exists and has data (`docker exec -it earthsync-redis-1 redis-cli -a password llen spectrogram_history`).
  - Ensure the server has initialized `spectrogram_history` (`docker-compose logs server` should show "Initializing empty spectrogram_history list").
- **Dashboard Not Provisioned**: 
  - Check Grafana logs (`docker-compose logs grafana`) for errors like "Failed to load dashboard" or "permission denied".
  - Verify the dashboard file exists in the container: `docker exec -it earthsync_grafana_1 ls -l /etc/grafana/provisioning/dashboards/earthsync-dashboard.json`.
  - Ensure the file is readable: `docker exec -it earthsync_grafana_1 cat /etc/grafana/provisioning/dashboards/earthsync-dashboard.json`.
  - Restart Grafana: `docker-compose restart grafana`.
- **Port conflicts**: Check with `netstat -tuln` (Linux) or `netstat -aon` (Windows) and adjust `docker-compose.yml`.
- View logs: `docker-compose logs <service_name>`.

## CI/CD with GitHub Actions
The repository includes a GitHub Actions workflow (`build-and-test.yml`) that:
- Builds all Docker images on push or pull request to `main`.
- Runs tests for API endpoints (health, register, login, key exchange, history, metrics) and WebSocket connectivity using Redis streams.
- Cleans up resources afterward.

## License
MIT License (see LICENSE file for details).
