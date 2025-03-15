# EarthSync Project

## Overview
EarthSync is a web application that visualizes Schumann Resonance data in 3D using real-time spectrogram data. It includes a client interface, a server for handling API and WebSocket connections, a detector to generate synthetic data, and monitoring with Prometheus and Grafana.

## Features
- Real-time 3D visualization of Schumann Resonance with labeled axes (Frequency, Time, Amplitude).
- User authentication (register/login).
- Historical data retrieval.
- Adjustable time windows, color scales, and normalization.
- Configurable log levels via environment variables.
- Monitoring with Prometheus and Grafana.
- CI/CD pipeline with GitHub Actions.

## Prerequisites
- Docker
- Docker Compose
- GitHub account for CI/CD

## Installation
1. Clone or download the repository.
2. Navigate to the project directory: `cd earthsync`
3. Ensure the setup script is executable: `chmod +x setup_earthsync.sh`
4. Run the setup script: `./setup_earthsync.sh`
5. Start the application: `docker-compose up --build`

## Usage
- **Client Interface**: Open `http://localhost:3001` in your browser, log in or register with a username and password, and use the interface to switch between real-time and historical data, adjust settings, and toggle themes. The client automatically falls back to `http://localhost:3000` if `http://server:3000` is not resolvable (e.g., on Windows with WSL2).
- **Prometheus Metrics**: Access at `http://localhost:9090` to view raw metrics scraped from the server.
- **Grafana Dashboard**: Access at `http://localhost:3002` (default login: admin/admin). The "EarthSync Server Metrics" dashboard is pre-configured and loaded automatically with Prometheus as the data source, displaying:
  - **HTTP Requests Rate**: A graph showing the rate of HTTP requests per second, broken down by method, route, and status.
  - **WebSocket Connections**: A graph showing the number of active WebSocket connections over time.
- **Logs**: Check service logs with `docker-compose logs <service_name>` (e.g., `docker-compose logs server`).

## Stopping the Application
- Stop and remove containers: `docker-compose down`
- Stop and remove containers with volumes (reset data): `docker-compose down -v`

## Environment Variables
Edit `.env` files in `client`, `server`, and `detector` directories to configure:
- `REACT_APP_API_BASE_URL` (client): API endpoint (default: `http://server:3000`, overridden by fallback to `http://localhost:3000` if needed)
- `REACT_APP_WS_URL` (client): WebSocket endpoint (default: `ws://server:3000`, overridden by fallback to `ws://localhost:3000` if needed)
- `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`: Redis connection details
- `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`: PostgreSQL details
- `JWT_SECRET`: Secret for JWT authentication (set in `docker-compose.yml`)
- `DETECTOR_INTERVAL`: Interval for detector data generation (ms)
- `LOG_LEVEL`: Log level (e.g., `error`, `warn`, `info`, `debug`, default: `info`)

## Monitoring
- **Prometheus**: Scrapes metrics from `http://server:3000/metrics`, including HTTP requests and WebSocket connections.
- **Grafana**: Automatically configured to use Prometheus as a data source via provisioning. The "EarthSync Server Metrics" dashboard is loaded by default.

## Troubleshooting
- **Build fails**: Ensure Docker and Docker Compose are installed and running.
- **Connection issues**: Verify ports (3000, 3001, 6379, 5432, 9090, 3002) are free and `.env` settings match. On Windows/WSL2, the client falls back to `localhost:3000` if `server:3000` isn’t resolvable.
- **Log level not applied**: Check `.env` files for correct `LOG_LEVEL`.
- **Graph height issue**: Resize browser window; check console logs for height computation.
- **Historical data error**: Ensure Redis contains valid data; check server logs.
- **Grafana dashboard not visible**: Verify provisioning files are mounted correctly (`docker-compose.yml`) and restart Grafana (`docker-compose restart grafana`).
- View logs: `docker-compose logs <service_name>`.

## CI/CD with GitHub Actions
The repository includes a GitHub Actions workflow (`build-and-test.yml`) that:
- Builds all Docker images on push or pull request to `main`.
- Runs tests for API endpoints (health, register, login, key exchange, history) and WebSocket connectivity.
- Cleans up resources afterward.

## License
MIT License (see LICENSE file for details).
