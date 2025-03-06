# EarthSync Project

## Overview
EarthSync is a web application that visualizes Schumann Resonance data in 3D using real-time spectrogram data. It includes a client interface, a server for handling API and WebSocket connections, a detector to generate synthetic data, and a test suite to validate functionality.

## Features
- Real-time 3D visualization of Schumann Resonance with labeled axes (Frequency, Time, Amplitude).
- User authentication (register/login).
- Historical data retrieval.
- Adjustable time windows, color scales, and normalization.
- Configurable log levels via environment variables.

## Prerequisites
- Docker
- Docker Compose (optional for manual setup)
- Node.js 18.x

## Installation
1. Clone or download the repository.
2. Navigate to the project directory: `cd earthsync`
3. Run the setup script: `./setup_earthsync.sh`
4. Execute the build and run script: `./build_and_run.sh`

## Usage
- Access the application at `http://localhost:3001`.
- Log in or register with a username and password.
- Use the interface to switch between real-time and historical data, adjust settings, and toggle themes.
- Check logs with `docker logs <container_name>` (e.g., `docker logs earthsync-server`).

## Environment Variables
- Edit `.env` files in `client`, `server`, `detector`, and `test` directories to configure:
  - `REACT_APP_API_BASE_URL` (client): API endpoint (default: `http://localhost:3000`)
  - `REACT_APP_WS_URL` (client): WebSocket endpoint (default: `ws://localhost:3000`)
  - `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`: Redis connection details
  - `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`: PostgreSQL details
  - `JWT_SECRET`: Secret for JWT authentication
  - `DETECTOR_INTERVAL`: Interval for detector data generation (ms)
  - `LOG_LEVEL`: Log level (e.g., `error`, `warn`, `info`, `debug`, default: `info`)

## Troubleshooting
- **Build fails**: Ensure Docker is running and all dependencies are installed.
- **Connection issues**: Verify network settings and container names in the Docker network.
- **Log level not applied**: Check `.env` files for correct `LOG_LEVEL` setting.
- **Graph height issue**: Ensure browser window is resized; check console logs for height computation.
- **Historical data error**: Ensure Redis contains valid data; check server logs for errors.
- View container logs for detailed errors: `docker logs <container_name>`.

## GitHub Actions
This repository includes a GitHub Actions workflow (`build-and-test.yml`) that:
- Builds all Docker images on push or pull request to the `main` branch.
- Runs the test suite and checks for successful completion.
- Cleans up resources after execution.

## License
MIT License (see LICENSE file for details).
