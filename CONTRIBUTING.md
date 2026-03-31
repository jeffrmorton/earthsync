# Contributing to EarthSync

EarthSync is a citizen science project. There are several ways to contribute:

## Build a Station

The most valuable contribution is deploying a measurement station. See [`hardware/REQUIREMENTS.md`](hardware/REQUIREMENTS.md) for:
- Complete bill of materials (~$250-400)
- Sensor construction guide (induction coil magnetometer)
- Analog front-end design (OPA209 preamp, Sallen-Key LPF, Twin-T notch)
- Site requirements (5+ km from power lines)
- Calibration procedure
- Step-by-step validation

Document your build and share your experience -- station diversity strengthens the network.

## Contribute Code

### Prerequisites

- Python 3.13+ and [uv](https://docs.astral.sh/uv/)
- Node.js 22+ and [pnpm](https://pnpm.io/)
- Docker and Docker Compose

### Development Setup

```bash
git clone https://github.com/jeffrmorton/earthsync.git
cd earthsync

# Python packages (server, simulator, firmware)
uv sync

# Web dashboard
cd web && pnpm install && cd ..
```

### Running Locally

Start infrastructure services first:

```bash
docker compose up redis postgres -d
```

Then run the server and web dashboard in separate terminals:

```bash
# Terminal 1: FastAPI server
cd server && uv run uvicorn earthsync_server.main:app --reload --port 8000

# Terminal 2: Web dashboard (Vite dev server with proxy to backend)
cd web && pnpm dev

# Terminal 3 (optional): Run a simulator
cd simulator && EARTHSYNC_SIMULATOR_STATION_MODEL=sierra_nevada uv run python -m earthsync_simulator.main
```

Or use Docker Compose for the full stack with simulators:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build -d
```

### Testing

All packages enforce 100% test coverage:

```bash
# Server (99% -- entry points excluded)
cd server && uv run pytest --cov=earthsync_server --cov-fail-under=99

# Simulator
cd simulator && uv run pytest --cov=earthsync_simulator --cov-fail-under=100

# Firmware
cd firmware && uv run pytest --cov=earthsync_station --cov-fail-under=100

# Web
cd web && pnpm test:coverage
```

### Code Style

- **Python**: [Ruff](https://docs.astral.sh/ruff/) handles both linting and formatting. Configuration in root `pyproject.toml`. Line length 100, target Python 3.13.
- **TypeScript**: [Biome](https://biomejs.dev/) handles linting, formatting, and import sorting. Configuration in root `biome.json`. Single quotes, trailing commas, semicolons.

```bash
# Python lint (all packages)
cd server && uv run ruff check src/ tests/
cd simulator && uv run ruff check src/ tests/

# TypeScript lint
cd web && pnpm lint
```

### Pull Requests

- One feature or fix per PR
- All tests pass with 100% coverage
- Lint clean (Ruff for Python, Biome for TypeScript)
- Update documentation if you change APIs or data formats
- Include tests for any new functionality

## Report Issues

Open an issue on GitHub for:
- Bug reports (include logs and steps to reproduce)
- Feature requests
- Documentation improvements
- Station deployment questions

## Data Licensing

- Code: MIT License
- Community-contributed data: CC-BY-4.0 (planned)

## Community

- GitHub Issues for bug reports and feature requests
- Discussions for general questions and station deployment help
