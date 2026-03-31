# EarthSync

**Open-source citizen science platform for distributed Schumann Resonance monitoring.**

EarthSync is a distributed network of low-cost measurement stations that detect, track, and visualize the electromagnetic resonances of the Earth-ionosphere cavity. The backend processes raw time-domain samples through a rigorous DSP pipeline (Welch PSD, Lorentzian curve fitting, peak tracking) and streams results to a real-time web dashboard. Each station costs approximately $250-400 to build. The more stations, the better the science. The ADS1299 front-end from the [Lucid BCI project](https://github.com/jeffrmorton/lucid) can be repurposed as an SR monitoring station (see [hardware crossover note](hardware/STATION_OPTIONS.md#ads1299-crossover-note----earthsync--lucid-synergy)).

### Scientific Features

- **Multitaper spectral estimation** -- DPSS/Slepian tapers (Thomson 1982) for low-variance PSD with configurable NW and taper count
- **SR band filtering** -- Peak detection restricted to 8 canonical Schumann mode bands, eliminating spurious detections
- **Lorentzian curve fitting** -- Multi-mode fitting with Hessian error propagation for frequency, amplitude, and Q-factor uncertainties
- **Inter-station Q-burst correlation** -- Global transient event detection across multiple stations within configurable time windows
- **Realistic observatory simulation** -- Diurnal Q-factor modulation, correlated mode amplitudes, harmonic injection, and damped-oscillation Q-bursts

## What Are Schumann Resonances?

The Earth and ionosphere form a natural electromagnetic cavity. Global lightning activity excites standing waves at a fundamental frequency of ~7.83 Hz with harmonics at ~14.3, 20.8, 27.3, 33.8, 39.0, 45.0, and 51.0 Hz. These are the Schumann Resonances, first predicted by Winfried Otto Schumann in 1952. SR measurements are used in geophysics, space weather monitoring, and climate research. A distributed network of stations can triangulate global thunderstorm activity and detect ionospheric disturbances that no single station can resolve.

## Architecture

```
Stations / Simulators             EarthSync Server                  Web Dashboard
┌───────────────────┐          ┌──────────────────────┐          ┌──────────────────┐
│ Sierra Nevada     │          │  Redis Stream         │          │ WebGPU/WebGL     │
│ (mag, 256 Hz)     │──┐      │  Consumer Group       │     ┌──→│  Spectrogram     │
│                   │  │      │       │               │     │   │                  │
│ Modra             │  │      │       ▼               │     │   │ uPlot PSD +      │
│ (elec, 200 Hz)    │──┼─────→│  Welch PSD (scipy)    │     │   │  Peak Trends     │
│                   │  │      │  Lorentzian Fit (lmfit)│     │   │                  │
│ HeartMath         │  │      │  Peak Tracking         │─────┘   │ Station Globe    │
│ (mag, 130 Hz)     │──┘      │  Q-Burst Detection     │  WS     │ (react-globe.gl) │
│                   │         │  Cross-Validation      │ (AES)   │                  │
│ Hardware Stations │────────→│       │               │         │ Dark Theme       │
│ (RPi + ADS1256)   │  HTTP   │       ▼               │         │ Tailwind 4       │
└───────────────────┘         │  TimescaleDB Archival  │         └──────────────────┘
                              └──────────────────────┘
```

## Build a Station (~$250-400)

| Component | Purpose | Est. Cost |
|-----------|---------|-----------|
| Induction coil magnetometer | Sensor (20k-40k turns, high-mu core) | $50-150 |
| Preamplifier (OPA209) | Ultra-low-noise first gain stage (3.3 nV/rtHz) | $10-20 |
| Filter + gain chain | Sallen-Key LPF, Twin-T notch, variable gain | $30-45 |
| ADC (ADS1256, 24-bit) | Delta-sigma digitizer, SPI interface | $15-25 |
| Raspberry Pi 4 | Compute + network | $45-75 |
| GPS module (u-blox NEO-M8, PPS) | UTC timestamps + 1 PPS synchronization | $12-18 |
| Power (battery + solar) | LiPo, MPPT controller, LDO analog supply | $45-83 |
| Enclosure + cabling | IP65 box, shielded cable, earth rod | $46-83 |

See [`hardware/REQUIREMENTS.md`](hardware/REQUIREMENTS.md) for the complete build guide with schematics, site selection guidance, and calibration procedures. Component details and sourcing in [`hardware/bom.yaml`](hardware/bom.yaml).

## Quick Start

```bash
git clone https://github.com/jeffrmorton/earthsync.git
cd earthsync

# Production: server + database + cache + web dashboard
docker compose up --build -d

# Development: adds 3 simulated observatory stations
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build -d

# Dashboard: http://localhost:3080
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Server** | Python 3.13, FastAPI, uvicorn |
| **DSP** | scipy (Welch PSD, peak detection), lmfit (multi-Lorentzian fitting + Hessian errors), numpy |
| **Web** | React 19.2, TypeScript 6.0, Vite 8, Tailwind 4.2 |
| **Visualization** | uPlot, WebGPU/WebGL spectrogram, react-globe.gl |
| **State** | Jotai, TanStack Query v5 |
| **Database** | TimescaleDB (PostgreSQL 16) |
| **Cache** | Redis 7.2 |
| **Testing** | pytest (412 server + 57 simulator + 70 firmware), Vitest (194 tests, 100% coverage) -- 733 total |
| **Linting** | Ruff (Python), Biome 2.4.9 (TypeScript) |
| **CI** | GitHub Actions |

## Project Structure

```
earthsync/
├── server/                          # FastAPI backend (earthsync-server)
│   ├── src/earthsync_server/
│   │   ├── app.py                   # Application factory
│   │   ├── main.py                  # Uvicorn entry point
│   │   ├── config.py                # Pydantic Settings (EARTHSYNC_ prefix)
│   │   ├── constants.py             # Schumann frequencies, algorithm version
│   │   ├── models.py                # Pydantic v2 data models
│   │   ├── dsp/                     # 7 DSP modules (pure functions, 100% coverage)
│   │   ├── routes/                  # API route handlers (7 modules)
│   │   ├── services/                # StreamProcessor, archiver, cross-validator, WebSocket
│   │   ├── db/                      # asyncpg pool, schema (7 tables + hypertables)
│   │   ├── redis/                   # Two async Redis clients (main + stream)
│   │   └── middleware/              # JWT + API key auth dependencies, rate limits
│   └── tests/                       # pytest (unit + integration)
├── simulator/                       # Observatory simulators (earthsync-simulator)
│   ├── src/earthsync_simulator/
│   │   ├── main.py                  # Redis publish loop
│   │   ├── config.py                # Pydantic Settings (EARTHSYNC_SIMULATOR_ prefix)
│   │   ├── profiles.py             # Sierra Nevada, Modra, HeartMath profiles
│   │   └── signal_generator.py     # IIR biquad SR synthesis + Q-bursts
│   └── tests/
├── firmware/                        # Raspberry Pi station (earthsync-station)
│   ├── src/earthsync_station/
│   │   ├── main.py                  # Acquisition loop
│   │   ├── config.py                # Pydantic Settings (EARTHSYNC_STATION_ prefix)
│   │   ├── adc.py                   # ADS1256 SPI driver
│   │   ├── gps.py                   # GPS PPS timing via gpsd
│   │   └── uploader.py             # HTTP upload with retry
│   └── tests/
├── web/                             # React dashboard (@earthsync/web)
│   ├── src/
│   │   ├── App.tsx                  # Root component (Jotai Provider)
│   │   ├── lib/                     # Colormap, API client, WS client (AES-256-GCM)
│   │   ├── atoms/                   # Jotai atoms (spectrogram, peaks, stations)
│   │   ├── hooks/                   # use-auth, use-theme
│   │   ├── components/viz/          # SpectrogramCanvas, PSDCurve, PeakTrends
│   │   ├── components/layout/       # Header, Sidebar
│   │   ├── features/dashboard/      # DashboardLayout, DashboardPage
│   │   └── types/                   # TypeScript interfaces
│   ├── vite.config.ts
│   └── vitest.config.ts
├── hardware/                        # Hardware documentation
│   ├── REQUIREMENTS.md              # Build guide + site selection
│   ├── DESIGN_NOTES.md              # Analog design rationale
│   └── bom.yaml                     # Detailed BOM with references
├── research/                        # 5 literature reviews (51 citations)
│   ├── SR_INSTRUMENTATION.md
│   ├── SR_SIGNAL_PROCESSING.md
│   ├── SR_OBSERVATORIES.md
│   ├── SR_CITIZEN_SCIENCE.md
│   └── REFERENCES.md
├── docker-compose.yml               # Production services
├── docker-compose.dev.yml           # Development simulators
├── pyproject.toml                   # uv workspace root
├── biome.json                       # TypeScript linting config
└── .github/workflows/ci.yml        # CI pipeline
```

## Documentation

- [Developer Guide](CLAUDE.md) -- Full architecture, config, API, database schema
- [Hardware Build Guide](hardware/REQUIREMENTS.md) -- BOM, schematics, site selection
- [Hardware Design Notes](hardware/DESIGN_NOTES.md) -- Analog front-end rationale
- [Contributing](CONTRIBUTING.md) -- Development setup, PR requirements
- [Changelog](CHANGELOG.md) -- Release history

## Research Foundation

The signal processing pipeline and hardware designs are grounded in peer-reviewed Schumann Resonance literature (51 citations across 5 research documents):

- [`research/SR_INSTRUMENTATION.md`](research/SR_INSTRUMENTATION.md) -- Sensor design, analog front-ends, ADC selection
- [`research/SR_SIGNAL_PROCESSING.md`](research/SR_SIGNAL_PROCESSING.md) -- Welch PSD, Lorentzian fitting, peak tracking methods
- [`research/SR_OBSERVATORIES.md`](research/SR_OBSERVATORIES.md) -- Reference observatories and monitoring networks
- [`research/SR_CITIZEN_SCIENCE.md`](research/SR_CITIZEN_SCIENCE.md) -- Citizen science SR projects and precedents
- [`research/REFERENCES.md`](research/REFERENCES.md) -- Master reference list (51 citations)

## License

MIT License for code. See [LICENSE](LICENSE).

CC-BY-4.0 for community-contributed data (planned).
