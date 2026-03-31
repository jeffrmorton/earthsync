# Changelog

## [0.1.1] - 2026-03-30

### Breaking Changes
- API: /api/detectors/ -> /api/stations/ (all endpoints)
- DB: detector_id -> station_id, detector_calibration -> station_calibration
- WebSocket: detector_id field -> station_id
- Config: EARTHSYNC_SIMULATOR_DETECTOR_ID -> EARTHSYNC_SIMULATOR_STATION_ID
- Simulator: DetectorProfile -> StationProfile

### Scientific Improvements
- SR frequency band filtering: peak detection restricted to 8 canonical Schumann mode bands (7-8 peaks per segment, was 17-23)
- Multitaper spectral estimation: DPSS/Slepian tapers via scipy, configurable NW and taper count (Thomson 1982)
- Enhanced simulator realism: diurnal Q-factor modulation (±30%), correlated mode amplitudes, 2nd harmonic injection, mains harmonic contamination, damped oscillation Q-bursts
- Inter-station Q-burst correlation: new QBurstCorrelator service detects global transient events across 2+ stations within configurable time window
- TimescaleDB hypertable configuration: 1-day chunk intervals, compression policies, per-statement error handling

### Frontend
- Lorentzian fit overlay on PSD curve (dashed yellow model curve)
- Peak uncertainty display: ±freq_err, ±amp_err, ±q_err on all detected peaks
- Q-burst transient indicator: pulsing yellow badge in header during active Q-bursts
- Chi²/dof quality metric with green/yellow/red color coding
- Lorentzian convergence status in quality panel

### Infrastructure
- qburst_events database table with timestamp index
- GET /api/public/qbursts endpoint for global Q-burst event retrieval
- DatabaseStore backed by asyncpg (replaces in-memory store in production)
- 733 tests total (412 server + 57 simulator + 70 firmware + 194 frontend)

## [0.1.0] - 2026-03-29

### Added
- Python FastAPI server: Welch PSD (scipy), Lorentzian fitting (lmfit) with Hessian error propagation, peak detection/tracking, Q-burst detection, cross-validation
- React 19.2 web dashboard: WebGPU/WebGL spectrogram, uPlot PSD and peak trends, station globe, professional dark theme
- Observatory simulators: Sierra Nevada (256 Hz), Modra (200 Hz), HeartMath (130 Hz) -- IIR biquad SR synthesis with diurnal modulation and Q-bursts
- Raspberry Pi station firmware: ADS1256 ADC driver, GPS PPS timing, HTTP upload
- Hardware documentation: research-grounded BOM ($250-400), build guide, site selection, calibration procedures
- Research literature reviews: SR instrumentation, signal processing, observatories, citizen science (30+ citations)
- TimescaleDB for time-series archival with automatic partitioning
- AES-256-GCM encrypted WebSocket streaming
- JWT authentication with Argon2 password hashing
- REST API: auth, data ingest, history, calibration, export, public endpoints
- Docker Compose with health checks on all services
- 100% test coverage across all packages (~330 tests)

### Infrastructure
- Python: uv workspaces, Ruff linting, pytest + pytest-asyncio
- TypeScript: pnpm, Biome 2.x linting, Vitest 4.x
- CI: GitHub Actions -- lint, typecheck, test, build, Docker
