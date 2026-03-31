# EarthSync Station Firmware

Raspberry Pi station software for real Schumann Resonance measurement hardware.
Acquires time-domain samples from an ADS1256 24-bit ADC, timestamps via GPS PPS,
and uploads segments to the EarthSync backend.

## Hardware Requirements

- Raspberry Pi 4 (or newer)
- ADS1256 24-bit ADC module (SPI)
- Induction coil magnetometer with analog front-end
- GPS module with PPS output (e.g. u-blox NEO-6M)
- Stable power supply
- Weatherproof enclosure for outdoor deployment

See `hardware/REQUIREMENTS.md` in the project root for the full BOM, sensor
construction guide, and site selection criteria.

## Software Prerequisites

```bash
# System packages (Raspberry Pi OS)
sudo apt-get update
sudo apt-get install -y python3.13 gpsd gpsd-clients python3-spidev

# Enable SPI
sudo raspi-config nonint do_spi 0

# Enable and start gpsd
sudo systemctl enable gpsd
sudo systemctl start gpsd
```

## Installation

```bash
cd firmware
pip install -e ".[dev]"
```

## Configuration

All settings are read from environment variables with the `EARTHSYNC_STATION_`
prefix. Create a `.env` file or export them directly:

```bash
export EARTHSYNC_STATION_STATION_ID="station-sierra-01"
export EARTHSYNC_STATION_API_KEY="your-api-key"
export EARTHSYNC_STATION_SERVER_URL="https://earthsync.example.com"
export EARTHSYNC_STATION_LATITUDE=37.7749
export EARTHSYNC_STATION_LONGITUDE=-122.4194
export EARTHSYNC_STATION_SAMPLE_RATE_HZ=256
export EARTHSYNC_STATION_SEGMENT_DURATION_S=10.0
export EARTHSYNC_STATION_ADC_GAIN=1
export EARTHSYNC_STATION_GPS_ENABLED=true
export EARTHSYNC_STATION_LOG_LEVEL=info
```

| Variable | Default | Description |
|----------|---------|-------------|
| `STATION_ID` | (required) | Unique station identifier |
| `API_KEY` | (required) | Backend API key for data ingest |
| `SERVER_URL` | `http://localhost:3000` | Backend URL |
| `SAMPLE_RATE_HZ` | `256` | ADC sampling rate |
| `SEGMENT_DURATION_S` | `10.0` | Seconds per upload segment |
| `LATITUDE` | `0.0` | Station latitude |
| `LONGITUDE` | `0.0` | Station longitude |
| `SENSOR_TYPE` | `induction_coil` | Sensor description |
| `ADC_GAIN` | `1` | PGA gain (1/2/4/8/16/32/64) |
| `GPS_ENABLED` | `true` | Use GPS PPS for timestamps |
| `UPLOAD_RETRY_MAX` | `3` | Max upload retry attempts |
| `UPLOAD_RETRY_DELAY_S` | `5.0` | Base retry delay (multiplied by attempt) |
| `LOG_LEVEL` | `info` | Logging level |

## Running

```bash
# With real hardware (on Raspberry Pi)
python -m earthsync_station.main

# With mock hardware (for development/testing)
EARTHSYNC_STATION_STATION_ID=dev-01 \
EARTHSYNC_STATION_API_KEY=dev-key \
python -c "
import asyncio
from earthsync_station.adc import MockADC
from earthsync_station.gps import MockGPS
from earthsync_station.uploader import Uploader
from earthsync_station.main import Station
from earthsync_station.config import StationSettings

settings = StationSettings(station_id='dev-01', api_key='dev-key')
station = Station(
    adc=MockADC(),
    gps=MockGPS(),
    uploader=Uploader(settings.server_url, settings.api_key),
    config=settings,
)
asyncio.run(station.run())
"
```

## Testing

```bash
cd firmware
pytest -v
pytest --cov=earthsync_station
```

Tests use `MockADC` and `MockGPS` so no hardware is needed. The SPI and gpsd
drivers are behind abstraction layers (`ADCInterface`, `GPSInterface`) that
are swapped out in test fixtures.

## Architecture

```
Induction Coil -> Analog Front-End -> ADS1256 (SPI) -> Raspberry Pi
                                                            |
                                                    GPS PPS timing
                                                            |
                                                    HTTP POST /api/data-ingest
                                                            |
                                                    EarthSync Backend
```

The station sends raw time-domain samples. All DSP (Welch PSD, Lorentzian
fitting, peak detection) happens on the backend.
