# Station Hardware Options -- From $50 to $7,000

A comprehensive guide to all viable hardware combinations for building a
Schumann Resonance monitoring station compatible with the EarthSync platform.
Choose a tier based on your budget, goals, and willingness to build.

---

## Tier 1: Minimum Viable ($50--80)

The cheapest path to hearing Schumann Resonances. Proves the concept before
you invest real money.

| Component | Option | Cost |
|-----------|--------|------|
| Sensor | DIY induction coil on ferrite or recycled transformer steel core | $30--50 (wire + core) |
| ADC | PC sound card LINE input (use existing computer) | $0 |
| Computer | Existing PC | $0 |
| Software | SpectrumLab, Audacity, or EarthSync firmware | $0 |
| GPS | None (NTP timing only) | $0 |
| Power | Mains only | $0 |
| **Total** | | **$30--50** |

**Proven by:** The Cumiana station (vlf.it), operational since 2011, runs a
PC sound card input with a homemade induction coil and consistently detects
all five primary Schumann modes.

**Limitations:**

- No GPS timing -- cannot participate in cross-station correlation
- Tied to a PC -- no remote or unattended operation
- Sensitivity depends entirely on build quality and site noise
- Mains power introduces 50/60 Hz coupling into the analog front-end

**Best for:** Hobbyists who want to verify SR detection before investing more.
If you can see the 7.83 Hz peak on a sound card spectrogram, you know your
site and coil are viable before spending $300+ on a standalone station.

---

## Tier 2: Budget Standalone ($250--400)

The recommended entry point for citizen scientists. A fully autonomous station
that runs headless on a Raspberry Pi, uploads data to the EarthSync network,
and can operate on solar power.

| Component | Option | Cost |
|-----------|--------|------|
| Sensor | DIY induction coil with mu-metal core | $100--150 |
| Amplifier | Custom PCB, OPA209 preamplifier | $10--20 |
| ADC | Waveshare ADS1256 HAT (24-bit, 30 kSPS, 64x PGA) | $20--30 |
| Computer | Raspberry Pi Zero 2W + 32 GB microSD (Class 10) | $25 |
| GPS | Adafruit Ultimate GPS HAT with PPS | $30 |
| Power | USB power supply ($10) or solar: Waveshare UPS HAT ($20) + LiPo | $10--40 |
| Enclosure | IP67 ABS junction box | $15--25 |
| Cabling | Shielded coax, BNC connectors, SPI ribbon | $15--25 |
| **Total** | | **$240--390** |

### Sensor Detail

- **Core:** Mu-metal rod, relative permeability ~200,000. Sources: Magnetic
  Shield Corporation (mu-metal rods), Goodfellow (Ni-Fe alloy rods).
- **Wire:** 40,000+ turns of 0.2 mm (AWG 32) enameled copper magnet wire.
  Bank-wound with Kapton tape every 4--6 layers to reduce distributed
  capacitance.
- **Reference design:** Christofilakis, V. et al. (2018). "A Low-Cost Receiver
  for Schumann Resonance Observations." IEEE Trans. Antennas Propag., 67(9),
  5845--5854.
- **Expected sensitivity:** 1--2 mV/pT at 7.83 Hz with a 30 cm core.

**Best for:** Citizen scientists building their first standalone station. This
is the tier described in detail by the [Build Guide](BUILD_GUIDE.md) and
[Bill of Materials](bom.yaml).

---

## Tier 3: Recommended ($800--1,500)

Two paths to higher-quality data: a professional DAQ with a DIY sensor, or a
commercial sensor with a budget DAQ.

### Option A -- DIY Sensor + Pro DAQ ($1,000--1,100)

| Component | Option | Cost |
|-----------|--------|------|
| Sensor | ICS101 induction coil (vlf.it design, self-built) | $100--200 |
| DAQ | Symmetric Research USB4CH (24-bit, 9700 SPS) | $700 |
| Computer | Raspberry Pi 5 4GB | $75 |
| GPS | Uputronics u-blox GPS/GNSS HAT with PPS | $50 |
| Power | USB-C power supply or solar | $20--50 |
| Enclosure | IP65 junction box | $20--30 |
| **Total** | | **$1,000--1,100** |

The Symmetric Research USB4CH is the same DAQ family used by the HeartMath
Institute's Global Coherence Monitoring System (GCMS). It provides a clean,
well-characterized acquisition path with no PGA or filter design required --
just connect the sensor and sample.

### Option B -- Commercial Sensor + Budget DAQ ($500--600)

| Component | Option | Cost |
|-----------|--------|------|
| Sensor | MSI MC910 induction coil (5--600 Hz) | $195 |
| Amplifier | OPA209 gain stage (custom PCB) | $20--30 |
| ADC | Waveshare ADS1263 HAT (32-bit, 10-ch, 38.4 kSPS) | $35--50 |
| Computer | Raspberry Pi 5 4GB | $75 |
| GPS | Adafruit Ultimate GPS HAT with PPS | $30 |
| Power | PV PI HAT solar charger ($50--80) + LiFePO4 battery ($40) | $90--120 |
| Enclosure | Sixfab IP65 outdoor enclosure for Raspberry Pi | $35 |
| **Total** | | **$500--600** |

The MSI MC910 is the only readily available commercial induction coil covering
the 5--600 Hz band. It eliminates the coil-winding effort entirely. An OPA209
gain stage is still needed to match its output level to the ADS1263 input range.

---

## Tier 4: Research Grade ($3,500--7,000)

Matches the data quality of professional observatories. Suitable for
publishable scientific results.

| Component | Option | Cost |
|-----------|--------|------|
| Sensor | Zonge ANT/4 induction coil (broadband) | $2,000--5,000 |
| DAQ | Symmetric Research USB8CH (24-bit, 8-ch, 9700 SPS) | $980 |
| GPS option | Symmetric Research GPS board | $125 |
| Computer | Raspberry Pi 5 8GB or ruggedized industrial SBC | $95--300 |
| Timing | u-blox ZED-F9T precision timing module | $100+ |
| Power | Dedicated solar array + LiFePO4 battery bank (100+ Ah) | $200--400 |
| Enclosure | NEMA 4X weatherproof cabinet | $100--200 |
| Grounding | Proper earth ground system (copper rod + radials) | $50--100 |
| **Total** | | **$3,500--7,000** |

**Sensor alternatives:**

| Product | Frequency Range | Approx. Cost | Used By |
|---------|----------------|--------------|---------|
| Zonge ANT/4 | Broadband | $2,000--5,000 | HeartMath GCMS |
| LEMI-120 | 0.0001--1000 Hz | $2,000--6,000 | CARISMA network |
| Metronix MFS-06e | 0.0001--10,000 Hz | $3,000--8,000 | MT research groups |

This tier matches HeartMath GCMS quality. The combination of a Zonge ANT/4
sensor and Symmetric Research USB8CH DAQ is the exact hardware used by six
GCMS stations worldwide. Data from this tier is directly publishable in
geophysics journals.

---

## Tier 5: Full Observatory ($15,000--30,000+)

A three-axis electromagnetic observatory capable of full-vector magnetic and
electric field measurement.

| Component | Option | Cost |
|-----------|--------|------|
| Sensors | 2x horizontal induction coils (N/S + E/W) + 1x vertical E-field ball antenna | $10,000--20,000 |
| DAQ | Symmetric Research USB8CH or NI cDAQ-9178 | $1,000--3,000 |
| Computing | Ruggedized industrial PC (fanless, wide-temp) | $500--1,000 |
| Timing | GNSS disciplined oscillator (Trimble, Jackson Labs) | $500+ |
| Calibration | NIST-traceable reference source | $500+ |
| Infrastructure | Weatherproof shelter, grounding grid, lightning protection | $1,000--3,000 |
| **Total** | | **$15,000--30,000+** |

Three-axis measurement enables polarization analysis and source direction
estimation. The E-field ball antenna adds electric field data for full
electromagnetic characterization. At this level you are building a permanent
geophysical observatory, not a monitoring station.

---

## Component Reference Tables

### Sensors

| Product | Type | Freq Range | Approx. Cost | SR Validated |
|---------|------|-----------|--------------|-------------|
| DIY mu-metal coil | Induction | 0.1--100 Hz | $50--150 | Yes (Tatsis et al. 2018) |
| Air-core loop antenna | Loop | 0.1--100 Hz | $20--50 | Yes (vlf.it Cumiana) |
| MSI MC910 | Induction | 5--600 Hz | $195 | Needs independent testing |
| Zonge ANT/4 | Induction | Broadband | $2,000--5,000 | Yes (HeartMath GCMS) |
| LEMI-120 | Induction | 0.0001--1000 Hz | $2,000--6,000 | Yes (CARISMA network) |
| Metronix MFS-06e | Induction | 0.0001--10,000 Hz | $3,000--8,000 | Yes (MT research) |

### ADCs

| Product | Resolution | Channels | Max SPS | PGA | Approx. Cost | SR Suitable |
|---------|-----------|----------|---------|-----|--------------|-------------|
| ADS1256 module | 24-bit | 8 SE / 4 diff | 30,000 | 1--64x | $20--30 | Excellent |
| ADS1263 HAT | 32-bit | 10 | 38,400 | 1--32x | $35--50 | Excellent |
| ADS1299 (Lucid BCI) | 24-bit | 8 diff | 16,000 | 1--24x | $15--25 (IC only) | Very good |
| Symmetric USB4CH | 24-bit | 4 | 9,700 | N/A | $700 | Proven (HeartMath) |
| Symmetric USB8CH | 24-bit | 8 | 9,700 | N/A | $980 | Proven (HeartMath) |
| PC sound card | 16--24 bit | 2 | 192,000 | N/A | $0--200 | Viable (Cumiana) |
| HX711 | 24-bit* | 1 | 80 | 128x | $1--3 | NOT viable |

*The HX711 has 24-bit nominal resolution but only 16--20 effective bits due to
its architecture as a load-cell excitation driver, not a general-purpose ADC.

### GPS / Timing

| Product | PPS Accuracy | Interface | Approx. Cost | Notes |
|---------|-------------|-----------|--------------|-------|
| Adafruit Ultimate GPS | ~30 ns | UART + PPS | $30 | Good entry-level, u-blox PA1616S |
| Uputronics u-blox HAT | ~30 ns | UART + PPS | $50 | Designed for Raspberry Pi, better antenna |
| u-blox ZED-F9T | <5 ns | UART + PPS | $100+ | Precision timing module, multi-band GNSS |
| Symmetric Research GPS | ~100 ns | Proprietary | $125 | Pairs with USB4CH/USB8CH DAQs |
| GNSS disciplined oscillator | <1 ns | 10 MHz + PPS | $500+ | Trimble, Jackson Labs -- for observatories |

### Single-Board Computers

| Product | Power Draw | Key Feature | Approx. Cost | Notes |
|---------|-----------|-------------|--------------|-------|
| Raspberry Pi Zero 2W | ~1W idle | Lowest power | $15 | Sufficient for basic acquisition |
| Raspberry Pi 4B 2GB | ~3W idle | Mature ecosystem | $45 | Well-supported, good balance |
| Raspberry Pi 5 4GB | ~3.5W idle | Fastest Pi | $75 | Best for local DSP processing |
| Raspberry Pi 5 8GB | ~4W idle | Maximum RAM | $95 | For concurrent heavy workloads |
| Orange Pi 3B | ~2.5W idle | Budget alternative | $30--40 | Rockchip RK3566, less community support |

---

## Hardware That Does NOT Work for SR

Common suggestions that are not viable for Schumann Resonance measurement:

| Technology | Why It Fails |
|-----------|-------------|
| RTL-SDR / HackRF / any SDR dongle | Minimum tunable frequency is ~500 kHz. SR lives at 7.83 Hz -- five orders of magnitude below the SDR passband. |
| MEMS magnetometers (LSM303, BMM150, etc.) | Noise floor ~3 nT. SR magnetic field amplitude is ~1 pT. You need ~3000x better sensitivity than MEMS can provide. |
| HX711 load cell ADC | Only 16--20 effective bits despite 24-bit nominal. Designed as an excitation bridge driver for strain gauges, not a general-purpose ADC. Maximum 80 SPS. |
| Stefan Mayer FLC3-70 fluxgate | 1 nT noise floor. Approximately 1000x too noisy for SR detection. Fluxgates in general are designed for DC and ULF fields, not ELF. |
| Raspberry Shake seismometer | ADC is impedance-matched and filtered for geophone signals. Modifying it for induction coil input is more work than starting from scratch with an ADS1256. |
| Smartphone magnetometers | MEMS-based, same noise floor problem as standalone MEMS chips. Also lacks the sample rate stability needed for spectral analysis. |
| Arduino analog inputs | 10-bit resolution (1024 steps). SR signals require at minimum 16 effective bits to resolve above the quantization noise floor. |

---

## ADS1299 Crossover Note -- EarthSync / Lucid Synergy

The ADS1299, used in the [Lucid BCI project](../README.md) for EEG
acquisition, has a noise specification of 1 uVpp in the 0.01--70 Hz band.
This frequency range is almost perfectly aligned with the Schumann Resonance
spectrum (7.83--45 Hz).

An ADS1299 front-end designed for EEG measurement could be repurposed for SR
measurement by connecting an induction coil to the differential inputs instead
of scalp electrodes. The 24-bit resolution, 8 differential channels, and
built-in PGA (1--24x) make it well-suited to the task. The 16 kSPS maximum
sample rate is more than adequate for SR frequencies.

This represents a potential hardware synergy between the EarthSync and Lucid
projects: a single ADS1299-based board could serve as either an EEG
acquisition front-end or an SR monitoring station, depending on what is
connected to its inputs.

Key differences from dedicated SR ADCs like the ADS1256:

| Parameter | ADS1299 | ADS1256 |
|-----------|---------|---------|
| Max PGA gain | 24x | 64x |
| Max sample rate | 16,000 SPS | 30,000 SPS |
| Differential channels | 8 | 4 |
| Input bias current | 200 pA | 30 nA |
| Primary use case | EEG / biopotential | General precision |
| Advantage for SR | Lower bias current (better for high-Z coils) | Higher PGA, faster sample rate |

---

## EarthSync Software Compatibility

All tiers connect to the EarthSync platform using the same data path. The
station firmware (`earthsync-station` package) handles acquisition and upload.

### Connection Methods

**HTTP API (recommended for WAN):**

```
POST /api/data-ingest
Header: X-API-Key: <your-api-key>
Content-Type: application/json
```

**Redis stream (for LAN deployment):**

```
XADD spectrogram_stream * station_id <id> samples <json> ...
```

### Ingest Payload

```json
{
  "samples": [0.0012, -0.0008, 0.0015, ...],
  "sampleRateHz": 256,
  "segmentDurationS": 10.0,
  "stationId": "station-backyard-01",
  "timestamp": "2026-03-28T12:00:00Z",
  "location": { "lat": 45.05, "lon": 7.35 }
}
```

- `samples`: Raw time-domain ADC readings (float array)
- `sampleRateHz`: ADC sample rate, 90--10,000 Hz accepted
- `segmentDurationS`: Duration of the sample window, 1--600 seconds
- `stationId`: Unique station identifier string
- `timestamp`: ISO 8601 UTC timestamp
- `location`: Station coordinates (latitude, longitude)

### Firmware Installation (Raspberry Pi)

```bash
# Quick install
curl -fsSL https://earthsync.dev/install.sh | bash

# Or manual
git clone https://github.com/earthsync/firmware.git
cd firmware
python3 -m venv venv && source venv/bin/activate
pip install -e .
earthsync-config init   # interactive setup wizard
sudo systemctl enable earthsync && sudo systemctl start earthsync
```

The firmware supports Raspberry Pi with ADS1256 ADC out of the box. Other
ADCs require implementing the `ADCInterface` abstract base class in
`firmware/src/earthsync_station/adc.py`.

---

## Decision Guide: Which Tier?

```
Do you just want to see if SR is real?
  Yes --> Tier 1 ($50). Sound card + DIY coil.

Do you want a standalone station on the EarthSync network?
  Yes, budget under $400 --> Tier 2. DIY coil + ADS1256 + Pi Zero 2W.
  Yes, budget $500-1500  --> Tier 3. Commercial sensor or pro DAQ.

Do you want publishable data?
  Yes --> Tier 4 ($3,500+). Zonge ANT/4 + Symmetric Research USB8CH.

Are you building a permanent observatory?
  Yes --> Tier 5 ($15,000+). Three-axis sensors + GNSS disciplined oscillator.
```

The Tier 2 build is described step-by-step in the [Build Guide](BUILD_GUIDE.md)
with a complete [Bill of Materials](bom.yaml). Tiers 3--5 use the same firmware
and software stack; only the hardware changes.
