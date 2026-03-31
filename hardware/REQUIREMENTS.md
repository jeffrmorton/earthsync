# EarthSync — Hardware Requirements for Real Schumann Resonance Measurement

This document describes what hardware is needed to replace EarthSync's simulated stations with real Schumann Resonance (SR) measurement stations, and how to interface that hardware with the existing software pipeline.

## Viability Assessment

**This system is viable.** Schumann Resonances have been continuously measured since the 1960s by research stations worldwide. The physics is well-characterized, the electronics are documented in peer-reviewed literature, and multiple DIY builds have successfully detected SR signals. The EarthSync software already accepts external data via a clean API — hardware integration requires no backend changes.

**However, success depends almost entirely on site selection.** The electronics can be built for $250-400 and the software integration is straightforward, but SR measurement requires electromagnetic quiet that does not exist in urban or suburban environments. If you cannot access a location 5+ km from power lines, the project stops at the site constraint regardless of hardware quality.

### Key Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| **No suitable quiet site available** | **Critical** | Validate site before buying hardware (see Phase 0 below). This is the most likely failure mode. |
| **Analog front-end noise too high** | High | Do not substitute cheaper op-amps in the preamplifier stage. The LT1028 or OPA209 is not optional — an OP07 will see 3 harmonics where an LT1028 sees 7. |
| **50/60 Hz mains hum dominates signal** | High | Cascaded Twin-T notch filters (45+ dB rejection). Orient coil to null nearest power line. Battery-power everything at the measurement point. |
| **Coil sensitivity insufficient** | Medium | Use mumetal core over ferrite. More turns = more signal, but also more resistance and thermal noise. The Tatsis et al. 2018 design (40,000 turns, mumetal) is proven. |
| **Grounding/shielding problems at 100 dB gain** | Medium | This is not a weekend breadboard project. Layout matters. Keep digital electronics 2-3m from sensor. Use shielded cable between coil and front-end. Expect iteration. |
| **Coil winding is labor-intensive** | Low | 20,000-40,000 turns of fine wire is tedious but not technically difficult. Budget a full day. |
| **Multi-station logistics** | Low | Start with one station. Three remote sites with power, network, and maintenance access is a significant logistical commitment. |

### What's Proven vs What's Not

| Aspect | Status |
|--------|--------|
| SR physics and measurement theory | Proven since 1960s, continuously measured by dozens of research stations |
| Induction coil magnetometer designs | Multiple peer-reviewed and DIY builds documented |
| Analog front-end signal conditioning | Published designs with measured performance (Tatsis et al. 2018) |
| EarthSync software interface | Working — ingest API and Redis stream accept external data today |
| Specific component combinations at specific sites | **Not proven until you build and deploy** — your coil, your front-end, your site |

## The Challenge

Schumann Resonances are electromagnetic standing waves in the Earth-ionosphere cavity, with a fundamental at ~7.83 Hz and harmonics at ~14.3, 20.8, 27.3, 33.8, 39.0, 45.0, and 51.0 Hz. The magnetic field amplitude is on the order of **1 picotesla per harmonic** — roughly 50 million times weaker than Earth's DC magnetic field. Extracting these signals requires sensitive hardware, aggressive filtering, and a quiet measurement site.

---

## Minimum Hardware Per Station (~$250-400)

| Component | Spec | Purpose | Est. Cost |
|-----------|------|---------|-----------|
| Induction coil magnetometer | 20,000-40,000 turns, 0.25 mm wire, high-mu core, 30-60 cm | Sensor — detects SR magnetic field | $50-150 |
| Preamplifier (OPA209 or LT1028) | Gain ~35x, <3.3 nV/√Hz input noise | First gain stage, dominates noise figure | $10-20 |
| Filter + gain chain | Sallen-Key LPF (46 Hz), Twin-T 50/60 Hz notch (x2), HPF (1 Hz) | Reject mains hum, shape passband | $20-30 |
| Additional gain stages | 2-3 op-amp stages, total system gain ~100 dB | Bring pT-level signals to mV range | $10-15 |
| ADC module | ADS1256 (24-bit) or ADS1263, 200 Hz sample rate | Digitize the analog signal | $15-25 |
| Raspberry Pi (any model, 2GB+) | Reads ADC, publishes raw samples to EarthSync | Compute + network | $35-75 |
| GPS module (u-blox, PPS) | Accurate timestamps + location | Required for multi-station correlation | $15 |
| Power | 12V battery + optional solar panel | **No mains power near sensor** | $30-60 |
| Shielded cable (5-10m) | Connects coil to electronics enclosure | Separates sensor from digital noise | $10-15 |
| Weatherproof enclosure | IP65, for Pi + electronics | Outdoor deployment | $20 |

**Total: ~$215-425 per station** depending on coil construction choices.

### Optional Additions

| Component | Purpose | Est. Cost |
|-----------|---------|-----------|
| Second orthogonal coil | N-S + E-W measurement (both horizontal H-field components) | +$50-150 |
| Mumetal core (vs ferrite) | Higher permeability = better sensitivity | +$50-100 |
| PoE HAT for Pi | Single cable for power + network on long runs | +$20 |

---

## Component Details

### Induction Coil Magnetometer (The Sensor)

This is the most critical component. An induction coil detects changing magnetic fields via Faraday's law — the SR magnetic field oscillations induce a tiny voltage in the coil proportional to the number of turns, core permeability, and rate of change.

**Minimum viable coil:**
- **Wire:** 20,000-40,000 turns of 0.25 mm enameled copper
- **Core:** High-permeability material, 30-60 cm long
  - **Best:** Mumetal rod (relative permeability ~200,000). Expensive but dramatically increases sensitivity.
  - **Budget:** Stacked silicon steel laminations or bundled ferrite rods. Less sensitive but functional.
  - **DIY option:** 10 lengths of 3mm flat steel bar (16-40 mm wide, 2m long) threaded through a PVC pipe — documented working builds exist at vlf.it
- **Form factor:** PVC pipe as bobbin, coil wound in layers with insulation between layers
- **Orientation:** Horizontal, aimed N-S or E-W (SR magnetic field is horizontal)

**Reference design (Tatsis et al., 2018 — published, peer-reviewed):**
- Mumetal core (ASTM A753 Alloy 4), 300 mm x 25 mm diameter
- 40,000 turns of 0.25 mm wire per coil section
- Measured inductance: 249 H
- Resistance: 1,560 ohm
- System sensitivity: 70 nV/pT/Hz at antenna output
- Total receiver sensitivity: 210 mV/pT near 20 Hz

### Analog Front-End (Signal Conditioning)

The raw coil output at SR frequencies is in the **nanovolt range**. You need ~100 dB of gain (100,000x voltage amplification) with extremely low noise and aggressive mains rejection.

**Signal chain (5 stages):**

**Stage 1 — Preamplifier (critical — dominates system noise):**
- Op-amp: OPA209 (3.3 nV/√Hz) or LT1028 (1.0 nV/√Hz) — do not substitute cheaper parts here
- Configuration: Non-inverting, gain ~35x
- This single stage determines whether you can see SR or not

**Stage 2 — Low-pass filter + first notch:**
- Sallen-Key 2nd-order LPF, cutoff 46 Hz, gain ~3.5x
- Twin-T notch at 50 Hz (or 60 Hz for North America), ~10 dB rejection
- High-pass at 1.3 Hz to reject DC drift

**Stage 3 — Cascaded notch filters:**
- Two additional Twin-T notch stages at 50/60 Hz, gain ~3.3x
- Combined with Stage 2: ~45 dB of mains frequency rejection
- This is essential — 50/60 Hz mains hum is your biggest enemy

**Stage 4 — Anti-alias low-pass:**
- Sallen-Key 2nd-order, cutoff 52 Hz, gain ~2.4x
- Sharp rolloff above 55 Hz to prevent aliasing

**Stage 5 — Variable gain:**
- Adjustable 1x to 21x for calibration per deployment
- Allows matching signal levels to ADC input range

**Total passband gain at 10 Hz: ~112 dB (~400,000x)**

**Op-amp alternatives for the preamplifier (in order of preference):**

| Part | Input Noise (10 Hz) | Cost | Notes |
|------|---------------------|------|-------|
| AD797 | 0.9 nV/√Hz | ~$8 | Excellent, classic choice |
| LT1028 | 1.0 nV/√Hz | ~$6 | Widely available |
| OPA209 | 3.3 nV/√Hz | ~$4 | Used in reference design |
| OP07 | ~10 nV/√Hz | ~$1 | Budget option, used in Elektor build |

### ADC (Analog-to-Digital Converter)

**Requirements:**
- Sample rate: **200 Hz** (Nyquist for 55 Hz band, with headroom for anti-alias filter rolloff)
- Bit depth: **16-bit minimum**, 24-bit preferred
- Research shows the difference between 16 and 24 bits is "negligible" for SR — the analog noise floor dominates
- The ADC noise floor must be below the analog chain's noise floor

**Recommended:**

| Part | Resolution | Max Rate | Interface | Cost |
|------|-----------|----------|-----------|------|
| ADS1256 | 24-bit | 30 kSPS | SPI | $15-25 (breakout board) |
| Waveshare ADS1263 HAT | 32-bit | 38.4 kSPS | SPI (Pi HAT) | $30-40 |

The ADS1256 on a breakout board is the sweet spot — 24-bit resolution, SPI interface to Pi, well-documented Python libraries, and cheap.

**Do not use:** Arduino's built-in 10-bit ADC (insufficient resolution and too noisy).

### Compute (Raspberry Pi)

Any Raspberry Pi model works — the compute requirements are minimal:
- Sample ADC via SPI at configured rate (e.g., 256 Hz)
- Buffer one segment of raw samples (e.g., 10 seconds = 2560 samples)
- Publish raw time-domain samples to EarthSync via Redis stream or HTTP API

No spectral processing is needed on the Pi. All FFT, PSD, and peak detection happens server-side.

A Pi Zero 2 W ($15) could handle this easily (~1% CPU). A Pi 4/5 is comfortable overkill.

---

## Site Requirements

**This is the hardest constraint.** Schumann Resonance measurement requires electromagnetic quiet that does not exist in urban or suburban environments.

### Minimum Distance from Interference Sources

| Source | Minimum Distance |
|--------|-----------------|
| Power lines (any voltage) | 5+ km |
| Villages/settlements | 5+ km |
| Electric railways | 10+ km |
| Switching power supplies, inverters, solar inverters | Not present at site |
| Paved roads with traffic | 1+ km |

### Site Selection Criteria

- **Rural/wilderness location** — farmland, forest, mountain, desert
- **No mains power at the measurement point** — battery power only
- **Low geomagnetic noise** — away from geological formations with high conductivity
- **Accessible for maintenance** — but remote enough for quiet
- **Clear ground** — avoid metal structures, fences, buried pipes within 50m

### Practical Mitigation for Less-Than-Perfect Sites

If 5+ km from power lines isn't achievable:
- Orient the coil to **null the direction** of the nearest power line (minimizes pickup)
- Add more aggressive notch filtering (50/60 Hz and harmonics at 100/120, 150/180 Hz)
- Measure at night when industrial activity is lower
- Use **longer averaging** (more FFT windows) to improve SNR
- Accept that you may only resolve the first 3-4 harmonics cleanly instead of all 8

### Sensor Placement

- Bury the coil 30-50 cm underground to reduce wind vibration and some EMI
- Keep all digital electronics (Pi, ADC) at least 2-3 meters from the coil, connected by shielded cable
- The coil must be horizontal (SR magnetic field is horizontal)
- For two-axis measurement, place two coils orthogonally (N-S and E-W)

---

## Software Interface Contract

The EarthSync backend accepts raw time-domain samples from hardware stations. Both Redis stream and HTTP API expect the same JSON payload format.

### JSON Payload Format

```json
{
  "samples": [float array, length = sampleRateHz * segmentDurationS],
  "sampleRateHz": 256,
  "segmentDurationS": 10,
  "stationId": "hardware-station-01",
  "timestamp": "2026-03-26T12:34:56.789Z",
  "location": {"lat": 40.7128, "lon": -74.0060},
  "sensorType": "magnetic_ns",
  "metadata": {
    "is_calibrated": true,
    "sensor_type": "induction_coil_magnetometer",
    "model": "custom_build_v1"
  }
}
```

### Option A: Redis Stream (Preferred for Local/LAN Deployment)

```
XADD spectrogram_stream * data '<JSON payload>'
```

### Option B: HTTP API (Preferred for Remote/Internet Deployment)

```
POST http://<backend>:3000/api/data-ingest
X-API-Key: <configured key>
Content-Type: application/json

<JSON payload>
```

### Data Format Requirements

| Parameter | Value | Notes |
|-----------|-------|-------|
| Sample rate | 90-10,000 Hz | Minimum 90 Hz to cover SR band via Nyquist. 100-256 Hz recommended. |
| Segment duration | 1-600 seconds | 10 seconds recommended (matches observatory practice) |
| Samples per segment | sampleRateHz x segmentDurationS | e.g., 2560 for 256 Hz x 10s |
| Value type | Float | Raw ADC values, arbitrary units (calibration applied separately) |
| Update interval | Equal to segment duration | One segment every 10 seconds recommended |
| Timestamp | ISO 8601 UTC | Optional (server uses current time if omitted) |

### What the Hardware Produces

The hardware station produces raw time-domain samples — the direct output of the ADC after analog signal conditioning. No spectral computation is needed on the hardware side.

The signal chain is:

```
Induction Coil → Analog Front-End → ADC (SPI) → Pi
                                                  ↓
                                           [Python station script]
                                           1. Read ADC at configured rate (e.g., 256 Hz)
                                           2. Buffer one segment (e.g., 10 seconds = 2560 samples)
                                           3. Publish raw samples to EarthSync via Redis or HTTP
                                                  ↓
                                           [EarthSync Backend]
                                           1. Welch PSD (Hann window, zero-pad)
                                           2. Lorentzian fitting (peak parameters)
                                           3. Quality validation
                                           4. Display grid resampling (1,101 points)
```

The hardware does NOT need to:
- Compute FFTs or power spectral density
- Downsample or resample data
- Detect peaks or fit models
- Produce any specific number of frequency bins

All spectral processing happens server-side. This means:
- Different stations can use different sample rates (130, 200, 256 Hz, etc.)
- The backend handles all spectral estimation with consistent, validated algorithms
- Hardware complexity is minimized — just sample the ADC and send the data

---

## Calibration Procedure

### Hardware vs Software Responsibility

| Capability | Source | Frequency | Notes |
|---|---|---|---|
| Coil sensitivity (nV/pT/Hz) | Hardware measurement or calculation | Once per build | From coil geometry + core permeability, or measured with Helmholtz coil |
| Gain chain transfer function H(f) | Hardware measurement (signal sweep) | Once per build; repeat if analog components change | Sweep known-amplitude sine wave 1-55 Hz, measure ADC output |
| Noise floor (pT/√Hz) | Hardware measurement (shorted input) | Once per build, periodic re-verify | Record with shorted input, post-process for PSD |
| Confidence intervals | Pure software | Every spectrum | Computed from spectral variance across recent measurements |
| SNR per peak | Pure software | Every peak detection | Peak amplitude / local noise floor estimate |
| Quality flags | Pure software | Every spectrum | Clipping, saturation, dead channel, mains contamination detection |
| Algorithm versioning | Pure software | Static | Version tag embedded in processing code |
| Cross-validation | Pure software (network) | Periodic (hourly) | Fetch reference data from public SR monitoring stations |
| Provenance metadata | Pure software | Every message | Sensor ID, calibration status, algorithm version attached to each record |

### Step-by-Step Calibration

**Step 1 — Noise floor measurement:**
- Short the coil input (connect shielded cable inner conductor to ground at coil end)
- Power on full analog chain + ADC + Pi
- Record 10 minutes of data using the station script in its standard recording mode
- Save the raw samples for noise floor analysis
- Post-process to compute PSD and extract the noise floor characteristics
- A dedicated calibration mode for the station script is planned. In the meantime, use the standard recording mode and post-process the calibration data.

**Step 2 — Gain chain transfer function:**
- Connect a signal generator to the preamplifier input (disconnect the coil)
- Sweep a known-amplitude sine wave from 1 Hz to 55 Hz in 0.5 Hz steps
- At each frequency, record the ADC output using the station script and compute RMS from the raw samples
- Compile the results into `calibration/gain_curve.json`
- Format: `{ "timestamp": "ISO8601", "frequencies_hz": [float array], "gain_db": [float array], "input_amplitude_vrms": float }`
- A dedicated calibration mode for the station script is planned. In the meantime, use the standard recording mode and post-process the calibration data.

**Step 3 — Coil sensitivity:**
- Provide in `calibration/coil_sensitivity.yaml`:
```yaml
coil:
  turns: 40000
  core_material: mumetal
  core_length_mm: 300
  core_diameter_mm: 25
  wire_diameter_mm: 0.25
  measured_inductance_h: 249
  measured_resistance_ohm: 1560
  calculated_sensitivity_nv_per_pt_per_hz: 70
  measurement_method: calculated  # or "measured"
```

**Step 4 — Upload calibration to EarthSync:**
```bash
curl -X PUT http://<backend>:3000/api/stations/<stationId>/calibration \
  -H "X-API-Key: <key>" \
  -H "Content-Type: application/json" \
  -d '{
    "coilSensitivity": {"value": 70, "unit": "nV/pT/Hz", "referenceFreqHz": 20.0},
    "transferFunction": [
      {"freqHz": 1.0, "gainDB": 95.0},
      {"freqHz": 7.83, "gainDB": 100.0},
      {"freqHz": 20.0, "gainDB": 100.0},
      {"freqHz": 45.0, "gainDB": 98.0},
      {"freqHz": 55.0, "gainDB": 96.0}
    ],
    "noiseFloorPT": {"value": 0.3, "unit": "pT/sqrt(Hz)", "atFreqHz": 20.0}
  }'
```

Note: The backend accepts the `calibration_data` field as a generic JSON object. The structure shown above is recommended but not strictly enforced by the API.

**Step 5 — Verification:**
- Deploy the calibrated station at the measurement site
- Record 1 hour of data
- Check that Mode 1 (~7.83 Hz) amplitude is in the expected range for calibrated pT units (typically 0.5-2.0 pT)
- If amplitude is orders of magnitude off, re-check gain curve and coil sensitivity values
- The EarthSync frontend will show a "Calibrated" badge for this station

### Calibration File Structure

```
calibration/
  noise_floor.json        # From shorted-input recording, post-processed
  gain_curve.json         # From signal generator sweep, post-processed
  coil_sensitivity.yaml   # Manual entry or calculated
  calibration_status.json # Auto-generated summary
```

---

## Processing Pipeline (What the Backend Does)

You do **not** need to implement any of this on the hardware side — the backend handles it all:

1. **Time-domain validation** — Checks for clipping, saturation, flatline, NaN values. Unusable segments are flagged and skipped.
2. **Q-burst detection** — Identifies transient events in the raw waveform using sliding-window RMS analysis.
3. **Welch PSD computation** — Applies Hann window, zero-pads to next power of 2, computes one-sided power spectral density. Frequency resolution depends on sample rate and segment length (e.g., ~0.06 Hz for 256 Hz x 10s with 4096-point FFT).
4. **Spectral quality validation** — Checks for mains contamination (50/60 Hz), excessive noise floor.
5. **Peak detection** — Smoothing, prominence filtering, parabolic interpolation for sub-bin frequency precision.
6. **Lorentzian fitting** — Fits sum of Lorentzians + linear background to the PSD using Levenberg-Marquardt optimization. Extracts per-mode frequency, amplitude, and Q-factor with uncertainties.
7. **SNR computation** — Signal-to-noise ratio per peak using annular noise window.
8. **Peak tracking** — Matches peaks across time with persistent UUIDs.
9. **Noise floor estimation** — MAD-based robust broadband noise floor excluding SR mode regions.
10. **Display grid resampling** — Resamples native PSD to fixed 1,101-point grid (0-55 Hz) for frontend visualization.
11. **Archival** — Redis (recent 24-72h) → PostgreSQL (long-term).
12. **WebSocket broadcast** — Encrypted real-time push to frontend.
13. **Cross-validation** — Periodic comparison against known SR fundamentals (hourly).

The hardware just needs to produce raw time-domain samples. Everything else is handled.

---

## Station Software Architecture

A hardware station runs a small script on the Raspberry Pi that reads the ADC and publishes raw samples:

```
Induction Coil → Analog Front-End → ADC (SPI at 256 Hz) → Pi
                                                            ↓
                                                     [Station Script]
                                                     1. Configure ADC (sample rate, gain)
                                                     2. Read samples continuously
                                                     3. Buffer 10 seconds of data
                                                     4. Publish to EarthSync backend
                                                     5. Repeat
```

The station script is intentionally simple — it's a data collector, not a processor. All analysis happens on the backend. This means:
- The Pi only needs enough compute to read the ADC and send data (~1% CPU on a Pi Zero)
- Hardware bugs don't corrupt the science (raw data is preserved, reprocessable)
- Algorithm improvements on the backend automatically apply to all historical data

### Integration Options

**Option A: Redis Stream (preferred for local/LAN deployment)**
```
XADD spectrogram_stream * data '<JSON payload>'
```

**Option B: HTTP API (preferred for remote/internet deployment)**
```
POST http://<backend>:3000/api/data-ingest
X-API-Key: <configured key>
Content-Type: application/json
```

Both accept the same JSON payload format (see Software Interface Contract above).

### Docker Integration

For a hardware station, run the station script natively on the Pi (not in Docker — it needs direct SPI access to the ADC). The script publishes to the EarthSync backend's HTTP API endpoint over the network.

---

## Known Open-Source Reference Designs

| Project | Approach | Availability |
|---------|----------|-------------|
| **MatejGomboc/ELF-Schumann-Resonance-Receiver** | KiCad PCB with LMP7721 preamp | GitHub, AGPL-3.0, full schematic + PCB |
| **Tatsis et al. (2018)** | Full receiver design, peer-reviewed | Published paper (Springer), complete circuit diagrams |
| **vlf.it ICS-101** | Induction coil sensor with built-in preamp | Documented build at vlf.it |
| **Elektor ELF Receiver (Oct 2014)** | Arduino + OP07/TL074 op-amps | Magazine article (~5 EUR) |
| **techlib.com Converter** | Upconverts 8 Hz to 2 kHz for sound card recording | Full schematic at techlib.com |
| **ELFquake** | Arduino + ESP8266 front-end | WordPress blog + code |

The **MatejGomboc** PCB design is the most directly usable — order the PCB, populate it, connect to a coil and ADC.

---

## Comparison: Simulated vs Real Hardware

| Aspect | Current Simulator | Real Hardware |
|--------|-------------------|---------------|
| Signal source | Time-domain synthetic signal (biquad resonant filters) | Actual Earth-ionosphere cavity resonances |
| Peak frequencies | Hardcoded [7.83, 14.3, 20.8, ...] | Naturally occurring (drift ±0.5 Hz with ionospheric conditions) |
| Amplitude variation | Simulated diurnal cycle | Real diurnal, seasonal, solar, and lightning-driven variation |
| Q-bursts | Random 0.5% probability | Real lightning-driven transients (correlate with global thunderstorm activity) |
| Noise | Synthetic Gaussian | Real geomagnetic noise + local EMI |
| Cost per station | $0 | ~$250-400 |
| Site requirements | None | Remote, 5+ km from power lines |
| Scientific value | None | Real data, publishable, contributes to geophysics |

---

## Estimated Total Cost for 3-Station Network

Matching the current 3-station EarthSync deployment (NYC, London, Sydney equivalent):

| Item | Per Station | x3 Stations |
|------|------------|-------------|
| Induction coil + core | $100 | $300 |
| Analog front-end (PCB + components) | $60 | $180 |
| ADC (ADS1256 module) | $20 | $60 |
| Raspberry Pi (any model) | $45 | $135 |
| GPS module | $15 | $45 |
| Power (battery + optional solar) | $45 | $135 |
| Enclosure + cables | $30 | $90 |
| **Per-station total** | **~$315** | **$945** |

Plus: 3 suitable measurement sites, which is the real constraint.

---

## Getting Started: Incremental Path

You don't need to build all 3 stations at once. Each phase validates the next before committing more time and money.

### Phase 0 — Validate the Site ($0, 1 afternoon)

**Do this before spending anything on hardware.** The site is the most likely failure point.

Take a smartphone with a magnetometer/spectrum analyzer app (or a cheap audio recorder with a long wire as an antenna) to your candidate location. What you're looking for:
- **50/60 Hz hum level** — If it's overwhelmingly dominant below 100 Hz, the site is too noisy for SR measurement. All sites will show some 50/60 Hz; the question is whether it's manageable with notch filters or completely saturating.
- **Broadband noise floor** — Listen/look for buzzing from nearby inverters, transformers, or electric fences.
- **Physical access** — Can you leave equipment here? Is there cellular coverage for data uplink? Can you return for maintenance?

If you cannot find a site where 50/60 Hz is at least tolerable, stop here. No amount of hardware will fix a fundamentally noisy location.

**Good candidate sites:** Remote farmland, forest clearings, mountain meadows, desert. Ideally 5+ km from the nearest power line.

**Marginal sites (may work with extra filtering):** Rural areas 1-5 km from low-voltage power lines. Expect to see only the first 3-4 SR harmonics. Nighttime measurement may be significantly quieter.

**Non-viable sites:** Anything suburban or urban. Within 1 km of high-voltage transmission lines. Near rail corridors or industrial areas.

### Phase 1 — Build and Bench-Test the Electronics (~$300, 1-2 weekends)

Build one coil and analog front-end on a breadboard. You can validate the electronics work even in a noisy indoor environment:
- You'll see 50/60 Hz hum loud and clear — this confirms your gain chain and ADC are functioning
- Connect the ADC to a Pi and run a simple FFT script to verify the full signal chain
- Measure the noise floor with the coil input shorted to confirm your front-end meets spec

**Success criteria:** The system produces clean spectral data with expected gain. You can identify 50/60 Hz and its harmonics in the FFT output.

### Phase 2 — Field Test at Your Validated Site (~$0 additional, 1 day)

Take the breadboard prototype to the quiet site from Phase 0. Run on battery power. Acquire 10+ minutes of data and compute averaged spectra (Welch's method).

**Success criteria:** You can see the 7.83 Hz fundamental peak in the averaged power spectrum. If you can also see the 14.3 Hz second harmonic, the system is working well.

**If you can't see SR peaks:** Check that the site is truly quiet (re-run Phase 0 checks). Verify the coil orientation (must be horizontal). Try longer averaging. Consider whether the coil sensitivity is sufficient — this is where mumetal vs ferrite core matters.

### Phase 3 — Integrate with EarthSync (~$0 additional, 1 evening)

Write the Pi station script: read ADC, buffer raw samples, publish to EarthSync HTTP API. Verify the backend processes it correctly alongside the existing simulators.

**Success criteria:** Real hardware data appears in the EarthSync frontend. Peak detection identifies SR modes in the real data. You can compare real vs simulated spectra side by side.

### Phase 4 — Deploy One Permanent Field Station (~$50 additional for enclosure/power)

Weatherproof the electronics. Set up battery + optional solar power. Establish a reliable network uplink (cellular, WiFi, or store-and-forward).

**Success criteria:** The station runs unattended for 1+ week, producing continuous SR data with <5% downtime.

### Phase 5 — Scale to Multiple Stations (if Phase 4 succeeds)

Each station is an independent station with its own ID and location. The EarthSync backend handles multi-station display and archival natively. But running 3 remote stations means 3 quiet sites with power, network, and physical access for maintenance — this is a significant logistical commitment.

The software is already designed for this — the station is a pluggable data source. The hard part is the analog electronics and finding quiet sites.
