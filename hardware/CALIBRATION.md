# Sensor Calibration Procedures

Calibration establishes the quantitative relationship between the physical
magnetic field (in picoTesla) and the digital output of the EarthSync station.
Without calibration, the station produces relative measurements only. Proper
calibration enables absolute measurements that can be compared across the
global EarthSync network.

## References

- **Tatsis, G. et al. (2020)** -- "Design and Implementation of a Test Platform for ELF Schumann Resonance Receivers." Electronics 9(6), 895.
- **Christofilakis, V. et al. (2018)** -- "A Low-Cost Receiver for Schumann Resonance Observations." IEEE Trans. Antennas Propag.
- **Nickolaenko, A.P. & Hayakawa, M. (2002)** -- _Resonances in the Earth-Ionosphere Cavity._ Kluwer Academic.
- **Mushtak, V.C. & Williams, E.R. (2002)** -- "ELF propagation parameters for uniform models of the Earth-ionosphere waveguide." J. Atmos. Solar-Terr. Phys.

---

## 1. Test Fixture Calibration Method

This is the primary calibration method, based on the approach described by
Tatsis et al. (2020). A calibration coil of known geometry produces a known
magnetic field when driven with a known current.

### 1.1 Calibration Coil Construction

Build a Helmholtz-like calibration coil:

1. Wind 20 turns of insulated hookup wire on a non-magnetic form (PVC pipe
   or wooden frame) with diameter 30--50 cm.
2. The calibration coil should be large enough to fully enclose the sensor
   coil with at least 5 cm clearance on all sides.
3. Measure and record the exact dimensions:
   - Number of turns: N_cal
   - Radius of calibration coil: r_cal (meters)
   - Length of calibration coil: l_cal (meters, if solenoid) or use
     Helmholtz pair spacing = r_cal

### 1.2 Magnetic Field Calculation

For a single circular coil at the center, the magnetic field is:

```
B = mu_0 * N_cal * I / (2 * r_cal)
```

Where:
- mu_0 = 4*pi*10^-7 T*m/A (permeability of free space)
- N_cal = number of turns
- I = current in amperes
- r_cal = coil radius in meters

For a Helmholtz pair (two coils separated by one radius), the field at the
center is more uniform:

```
B = (4/5)^(3/2) * mu_0 * N_cal * I / r_cal
    = 0.7155 * mu_0 * N_cal * I / r_cal
```

**Example:** Helmholtz pair, N_cal = 20, r_cal = 0.2 m, I = 1 mA:
```
B = 0.7155 * 4*pi*10^-7 * 20 * 0.001 / 0.2
  = 0.7155 * 2.513e-8 * 0.005
  = 8.99e-11 T
  ~ 90 pT
```

This is well within the range of Schumann resonance signals (typically 0.5--5
pT at the fundamental).

### 1.3 Calibration Procedure

1. Place the sensor coil at the center of the calibration coil, with axes
   aligned (both pointing in the same direction).
2. Connect a function generator to the calibration coil through a precision
   series resistor (10 kohm, 0.1%). The resistor converts the generator's
   voltage output to a known current:
   ```
   I = V_gen / R_series
   ```
3. Set the function generator to output a sine wave at 7.83 Hz (fundamental
   Schumann frequency) with an amplitude that produces approximately 1 pT
   at the sensor.
4. Record the EarthSync station output (ADC counts or voltage) while the
   calibration field is applied.
5. Calculate the calibration factor:
   ```
   K = B_applied / V_output   [pT per ADC count, or pT per volt]
   ```
6. Repeat at multiple frequencies: 5, 7.83, 10, 14.3, 20, 20.8, 27.3, 30,
   33.8, 39, 45 Hz to characterize the frequency response.
7. Record all measurements in a calibration log.

### 1.4 Current Measurement

For accurate calibration, the current through the calibration coil must be
precisely known:

- **Method 1:** Measure the voltage across the precision series resistor with
  a calibrated multimeter. I = V_R / R.
- **Method 2:** Use a calibrated current probe (e.g., Tektronix TCP0030)
  if available.
- **Method 3:** For sub-milliamp currents, use a transimpedance amplifier
  to convert current to a measurable voltage.

The current must be measured at each test frequency, as the calibration coil's
impedance varies with frequency (L and R are frequency-dependent).

---

## 2. Frequency-Domain Transfer Function Measurement

The complete transfer function characterizes the station's response at every
frequency in the band of interest.

### 2.1 Sine Sweep Method

1. Set up the calibration fixture as described in Section 1.
2. Configure the function generator for a logarithmic sine sweep from 1 Hz
   to 60 Hz.
3. At each frequency point (recommend 1 Hz steps from 1--10 Hz, then 2 Hz
   steps from 10--60 Hz), measure:
   - Applied magnetic field amplitude B_in (from known current and coil geometry)
   - Station output amplitude V_out (from ADC reading)
   - Phase difference between input and output (if phase-sensitive measurement
     is available)
4. Compute the transfer function magnitude and phase:
   ```
   H(f) = V_out(f) / B_in(f)   [V/pT or counts/pT]
   phase(f) = phi_out(f) - phi_in(f)   [degrees]
   ```

### 2.2 Chirp Method (Alternative)

For faster characterization, use a linear chirp signal:

1. Generate a linear chirp from 1 Hz to 60 Hz over 60 seconds.
2. Record both the calibration coil drive signal (via a second ADC channel or
   oscilloscope) and the station output simultaneously.
3. Compute the cross-spectral density and auto-spectral density.
4. The transfer function is:
   ```
   H(f) = S_xy(f) / S_xx(f)
   ```
   Where S_xy is the cross-spectrum and S_xx is the input auto-spectrum.

### 2.3 Expected Transfer Function Shape

The transfer function should show:

```
Magnitude (dB)
  ^
  |         xxxxxxxxxx
  |       xx          xxxxxxxx
  |     xx                    xx
  |   xx                        xx  <-- LPF rolloff at 46 Hz
  | xx                           \
  |x                              \
  | <-- coil response rising       \       xx <-- notch at 50 Hz
  |     at 6 dB/octave              xxxxxxx
  +----+----+----+----+----+----+----+----> f (Hz)
  0    5   10   15   20   30   40   50  60

Phase (degrees)
  ^
  |         xxxxxxxxxx
  | xxxxxxx           xxxxxxxxxxxx
  |x                              xxxxxxx
  |                                      x
  +----+----+----+----+----+----+----+----> f (Hz)
  0    5   10   15   20   30   40   50  60
```

The induction coil response rises at 6 dB/octave (20 dB/decade) due to
Faraday's law (output proportional to dB/dt). The LPF rolls off at -12
dB/octave above 46 Hz. The combination produces a bandpass shape with peak
response around 20--40 Hz. The notch filter produces a sharp dip at 50 Hz
(or 60 Hz).

### 2.4 Transfer Function Data Format

Record the transfer function as a CSV file or JSON array:

```json
{
  "station_id": "es-001",
  "calibration_date": "2026-03-28T14:30:00Z",
  "calibration_coil": {
    "turns": 20,
    "radius_m": 0.20,
    "type": "helmholtz"
  },
  "transfer_function": [
    {"frequency_hz": 1.0, "magnitude_vppt": 0.012, "phase_deg": 85.2},
    {"frequency_hz": 2.0, "magnitude_vppt": 0.024, "phase_deg": 84.8},
    {"frequency_hz": 3.0, "magnitude_vppt": 0.037, "phase_deg": 83.1},
    {"frequency_hz": 5.0, "magnitude_vppt": 0.061, "phase_deg": 78.5},
    {"frequency_hz": 7.83, "magnitude_vppt": 0.095, "phase_deg": 71.2},
    {"frequency_hz": 10.0, "magnitude_vppt": 0.118, "phase_deg": 65.3},
    {"frequency_hz": 14.3, "magnitude_vppt": 0.156, "phase_deg": 52.1},
    {"frequency_hz": 20.0, "magnitude_vppt": 0.192, "phase_deg": 38.7},
    {"frequency_hz": 20.8, "magnitude_vppt": 0.196, "phase_deg": 36.2},
    {"frequency_hz": 27.3, "magnitude_vppt": 0.210, "phase_deg": 22.5},
    {"frequency_hz": 30.0, "magnitude_vppt": 0.212, "phase_deg": 15.8},
    {"frequency_hz": 33.8, "magnitude_vppt": 0.205, "phase_deg": 5.3},
    {"frequency_hz": 39.0, "magnitude_vppt": 0.185, "phase_deg": -10.2},
    {"frequency_hz": 45.0, "magnitude_vppt": 0.142, "phase_deg": -28.5},
    {"frequency_hz": 50.0, "magnitude_vppt": 0.003, "phase_deg": -89.1},
    {"frequency_hz": 55.0, "magnitude_vppt": 0.068, "phase_deg": -55.3},
    {"frequency_hz": 60.0, "magnitude_vppt": 0.045, "phase_deg": -62.1}
  ]
}
```

---

## 3. Stage-by-Stage Gain Verification

Verify the gain of each individual stage to isolate any problems.

### 3.1 Preamplifier Gain

1. Disconnect the sensor coil from the preamplifier input.
2. Apply a known sine wave (e.g., 100 uV RMS at 10 Hz) from a function
   generator to the preamplifier input through a precision attenuator
   or voltage divider.
3. Measure the output amplitude with an oscilloscope or multimeter (AC RMS).
4. Calculate gain: G_preamp = V_out / V_in.
5. Compare to the design value (e.g., 100x = 40 dB).
6. Acceptable tolerance: +/- 5% of design value.

### 3.2 Filter Stage Gain

1. Apply a 10 Hz sine wave at the filter stage input at the level expected
   from the preamplifier output (e.g., 10 mV RMS).
2. Measure the output. For a unity-gain Sallen-Key, the output should be
   within 0.5 dB of the input at 10 Hz.
3. Repeat at 46 Hz (the -3 dB point). Output should be 0.707x the input
   (+/- 10%).
4. Repeat at 50 Hz. With the Twin-T notch, the output should be < 1/30th
   of the input (-30 dB or more).

### 3.3 Variable Gain Stage

1. Apply a known signal at the VGA input.
2. Step through each gain setting and record the output amplitude.
3. Verify each setting matches its design value within +/- 5%.

### 3.4 ADC Verification

1. Apply a known DC voltage to the ADC differential input (e.g., 1.000 V
   from a precision reference).
2. Read the ADC output code.
3. Calculate: V_measured = code * V_ref / (2^23 * PGA_gain)
4. Compare to the applied voltage. Error should be < 0.1%.

---

## 4. Noise Floor Measurement

The noise floor determines the weakest signal the station can detect.

### 4.1 Measurement Procedure

1. Short the preamplifier input to analog ground using a short wire (< 5 cm).
2. Set all gain stages to their normal operating values.
3. Record data for a minimum of 10 minutes (longer is better; 1 hour is
   ideal for accurate low-frequency noise characterization).
4. Compute the power spectral density (PSD) of the recording:
   ```bash
   earthsync-cli noise-floor --input recording.hdf5 --output noise_psd.csv
   ```
5. Convert the PSD from electrical units to magnetic field units using the
   calibration transfer function:
   ```
   PSD_magnetic(f) = PSD_electrical(f) / |H(f)|^2   [pT^2/Hz]
   noise_floor(f) = sqrt(PSD_magnetic(f))             [pT/sqrt(Hz)]
   ```

### 4.2 Validation Criteria

| Frequency  | Maximum Noise Floor | Notes                        |
|------------|--------------------|-----------------------------|
| 3 Hz       | 0.5 pT/sqrt(Hz)    | Below SR fundamental        |
| 7.83 Hz    | 0.1 pT/sqrt(Hz)    | At SR fundamental           |
| 14.3 Hz    | 0.1 pT/sqrt(Hz)    | At 2nd SR mode              |
| 20.8 Hz    | 0.1 pT/sqrt(Hz)    | At 3rd SR mode              |
| 33.8 Hz    | 0.15 pT/sqrt(Hz)   | At 5th SR mode              |
| 45 Hz      | 0.2 pT/sqrt(Hz)    | Near filter rolloff         |

The primary target is **noise floor < 0.1 pT/sqrt(Hz) across the 3--50 Hz
band**. This is achievable with a well-designed station using a 30+ cm
mu-metal core coil.

For comparison, typical Schumann resonance signal amplitudes are:
- Fundamental (7.83 Hz): 1--3 pT
- 2nd mode (14.3 Hz): 0.5--1.5 pT
- 3rd mode (20.8 Hz): 0.3--1.0 pT
- Higher modes: 0.1--0.5 pT

A noise floor of 0.1 pT/sqrt(Hz) provides approximately 10--30 dB SNR for
the fundamental and 0--10 dB SNR for the higher modes (assuming 1 Hz
resolution bandwidth).

### 4.3 Diagnosing Excess Noise

If the noise floor exceeds the targets:

| Noise Signature | Likely Cause | Fix |
|----------------|-------------|-----|
| Flat, elevated floor | Resistor thermal noise or op-amp noise | Check component values, replace op-amp |
| Rising at low frequency (1/f) | Op-amp 1/f noise | Use lower 1/f corner op-amp |
| Peaks at mains harmonics | Electromagnetic pickup | Improve shielding, check grounding |
| Broadband "hash" | Digital noise coupling | Separate analog/digital power, improve layout |
| Narrow peak at unexpected frequency | External interference | Site survey, identify source |
| Oscillation (very high, narrow peak) | Amplifier instability | Check compensation, decoupling |

---

## 5. Inter-Station Calibration

When multiple EarthSync stations are deployed, inter-station calibration
ensures measurement consistency across the network.

### 5.1 Co-Location Method

1. Deploy two or more stations at the same location (sensor coils within
   5 m of each other, aligned in the same direction).
2. Record simultaneously for at least 48 hours.
3. Compute the cross-correlation and transfer function between stations:
   ```bash
   earthsync-cli cross-calibrate \
     --station-a es-001-recording.hdf5 \
     --station-b es-002-recording.hdf5 \
     --output cross_cal_report.pdf
   ```
4. The transfer function between stations should be flat (within +/- 3 dB)
   across the 3--45 Hz band. Any deviation indicates a calibration error
   in one or both stations.

### 5.2 Remote Cross-Calibration

For stations that cannot be co-located:

1. Use the Schumann resonance itself as a common reference signal. During
   periods of high global lightning activity (typically 14:00--20:00 UTC,
   when the African thunderstorm center is most active), the SR signal is
   strong and coherent over continental distances.
2. Compare the amplitude of the fundamental mode (7.83 Hz) between stations
   after calibration correction. Stations within the same hemisphere should
   agree within +/- 6 dB for the fundamental amplitude.
3. Compare the fundamental frequency measurement. All stations should agree
   within +/- 0.1 Hz on the fundamental frequency (it varies between
   approximately 7.5 and 8.2 Hz).

### 5.3 Network Calibration Metrics

The EarthSync server computes the following network-wide calibration metrics:

- **Amplitude consistency:** Standard deviation of calibrated fundamental
  amplitude across all stations (target: < 3 dB).
- **Frequency agreement:** Standard deviation of measured fundamental
  frequency across all stations (target: < 0.05 Hz).
- **Cross-correlation coefficient:** Between pairs of stations at distances
  < 2000 km (target: > 0.7 for the fundamental mode).

---

## 6. Periodic Recalibration Schedule

Calibration can drift over time due to temperature cycling, component aging,
mechanical stress, and environmental changes.

### Recommended Schedule

| Interval   | Procedure                                  | Time Required |
|-----------|-------------------------------------------|---------------|
| Monthly   | Noise floor measurement (shorted input)    | 30 minutes    |
| Monthly   | Visual inspection of cables and connectors | 15 minutes    |
| Quarterly | Full transfer function measurement         | 2 hours       |
| Quarterly | Stage-by-stage gain verification           | 1 hour        |
| Annually  | Calibration coil verification              | 1 hour        |
| Annually  | Earth rod ground resistance measurement    | 30 minutes    |

### Drift Thresholds

Recalibrate immediately if:
- Noise floor increases by more than 6 dB from baseline
- Gain at any frequency changes by more than 3 dB from initial calibration
- New interference peaks appear in the noise floor spectrum
- Physical damage to any component is observed

### Calibration Log

Maintain a calibration log (paper or digital) recording:
- Date and time of each calibration
- Environmental conditions (temperature, humidity, weather)
- All measured values
- Any anomalies observed
- Corrective actions taken

The EarthSync firmware stores calibration history in the local database and
syncs it to the server.

---

## 7. Software Calibration Upload

After completing the transfer function measurement, upload the calibration
data to the EarthSync server so that all data from your station is correctly
scaled.

### 7.1 API Endpoint

```
POST /api/stations/:id/calibration
Content-Type: application/json
Authorization: Bearer <station_api_key>
```

### 7.2 Request Body

```json
{
  "calibration_date": "2026-03-28T14:30:00Z",
  "calibration_method": "helmholtz_coil",
  "calibration_coil": {
    "turns": 20,
    "radius_m": 0.20,
    "type": "helmholtz",
    "series_resistance_ohm": 10000
  },
  "environment": {
    "temperature_c": 22.5,
    "humidity_pct": 45,
    "location": "indoor_lab"
  },
  "noise_floor": {
    "measurement_duration_s": 600,
    "input_condition": "shorted",
    "values": [
      {"frequency_hz": 7.83, "noise_pt_per_rthz": 0.08},
      {"frequency_hz": 14.3, "noise_pt_per_rthz": 0.06},
      {"frequency_hz": 20.8, "noise_pt_per_rthz": 0.05},
      {"frequency_hz": 27.3, "noise_pt_per_rthz": 0.07},
      {"frequency_hz": 33.8, "noise_pt_per_rthz": 0.09}
    ]
  },
  "transfer_function": [
    {"frequency_hz": 1.0, "magnitude_vppt": 0.012, "phase_deg": 85.2},
    {"frequency_hz": 2.0, "magnitude_vppt": 0.024, "phase_deg": 84.8},
    {"frequency_hz": 3.0, "magnitude_vppt": 0.037, "phase_deg": 83.1},
    {"frequency_hz": 5.0, "magnitude_vppt": 0.061, "phase_deg": 78.5},
    {"frequency_hz": 7.83, "magnitude_vppt": 0.095, "phase_deg": 71.2},
    {"frequency_hz": 10.0, "magnitude_vppt": 0.118, "phase_deg": 65.3},
    {"frequency_hz": 14.3, "magnitude_vppt": 0.156, "phase_deg": 52.1},
    {"frequency_hz": 20.0, "magnitude_vppt": 0.192, "phase_deg": 38.7},
    {"frequency_hz": 20.8, "magnitude_vppt": 0.196, "phase_deg": 36.2},
    {"frequency_hz": 27.3, "magnitude_vppt": 0.210, "phase_deg": 22.5},
    {"frequency_hz": 30.0, "magnitude_vppt": 0.212, "phase_deg": 15.8},
    {"frequency_hz": 33.8, "magnitude_vppt": 0.205, "phase_deg": 5.3},
    {"frequency_hz": 39.0, "magnitude_vppt": 0.185, "phase_deg": -10.2},
    {"frequency_hz": 45.0, "magnitude_vppt": 0.142, "phase_deg": -28.5},
    {"frequency_hz": 50.0, "magnitude_vppt": 0.003, "phase_deg": -89.1},
    {"frequency_hz": 55.0, "magnitude_vppt": 0.068, "phase_deg": -55.3},
    {"frequency_hz": 60.0, "magnitude_vppt": 0.045, "phase_deg": -62.1}
  ],
  "gain_stages": {
    "preamplifier_db": 40.0,
    "lpf_gain_db": 0.0,
    "notch_gain_db": 0.0,
    "variable_gain_db": 20.0,
    "adc_pga_db": 12.0,
    "total_db": 72.0
  }
}
```

### 7.3 Response

```json
{
  "status": "accepted",
  "calibration_id": "cal-20260328-143000-es001",
  "validation": {
    "noise_floor_check": "PASS",
    "gain_flatness_check": "PASS",
    "frequency_coverage_check": "PASS",
    "notch_depth_check": "PASS"
  },
  "warnings": [],
  "effective_from": "2026-03-28T14:30:00Z"
}
```

### 7.4 CLI Upload

Alternatively, use the command-line tool:

```bash
earthsync-cli calibration upload \
  --transfer-function cal_tf_20260328.json \
  --noise-floor cal_nf_20260328.json \
  --notes "Quarterly recalibration, no issues"
```

### 7.5 Automated Calibration Verification

After uploading, the server runs validation checks:

| Check                  | Criterion                              | Action on Fail |
|-----------------------|----------------------------------------|----------------|
| Noise floor           | < 0.1 pT/sqrt(Hz) at 7.83 Hz          | Warning         |
| Gain flatness         | +/- 3 dB over 3--50 Hz                 | Warning         |
| Notch depth           | > 30 dB at 50/60 Hz                    | Warning         |
| Frequency coverage    | Data at >= 10 frequency points         | Reject          |
| Consistency           | < 6 dB change from previous calibration | Warning         |
| Transfer function shape | Rising below ~30 Hz (coil response)  | Warning         |

---

## 8. Validation Criteria Summary

A properly calibrated EarthSync station must meet all of the following:

| Parameter                        | Criterion                    |
|----------------------------------|------------------------------|
| Noise floor (3--50 Hz)           | < 0.1 pT/sqrt(Hz)           |
| Gain flatness (3--50 Hz)         | +/- 3 dB                    |
| Notch depth (50 or 60 Hz)        | > 30 dB                     |
| Phase linearity (3--45 Hz)       | < 10 deg deviation from fit |
| Stage gain accuracy              | +/- 5% of design value      |
| ADC linearity                    | < 0.1% error                |
| Calibration repeatability        | < 1 dB between runs         |
| Inter-station consistency        | < 6 dB amplitude difference |
| Fundamental frequency agreement  | +/- 0.1 Hz across network   |

Stations meeting all criteria are assigned "calibrated" status on the
EarthSync network and their data is included in the global analysis products.
Stations failing one or more criteria are flagged for maintenance and their
data is excluded from network products until recalibrated.
