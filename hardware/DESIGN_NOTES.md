# Signal Chain Design Rationale

Design notes for the EarthSync citizen-science Schumann Resonance monitoring
station analog front-end. This document explains component selection, gain
budgeting, and noise analysis for each stage of the signal chain.

## References

- **Christofilakis et al. 2018** -- "A Low-Cost Receiver for Schumann Resonance Observations." IEEE Trans. Antennas Propag.
- **Gazquez Parra et al. 2015** -- "New design of a low-cost system for Schumann resonance measurements." Measurement Science and Technology.
- **Tatsis et al. 2020** -- "Design and Implementation of a Test Platform for ELF Schumann Resonance Receivers." Electronics 9(6).
- **Sierra Luna et al. 2017** -- "A portable Schumann-resonance station." Annals of Geophysics 60(6).
- **Tritakis et al. 2021** -- "Electromagnetic interference on Schumann resonance measurements." Journal of Atmospheric and Solar-Terrestrial Physics.
- **Nickolaenko & Hayakawa 2002** -- _Resonances in the Earth-Ionosphere Cavity._ Kluwer Academic Publishers.

---

## Signal Chain Block Diagram

```
                        ANALOG FRONT-END
  ┌─────────┐   ┌────────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
  │Induction │   │ Preamp     │   │ Sallen-  │   │ Twin-T   │   │ Variable │
  │  Coil    ├──>│ OPA209     ├──>│ Key LPF  ├──>│ Notch    ├──>│ Gain     │
  │Magneto-  │   │ G=100-1000 │   │ fc=46 Hz │   │ f0=50 Hz │   │ G=1-21x  │
  │ meter    │   │ (40-60 dB) │   │ 2nd order│   │ (or 60)  │   │ (0-26 dB)│
  └─────────┘   └────────────┘   └──────────┘   └──────────┘   └─────┬────┘
       |                                                              |
       |  ~1 pT signal                                                v
       |  ~1-2 mV/pT                               ┌─────────────────────┐
       |                                            │    ADS1256 ADC      │
       |                                            │  24-bit, 100-256 Hz │
       |                                            │  SPI to Raspberry Pi│
       |                                            └────────┬────────────┘
       |                                                     |
       |              DIGITAL DOMAIN                         v
       |         ┌──────────────────────────────────────────────┐
       |         │           Raspberry Pi 4                     │
       |         │  ┌──────────┐  ┌──────────┐  ┌───────────┐  │
       |         │  │ SPI      │  │ DSP /    │  │ WebSocket │  │
       |         │  │ Driver   ├─>│ PSD /    ├─>│ Stream to │  │
       |         │  │          │  │ Peak Det │  │ Server    │  │
       |         │  └──────────┘  └──────────┘  └───────────┘  │
       |         │                                              │
       |         │  ┌──────────┐                                │
       |         │  │ GPS/PPS  │ <-- NEO-M8 (UART + 1PPS)      │
       |         │  │ Timing   │                                │
       |         │  └──────────┘                                │
       |         └──────────────────────────────────────────────┘
       |
  ┌────┴────┐
  │ Battery │   Solar + LiPo + LDO regulators
  │ Power   │   Analog/digital domains separated
  └─────────┘
```

### Gain Budget Summary

| Stage           | Gain (linear) | Gain (dB) | Cumulative (dB) |
|-----------------|---------------|-----------|------------------|
| Coil (V/pT)    | 0.001-0.002   | n/a       | n/a              |
| Preamplifier    | 100-1000      | 40-60     | 40-60            |
| Sallen-Key LPF  | 1 (unity)     | 0         | 40-60            |
| Twin-T Notch    | ~1 (passband) | 0         | 40-60            |
| Variable Gain   | 1-21          | 0-26      | 40-86            |
| ADS1256 PGA     | 1-64          | 0-36      | 40-122           |
| **Typical total** | --          | --        | **66-86**        |

The typical operating point uses preamplifier gain of 100x (40 dB), variable
gain of 10x (20 dB), and ADC PGA of 4x (12 dB) for a total of 72 dB.
Maximum available gain is 122 dB for extremely weak signals.

---

## 1. Sensor: Induction Coil Magnetometer

### Why Induction Coil?

Three sensor technologies are capable of detecting Schumann resonance signals
in the 1--50 Hz ELF band:

| Technology      | Sensitivity        | Cost      | Complexity | Power   |
|-----------------|--------------------|-----------|------------|---------|
| SQUID           | ~1 fT/sqrt(Hz)     | >$50,000  | Cryogenic  | High    |
| Fluxgate        | ~1-10 pT/sqrt(Hz)  | $500-5000 | Moderate   | ~1 W    |
| Induction Coil  | 0.01-1 pT/sqrt(Hz) | $50-150   | Low        | Passive |

The induction coil magnetometer is the only viable option for a citizen-science
station at the $250--400 price point. It is entirely passive (no power required
for the sensor itself), mechanically simple, and achievable with commodity
materials. Fluxgate magnetometers approach the required sensitivity but cost
5--30x more. SQUIDs are confined to research institutions.

### Sensitivity Calculation

The output voltage of an induction coil in a time-varying magnetic field is
given by Faraday's law:

```
V = -N * mu_r * A * (dB/dt)
```

Where:
- `N` = number of turns
- `mu_r` = effective relative permeability of the core
- `A` = cross-sectional area of the core
- `dB/dt` = time derivative of the magnetic field

For a sinusoidal magnetic field at frequency `f` with amplitude `B_0`:

```
V_rms = 2 * pi * f * N * mu_eff * A * B_0 / sqrt(2)
```

**Example calculation** (portable station):
- Core: mu-metal, 25 cm length, 10 mm diameter
- `mu_eff` ~ 500 (demagnetization factor reduces apparent permeability)
- `A` = pi * (0.005)^2 = 7.85 x 10^-5 m^2
- `N` = 50,000 turns
- `f` = 7.83 Hz (fundamental Schumann mode)
- `B_0` = 1 pT = 10^-12 T

```
V_rms = 2 * pi * 7.83 * 50000 * 500 * 7.85e-5 * 1e-12 / 1.414
       = 6.82 x 10^-5 V
       ~ 68 uV per pT at 7.83 Hz
```

This gives approximately 68 uV/pT at the fundamental frequency, or about
1--2 mV/pT when using a 1.35 m core with higher effective permeability as in
Christofilakis et al. 2018.

### Coil Electrical Model

The induction coil presents a complex impedance to the preamplifier:

```
Z_coil = R_dc + j*2*pi*f*L + 1/(j*2*pi*f*C_dist)
```

Where `R_dc` is the DC resistance (2--6 kohm for 40,000--80,000 turns of
0.2 mm wire), `L` is the inductance (50--200 H), and `C_dist` is the
distributed capacitance between winding layers (typically 50--500 pF).

The self-resonant frequency must be well above the Schumann band:

```
f_res = 1 / (2 * pi * sqrt(L * C_dist))
```

Target: `f_res` > 100 Hz. This requires careful winding technique to minimize
distributed capacitance, such as sectioned (bank-wound) coils with inter-layer
insulation.

---

## 2. Preamplifier Stage

### Op-Amp Selection: OPA209

The preamplifier is the most critical stage for noise performance. The total
referred-to-input noise determines the system noise floor.

**OPA209 key parameters:**
- Voltage noise density: 3.3 nV/sqrt(Hz) at 1 kHz, approximately 10 nV/sqrt(Hz) at 10 Hz
- Current noise density: 3.5 pA/sqrt(Hz)
- 1/f corner frequency: ~100 Hz
- Input bias current: 10 nA typical
- GBW: 18 MHz
- CMRR: 140 dB

**Why OPA209 over alternatives:**

The AD797 (0.9 nV/sqrt(Hz)) and LT1028 (0.85 nV/sqrt(Hz)) offer lower voltage
noise, but at our source impedance of 2--6 kohm, the current noise contribution
becomes significant. The total input-referred noise is:

```
e_n_total = sqrt(e_n^2 + (i_n * R_s)^2 + 4*k*T*R_s)
```

For the OPA209 with R_s = 4 kohm:
```
e_n_total = sqrt(3.3^2 + (3.5e-3 * 4000)^2 + 4*1.38e-23*300*4000 * 1e18)
          = sqrt(10.89 + 196 + 8.12) [all in nV^2/Hz]
          = sqrt(215) ~ 14.7 nV/sqrt(Hz)
```

The current noise term (14 nV/sqrt(Hz) equivalent) dominates at this source
impedance. The OPA209's moderate current noise of 3.5 pA/sqrt(Hz) is a
reasonable compromise. BJT-input op-amps with sub-1 nV/sqrt(Hz) voltage noise
often have 1--4 pA/sqrt(Hz) current noise, yielding similar total noise at
these impedances.

### Gain Configuration

The preamplifier is configured as a non-inverting amplifier:

```
        R_f
    ┌───/\/\/───┐
    │            │
    │    ┌───┐  │
 ───┤    │   ├──┴─── V_out
    │  +-│OPA│
    │    │209│
    ├──  │   │
    │  ──┤   │
    │    └───┘
    │
   R_g
    │
   GND
```

Gain: `G = 1 + R_f/R_g`

Typical values:
- G = 100 (40 dB): R_f = 99 kohm, R_g = 1 kohm
- G = 1000 (60 dB): R_f = 999 kohm, R_g = 1 kohm

A DC-blocking capacitor (1 uF film) is placed in series with the input to
prevent DC magnetization currents from saturating the amplifier. The resulting
high-pass corner is:

```
f_hp = 1 / (2 * pi * R_in * C_block)
     = 1 / (2 * pi * 1e6 * 1e-6)
     = 0.16 Hz
```

This is well below the Schumann fundamental at 7.83 Hz.

### Noise Budget

The total system noise budget, referred to the input (in pT/sqrt(Hz)):

| Source                    | Contribution at 7.83 Hz |
|---------------------------|-------------------------|
| Op-amp voltage noise      | ~0.05 pT/sqrt(Hz)       |
| Op-amp current noise      | ~0.2 pT/sqrt(Hz)        |
| Coil thermal noise        | ~0.1 pT/sqrt(Hz)        |
| Resistor thermal noise    | ~0.02 pT/sqrt(Hz)       |
| **Total (RSS)**           | **~0.23 pT/sqrt(Hz)**   |
| **Target**                | **< 0.1 pT/sqrt(Hz)**   |

To achieve the target noise floor of 0.1 pT/sqrt(Hz), a longer coil (higher
sensitivity) and/or lower-impedance coil design is required. A 1 m core with
50,000 turns can achieve 0.05 pT/sqrt(Hz) system noise floor.

---

## 3. Filter Stage 1: Sallen-Key Low-Pass Filter

### Design Rationale

The Schumann resonance modes occur at approximately 7.83, 14.3, 20.8, 27.3,
33.8, and 39.0 Hz. All energy of interest lies below 45 Hz. The anti-aliasing
filter must attenuate signals at and above the Nyquist frequency (half the
sampling rate).

For a sampling rate of 100 Hz (Nyquist = 50 Hz), a 2nd-order Butterworth
filter at 46 Hz provides:
- -3 dB at 46 Hz
- -6 dB at 50 Hz (mains frequency partially attenuated)
- -12 dB at 65 Hz
- -24 dB at 100 Hz (Nyquist)

For a sampling rate of 256 Hz, the anti-aliasing requirement is more relaxed,
but the 46 Hz cutoff still serves to reject mains interference.

### Sallen-Key Topology

The Sallen-Key topology is chosen for its simplicity and low component
sensitivity. Unity-gain configuration minimizes gain error and provides
the best passband flatness.

```
         C1
  V_in ──┤├──┬──/\/\/──┬─── V_out
               R1       │
               │    ┌───┤
               │    │   │
              C2    │ +-│──── V_out (feedback)
               │    │   │
              GND   │   │
                    └───┘
                   OPA209
```

Butterworth coefficients (Q = 0.707):
```
f_c = 1 / (2 * pi * sqrt(R1*R2*C1*C2))
Q = sqrt(R1*R2*C1*C2) / (C2*(R1+R2))
```

**Component values for fc = 46 Hz, Butterworth:**
- C1 = 100 nF (C0G/NP0)
- C2 = 100 nF (C0G/NP0)
- R1 = 24.3 kohm (1%)
- R2 = 48.7 kohm (1%)

Giving: fc = 46.1 Hz, Q = 0.707

### Higher-Order Option

For installations near power lines or in urban environments, a 4th-order
filter (two cascaded Sallen-Key stages) is recommended. This provides 24
dB/octave rolloff and approximately 48 dB rejection at the Nyquist frequency
for 100 Hz sampling.

---

## 4. Filter Stage 2: Twin-T Notch at 50/60 Hz

### Design Rationale

Even with battery operation and rural siting, some residual 50/60 Hz
interference is inevitable. It couples through the atmosphere and nearby
wiring. A dedicated notch filter provides targeted rejection at the mains
fundamental frequency.

The Twin-T topology is chosen because:
1. It can achieve deep notches (>40 dB) with matched components
2. No inductors required (inductors at 50 Hz would be enormous)
3. Active feedback can boost the Q factor for a sharper notch
4. Minimal impact on nearby Schumann resonance modes

### Circuit Topology

```
              R       R
  V_in ──┬──/\/\/──┬──/\/\/──┬─── V_out
          │         │         │
         2C        R/2        │
          │         │         │
          └────┬────┘    ┌────┘
               │         │
               C     ┌───┤
               │     │   │
              GND    │ +-│──── V_out
                     │   │
                     └───┘
                    OPA209
```

Notch frequency: `f_notch = 1 / (2 * pi * R * C)`

**Component values for 50 Hz notch:**
- R = 31.8 kohm (use 31.6 kohm, 0.1%)
- C = 100 nF (C0G/NP0, 1%)

**Component values for 60 Hz notch:**
- R = 26.5 kohm (use 26.7 kohm, 0.1%)
- C = 100 nF (C0G/NP0, 1%)

### Active Feedback for Enhanced Q

Without feedback, the passive Twin-T has Q ~ 0.25, meaning a very broad notch
that attenuates the nearby 5th Schumann mode (33.8 Hz) and the 3rd mode
(20.8 Hz). Adding positive feedback through the op-amp increases Q to 10--20,
narrowing the notch to approximately +/-2 Hz bandwidth.

The feedback fraction controls Q:
```
Q = 1 / (4 * (1 - k))    where k is the feedback fraction (0 < k < 1)
```

For Q = 10: k = 0.975 (feedback resistor ratio 39:1)

### Cascade for Deeper Rejection

A single active Twin-T provides 30--40 dB of notch depth. For environments
with strong mains interference, two cascaded stages provide 50--60 dB
rejection. The second stage uses slightly detuned components (+2%) to widen
the combined rejection bandwidth and account for component tolerances.

---

## 5. Variable Gain Stage

### Design Rationale

Different coil designs, core lengths, and site conditions produce widely
varying signal levels. The variable gain stage allows matching the signal
level to the ADC input range without modifying the preamplifier.

Gain range: 1x to 21x (0 to 26 dB)

This is implemented as a non-inverting amplifier with a switchable feedback
network. A DIP switch or precision potentiometer selects the gain. For remote
stations, digital gain control (e.g., a digital potentiometer controlled via
I2C) enables software-controlled gain adjustment.

### Setting the Gain

The gain should be set so the maximum expected signal occupies approximately
70% of the ADC input range:

```
V_adc_max = V_ref / PGA_gain = 5.0 / 1 = 5.0 V (differential)
V_signal_max = B_max * S_coil * G_preamp * G_variable
```

Where `B_max` is the maximum expected magnetic field amplitude during
geomagnetic storms (approximately 5--10 pT at the fundamental).

Target: `V_signal_max` ~ 3.5 V (70% of 5 V range) at maximum expected signal.

---

## 6. ADC Interface: ADS1256

### Configuration

The ADS1256 is a 24-bit delta-sigma ADC with an on-chip programmable gain
amplifier (PGA) and digital filter. Key configuration for Schumann resonance
monitoring:

- **Sample rate:** 100 SPS (50 Hz mains rejection) or 256 SPS (higher bandwidth)
- **Input mode:** Differential (AIN0-AIN1) for common-mode rejection
- **PGA gain:** 1x or 2x (additional analog gain from previous stages is sufficient)
- **Buffer:** Enabled (high-impedance input, reduces kickback to filter stage)
- **Auto-calibration:** Perform offset and gain calibration at startup

### SPI Interface

The ADS1256 communicates via SPI with the following connections to the
Raspberry Pi:

| ADS1256 Pin | RPi GPIO | Function    |
|-------------|----------|-------------|
| SCLK        | GPIO 11  | SPI Clock   |
| DIN         | GPIO 10  | MOSI        |
| DOUT        | GPIO 9   | MISO        |
| CS           | GPIO 8   | Chip Select |
| DRDY        | GPIO 17  | Data Ready  |
| RESET       | GPIO 18  | Reset       |
| PDWN        | 3.3V     | Power Down (tie high) |

The DRDY pin should be connected to a GPIO with interrupt capability. The
firmware waits for DRDY to go low before reading each sample, ensuring
precise timing aligned to the ADC's internal clock.

### Single-Ended vs. Differential

**Always use differential input mode.** Single-ended mode is susceptible to
ground noise and common-mode interference. Differential mode provides:
- 100+ dB common-mode rejection ratio (CMRR)
- Rejection of ground loop voltages
- Rejection of coupled digital noise on the ground plane

Connect the filter output to AIN0 (positive) and the analog ground reference
to AIN1 (negative).

---

## 7. Power System Design

### Battery Operation: Not Optional

Battery operation is not a convenience feature; it is a fundamental requirement
for Schumann resonance detection (Christofilakis et al. 2018, Tritakis et al.
2021). Mains-powered equipment couples 50/60 Hz interference directly into
the analog front-end through:

1. Conducted noise on the power supply rails
2. Radiated magnetic field from transformers and switch-mode converters
3. Ground loop currents between mains earth and signal ground

Even with aggressive filtering, mains-connected systems show 20--40 dB higher
noise floor at 50/60 Hz than battery-powered equivalents.

### Power Architecture

```
  ┌────────┐    ┌─────────────┐    ┌──────────┐
  │ Solar  ├───>│ MPPT Charge ├───>│  LiPo    │
  │ Panel  │    │ Controller  │    │ Battery  │
  │ 6V/3W  │    └─────────────┘    └────┬─────┘
  └────────┘                            │ 3.0-4.2V
                                        │
                    ┌───────────────────┬┘
                    │                   │
              ┌─────┴──────┐     ┌──────┴─────┐
              │ Digital LDO│     │ Analog LDO │
              │  5.1V/3A   │     │ +/-9V or   │
              │ (buck/boost)│     │  +/-12V    │
              └─────┬──────┘     └──────┬─────┘
                    │                   │
              ┌─────┴──────┐     ┌──────┴─────┐
              │ RPi + GPS  │     │ Op-amps +  │
              │ + ADS1256  │     │ Analog     │
              │ (digital)  │     │ filters    │
              └────────────┘     └────────────┘
```

### Power Budget

| Component       | Voltage | Current   | Power   |
|-----------------|---------|-----------|---------|
| Raspberry Pi 4  | 5.0 V   | 600 mA   | 3.0 W   |
| ADS1256 module  | 5.0 V   | 15 mA    | 0.075 W |
| GPS NEO-M8      | 3.3 V   | 25 mA    | 0.083 W |
| Analog front-end| +/-9 V  | 20 mA    | 0.36 W  |
| **Total**       |         |           | **~3.5 W** |

With a 10,000 mAh (37 Wh) LiPo battery and 80% converter efficiency:
```
Runtime = 37 * 0.80 / 3.5 = 8.5 hours (Pi 4)
Runtime = 37 * 0.80 / 1.5 = 19.7 hours (Pi Zero 2 W)
```

A 6V/3W solar panel provides approximately 2.5W average in temperate latitudes,
which is insufficient for continuous Pi 4 operation but adequate for a Pi Zero
2 W. A 6W panel or duty-cycled operation is required for the Pi 4.

### Analog Supply Noise

The analog LDO must have ultra-low noise in the Schumann band (1--50 Hz).
Recommended regulators:

| Regulator | Noise (10 Hz--100 kHz) | Output  |
|-----------|------------------------|---------|
| ADP7118   | 1.5 uV RMS            | Adj.    |
| LP5907    | 6.5 uV RMS            | Fixed   |
| ADM7154   | 1.6 uV RMS            | Adj.    |

The ADP7118 is preferred for its ultra-low noise and adjustable output
voltage. Use separate regulators for the positive and negative analog
supply rails.

---

## 8. Grounding and Shielding

### Star Ground Topology

All ground connections must follow a star topology, meeting at a single point
near the ADC:

```
                    STAR GROUND POINT
                         │
          ┌──────────────┼──────────────┐
          │              │              │
     ┌────┴────┐   ┌────┴────┐   ┌────┴────┐
     │ Digital │   │ Analog  │   │ Shield/ │
     │ Ground  │   │ Ground  │   │ Earth   │
     │ (RPi,   │   │ (Preamp,│   │ (Coax,  │
     │  GPS)   │   │  Filter,│   │  Enclo- │
     │         │   │  ADC    │   │  sure,  │
     │         │   │  analog)│   │  Earth  │
     │         │   │         │   │  Rod)   │
     └─────────┘   └─────────┘   └─────────┘
```

- Digital and analog ground planes must be separate on the PCB
- Single connection point between digital and analog ground
- Shield ground connects to earth rod and coaxial cable shield
- Never route digital signals over the analog ground plane

### Cable Shielding

The coaxial cable between the sensor and electronics must be grounded at the
amplifier end only. Grounding both ends creates a ground loop antenna that
picks up magnetic field interference. The coil end of the shield should be
left floating or connected through a high-value resistor (1 Mohm) for
static discharge.

---

## Design Validation Checklist

Before building, verify:

- [ ] Coil self-resonant frequency > 100 Hz
- [ ] Preamplifier gain provides > 1 mV output for 1 pT input
- [ ] Sallen-Key filter -3 dB point is at 46 +/- 2 Hz
- [ ] Twin-T notch depth > 30 dB at 50/60 Hz
- [ ] Total gain chain does not clip ADC at 10 pT input
- [ ] Noise budget predicts < 0.1 pT/sqrt(Hz) at 7.83 Hz
- [ ] Power budget allows > 8 hours battery runtime
- [ ] Analog and digital power supplies are independent
- [ ] Star ground topology is maintained throughout
- [ ] All analog signal cables are shielded
