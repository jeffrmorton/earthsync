# Citizen Science Approaches to Schumann Resonance Monitoring

## Abstract

Schumann Resonance (SR) monitoring has historically been restricted to well-funded academic observatories due to the extreme sensitivity requirements and electromagnetic noise challenges. However, advances in low-cost electronics, open-source hardware, and internet connectivity have made citizen-scale SR detection feasible at budgets of $200--400. This document reviews documented citizen science and low-cost SR measurement approaches, identifies the minimum viable hardware requirements, discusses site selection constraints, and contextualizes the gap that EarthSync aims to fill.

---

## 1. The Case for Citizen Science SR Monitoring

### 1.1 Scientific Motivation

Professional SR observatories number only 25--30 worldwide, with heavy geographic concentration in Europe. This sparse coverage leaves large regions (Africa, South America, most of Asia, all oceans) with no nearby monitoring. Citizen science stations, even with reduced sensitivity, can:

1. **Fill geographic gaps** in the global SR monitoring network
2. **Increase temporal coverage** through redundancy
3. **Detect regional anomalies** missed by distant professional stations
4. **Provide educational engagement** with atmospheric physics and electromagnetic phenomena
5. **Generate open data** freely available to the research community

### 1.2 Feasibility Assessment

The fundamental question is whether SR signals can be detected with low-cost hardware. The answer is definitively **yes**, as demonstrated by multiple independent groups:

| Group/Project          | Budget (approx.) | SR Modes Detected | Reference                    |
|------------------------|-------------------|--------------------|------------------------------|
| Christofilakis et al.  | ~$300             | 4--5               | Christofilakis et al. 2018   |
| vlf.it minimal loop    | ~EUR 50           | 1--3               | vlf.it community             |
| MatejGomboc KiCad      | ~$150             | 3--4               | GitHub open-source           |
| Raspberry Pi approach  | ~$200             | 3--4               | Various community reports    |

The key constraint is not electronic sensitivity (which is achievable cheaply) but **site selection** -- finding a location sufficiently distant from anthropogenic electromagnetic noise.

---

## 2. Documented Low-Cost SR Receivers

### 2.1 Christofilakis et al. 2018: The Reference Portable Receiver

The most thoroughly documented citizen-science-grade SR receiver is that of Christofilakis et al. (2018), published in the Journal of Atmospheric and Solar-Terrestrial Physics. This design has become the de facto reference for low-cost SR instrumentation.

**Design specifications:**

| Parameter              | Value                    |
|------------------------|--------------------------|
| Sensor                 | Custom induction coil    |
| Core                   | Mu-metal, ~0.3 m         |
| Turns                  | ~100,000                 |
| Wire diameter           | 0.18 mm enameled copper  |
| Preamplifier           | Low-noise op-amp         |
| Anti-alias filter       | 2nd-order LP, ~45 Hz     |
| Notch filter            | 50 Hz rejection          |
| ADC                    | 24-bit                   |
| Sample rate             | 100 Hz                   |
| Power                  | Battery                  |
| Autonomy               | 45 days                  |
| Approximate cost       | ~$300                    |
| Modes reliably detected| 4--5                     |

**Key innovations:**
- **Battery-only operation**: Eliminates conducted mains interference entirely
- **45-day autonomous operation**: Enables deployment at remote sites without infrastructure
- **Compact design**: Portable enough for a single researcher to deploy
- **Published schematics**: Sufficient detail for independent replication

**Limitations:**
- Single-axis measurement (one magnetic component only)
- No GPS timing (limits cross-station correlation)
- No telemetry (requires physical data retrieval)
- Sensitivity adequate for modes 1--4 but marginal for modes 5--6

### 2.2 vlf.it Minimal Loop Receiver

The vlf.it community (Italian VLF radio enthusiasts) has demonstrated SR detection with an extremely minimal setup costing approximately EUR 50.

**Design:**
- Simple air-core or ferrite-core loop antenna
- Single-stage amplification
- PC sound card as ADC (16-bit, 48 kHz -- vastly oversampled for SR)
- Free software for spectral analysis (Spectrum Lab or similar)

**Performance:**
- Reliably detects modes 1--3 under favorable site conditions
- Mode 4 and above typically lost in noise floor
- Highly sensitive to site conditions; works primarily at very quiet rural locations

**Value:**
This approach demonstrates the **absolute minimum entry point** for SR detection. While not suitable for research-quality data, it serves an important educational and proof-of-concept role.

### 2.3 Open-Source KiCad Designs

**MatejGomboc/ELF-Schumann-Resonance-Receiver (GitHub):**

An open-source KiCad PCB design for an SR receiver front-end, featuring:

- **LMP7721** ultra-low input bias current op-amp as the first stage
- Designed for direct interface to standard microcontroller ADCs
- Full schematic, PCB layout, and bill of materials published under open-source license
- Community-contributed modifications and improvements

The LMP7721 is an unconventional choice for SR preamplification (its primary advantage is ultra-low input bias current, which is more relevant for high-impedance electrometer applications). However, it demonstrates the principle of open-source hardware development for SR instrumentation.

### 2.4 Raspberry Pi-Based Systems

Multiple community implementations have demonstrated SR detection using Raspberry Pi single-board computers:

**Typical configuration:**
- External ADC (ADS1256 or ADS1115) connected via SPI or I2C
- Induction coil sensor (commercial or custom)
- Python-based data acquisition and processing
- Sample rates demonstrated up to 240 samples/second
- Local storage to SD card
- Optional WiFi/cellular telemetry

**Advantages:**
- Familiar development environment (Python, Linux)
- Large community support base
- Abundant documentation and tutorials
- Low cost (~$35 for the Pi, ~$15 for external ADC)

**Disadvantages:**
- Not a real-time operating system (potential for sample timing jitter)
- Requires continuous power (not battery-friendly without additional hardware)
- SD card reliability concerns for long-term autonomous deployment
- WiFi radio may introduce electromagnetic interference if not carefully managed

### 2.5 ESP32 LoRa32 for Remote Recording

The ESP32 microcontroller family, particularly variants with integrated LoRa radio (e.g., Heltec WiFi LoRa 32), has been proposed for remote SR recording:

**Concept:**
- ESP32 handles ADC sampling and local buffering
- LoRa radio transmits compressed SR spectra to a gateway at ranges up to 10+ km
- Ultra-low power consumption enables solar/battery operation
- Multiple sensor nodes form a mesh network

**Status:**
This approach is at the prototype/concept stage. The ESP32's 12-bit built-in ADC is insufficient for SR work, requiring an external high-resolution ADC (ADS1256 or similar). The LoRa data rate (~300 bps to 50 kbps) is too low for raw waveform telemetry but sufficient for transmitting processed spectral parameters (mode frequencies, amplitudes, Q-factors) at 10-minute intervals.

---

## 3. Minimum Viable Hardware Specification

Based on the documented systems above, the minimum viable SR citizen science station requires:

### 3.1 Component Budget

| Component                  | Specification                     | Approx. Cost |
|----------------------------|-----------------------------------|---------------|
| Induction coil             | 40K+ turns, mu-metal or ferrite   | $50--150      |
| Preamplifier board         | OPA209 or equivalent, 2-stage     | $20--40       |
| Anti-alias filter           | Sallen-Key, 46 Hz                 | $5--10        |
| Notch filter                | Twin-T, 50 or 60 Hz              | $5--10        |
| ADC                        | ADS1256 (24-bit) breakout         | $10--20       |
| Microcontroller            | Raspberry Pi or ESP32             | $15--45       |
| Power (battery + regulator)| 12V lead-acid or LiFePO4         | $30--60       |
| Enclosure + connectors     | Weatherproof box, cables          | $20--40       |
| **Total**                  |                                   | **$200--400** |

### 3.2 Expected Performance at Minimum Budget

- **Modes detected**: 3--4 (fundamental through ~26.4 Hz)
- **Frequency accuracy**: 0.1 Hz (limited by spectral resolution)
- **Amplitude accuracy**: ~20% (limited by calibration)
- **Temporal resolution**: 10-minute parameter updates
- **Autonomous operation**: Days to weeks depending on power budget

### 3.3 Upgrades for Research-Quality Data

To approach observatory-quality performance, citizen stations can upgrade:

| Upgrade                    | Benefit                          | Added Cost |
|----------------------------|----------------------------------|------------|
| More turns (>200K)         | Detect modes 5--6                | $50--100   |
| GPS module                 | Cross-station correlation        | $15--30    |
| Second coil (orthogonal)   | Both horizontal components       | $100--200  |
| Cellular modem             | Real-time telemetry              | $30--60    |
| Solar panel + controller   | Indefinite autonomous operation  | $50--100   |

---

## 4. Site Selection for Citizen Science

### 4.1 The Critical Constraint: Distance from Power Lines

Site selection is the single most important factor determining whether a citizen science SR station will succeed. Tritakis et al. (2021) systematically studied the effect of power line proximity on SR detection:

**Key findings:**
- **5+ km from power lines**: Recommended minimum distance for reliable SR detection
- **1 km from power lines**: Demonstrated as **insufficient** even with aggressive notch filtering
- Power line interference includes not only the fundamental (50/60 Hz) but harmonics, sub-harmonics, and broadband noise from arcing and switching transients
- High-voltage transmission lines are worse than low-voltage distribution lines, but both are problematic

This distance requirement is the primary barrier to citizen science SR monitoring. In densely populated or electrified regions, finding a suitable site may require traveling to remote rural areas, national parks, or mountain locations.

### 4.2 Additional Site Considerations

**Electromagnetic interference sources to avoid:**

| Source                    | Minimum Distance | Notes                          |
|---------------------------|------------------|--------------------------------|
| High-voltage power lines  | 5+ km            | Tritakis et al. 2021           |
| Electric railways         | 10+ km           | 16.7 Hz interferes with mode 2 |
| Wind turbines             | 2+ km            | Generator and power electronics |
| Solar farms               | 1+ km            | Inverter switching noise        |
| Urban areas               | 5+ km            | Aggregate power grid noise      |
| Industrial facilities     | 3+ km            | Variable, depends on equipment  |

**European railway interference:**
In continental Europe (and parts of Asia), electric railways operate at 16.7 Hz (one-third of the 50 Hz mains frequency). This places strong narrowband interference uncomfortably close to the second SR mode at 14.1 Hz. The 16.7 Hz interference has been documented as a significant problem for European SR stations and is essentially impossible to notch filter without also removing the second SR mode due to the narrow frequency separation.

### 4.3 Altitude Benefits

Higher altitude sites consistently show better SR detection performance:

| Station Example    | Altitude | Benefit Observed                        |
|--------------------|----------|-----------------------------------------|
| Sierra Nevada      | 2500 m   | Excellent SNR, modes 1--6 clearly       |
| Calar Alto         | 2168 m   | Very good SNR                           |
| Hylaty             | ~700 m   | Good SNR for rural Eastern Europe       |
| Modra              | 530 m    | Adequate SNR with some noise management |
| Typical lowland    | <100 m   | Challenging, site-dependent             |

The altitude benefit is primarily due to **increased distance from power grid infrastructure** and reduced atmospheric moisture, rather than any fundamental atmospheric physics advantage.

### 4.4 Practical Site Assessment Protocol

For citizen scientists evaluating a candidate site:

1. **Desktop survey**: Check satellite imagery for visible power lines, substations, and industrial facilities within 5 km
2. **Radio survey**: Visit site with AM radio receiver and listen for buzz/hum at low frequencies
3. **Preliminary measurement**: Deploy sensor overnight and examine raw data for mains frequency and harmonics
4. **Extended test**: Run for 1--2 weeks to assess diurnal noise pattern and identify intermittent interference sources
5. **Decision**: If mains-frequency interference is more than 20 dB above the expected SR signal level after notch filtering, the site is unsuitable

---

## 5. Software and Data Infrastructure Gap

### 5.1 Current State

Despite the availability of affordable hardware, there is a notable absence of comprehensive open-source software infrastructure for citizen science SR monitoring. Existing tools are fragmented:

- **Spectrum Lab** (Windows): General-purpose audio spectrum analysis; can detect SR but not optimized for it
- **Custom MATLAB scripts**: Used in academic publications but not freely available
- **Python snippets**: Various community-shared code fragments, not integrated into a coherent platform

### 5.2 What Is Missing

No existing open-source project provides:

1. **End-to-end data pipeline**: From ADC sampling through spectral processing to parameter extraction
2. **Real-time visualization**: Web-based dashboards showing SR parameters as they are measured
3. **Standardized data format**: Common schema for interoperability between stations
4. **Network coordination**: Tools for cross-station correlation and Q-burst identification
5. **Automated QA/QC**: Data quality flags, noise detection, interference identification
6. **Community data sharing**: Centralized or federated data repository

### 5.3 EarthSync: Filling the Gap

EarthSync is designed to address this comprehensive infrastructure gap. By providing an integrated, open-source platform that spans from firmware through signal processing to web visualization, EarthSync lowers the barrier to entry for citizen science SR monitoring from "expert electronics and signal processing knowledge required" to "assemble documented hardware and install software."

**EarthSync components addressing each gap:**

| Gap                       | EarthSync Component              |
|---------------------------|----------------------------------|
| Data acquisition firmware | ESP32/Raspberry Pi firmware      |
| Signal processing         | Python processing pipeline       |
| Real-time visualization   | Web dashboard with WebSocket     |
| Data format               | Standardized JSON/HDF5 schemas   |
| Network coordination      | Server with multi-station support|
| QA/QC                     | Automated quality flagging       |
| Data sharing              | Open API for data access         |

---

## 6. Educational Outreach Potential

### 6.1 Interdisciplinary Learning

SR monitoring naturally spans multiple STEM disciplines:

- **Physics**: Electromagnetic wave propagation, resonance, waveguide theory
- **Electronics**: Sensor design, analog signal conditioning, data acquisition
- **Computer Science**: Digital signal processing, data pipelines, web development
- **Earth Science**: Lightning climatology, ionospheric physics, global electric circuit
- **Statistics**: Spectral estimation, noise analysis, time series analysis

### 6.2 Classroom Integration

A citizen science SR station can support educational activities at multiple levels:

- **High school**: Build a simple sensor, observe SR peaks on a spectrogram
- **Undergraduate**: Implement Welch PSD estimation, understand windowing and spectral leakage
- **Graduate**: Lorentzian fitting, Q-burst detection, cross-station analysis
- **Research**: Novel analysis methods, long-term trend studies, geophysical correlations

### 6.3 Community Building

The SR citizen science community, while small, is active online:
- vlf.it forums: European VLF/ELF enthusiast community
- Reddit r/VLF: Discussion of very low frequency phenomena
- Various amateur radio and geophysics mailing lists
- GitHub repositories with open-source hardware designs

---

## 7. Challenges and Limitations

### 7.1 Calibration

Professional SR stations undergo careful absolute calibration using reference signals or comparison with calibrated instruments. Citizen science stations typically lack:
- Calibrated reference signal sources at SR frequencies
- Access to calibrated professional instruments for comparison
- Environmental chamber testing for temperature coefficient characterization

**Mitigation**: Relative calibration through inter-station comparison; focus on frequency and Q-factor parameters (which are amplitude-independent) rather than absolute amplitude measurements.

### 7.2 Data Continuity

Citizen science stations may suffer from:
- Power interruptions (battery depletion)
- Hardware failures without timely repair
- Operator fatigue (initial enthusiasm waning)
- Software updates causing processing discontinuities

**Mitigation**: Robust firmware with watchdog timers and automatic recovery; low-maintenance solar power; strong community support.

### 7.3 Data Quality Assurance

Without professional oversight, citizen science data may include:
- Unrecognized interference masquerading as signal
- Systematic errors from misconfigured hardware or software
- Timing errors from unsynchronized clocks

**Mitigation**: Automated QA/QC in the EarthSync pipeline; cross-station consistency checks; community peer review.

---

## 8. Summary

Citizen science SR monitoring is technically feasible at budgets of $200--400, with documented designs achieving detection of 3--5 SR modes. The primary challenges are:

1. **Site selection**: The 5+ km distance requirement from power lines (Tritakis et al. 2021) is the dominant constraint
2. **Software infrastructure**: No comprehensive open-source SR monitoring platform exists -- this is the gap EarthSync is designed to fill
3. **Calibration**: Relative calibration is achievable; absolute calibration remains difficult without professional equipment
4. **Data continuity**: Autonomous operation and robust firmware are essential for long-term monitoring

The Christofilakis et al. (2018) portable receiver design provides the most complete and replicable hardware reference for citizen science SR stations. Combined with an integrated software platform like EarthSync, this level of hardware capability can contribute meaningfully to the global SR monitoring effort.
