# Documented Schumann Resonance Observatories Worldwide

## Abstract

This document catalogs operational and historical Schumann Resonance (SR) monitoring stations worldwide, with emphasis on their hardware configurations, data acquisition parameters, and scientific contributions. The SR observatory landscape ranges from single-investigator academic stations to multi-site global networks. Understanding the design choices and capabilities of existing stations informs the development of new monitoring platforms and citizen science instrumentation.

---

## 1. Observatory Summary Table

| Station               | Country  | Turns     | Core Length | ADC Bits | Sample Rate | Altitude | Status       |
|-----------------------|----------|-----------|-------------|----------|-------------|----------|--------------|
| Sierra Nevada         | Spain    | ~10^6     | 1.35 m      | 16       | 256 Hz      | 2500 m   | Active       |
| Nagycenk              | Hungary  | N/A       | N/A         | Varies   | Varies      | ~160 m   | Active       |
| Modra                 | Slovakia | 150,000   | N/A         | 16       | 200 Hz      | 530 m    | Active       |
| HeartMath GCMS (x6)   | Global   | Zonge ANT4| Commercial  | 24       | 130 Hz      | Varies   | Active       |
| Hylaty                | Poland   | Active    | 1 m antenna | 16       | 175 Hz      | ~700 m   | Active       |
| Chinese Network (x12) | China    | N/A       | N/A         | N/A      | 100 Hz      | Varies   | Active       |
| Eskdalemuir BGS       | UK       | Metronix  | Commercial  | N/A      | 128 Hz      | 242 m    | Active       |
| Calar Alto            | Spain    | 300,000   | 2.0 m       | 24       | 187 Hz      | 2168 m   | Active       |
| Doliana               | Greece   | 90,000    | ~0.5 m      | N/A      | N/A         | ~550 m   | Research     |
| Mitzpe Ramon          | Israel   | N/A       | N/A         | N/A      | N/A         | 900 m    | Active       |
| West Greenwich (RI)   | USA      | N/A       | N/A         | N/A      | N/A         | ~40 m    | Historical   |
| Arrival Heights       | Antarctic| N/A       | N/A         | N/A      | N/A         | 184 m    | Active       |

---

## 2. Detailed Station Profiles

### 2.1 Sierra Nevada Observatory (Spain)

**Location**: Sierra Nevada mountain range, southern Spain, 2500 m altitude
**Operated by**: University of Granada / CIESOL research center
**Primary reference**: Gazquez Parra et al. (2015)

The Sierra Nevada station represents one of the most thoroughly documented SR installations in the literature, with detailed published specifications for every stage of the instrumentation chain.

**Sensor specifications:**
- Induction coil magnetometer with approximately 10^6 (one million) turns
- Mu-metal core, 1.35 m length
- Enameled copper wire, 0.14 mm diameter
- Two orthogonal horizontal coils (N-S and E-W magnetic components)

**Electronics:**
- 4-stage analog chain with OPA209 preamplifier
- 2nd-order Sallen-Key anti-alias filter at 46 Hz
- Twin-T cascaded notch filter for 50 Hz rejection
- Total gain: 66--112 dB (adjustable)

**Data acquisition:**
- 16-bit ADC
- 256 Hz sample rate
- Continuous recording

**Signal processing:**
- Welch PSD estimation (Hann window, 10-second segments, 50% overlap)
- 10-minute analysis windows
- Lorentzian fitting for mode parameter extraction

**Site advantages:**
The 2500 m altitude places the station above much of the atmospheric boundary layer, reducing local electromagnetic noise. The mountain location also provides natural distance from urban infrastructure and power distribution networks.

### 2.2 Nagycenk Observatory (Hungary)

**Location**: Nagycenk, western Hungary, ~160 m altitude
**Operated by**: Geodetic and Geophysical Institute, Hungarian Academy of Sciences
**Primary references**: Satori et al. (1996); Satori (2003)

Nagycenk holds the distinction of being the **oldest continuously operating SR monitoring station** in the world, with data records extending back to the 1960s. This long baseline makes Nagycenk data invaluable for studying long-term trends in SR parameters.

**Scientific contributions:**
- Establishment of the diurnal frequency variation pattern linked to global thunderstorm activity
- Long-term trend analysis of SR frequencies in relation to global temperature and lightning activity
- Cross-correlation studies with tropical thunderstorm indices

**Instrumentation:**
Instrumentation has been upgraded multiple times over the decades. Current specifications are not fully documented in recent open literature, but the station measures both electric and magnetic SR components.

### 2.3 Modra Observatory (Slovakia)

**Location**: Modra, western Slovakia, 530 m altitude
**Operated by**: Comenius University, Bratislava
**Primary reference**: Ondrasova et al. (2007)

The Modra station is notable for its use of **ball antenna electric field measurement** alongside magnetic field sensors, enabling full electromagnetic characterization of the SR field.

**Sensor specifications:**
- Induction coil: 150,000 turns for magnetic field
- Ball antenna for vertical electric field (E_z component), following the design principles of Ogawa (1966)

**Data acquisition:**
- 16-bit ADC
- 200 Hz sample rate

**Scientific contributions:**
- Simultaneous electric and magnetic SR measurement techniques
- Diurnal and seasonal variation studies from a Central European location
- Validation of ball antenna technique for SR electric field monitoring

### 2.4 HeartMath Global Coherence Monitoring System (GCMS)

**Location**: 6 sites worldwide
**Operated by**: HeartMath Institute
**Primary reference**: McCraty et al. (2017)

The GCMS is the most extensive dedicated SR monitoring network currently in operation, with the explicit goal of continuous global coverage. The six sites are geographically distributed to ensure at least one station has favorable nighttime conditions at any given time.

**GCMS Station Locations:**

| Site                | Country      | Latitude  | Longitude  |
|---------------------|-------------|-----------|------------|
| Boulder Creek       | USA (CA)     | 37.1 N    | 122.1 W    |
| Hofuf               | Saudi Arabia | 25.4 N    | 49.6 E     |
| Northland           | New Zealand  | 35.1 S    | 173.8 E    |
| Kwazulu-Natal       | South Africa | 28.5 S    | 30.2 E     |
| Alberta             | Canada       | 51.0 N    | 113.5 W    |
| Lituania            | Lithuania    | 54.9 N    | 24.1 E     |

**Sensor specifications:**
- Zonge ANT4 induction coil magnetometer (commercial)
- Frequency range: 0.01--300 Hz (broader than SR-only systems)
- Two orthogonal horizontal coils per site

**Data acquisition:**
- Symmetric Research USB8CH data acquisition board ($980)
- ADS1255 24-bit ADC
- 130 Hz sample rate
- 8 synchronized channels per site
- Continuous recording with local storage and internet upload

**Unique features:**
- Broadband operation (0.01--300 Hz) captures not only SR but also geomagnetic pulsations and ULF waves
- Network synchronization enables global cross-correlation studies
- Data used for research into potential relationships between geomagnetic field variations and human physiological parameters

### 2.5 Hylaty Station (Poland)

**Location**: Hylaty, Bieszczady Mountains, southeastern Poland, ~700 m altitude
**Operated by**: Jagiellonian University, Krakow
**Primary reference**: Kulak et al. (2014)

The Hylaty station uses a distinctive **active antenna** design rather than traditional passive induction coils.

**Sensor specifications:**
- 1 m active antennae (integrated amplifier at the antenna element)
- Two orthogonal horizontal components
- Active design reduces cable-related noise and susceptibility to interference

**Data acquisition:**
- 16-bit ADC
- 175 Hz sample rate
- GPS-disciplined timing for cross-station correlation

**Scientific contributions:**
- Development of active antenna methodology for SR monitoring
- ELF propagation studies within the Earth-ionosphere waveguide
- Q-burst detection and characterization
- Development of source triangulation methods using multi-station timing

### 2.6 Chinese 12-Station Network

**Primary reference**: Zhou et al. (2023)

China has established the most geographically extensive **national SR monitoring network**, with 12 stations distributed across the country. This network provides dense spatial sampling within a single continental region.

**Network specifications:**
- 12 stations across China
- Bandpass: 3--29 Hz (focused on SR modes 1--4)
- Sample rate: 100 Hz (minimum viable for SR)
- 50 Hz notch filter (Chinese mains frequency)
- Standardized instrumentation across all stations

**Scientific contributions:**
- High spatial resolution mapping of SR parameter variations across a continental scale
- Statistical analysis of SR diurnal patterns with dense station coverage
- Detection of regional anomalies in SR parameters

**Design philosophy:**
The network prioritizes **standardization and coverage** over per-station sensitivity. By using identical instrumentation at all 12 sites, systematic errors can be identified and corrected through intercomparison, and spatial gradients in SR parameters can be confidently attributed to physical processes rather than instrumental differences.

### 2.7 Eskdalemuir BGS Observatory (United Kingdom)

**Location**: Eskdalemuir, Scottish Borders, 242 m altitude
**Operated by**: British Geological Survey (BGS)
**Primary reference**: BGS technical reports

Eskdalemuir is a long-established geomagnetic observatory that includes SR monitoring capabilities as part of its broader geophysical measurement program.

**Sensor specifications:**
- Metronix MFS05 broadband induction coil magnetometer
- Commercial professional-grade instrument
- Frequency range extends below SR through ULF/VLF

**Data acquisition:**
- 128 Hz sample rate
- Aligned with seismological data standards

**Site characteristics:**
Eskdalemuir was originally selected in the early 20th century for its exceptional electromagnetic quietness, making it one of the best sites in the United Kingdom for sensitive magnetic measurements. However, the gradual encroachment of electrical infrastructure remains a long-term concern for all rural observatory sites.

### 2.8 Calar Alto Observatory (Spain)

**Location**: Calar Alto, Almeria, southern Spain, 2168 m altitude
**Operated by**: University of Almeria
**Primary reference**: Fernandez et al. (2020)

Calar Alto is co-located with the Calar Alto Astronomical Observatory, benefiting from the strict electromagnetic interference controls imposed for optical astronomy.

**Sensor specifications:**
- Custom induction coil with 2.0 m mu-metal core (one of the longest documented)
- 300,000 turns of enameled copper wire
- Very high sensitivity due to long core and high turn count

**Data acquisition:**
- 24-bit ADC
- 187 Hz sample rate

**Site advantages:**
- 2168 m altitude (second only to Sierra Nevada among documented SR stations)
- Electromagnetic protection regulations for co-located astronomical observatory
- Dry climate reduces precipitation-related noise

### 2.9 Doliana Station (Greece)

**Location**: Doliana, Arcadia, Peloponnese, Greece, ~550 m altitude
**Operated by**: University of Ioannina
**Primary reference**: Tatsis et al. (2020)

The Doliana station represents a cost-effective approach to SR monitoring that has been influential in guiding citizen science designs.

**Sensor specifications:**
- Induction coil with 90,000 turns
- Enameled copper wire, 0.25 mm diameter
- Mu-metal core
- Input noise: 0.04 pT (among the lowest published for a compact sensor)

**Scientific contributions:**
- Demonstration that compact, relatively low-turn-count coils can achieve adequate sensitivity
- Detailed noise analysis methodology applicable to citizen science sensor validation
- Comparison of analog vs. digital noise reduction techniques (Tatsis et al. 2015)

---

## 3. Observatory Site Selection Criteria

Across all documented stations, common site selection criteria emerge:

### 3.1 Distance from Power Infrastructure

The single most critical site requirement is adequate distance from AC power lines and transformers. Tritakis et al. (2021) established that:

- **5+ km** from power lines: Recommended minimum for reliable SR detection
- **1 km**: Demonstrated as **insufficient** even with notch filtering
- Power line interference is broadband (harmonics), not just at the fundamental 50/60 Hz

### 3.2 Altitude Benefits

High-altitude sites offer multiple advantages:

| Benefit                          | Mechanism                                      |
|----------------------------------|-------------------------------------------------|
| Reduced anthropogenic noise      | Greater distance from population and power grid |
| Lower atmospheric moisture       | Reduced microphonic and precipitation noise     |
| Thinner atmosphere               | Slightly closer to the ionosphere (negligible)  |
| Natural electromagnetic shielding| Mountain terrain blocks distant noise sources   |

### 3.3 Geographic Distribution

For global SR monitoring, stations should be distributed to:
- Cover all major time zones (for diurnal cycle characterization)
- Sample different distances from the three major tropical thunderstorm centers (Africa, Americas, Maritime Continent)
- Include both hemispheres

---

## 4. Data Sharing and Standardization

### 4.1 Current Situation

There is **no universal standard** for SR data formatting or sharing. Each observatory or network uses its own formats:

| Network/Station   | Data Format                    | Public Access          |
|-------------------|-------------------------------|------------------------|
| HeartMath GCMS    | Proprietary + derived products| Partially (via website)|
| Chinese Network   | Internal format               | Research collaboration |
| Nagycenk          | Custom ASCII                  | On request             |
| Hylaty            | Custom binary                 | Research collaboration |

### 4.2 Standardization Needs

The SR research community would benefit from:
1. Common data formats (e.g., standardized HDF5 or NetCDF schemas)
2. Shared metadata standards (sensor specifications, site coordinates, calibration data)
3. Open data repositories
4. Cross-calibration protocols between stations

EarthSync aims to address these gaps by providing a standardized, open-source data pipeline with well-defined output formats.

---

## 5. Emerging Observatory Concepts

### 5.1 CubeSat/Satellite-Based SR Measurement

Space-based SR measurement has been proposed, measuring the electromagnetic leakage above the ionosphere. While this would provide global coverage from a single platform, the signal is many orders of magnitude weaker above the ionosphere than at the surface.

### 5.2 Distributed Sensor Networks

Leveraging inexpensive sensor hardware and internet connectivity, distributed networks of modest-sensitivity stations can achieve through spatial averaging what individual stations achieve through expensive high-sensitivity instrumentation. This is the model pursued by HeartMath GCMS and the Chinese 12-station network, and is the approach most relevant to citizen science efforts.

### 5.3 Underwater SR Measurement

SR signals penetrate seawater to shallow depths due to the very low frequencies involved. Submarine SR measurement has been proposed for submarine communication verification and oceanographic applications.

---

## 6. Summary

The global SR observatory landscape includes approximately 25--30 stations of varying capability, concentrated in Europe and Asia. Key observations:

1. **No single design dominates**: Stations range from 90K to 10^6 turns, 16 to 24-bit ADCs, 100 to 256 Hz sample rates
2. **All functional stations meet the same fundamental requirements**: <1 pT/sqrt(Hz) noise floor, adequate mains rejection, continuous GPS-synchronized recording
3. **Data sharing remains fragmented**: No universal standards or open repositories exist
4. **High-altitude, remote sites consistently perform best**: Sierra Nevada (2500 m) and Calar Alto (2168 m) are exemplary
5. **The 5+ km distance requirement from power lines** (Tritakis et al. 2021) is the most critical site constraint
6. **Network approaches** (HeartMath, Chinese) provide redundancy and spatial coverage that single stations cannot
