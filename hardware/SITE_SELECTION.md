# Station Site Selection and EMI Requirements

Proper site selection is the single most important factor determining data
quality from a Schumann Resonance monitoring station. An excellent instrument
at a poor site will produce worse data than a modest instrument at a quiet
site. This guide covers electromagnetic environment requirements, physical
siting, and pre-installation characterization procedures.

## References

- **Tritakis, V. et al. (2021)** -- "Electromagnetic interference on Schumann resonance measurements." J. Atmos. Solar-Terr. Phys.
- **Christofilakis, V. et al. (2018)** -- "A Low-Cost Receiver for Schumann Resonance Observations." IEEE Trans. Antennas Propag.
- **Gazquez Parra, J.A. et al. (2015)** -- "New design of a low-cost system for Schumann resonance measurements." Meas. Sci. Technol.
- **Nickolaenko, A.P. & Hayakawa, M. (2002)** -- _Resonances in the Earth-Ionosphere Cavity._ Kluwer Academic.
- **Price, C. (2016)** -- "ELF Electromagnetic Waves from Lightning: The Schumann Resonances." Atmosphere 7(9).
- **Sierra Luna, S.A. et al. (2017)** -- "A portable Schumann-resonance station." Ann. Geophys. 60(6).

---

## 1. Distance from Power Infrastructure

### High-Voltage Transmission Lines

High-voltage power lines are the dominant source of electromagnetic
interference for Schumann Resonance measurements. The magnetic field from a
power line decreases approximately as the inverse of distance, but corona
discharge and harmonics can propagate much further.

**Minimum distances (from Tritakis et al. 2021):**

| Line Voltage | Minimum Distance | Recommended Distance |
|-------------|------------------|---------------------|
| < 33 kV     | 1 km             | 2 km                |
| 33-110 kV   | 2 km             | 5 km                |
| 110-400 kV  | 5 km             | 10 km               |
| > 400 kV    | 10 km            | 20 km               |

These are absolute minimums. The recommended distances provide a margin for
unusual propagation conditions and harmonic content.

### Distribution Lines

Local distribution lines (240V/120V residential service) produce weaker
fields but are much closer to typical installation sites. Maintain at least
100 m distance from overhead distribution lines. Underground cables produce
less magnetic interference but can still be significant within 20 m.

### Substations and Transformers

Power substations are broadband noise sources. Maintain at least 2 km distance
from any substation. Pole-mounted distribution transformers should be at
least 200 m away.

---

## 2. Urban and Industrial Interference

### Urban Distance Requirements

Urban environments produce a complex electromagnetic noise floor from
thousands of overlapping sources: switch-mode power supplies, LED drivers,
electric motors, HVAC systems, and digital electronics.

**Site classifications:**

| Environment    | Distance from Sensor | Suitability     |
|---------------|---------------------|-----------------|
| City center    | 0 km                | Not suitable    |
| Suburban       | 0 km                | Marginal        |
| Rural village  | 0 km                | Acceptable      |
| Rural, > 5 km from town | 5+ km   | Good            |
| Wilderness, > 10 km     | 10+ km  | Excellent       |

Ideal station locations include:
- National parks and wilderness areas
- Remote agricultural land
- Mountain observatories
- Island locations
- Desert locations with no nearby settlements

Urban and suburban sites can still detect the strongest Schumann resonance
signals (the fundamental at 7.83 Hz) if battery-powered operation is used
and the notch filter is properly tuned. However, higher-order modes (>20 Hz)
will be buried in the noise floor.

### Industrial Sources

Specific industrial interference sources to avoid:

- **Electric arc furnaces:** Produce broadband ELF noise. Maintain > 10 km.
- **Electric railways:** See Section 3 below.
- **Wind turbines:** Generators and power electronics produce interference.
  Maintain > 2 km.
- **Solar farms:** Inverters produce switching noise. Maintain > 1 km.
- **Radio transmitters:** AM broadcast and shortwave can intermodulate in
  non-linear junctions. Maintain > 500 m from any antenna tower.

---

## 3. Railway Interference

Electric railway systems are a particularly insidious source of interference
for Schumann Resonance measurements because their operating frequencies
overlap with the SR band.

### European AC Railways (16.7 Hz)

Many European rail networks operate at 16.7 Hz (16 2/3 Hz), including:
- Germany (DB), Austria (OBB), Switzerland (SBB), Sweden (SJ), Norway (Bane NOR)

The 16.7 Hz fundamental falls between the first (7.83 Hz) and second
(14.3 Hz) Schumann modes. Its harmonics at 33.3 Hz and 50 Hz overlap with
the 4th mode (27.3 Hz region) and mains frequency. This is a nearly
unrecoverable interference source.

**Minimum distance from 16.7 Hz railways: 20 km**

### 50/60 Hz DC Railways

DC-powered metro and commuter rail systems use rectified mains power.
The rectification process produces strong harmonics at multiples of 50/60 Hz,
including subharmonics due to unbalanced loads. These systems are less
problematic for SR measurements but still produce broadband ELF noise.

**Minimum distance from urban rail lines: 5 km**

### Identification

Check railway maps for your country before selecting a site. In Europe,
the OpenRailwayMap (openrailwaymap.org) is a valuable resource. Pay special
attention to electrification type (AC 16.7 Hz, AC 25 kV/50 Hz, DC 3 kV,
DC 750V).

---

## 4. Altitude Considerations

Higher altitude sites benefit from:

1. **Reduced atmospheric noise:** The lower atmosphere (troposphere) contains
   most weather-related ELF noise sources. Stations above 1500 m are above
   much of this noise.

2. **Reduced anthropogenic interference:** Mountain sites are naturally remote
   from population centers and power infrastructure.

3. **Clear ionospheric coupling:** The Schumann resonance signal propagates
   in the Earth-ionosphere waveguide. There is no altitude penalty for
   ground-based stations below the ionosphere (60+ km).

**Notable high-altitude SR stations in the literature:**

| Station                  | Altitude | Notes                              |
|--------------------------|----------|------------------------------------|
| Sierra Nevada, Spain     | 2500 m   | Gazquez Parra et al. 2015          |
| Mitzpe Ramon, Israel     | 900 m    | Price & Mushtak 2001               |
| Nagycenk, Hungary        | 180 m    | Historic reference station         |
| Antarctic bases          | ~50 m    | Very low interference, high latitude |

The Sierra Nevada station at 2500 m demonstrates that altitude combined with
remoteness produces excellent data quality. However, altitude alone is not
sufficient; a mountaintop near a city is worse than a lowland wilderness site.

---

## 5. Grounding Requirements

Proper grounding serves two purposes: safety (lightning protection) and signal
integrity (noise reduction).

### Earth Rod Installation

1. Drive a copper-clad steel earth rod (1.2 m minimum length, 10 mm diameter)
   into the ground near the sensor location.
2. Ensure good contact with moist soil. In rocky or sandy soil, multiple
   shorter rods connected with bare copper wire may be needed.
3. Measure ground resistance with a ground resistance tester if available.
   Target: < 25 ohm. Below 10 ohm is ideal.
4. In dry conditions, periodic watering of the earth rod area improves
   ground conductivity.

### Star Ground Topology

All grounding connections must follow a star topology converging at the earth
rod:

```
                      EARTH ROD
                         |
          +--------------+--------------+
          |              |              |
     Sensor         Electronics     Lightning
     Shield         Enclosure       Protection
     (coax          (chassis        (if installed)
      shield)        ground)
```

**Never** daisy-chain ground connections. Each ground wire should run
independently from its source to the earth rod clamp.

### Ground Wire Routing

- Use 10 AWG (2.5 mm^2) minimum wire gauge for ground connections.
- Keep ground wires short and direct. Avoid coiling or routing near signal
  cables.
- Use bare copper or green-insulated copper wire.
- Clamp connections at the earth rod must be weather-resistant (bronze clamps,
  not steel).

---

## 6. Sensor Orientation

The induction coil magnetometer detects the magnetic component of the
Schumann resonance field. The coil is sensitive to magnetic fields along its
axis (the direction the core points).

### Single-Axis Station

For a single coil, orient it in the **magnetic North-South** direction
(along the geomagnetic meridian). This orientation is sensitive to the H_NS
component of the horizontal magnetic field, which is the standard component
for most SR research.

To determine magnetic North:
1. Use a compass (declination-corrected for your location).
2. Or use the NOAA magnetic declination calculator:
   https://www.ngdc.noaa.gov/geomag/calculators/magcalc.shtml

### Two-Axis Station

For complete horizontal magnetic field measurement, deploy two orthogonal
coils:
- Coil 1: Magnetic North-South (H_NS)
- Coil 2: Magnetic East-West (H_EW)

Separate the coils by at least 3 m to minimize mutual coupling. Each coil
requires its own analog signal chain and ADC channel.

### Coil Positioning

1. Place the coil **horizontally**, parallel to the ground surface.
2. Elevate the coil 10--30 cm above ground level on non-metallic supports
   (wooden stakes, PVC pipe stands).
3. Do not place the coil directly on the ground; soil moisture and conductive
   minerals can affect the measurement.
4. The coil should be level to within 5 degrees. Use a spirit level during
   installation.
5. Note the coil orientation (bearing in degrees from magnetic North) in
   the station configuration.

---

## 7. Electromagnetic Environment Characterization

Before committing to a permanent installation, characterize the
electromagnetic environment at the candidate site.

### 24-Hour Background Recording

1. Deploy the complete station (or at minimum, the sensor + preamplifier +
   a portable recorder) at the candidate site.
2. Record continuously for at least 24 hours, covering a full diurnal cycle.
3. Compute the power spectral density (PSD) of the recording with 1 Hz
   resolution.

### Evaluation Criteria

Examine the PSD for:

| Feature | Acceptable | Marginal | Unacceptable |
|---------|-----------|----------|--------------|
| 50/60 Hz peak | < 20 dB above floor | 20-40 dB above floor | > 40 dB above floor |
| Broadband ELF noise (1-50 Hz) | < 1 pT/sqrt(Hz) | 1-10 pT/sqrt(Hz) | > 10 pT/sqrt(Hz) |
| SR modes visible in raw PSD | Yes, at least 3 modes | 1-2 modes | No modes visible |
| Transient interference | < 5% of recording | 5-20% | > 20% |
| 16.7 Hz peak (Europe) | Not present | < 10 dB above floor | > 10 dB above floor |

### Time-of-Day Analysis

Interference often varies with time of day:
- Industrial noise peaks during business hours (08:00--18:00 local)
- Railway noise follows train schedules
- Agricultural equipment (electric fences, irrigation pumps) may run on timers
- Lightning activity peaks in local afternoon/evening

If interference is only present during certain hours, the site may still be
usable with appropriate data quality flagging in the EarthSync software.

### Comparison with Reference Data

Compare your site's PSD with published reference spectra from established
stations (e.g., Nagycenk, Hungary or Hylaty, Poland). The EarthSync server
provides reference spectra for comparison:

```bash
earthsync-cli site-survey --reference nagycenk --input survey_data.hdf5
```

---

## 8. Indoor vs. Outdoor Deployment

### Sensor Placement: Outdoors Required

The induction coil sensor **must** be placed outdoors. Indoor placement
introduces several problems:

1. **Building steel:** Rebar, steel framing, and metal roofing attenuate and
   distort the magnetic field. Attenuation can exceed 20 dB in steel-framed
   buildings.
2. **Electrical wiring:** Building wiring creates a dense 50/60 Hz field
   that overwhelms the Schumann signal.
3. **Electronic devices:** Computers, appliances, and LED lighting produce
   broadband ELF interference.

### Electronics Placement: Indoor Acceptable

The electronics (Raspberry Pi, ADC, power supply) can be placed indoors if:

1. The sensor cable length is less than 50 m. Longer cables increase
   capacitive loading and pick up more interference.
2. Shielded coaxial cable (RG-174 or better) is used for the entire sensor-
   to-electronics run.
3. The cable shield is grounded at the electronics end only.
4. The cable does not run parallel to mains wiring for more than 2 m.

### Cable Length Considerations

| Cable Length | Signal Loss at 30 Hz | Capacitive Load | Recommendation |
|-------------|---------------------|-----------------|----------------|
| < 5 m       | Negligible          | < 50 pF         | Ideal          |
| 5-15 m      | < 1 dB              | 50-150 pF       | Good           |
| 15-50 m     | 1-3 dB              | 150-500 pF      | Acceptable     |
| > 50 m      | > 3 dB              | > 500 pF        | Not recommended|

For cables longer than 15 m, consider placing the preamplifier at the sensor
end (in a small weatherproof enclosure) and running the amplified signal
through the cable. This dramatically improves the signal-to-noise ratio on
long cable runs.

---

## 9. Temperature Considerations

### Sensor Drift

The induction coil itself has minimal temperature sensitivity (copper wire
resistance changes approximately 0.4%/degree C, but this does not directly
affect the transfer function at ELF frequencies).

### Analog Electronics Drift

Op-amp offset voltage and gain drift with temperature:

| Parameter           | OPA209 Drift       | Effect               |
|--------------------|--------------------|----------------------|
| Offset voltage     | 0.1 uV/deg C       | Negligible for AC    |
| Gain drift         | ~10 ppm/deg C       | < 0.1% over 10 deg C |
| Bandwidth drift    | Minimal             | Negligible           |

### ADC Drift

The ADS1256 internal reference drifts at 5 ppm/degree C. Over a 30 degree C
daily temperature swing, this introduces approximately 0.015% gain variation,
which is negligible for Schumann resonance measurements.

### Mitigation

1. Place the electronics in an insulated enclosure to reduce temperature
   swings.
2. Record the enclosure temperature (use a DS18B20 digital temperature sensor
   connected to the Pi's GPIO) for post-processing correction.
3. The EarthSync firmware logs temperature alongside magnetic field data for
   detrending.

---

## 10. Site Selection Checklist

Use this checklist when evaluating a candidate site:

### Electromagnetic Environment
- [ ] > 5 km from high-voltage transmission lines (>110 kV)
- [ ] > 2 km from medium-voltage lines (33-110 kV)
- [ ] > 100 m from low-voltage distribution lines
- [ ] > 2 km from power substations
- [ ] > 20 km from 16.7 Hz AC railways (Europe)
- [ ] > 5 km from DC/50 Hz AC railways
- [ ] > 2 km from wind turbines
- [ ] > 10 km from major urban areas (preferred)
- [ ] No electric fences within 500 m
- [ ] No large electric motors or industrial equipment within 1 km

### Physical Site
- [ ] Sensor location outdoors with no overhead metallic structures
- [ ] Clear sky view for GPS antenna
- [ ] Soil suitable for earth rod (moist, conductive)
- [ ] Non-metallic sensor mounting surface/supports
- [ ] Cable route from sensor to electronics < 50 m
- [ ] Protection from livestock, wildlife, and vandalism
- [ ] Access for maintenance (monthly calibration checks)

### Infrastructure
- [ ] Internet connectivity (WiFi, Ethernet, or cellular modem)
- [ ] Solar exposure for panel (if solar-powered)
- [ ] Shelter for electronics (indoor location or weatherproof enclosure)
- [ ] Power source (battery + solar, or battery with periodic recharge)

### 24-Hour Survey
- [ ] Background recording completed (minimum 24 hours)
- [ ] At least 2 Schumann modes visible in PSD
- [ ] 50/60 Hz peak < 20 dB above noise floor
- [ ] No persistent narrowband interference in 3-45 Hz band
- [ ] Transient interference < 5% of recording duration

---

## Appendix: Quick Site Assessment Without Full Equipment

If you do not yet have a complete station, a rough site assessment can be
performed with:

1. **Smartphone magnetometer app:** Apps like "Physics Toolbox" can show
   the magnetic noise spectrum. While the sensitivity is far too low for
   Schumann resonances, a clean spectrum (no strong peaks at 50/60 Hz
   harmonics) is a positive indicator.

2. **AM radio:** Tune an AM radio to an empty frequency and listen. Buzzing,
   clicking, or humming indicates nearby electromagnetic interference sources.

3. **Visual survey:** Walk the area and note power lines, transformers,
   substations, railway lines, and large buildings. Use satellite imagery
   (Google Maps) to check for power line routes and substations that may not
   be visible from ground level.

4. **Online resources:**
   - OpenStreetMap: shows power line routes and railway electrification
   - National grid operator maps: show transmission line locations
   - NOAA magnetic declination calculator: for sensor orientation
