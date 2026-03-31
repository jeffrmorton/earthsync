# Station Assembly Guide

Step-by-step instructions for building an EarthSync Schumann Resonance
monitoring station. Read the full [Signal Chain Design Notes](DESIGN_NOTES.md)
and [Bill of Materials](bom.yaml) before starting.

**Estimated build time:** 8--16 hours over 2--3 sessions
**Skill level:** Intermediate (soldering experience required)
**Tools required:** See bom.yaml `tools_required` section

---

## Which Tier Should I Build?

Before you start soldering, decide which hardware tier fits your situation.
See [Station Options](STATION_OPTIONS.md) for full details on every tier.

### Decision Tree

```
START
  |
  +-- "I just want to see if Schumann Resonances are real."
  |     |
  |     +--> Tier 1 ($50-80)
  |          Wind a coil, plug into your PC sound card, run SpectrumLab.
  |          No soldering, no Pi, no GPS. Just proof of concept.
  |
  +-- "I want a standalone station on the EarthSync network."
  |     |
  |     +-- Budget under $400?
  |     |     |
  |     |     +--> Tier 2 ($250-400) <-- THIS GUIDE COVERS TIER 2
  |     |          DIY coil + ADS1256 + Pi Zero 2W + GPS.
  |     |          Full standalone operation, solar-capable.
  |     |
  |     +-- Budget $500-1,500?
  |           |
  |           +-- Willing to wind your own coil?
  |           |     |
  |           |     +--> Tier 3A ($1,000-1,100)
  |           |          DIY sensor + Symmetric Research USB4CH DAQ.
  |           |          Pro-grade acquisition, same DAQ as HeartMath.
  |           |
  |           +-- Prefer a commercial sensor?
  |                 |
  |                 +--> Tier 3B ($500-600)
  |                      MSI MC910 coil + ADS1263 HAT.
  |                      No coil winding. Plug and play sensor.
  |
  +-- "I need publishable / research-quality data."
  |     |
  |     +--> Tier 4 ($3,500-7,000)
  |          Zonge ANT/4 + Symmetric Research USB8CH.
  |          Matches HeartMath GCMS observatory quality.
  |
  +-- "I am building a permanent geophysical observatory."
        |
        +--> Tier 5 ($15,000-30,000+)
             Three-axis sensors, GNSS disciplined oscillator,
             NIST-traceable calibration.
```

### Quick Comparison

| Tier | Cost | Sensor | ADC | Standalone | GPS | Publishable |
|------|------|--------|-----|-----------|-----|-------------|
| 1 | $50-80 | DIY / ferrite | Sound card | No | No | No |
| 2 | $250-400 | DIY / mu-metal | ADS1256 | Yes | Yes | With caveats |
| 3A | $1,000-1,100 | DIY / ICS101 | USB4CH | Yes | Yes | Yes |
| 3B | $500-600 | MSI MC910 | ADS1263 | Yes | Yes | Yes |
| 4 | $3,500-7,000 | Zonge ANT/4 | USB8CH | Yes | Yes | Yes |
| 5 | $15,000+ | 3-axis research | USB8CH / NI | Yes | GNSS | Yes |

### Upgrading Between Tiers

The EarthSync firmware and software stack is the same across all tiers. You
can start at Tier 1 to validate your site, upgrade to Tier 2 for standalone
operation, and later swap in a Tier 3 or 4 sensor and DAQ without changing
your software configuration. The server does not care what hardware produced
the samples -- it only sees the `sampleRateHz` and `samples` array in the
ingest payload.

**This guide covers the Tier 2 build in detail.** Steps 1--10 below walk
through coil winding, amplifier assembly, ADC wiring, GPS setup, and
software installation for the budget standalone configuration.

---

## Safety Warnings

- LiPo batteries can catch fire if punctured, shorted, or overcharged. Use
  a proper charge controller and never leave charging unattended.
- Soldering produces toxic fumes. Work in a ventilated area or use fume
  extraction.
- The induction coil can accumulate static charge. Discharge to ground before
  connecting to the preamplifier.

---

## Step 1: Induction Coil Construction

The sensor coil is the most time-consuming component to build. Allow 4--6
hours for winding.

### 1.1 Core Preparation

1. Obtain a mu-metal rod: 25--30 cm length, 10--12 mm diameter for a portable
   station. For fixed installations, 1--1.35 m rods yield significantly higher
   sensitivity (Christofilakis et al. 2018).
2. Clean the rod with isopropyl alcohol to remove oils and contaminants.
3. Wrap the rod in two layers of Kapton tape or thin polyimide film to provide
   electrical insulation between the core and winding.
4. Attach end cheeks (flanges) from 3D-printed PLA or turned nylon, friction-fit
   or glued. These keep the winding from sliding off the core ends. Leave 2 cm
   of bare core protruding at each end.

### 1.2 Winding

Proper winding technique is critical to minimize distributed capacitance and
achieve a self-resonant frequency above 100 Hz.

1. Mount the core in a winding jig or lathe chuck. A hand drill clamped in
   a vise works for small cores.
2. Use 0.2 mm (AWG 32) enameled copper magnet wire. Have the full spool
   mounted on a tensioning spindle.
3. Wind in sections (bank winding):
   - Wind a single layer across the core length, turn to turn, left to right.
   - At the end, step up and wind back right to left for the second layer.
   - After every 4--6 layers, apply a layer of thin Kapton tape or paper
     insulation. This reduces inter-layer capacitance.
   - Keep constant moderate tension. Too loose causes uneven layers; too tight
     can nick the enamel insulation.
4. Continue winding until you reach 40,000--80,000 turns total. Track the
   turn count using a mechanical counter attached to the winding jig, or
   estimate from the wire length consumed:
   ```
   turns = wire_length / (pi * (core_diameter + 2 * winding_thickness))
   ```
5. Bring out tap wires at 25%, 50%, and 75% of total turns. These allow
   testing with different effective turn counts.
6. Leave 30 cm lead wires at the start and end of the winding. Secure
   with a small dab of cyanoacrylate adhesive.

### 1.3 Potting

Potting protects the coil from moisture, vibration, and mechanical damage.

1. Slide the completed coil into a PVC pipe section (50--75 mm diameter)
   with one end capped.
2. Mix two-part epoxy resin (slow-cure, 24-hour type) or melt paraffin wax
   to approximately 70 degrees C.
3. Pour the potting compound slowly around the coil, tilting to eliminate
   air bubbles. Paraffin wax is preferred as it is reversible and does not
   generate mechanical stress on the windings during temperature cycling.
4. Cap the open end. If using PVC, drill a small vent hole to prevent
   pressure buildup during temperature changes.
5. Allow to cure for 24 hours (epoxy) or cool completely (wax).

### 1.4 Shielding

An electrostatic shield prevents electric-field coupling while allowing
magnetic fields to pass through.

1. Wrap the potted coil in a single layer of thin copper or aluminum foil.
2. **Critical:** Leave a gap (approximately 5 mm) along the length of the coil
   so the shield does not form a shorted turn. A shorted turn would block
   the magnetic field you are trying to measure.
3. Connect the shield to the cable shield (see Cabling, Step 4).
4. Wrap the shield in heat-shrink tubing or electrical tape for protection.

### 1.5 Verification

Before proceeding, measure and record:
- DC resistance between coil leads (expected: 2--6 kohm)
- Inductance if meter is available (expected: 50--200 H)
- Resistance between coil leads and shield (should be > 10 Mohm, indicating
  no shorts to the shield)

---

## Step 2: Preamplifier Board Assembly

The preamplifier can be built on a soldered breadboard (perfboard/stripboard)
or a custom PCB. A PCB is recommended for lowest noise.

### 2.1 PCB Layout Guidelines

If designing a PCB:
- Use a ground plane on one side (analog ground only).
- Keep input traces short and away from output traces.
- Place decoupling capacitors (100 nF + 10 uF) within 5 mm of the op-amp
  power pins.
- Use a guard ring around the inverting input pin to prevent leakage currents.
- Route the feedback resistor directly between output and inverting input,
  no vias.

### 2.2 Component Placement

1. Solder the IC socket (8-pin DIP) or surface-mount pads for the OPA209.
   An IC socket is recommended for easy replacement during debugging.
2. Solder the gain-setting resistors (R_f and R_g):
   - For G = 100 (40 dB): R_f = 99 kohm (use 100 kohm), R_g = 1 kohm
   - For G = 316 (50 dB): R_f = 316 kohm, R_g = 1 kohm
3. Solder the DC-blocking input capacitor: 1 uF polypropylene film cap in
   series with the non-inverting input.
4. Solder decoupling capacitors:
   - 100 nF C0G/NP0 ceramic from V+ to GND, close to pin 7
   - 100 nF C0G/NP0 ceramic from V- to GND, close to pin 4
   - 10 uF tantalum from V+ to GND
   - 10 uF tantalum from V- to GND
5. Solder the BNC input connector (panel-mount) with the center pin to the
   DC-blocking capacitor and the shield to analog ground.
6. Solder the output connector (BNC or header pin for next stage).

### 2.3 Power Connection

Connect the preamplifier to the analog power supply:
- V+ to positive analog rail (+9V or +12V from LDO)
- V- to negative analog rail (-9V or -12V from LDO)
- GND to analog ground bus

Do **not** power the preamplifier from the Raspberry Pi 5V/3.3V rails.

---

## Step 3: Filter Board Assembly

The Sallen-Key LPF and Twin-T notch can share a single board.

### 3.1 Sallen-Key Low-Pass Filter (fc = 46 Hz)

1. Solder the second OPA209 (or use an OPA2209 dual op-amp for both filter
   stages on a single IC).
2. Place components per the design values:
   - R1 = 24.3 kohm (1% metal film)
   - R2 = 48.7 kohm (1% metal film)
   - C1 = 100 nF (C0G/NP0)
   - C2 = 100 nF (C0G/NP0)
3. Wire in unity-gain Sallen-Key configuration (see DESIGN_NOTES.md for
   schematic).
4. Add decoupling capacitors on the op-amp supply pins.

### 3.2 Twin-T Notch Filter (50 Hz or 60 Hz)

1. Solder the third op-amp (or second half of OPA2209 dual).
2. Place components for 50 Hz notch:
   - R = 31.6 kohm (0.1% or hand-matched)
   - R/2 = 15.8 kohm (0.1% or hand-matched)
   - C = 100 nF (C0G/NP0, 1%)
   - 2C = 200 nF (two 100 nF in parallel for matching)
3. For 60 Hz (Americas): R = 26.7 kohm, R/2 = 13.3 kohm, same C values.
4. Add the active feedback network:
   - R_fb1 = 39 kohm (from output to non-inverting input)
   - R_fb2 = 1 kohm (from non-inverting input to ground)
   - This gives feedback fraction k = 39/40 = 0.975, yielding Q ~ 10
5. **Component matching is critical.** Measure each resistor and capacitor
   with a multimeter. Select components that match to within 0.5% for the
   resistor pairs and capacitor pairs.

### 3.3 Variable Gain Stage

1. Solder the fourth op-amp.
2. Wire as non-inverting amplifier with a 10-position DIP switch selecting
   different feedback resistors:
   - Position 1: G = 1 (jumper, 0 dB)
   - Position 2: G = 3 (R_f = 2k, R_g = 1k, 9.5 dB)
   - Position 3: G = 5 (R_f = 4k, R_g = 1k, 14 dB)
   - Position 4: G = 10 (R_f = 9k, R_g = 1k, 20 dB)
   - Position 5: G = 21 (R_f = 20k, R_g = 1k, 26.4 dB)
3. Alternatively, use a precision 10k potentiometer for continuously
   adjustable gain.

### 3.4 Inter-stage Connections

Connect the stages in order:
```
Preamp OUT --> Sallen-Key IN --> SK OUT --> Twin-T IN --> TT OUT --> VGA IN --> VGA OUT
```

Use short, direct wiring. If using separate boards, use shielded coaxial
jumpers with BNC connectors between stages.

---

## Step 4: ADC Connection to Raspberry Pi

### 4.1 SPI Wiring

Connect the ADS1256 module to the Raspberry Pi GPIO header:

| ADS1256 Pin | Wire Color (suggested) | RPi Physical Pin | RPi GPIO |
|-------------|------------------------|------------------|----------|
| VCC         | Red                    | Pin 2 (5V)       | --       |
| GND         | Black                  | Pin 6 (GND)      | --       |
| SCLK        | Yellow                 | Pin 23           | GPIO 11  |
| DIN (MOSI)  | Green                  | Pin 19           | GPIO 10  |
| DOUT (MISO) | Blue                   | Pin 21           | GPIO 9   |
| CS          | Orange                 | Pin 24           | GPIO 8   |
| DRDY        | White                  | Pin 11           | GPIO 17  |
| RESET       | Gray                   | Pin 12           | GPIO 18  |
| PDWN        | (tie to VCC)           | Pin 2 (5V)       | --       |

### 4.2 Analog Input Connection

1. Connect the variable gain stage output to ADS1256 AIN0 (positive
   differential input).
2. Connect the analog ground reference to ADS1256 AIN1 (negative
   differential input).
3. Use short, twisted-pair wiring for the differential connection. Keep
   the pair away from digital SPI lines.

### 4.3 SPI Configuration on the Raspberry Pi

1. Enable SPI interface:
   ```bash
   sudo raspi-config
   # Navigate to: Interface Options -> SPI -> Enable
   ```
2. Verify SPI device appears:
   ```bash
   ls /dev/spidev0.*
   # Should show: /dev/spidev0.0  /dev/spidev0.1
   ```
3. Set SPI clock speed in firmware configuration (default 1.92 MHz is fine
   for the ADS1256 at low sample rates).

### 4.4 Level Shifting

The ADS1256 digital I/O is 3.3V, which is compatible with Raspberry Pi GPIO
levels. No level shifting is required. However, the ADS1256 analog supply
is 5V. Ensure VCC is connected to the Pi's 5V pin (Pin 2), not 3.3V.

---

## Step 5: GPS Module Connection

### 5.1 UART Wiring

Connect the NEO-M8 GPS module to the Raspberry Pi:

| GPS Pin | RPi Physical Pin | RPi GPIO  | Function         |
|---------|------------------|-----------|------------------|
| VCC     | Pin 1 (3.3V)     | --        | Power            |
| GND     | Pin 14 (GND)     | --        | Ground           |
| TX      | Pin 10           | GPIO 15   | GPS TX -> RPi RX |
| RX      | Pin 8            | GPIO 14   | GPS RX -> RPi TX |
| PPS     | Pin 7            | GPIO 4    | 1 PPS signal     |

### 5.2 PPS Connection

The 1 PPS (pulse-per-second) output is critical for timing synchronization.

1. Connect the PPS pin to GPIO 4 through a 100 ohm series resistor (protects
   against overcurrent).
2. The PPS signal is typically a 100 ms positive pulse at the start of each
   UTC second, with accuracy of 30 ns.
3. Verify PPS operation after software installation (Step 9).

### 5.3 UART Configuration

1. Disable the Linux serial console (it conflicts with GPS UART):
   ```bash
   sudo raspi-config
   # Navigate to: Interface Options -> Serial Port
   # "Login shell accessible over serial?" -> No
   # "Serial port hardware enabled?" -> Yes
   ```
2. The GPS module defaults to 9600 baud, NMEA output. The firmware will
   configure it for 115200 baud and UBX binary protocol at startup.

### 5.4 Antenna Placement

1. Connect the GPS patch antenna or external active antenna via the u.FL
   or SMA connector on the GPS module.
2. Place the antenna with a clear view of the sky. Indoor operation requires
   the antenna near a window or on a windowsill.
3. A ground plane under the patch antenna (10 cm square of copper foil)
   improves reception.

---

## Step 6: Power System Setup

### 6.1 Battery Preparation

1. Use a 3.7V LiPo pack rated 10,000--20,000 mAh. Flat pouch cells or
   cylindrical 18650 packs (3S1P with balancer) both work.
2. Solder a JST-PH or XT30 connector to the battery leads if not already
   present. Observe polarity carefully.
3. Add an inline blade fuse (3A) on the positive lead for short-circuit
   protection.

### 6.2 Charge Controller

1. Connect the solar panel to the charge controller input.
2. Connect the LiPo battery to the charge controller battery terminals.
3. Verify the charge controller is configured for the correct battery
   chemistry (LiPo: 4.2V/cell charge voltage, 3.0V/cell cutoff).

### 6.3 Digital Power Supply

1. Connect the charge controller 5V output (or a separate buck-boost
   converter from the battery) to the Raspberry Pi USB-C power input.
2. Verify stable 5.1V output under load. The Pi 4 can draw up to 3A during
   boot; ensure the converter can supply this.

### 6.4 Analog Power Supply

1. Connect the battery to the analog LDO regulators (ADP7118 or equivalent).
2. For dual-supply op-amps (+/-9V), use two LDOs or a charge pump inverter:
   - Positive rail: Battery -> boost converter -> +9V LDO
   - Negative rail: +9V -> charge pump inverter -> -9V LDO
3. Verify output noise with an oscilloscope if available. Ripple should be
   < 10 mV peak-to-peak.

### 6.5 Ground Connections

1. Connect all grounds to a single star-ground point on the main board:
   - Digital ground (Pi, GPS, ADS1256 digital pins)
   - Analog ground (op-amps, ADS1256 analog pins, filter components)
   - Shield ground (coaxial cable shields, enclosure, earth rod)
2. These three ground domains should only meet at the star point.
3. Connect the earth rod to the shield ground via a short, heavy-gauge wire
   (10 AWG or thicker).

---

## Step 7: Enclosure Preparation

### 7.1 Electronics Enclosure

1. Select an IP65-rated ABS junction box (minimum 200x150x100 mm).
2. Mark and drill holes for:
   - Cable gland for sensor coaxial cable (PG9)
   - Cable gland for GPS antenna cable (PG7)
   - Cable gland for solar panel power cable (PG7)
   - Optional: SMA bulkhead for GPS antenna, BNC bulkhead for sensor
3. Mount the Raspberry Pi on brass standoffs inside the enclosure.
4. Mount the ADC board, filter board, and power board on standoffs. Arrange
   so analog boards are as far as possible from the Pi and its switching
   power supply.
5. Apply silicone sealant around all cable gland entries after final wiring.

### 7.2 Sensor Housing

1. The potted coil in its PVC pipe should have end caps glued and sealed
   with marine sealant or epoxy.
2. The coaxial cable exits through a cable gland in one end cap.
3. For permanent outdoor installation, mount the coil housing on wooden
   (non-metallic) stakes 10--30 cm above ground level. Avoid metal mounting
   hardware near the sensor.

### 7.3 Solar Panel Mounting

1. Mount the solar panel at the appropriate tilt angle for your latitude
   (approximately equal to your latitude in degrees, facing the equator).
2. Use a non-metallic mounting bracket if the panel is within 2 m of the
   sensor coil.
3. Route the solar panel cable to the enclosure through a cable gland.

---

## Step 8: Initial Power-Up and Smoke Test

Proceed methodically. Do not power everything at once.

### 8.1 Analog Supply Test

1. **Disconnect** the Raspberry Pi and ADS1256.
2. Connect the battery to the analog power supply only.
3. Measure the positive and negative supply rails with a multimeter:
   - V+ should read within 5% of target (e.g., +9.0V +/- 0.45V)
   - V- should read within 5% of target (e.g., -9.0V +/- 0.45V)
4. Measure the current draw (should be < 5 mA with no signal input).
5. Check for any hot components (indicates shorts or incorrect wiring).

### 8.2 Preamplifier Test

1. With the analog supply on, connect an oscilloscope probe to the
   preamplifier output.
2. Short the preamplifier input to ground. You should see a flat baseline
   with no oscillation. If you see oscillation, there is a stability issue
   (check compensation, decoupling, and layout).
3. Apply a known signal: touch the input with your finger (you should see
   50/60 Hz hum picked up by your body, confirming the amplifier works).

### 8.3 Filter Chain Test

1. Connect the preamplifier output to the filter chain input.
2. Monitor the filter output on the oscilloscope.
3. The 50/60 Hz hum from the finger test should be significantly reduced
   after the Twin-T notch filter.

### 8.4 Digital System Test

1. Connect the Raspberry Pi to its 5V power supply (separate from analog).
2. Boot the Pi and verify it reaches a login prompt (monitor via HDMI or
   SSH over WiFi/Ethernet).
3. Verify SPI is enabled:
   ```bash
   ls /dev/spidev0.0
   ```
4. Verify GPS UART is available:
   ```bash
   ls /dev/serial0
   ```

### 8.5 ADC Test

1. Connect the ADS1256 to the Raspberry Pi via SPI (Step 4 wiring).
2. Power the ADS1256 module from the Pi's 5V pin.
3. Connect the filter chain output to the ADC input.
4. Run the diagnostic script (installed in Step 9):
   ```bash
   earthsync-diag adc-test
   ```
5. You should see samples being read. With the sensor disconnected, values
   should be near zero with low noise.

---

## Step 9: Software Installation

### 9.1 Operating System

1. Flash Raspberry Pi OS Lite (64-bit) to a 32 GB microSD card using
   Raspberry Pi Imager.
2. Enable SSH and configure WiFi credentials in the imager's advanced
   settings before flashing.
3. Boot the Pi, connect via SSH.
4. Update the system:
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

### 9.2 EarthSync Firmware

1. Install the firmware package:
   ```bash
   curl -fsSL https://earthsync.dev/install.sh | bash
   ```
   Or, for manual installation:
   ```bash
   sudo apt install -y python3-pip python3-venv git
   git clone https://github.com/earthsync/firmware.git
   cd firmware
   python3 -m venv venv
   source venv/bin/activate
   pip install -e .
   ```
2. Configure the station:
   ```bash
   earthsync-config init
   ```
   This interactive wizard sets:
   - Station name and location
   - Server URL for data upload
   - ADC sample rate (100 or 256 Hz)
   - Mains frequency (50 or 60 Hz) for notch filter config
   - GPS PPS pin (default: GPIO 4)
3. Enable the systemd service:
   ```bash
   sudo systemctl enable earthsync
   sudo systemctl start earthsync
   ```

### 9.3 GPS and PPS Configuration

1. Install GPS daemon:
   ```bash
   sudo apt install -y gpsd gpsd-clients pps-tools
   ```
2. Configure gpsd:
   ```bash
   sudo nano /etc/default/gpsd
   # Set: DEVICES="/dev/serial0"
   # Set: GPSD_OPTIONS="-n"
   ```
3. Enable PPS kernel module:
   ```bash
   echo "pps-gpio" | sudo tee -a /etc/modules
   # Add to /boot/config.txt:
   # dtoverlay=pps-gpio,gpiopin=4
   ```
4. Reboot and verify:
   ```bash
   sudo reboot
   # After reboot:
   sudo ppstest /dev/pps0
   # Should show PPS pulses with jitter < 10 us
   ```

### 9.4 NTP with PPS Discipline

1. Install chrony for precise timekeeping:
   ```bash
   sudo apt install -y chrony
   ```
2. Add PPS reference to `/etc/chrony/chrony.conf`:
   ```
   refclock PPS /dev/pps0 lock NMEA refid PPS precision 1e-7
   refclock SHM 0 refid NMEA noselect offset 0.2
   ```
3. Restart chrony:
   ```bash
   sudo systemctl restart chrony
   ```
4. Verify time synchronization:
   ```bash
   chronyc sources -v
   # PPS source should show * (selected) with offset < 1 us
   ```

---

## Step 10: First Data Verification

### 10.1 Quick Check

1. View the real-time data stream:
   ```bash
   earthsync-cli monitor
   ```
   You should see time-series data scrolling with values in the expected
   range. Large DC offsets or rail-to-rail oscillation indicate a problem.

2. View the live power spectral density:
   ```bash
   earthsync-cli spectrum
   ```
   On a quiet site, you should see peaks near:
   - 7.83 Hz (fundamental mode)
   - 14.3 Hz (second mode)
   - 20.8 Hz (third mode)

   If you see a dominant peak at 50/60 Hz, the notch filter needs adjustment
   or the site has excessive mains interference.

### 10.2 24-Hour Test Recording

1. Start a 24-hour recording:
   ```bash
   earthsync-cli record --duration 24h --output /data/first_run/
   ```
2. After 24 hours, analyze the recording:
   ```bash
   earthsync-cli analyze /data/first_run/
   ```
3. The analysis report should show:
   - Schumann resonance peaks detected in the spectrogram
   - Diurnal variation (higher amplitude during local afternoon, when the
     African thunderstorm center is active)
   - Noise floor estimate
   - Any interference sources identified

### 10.3 Server Connection

1. Verify the station can connect to the EarthSync server:
   ```bash
   earthsync-cli status
   ```
2. If the station is registered and connected, data will automatically
   stream to the server via encrypted WebSocket.
3. View your station on the EarthSync dashboard at the configured server URL.

### 10.4 Troubleshooting Common Issues

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| No ADC readings | SPI not enabled or wired wrong | Check `raspi-config` SPI, verify wiring |
| Readings stuck at 0 or max | ADC input not connected or clipped | Check analog chain, reduce gain |
| Dominant 50/60 Hz peak | Notch filter mistuned or mains coupling | Retune notch, check battery operation |
| No GPS fix | Antenna obstructed or not connected | Move antenna to clear sky view |
| PPS not detected | GPIO pin wrong or kernel module missing | Check dtoverlay config, reboot |
| High noise floor | Ground loop or digital noise coupling | Check star ground, separate analog/digital |
| Spectrogram blank | Gain too low | Increase variable gain or preamp gain |
| Intermittent dropouts | Power supply issues or SD card errors | Check battery, use quality SD card |

---

## Next Steps

After successful first light:

1. Read [Site Selection](SITE_SELECTION.md) to optimize your station's
   permanent location.
2. Perform [Calibration](CALIBRATION.md) procedures to characterize your
   station's transfer function.
3. Register your station on the EarthSync network to contribute to the
   global monitoring dataset.
4. Consider building a second orthogonal coil (E-W if your first is N-S)
   for full horizontal magnetic field measurement.
