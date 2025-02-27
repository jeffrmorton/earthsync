### Schematic Diagram (Text Description)

#### Overview

The hardware consists of a magnetic induction coil, an analog front-end, a data acquisition system, and a power supply. The output is processed by a microcontroller, which calculates the dominant frequency and updates the SQL database via a network connection.

#### Components

1. **Magnetic Induction Coil**
  * **Core**: Two 30 cm permalloy rods (µ ~250), back-to-back (total 60 cm).

  * **Wire**: 90,000 turns of 36 AWG copper wire (45,000 per coil, series-connected).

  * **Shielding**: Aluminum tube (grounded) around the coil, open at ends.

  * **Output**: ~70 nV/pT/Hz at coil terminals (pins: Coil+ and Coil-).

3. **Analog Front-End**
  * **Preamplifier**:

    * **IC**: OPA227 (low-noise op-amp).

    * **Configuration**: Differential amplifier.

    * **Gain**: 60 dB (1000x).

    * **Input**: Coil+ to non-inverting input (pin 3), Coil- to inverting input (pin 2) via 10 kΩ resistors.

    * **Feedback**: 10 MΩ resistor and 100 pF capacitor in parallel between output (pin 6) and inverting input.

    * **Output**: Preamp_Out (~70 µV/pT).

  * **Bandpass Filter**:

    * **IC**: OPA227 (active filter).

    * **Topology**: Sallen-Key bandpass.

    * **Frequency Range**: 3 Hz - 50 Hz.

    * **Gain**: 52 dB (400x).

    * **Components**:

      * R1 = 53 kΩ, R2 = 53 kΩ (input resistors).

      * C1 = 1 µF, C2 = 1 µF (capacitors for frequency).

      * Feedback: 21 MΩ resistor between output (pin 6) and inverting input (pin 2).

    * **Input**: Preamp_Out to pin 3.

    * **Output**: Filter_Out (~28 mV/pT).

  * **Anti-Aliasing Filter**:

    * **Type**: Passive RC low-pass.

    * **Cutoff**: 60 Hz.

    * **Components**: R = 2.65 kΩ, C = 1 µF.

    * **Input**: Filter_Out.

    * **Output**: ADC_In.

5. **Data Acquisition System**
  * **ADC**:

    * **IC**: ADS1256 (24-bit).

    * **Sampling Rate**: 256 Hz.

    * **Input**: ADC_In to AIN0 (pin 5), AINCOM (pin 6) grounded.

    * **Power**: VDD (pin 1) = 5V, VSS (pin 2) = GND.

    * **Interface**: SPI (SCLK = pin 11, DIN = pin 12, DOUT = pin 13, CS = pin 10).

    * **Output**: Digital signal to microcontroller.

  * **Microcontroller**:

    * **IC**: ESP32-WROOM-32.

    * **Pins**:

      * SPI: SCLK (GPIO18), MOSI (GPIO23), MISO (GPIO19), CS (GPIO5) to ADS1256.

      * Power: 3V3 (pin 1), GND (pin 2).

      * Wi-Fi: Internal antenna for network connectivity.

    * **Storage**: MicroSD card module (SPI: CS = GPIO15, MOSI = GPIO23, MISO = GPIO19, SCLK = GPIO18).

7. **Power Supply**
  * **Source**: 2x 9V batteries (18V total).

  * **Regulators**:

    * LM7805: +5V for ADC and ESP32 (input = +9V, output = 5V).

    * LM7905: -5V for op-amps (input = -9V, output = -5V).

  * **Decoupling**: 100 nF + 10 µF capacitors at each IC power pin.

  * **Ground**: Common ground plane.

#### Connections

* **Coil to Preamplifier**: Coil+ → OPA227 pin 3, Coil- → OPA227 pin 2 (via 10 kΩ).

* **Preamplifier to Bandpass**: Preamp_Out (OPA227 pin 6) → Bandpass pin 3.

* **Bandpass to Anti-Aliasing**: Filter_Out (OPA227 pin 6) → R (2.65 kΩ) → C (1 µF) → ADC_In.

* **Anti-Aliasing to ADC**: ADC_In → ADS1256 AIN0 (pin 5).

* **ADC to ESP32**:

  * ADS1256 SCLK (pin 11) → ESP32 GPIO18.

  * ADS1256 DIN (pin 12) → ESP32 GPIO23.

  * ADS1256 DOUT (pin 13) → ESP32 GPIO19.

  * ADS1256 CS (pin 10) → ESP32 GPIO5.

* **Power**:

  * +9V → LM7805 VIN, -9V → LM7905 VIN.

  * LM7805 VOUT (+5V) → ADS1256 VDD, ESP32 3V3.

  * LM7905 VOUT (-5V) → OPA227 V- (pin 4).

  * OPA227 V+ (pin 7) → +5V.

* * *

### Supporting Software Controller

This software runs on the ESP32, samples the ADC, performs an FFT to detect the dominant Schumann frequency, and updates the PostgreSQL database via an HTTP POST request to the EarthSync server API.

#### Software Requirements

* **Language**: C++ (Arduino framework for ESP32).

* **Libraries**:

  * SPI.h: For ADC communication.

  * WiFi.h: For network connectivity.

  * HTTPClient.h: For API requests.

  * ArduinoFFT.h: For frequency analysis.

  * SD.h: For local storage (optional).

* **Database**: Assumes the frequency_history table exists (from db.js).

### Schematic Notes

* **Coil Sensitivity**: ~70 nV/pT/Hz, amplified to ~28 mV/pT at ADC input.

* **ADC Range**: 24-bit resolution covers the amplified signal (max ~1-2V).

* **FFT**: Detects peaks in the 3-50 Hz range, focusing on Schumann frequencies (7.83 Hz, 14.3 Hz, etc.).

#### Software Notes

* **WiFi**: Replace your-ssid, your-password, your-server.com, and your-api-key with actual values.

* **API**: The POST endpoint requires an API key (generated via /register-api-key in server.js).

* **Calibration**: Adjust FFT windowing or sampling rate if noise dominates the signal.

* * *

### Deployment Steps

1. **Assemble Hardware**: Build the circuit as described, ensuring proper shielding and grounding.

3. **Program ESP32**: Upload the earthsync_detector.ino code using the Arduino IDE.

5. **Test Locally**: Verify frequency detection via Serial Monitor and SD logs.

7. **Deploy**: Place in a low-EMI area, connect to WiFi, and confirm database updates via server logs.

#### Legend

* **Lines**: Represent connections (e.g., --- for wires).

* **Components**: Identified by labels (e.g., U1 for ICs, R1 for resistors).

* **Pins**: Specified in parentheses (e.g., (3) for pin 3).

* **Ground**: GND.

* **Power**: +5V, -5V.

#### Component List

* **Coil**: 2x 30 cm permalloy cores, 45,000 turns each (90,000 total), series-connected.

* **U1, U2**: OPA227 op-amps.

* **R1, R2**: 10 kΩ resistors (preamp input).

* **R3**: 10 MΩ resistor (preamp feedback).

* **C1**: 100 pF capacitor (preamp stability).

* **R4, R5**: 53 kΩ resistors (bandpass input).

* **C2, C3**: 1 µF capacitors (bandpass frequency).

* **R6**: 21 MΩ resistor (bandpass feedback).

* **R7**: 2.65 kΩ resistor (anti-aliasing).

* **C4**: 1 µF capacitor (anti-aliasing).

* **U3**: ADS1256 24-bit ADC.

* **U4**: ESP32-WROOM-32 microcontroller.

* **SD**: MicroSD card module.

* **Power**: 2x 9V batteries, LM7805 (+5V), LM7905 (-5V).

#### Notes

* **Shielding**: Enclose the coil in a grounded aluminum tube, leaving ends open for magnetic field detection.

* **Decoupling**: Add 100 nF + 10 µF capacitors near each IC's power pins (not shown for simplicity).

* **Grounding**: Use a single ground plane to minimize noise.