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