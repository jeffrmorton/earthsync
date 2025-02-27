### Visual Schematic Representation (Text-Based)

#### Legend

* **Lines**: Represent connections (e.g., --- for wires).

* **Components**: Identified by labels (e.g., U1 for ICs, R1 for resistors).

* **Pins**: Specified in parentheses (e.g., (3) for pin 3).

* **Ground**: GND.

* **Power**: +5V, -5V.

#### Schematic Layout

text

WrapCopy

`+-------------------+ | Magnetic Coil |\
| (2x 30 cm, 45k |\
| turns each) |\
| |\
| Coil+ Coil- |\
+---|---------|-----+\
| |\
| |\
R1 R2\
10kΩ 10kΩ\
| |\
| |\
U1: OPA227 (Preamplifier)\
| |\
(3)+ (2)-\
| |\
+---R3----+\
| 10MΩ |\
| |\
+---C1----+\
100pF\
|\
(6) Preamp_Out\
|\
|\
R4: 53kΩ\
|\
U2: OPA227 (Bandpass Filter)\
|\
(3)+\
|\
+---R5----+\
| 53kΩ |\
| |\
C2 C3\
1µF 1µF\
| |\
GND (2)-\
| |\
+---R6----+\
| 21MΩ |\
|\
(6) Filter_Out\
|\
R7: 2.65kΩ\
|\
C4: 1µF\
|\
ADC_In\
|\
U3: ADS1256 (ADC)\
|\
(5) AIN0\
|\
(6) AINCOM --- GND\
|\
(1) VDD --- +5V\
(2) VSS --- GND\
|\
(11) SCLK --- ESP32 GPIO18\
(12) DIN --- ESP32 GPIO23\
(13) DOUT --- ESP32 GPIO19\
(10) CS --- ESP32 GPIO5\
U4: ESP32-WROOM-32 (Microcontroller)\
|\
(1) 3V3 --- +5V\
(2) GND --- GND\
(18) GPIO18 --- U3 SCLK\
(23) GPIO23 --- U3 DIN\
(19) GPIO19 --- U3 DOUT\
(5) GPIO5 --- U3 CS\
(15) GPIO15 --- SD_CS\
SD Card Module\
|\
CS --- ESP32 GPIO15\
MOSI --- ESP32 GPIO23\
MISO --- ESP32 GPIO19\
SCLK --- ESP32 GPIO18\
|\
VCC --- +5V\
GND --- GND\
Power Supply:\
+---------+\
| 9V Bat+ | --- LM7805 VIN --- +5V --- U3 VDD, U4 3V3, U1(7), U2(7)\
| 9V Bat- | --- LM7905 VIN --- -5V --- U1(4), U2(4)\
+---------+\
|\
GND --- Common Ground Plane`

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