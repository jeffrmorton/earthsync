"""ADS1256 24-bit ADC interface via SPI."""
# pyright: reportMissingImports=false

from abc import ABC, abstractmethod

import numpy as np


class ADCInterface(ABC):
    """Abstract ADC interface for testability."""

    @abstractmethod
    def configure(self, sample_rate_hz: int, gain: int) -> None: ...

    @abstractmethod
    def read_samples(self, n_samples: int) -> np.ndarray: ...

    @abstractmethod
    def close(self) -> None: ...


class ADS1256(ADCInterface):
    """ADS1256 ADC driver via SPI (requires spidev on Raspberry Pi)."""

    VALID_GAINS = (1, 2, 4, 8, 16, 32, 64)
    VALID_RATES = (
        2.5,
        5,
        10,
        15,
        25,
        30,
        50,
        60,
        100,
        500,
        1000,
        2000,
        3750,
        7500,
        15000,
        30000,
    )

    def __init__(self, spi_bus: int = 0, spi_device: int = 0):
        self._spi_bus = spi_bus
        self._spi_device = spi_device
        self._spi = None
        self._configured = False

    def configure(self, sample_rate_hz: int, gain: int) -> None:
        if gain not in self.VALID_GAINS:
            raise ValueError(f"Invalid gain {gain}. Must be one of {self.VALID_GAINS}")
        try:
            import spidev  # noqa: PLC0415

            self._spi = spidev.SpiDev()
            self._spi.open(self._spi_bus, self._spi_device)
            self._spi.max_speed_hz = 1_000_000
            self._spi.mode = 1
        except ImportError as err:
            raise RuntimeError("spidev not available — are you running on a Raspberry Pi?") from err
        self._sample_rate = sample_rate_hz
        self._configured = True

    def read_samples(self, n_samples: int) -> np.ndarray:
        if not self._configured:
            raise RuntimeError("ADC not configured. Call configure() first.")
        # Real implementation would read from SPI
        # Placeholder: would use self._spi.xfer2() in a loop
        raise NotImplementedError(
            f"Hardware ADC read not yet implemented (requested {n_samples} samples)"
        )

    def close(self) -> None:
        if self._spi is not None:
            self._spi.close()
            self._spi = None
        self._configured = False


class ADS1263(ADCInterface):
    """ADS1263 32-bit ADC driver via SPI.

    Tier 2 alternative — higher resolution than ADS1256 (32-bit vs 24-bit).
    10 channels (5 differential), up to 38.4 kSPS, PGA up to 32x.
    Available as Waveshare HAT ($35-50).
    """

    VALID_GAINS = (1, 2, 4, 8, 16, 32)

    def __init__(self, spi_bus: int = 0, spi_device: int = 0):
        self._spi_bus = spi_bus
        self._spi_device = spi_device
        self._spi = None
        self._sample_rate = 100
        self._gain = 1
        self._configured = False

    def configure(self, sample_rate_hz: int, gain: int) -> None:
        if gain not in self.VALID_GAINS:
            raise ValueError(f"Invalid gain {gain}. Must be one of {self.VALID_GAINS}")
        try:
            import spidev  # noqa: PLC0415

            self._spi = spidev.SpiDev()
            self._spi.open(self._spi_bus, self._spi_device)
            self._spi.max_speed_hz = 2_000_000
            self._spi.mode = 1
        except ImportError as err:
            raise RuntimeError("spidev not available — are you running on a Raspberry Pi?") from err
        self._sample_rate = sample_rate_hz
        self._gain = gain
        self._configured = True

    def read_samples(self, n_samples: int) -> np.ndarray:
        if not self._configured:
            raise RuntimeError("ADC not configured. Call configure() first.")
        raise NotImplementedError(
            f"Hardware ADS1263 read not yet implemented (requested {n_samples} samples)"
        )

    def close(self) -> None:
        if self._spi is not None:
            self._spi.close()
            self._spi = None
        self._configured = False


class SoundCardADC(ADCInterface):
    """Sound card LINE-in ADC via sounddevice library.

    Tier 1 ($50) — proven at Cumiana station (vlf.it) since 2011.
    Uses the computer's audio input as a 16-24 bit ADC.
    AC coupled (no DC), but SR is AC at 7-45 Hz so this is appropriate.

    Requires: pip install sounddevice
    """

    def __init__(self, device: int | str | None = None, channels: int = 1):
        self._device = device
        self._channels = channels
        self._sample_rate = 44100
        self._sd = None
        self._configured = False

    def configure(self, sample_rate_hz: int, gain: int) -> None:  # noqa: ARG002
        """Configure sound card. Gain is ignored (set via OS mixer)."""
        try:
            import sounddevice as sd  # noqa: PLC0415

            self._sd = sd
            self._sample_rate = sample_rate_hz
            self._configured = True
        except ImportError as err:
            raise RuntimeError(
                "sounddevice not available — install with: pip install sounddevice"
            ) from err

    def read_samples(self, n_samples: int) -> np.ndarray:
        if not self._configured:
            raise RuntimeError("ADC not configured. Call configure() first.")
        recording = self._sd.rec(
            n_samples,
            samplerate=self._sample_rate,
            channels=self._channels,
            dtype="float64",
            device=self._device,
        )
        self._sd.wait()
        return recording.flatten()

    def close(self) -> None:
        self._configured = False


class SymmetricResearchADC(ADCInterface):
    """Symmetric Research USB4CH/USB8CH ADC interface.

    Tier 3 ($700-980) — proven at HeartMath GCMS stations.
    24-bit, 4 or 8 channels, GPS timestamping.
    Communicates via USB serial (FTDI).

    Requires: pip install pyserial
    """

    def __init__(self, port: str = "/dev/ttyUSB0", channels: int = 4):
        self._port = port
        self._channels = channels
        self._serial = None
        self._sample_rate = 100
        self._configured = False

    def configure(self, sample_rate_hz: int, gain: int) -> None:  # noqa: ARG002
        """Configure USB DAQ. Gain is ignored (fixed internal gain)."""
        try:
            import serial  # noqa: PLC0415

            self._serial = serial.Serial(self._port, baudrate=115200, timeout=5.0)
            self._sample_rate = sample_rate_hz
            self._configured = True
        except ImportError as err:
            raise RuntimeError(
                "pyserial not available — install with: pip install pyserial"
            ) from err
        except Exception as err:
            raise RuntimeError(f"Failed to open {self._port}: {err}") from err

    def read_samples(self, n_samples: int) -> np.ndarray:
        if not self._configured:
            raise RuntimeError("ADC not configured. Call configure() first.")
        raise NotImplementedError(
            f"Symmetric Research USB read not yet implemented (requested {n_samples} samples)"
        )

    def close(self) -> None:
        if self._serial is not None:
            self._serial.close()
            self._serial = None
        self._configured = False


class MockADC(ADCInterface):
    """Mock ADC for testing without hardware."""

    def __init__(self, sample_rate_hz: int = 256):
        self._sample_rate = sample_rate_hz
        self._gain = 1
        self._configured = False

    def configure(self, sample_rate_hz: int, gain: int) -> None:
        self._sample_rate = sample_rate_hz
        self._gain = gain
        self._configured = True

    def read_samples(self, n_samples: int) -> np.ndarray:
        if not self._configured:
            raise RuntimeError("ADC not configured")
        rng = np.random.default_rng()
        return rng.standard_normal(n_samples) * 0.001  # Simulate ~1mV noise

    def close(self) -> None:
        self._configured = False
