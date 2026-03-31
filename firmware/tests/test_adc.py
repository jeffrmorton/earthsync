"""Tests for ADC interface and all ADC implementations."""

import sys
from unittest.mock import MagicMock

import numpy as np
import pytest
from earthsync_station.adc import ADS1256, ADS1263, MockADC, SoundCardADC, SymmetricResearchADC
from earthsync_station.main import create_adc


class TestMockADC:
    def test_mock_adc_configure(self):
        adc = MockADC()
        adc.configure(sample_rate_hz=256, gain=1)
        assert adc._configured is True

    def test_mock_adc_read_samples_length(self):
        adc = MockADC()
        adc.configure(sample_rate_hz=256, gain=1)
        samples = adc.read_samples(2560)
        assert len(samples) == 2560

    def test_mock_adc_read_samples_type(self):
        adc = MockADC()
        adc.configure(sample_rate_hz=256, gain=1)
        samples = adc.read_samples(100)
        assert isinstance(samples, np.ndarray)

    def test_mock_adc_not_configured_raises(self):
        adc = MockADC()
        with pytest.raises(RuntimeError, match="not configured"):
            adc.read_samples(100)

    def test_mock_adc_close(self):
        adc = MockADC()
        adc.configure(sample_rate_hz=256, gain=1)
        assert adc._configured is True
        adc.close()
        assert adc._configured is False


class TestADS1256:
    def test_ads1256_invalid_gain_raises(self):
        adc = ADS1256()
        with pytest.raises(ValueError, match="Invalid gain 3"):
            adc.configure(sample_rate_hz=256, gain=3)

    def test_ads1256_no_spidev_raises(self):
        adc = ADS1256()
        with pytest.raises(RuntimeError, match="spidev not available"):
            adc.configure(sample_rate_hz=256, gain=1)

    def test_ads1256_configure_with_mock_spidev(self):
        """ADS1256.configure succeeds when spidev is available (mocked)."""

        mock_spidev = MagicMock()
        mock_spi_instance = MagicMock()
        mock_spidev.SpiDev.return_value = mock_spi_instance

        with pytest.MonkeyPatch.context() as mp:
            mp.setitem(sys.modules, "spidev", mock_spidev)
            adc = ADS1256(spi_bus=0, spi_device=1)
            adc.configure(sample_rate_hz=256, gain=1)

        assert adc._configured is True
        assert adc._spi is mock_spi_instance
        mock_spi_instance.open.assert_called_once_with(0, 1)
        assert mock_spi_instance.max_speed_hz == 1_000_000
        assert mock_spi_instance.mode == 1

    def test_ads1256_read_not_configured_raises(self):
        """read_samples before configure raises RuntimeError."""
        adc = ADS1256()
        with pytest.raises(RuntimeError, match="ADC not configured"):
            adc.read_samples(100)

    def test_ads1256_read_configured_raises_not_implemented(self):
        """read_samples after configure raises NotImplementedError (hardware stub)."""

        mock_spidev = MagicMock()
        mock_spidev.SpiDev.return_value = MagicMock()

        with pytest.MonkeyPatch.context() as mp:
            mp.setitem(sys.modules, "spidev", mock_spidev)
            adc = ADS1256()
            adc.configure(sample_rate_hz=256, gain=1)

        with pytest.raises(NotImplementedError, match="Hardware ADC read not yet implemented"):
            adc.read_samples(256)

    def test_ads1256_close_with_spi(self):
        """close() when _spi is set calls spi.close() and resets state."""

        mock_spidev = MagicMock()
        mock_spi_instance = MagicMock()
        mock_spidev.SpiDev.return_value = mock_spi_instance

        with pytest.MonkeyPatch.context() as mp:
            mp.setitem(sys.modules, "spidev", mock_spidev)
            adc = ADS1256()
            adc.configure(sample_rate_hz=256, gain=1)

        adc.close()
        mock_spi_instance.close.assert_called_once()
        assert adc._spi is None
        assert adc._configured is False

    def test_ads1256_close_without_spi(self):
        """close() when _spi is None does not raise."""
        adc = ADS1256()
        assert adc._spi is None
        adc.close()  # Should not raise
        assert adc._spi is None
        assert adc._configured is False


class TestADS1263:
    def test_invalid_gain(self):
        adc = ADS1263()
        with pytest.raises(ValueError, match="Invalid gain 3"):
            adc.configure(sample_rate_hz=100, gain=3)

    def test_valid_gains(self):
        assert ADS1263.VALID_GAINS == (1, 2, 4, 8, 16, 32)

    def test_no_spidev(self):
        adc = ADS1263()
        with pytest.raises(RuntimeError, match="spidev not available"):
            adc.configure(sample_rate_hz=100, gain=1)

    def test_configure_with_mock_spidev(self):
        mock_spidev = MagicMock()
        mock_spi = MagicMock()
        mock_spidev.SpiDev.return_value = mock_spi
        with pytest.MonkeyPatch.context() as mp:
            mp.setitem(sys.modules, "spidev", mock_spidev)
            adc = ADS1263()
            adc.configure(sample_rate_hz=100, gain=4)
        assert adc._configured is True
        assert mock_spi.max_speed_hz == 2_000_000

    def test_read_not_configured(self):
        adc = ADS1263()
        with pytest.raises(RuntimeError, match="ADC not configured"):
            adc.read_samples(100)

    def test_read_raises_not_implemented(self):
        mock_spidev = MagicMock()
        mock_spidev.SpiDev.return_value = MagicMock()
        with pytest.MonkeyPatch.context() as mp:
            mp.setitem(sys.modules, "spidev", mock_spidev)
            adc = ADS1263()
            adc.configure(100, 1)
        with pytest.raises(NotImplementedError, match="ADS1263"):
            adc.read_samples(100)

    def test_close(self):
        mock_spidev = MagicMock()
        mock_spi = MagicMock()
        mock_spidev.SpiDev.return_value = mock_spi
        with pytest.MonkeyPatch.context() as mp:
            mp.setitem(sys.modules, "spidev", mock_spidev)
            adc = ADS1263()
            adc.configure(100, 1)
        adc.close()
        mock_spi.close.assert_called_once()
        assert adc._configured is False


class TestSoundCardADC:
    def test_no_sounddevice(self):
        adc = SoundCardADC()
        with pytest.raises(RuntimeError, match="sounddevice not available"):
            adc.configure(44100, 1)

    def test_configure_with_mock(self):
        mock_sd = MagicMock()
        with pytest.MonkeyPatch.context() as mp:
            mp.setitem(sys.modules, "sounddevice", mock_sd)
            adc = SoundCardADC()
            adc.configure(48000, 1)
        assert adc._configured is True
        assert adc._sample_rate == 48000

    def test_read_not_configured(self):
        adc = SoundCardADC()
        with pytest.raises(RuntimeError, match="ADC not configured"):
            adc.read_samples(1000)

    def test_read_with_mock(self):
        mock_sd = MagicMock()
        mock_sd.rec.return_value = np.ones((1000, 1))
        mock_sd.wait.return_value = None
        with pytest.MonkeyPatch.context() as mp:
            mp.setitem(sys.modules, "sounddevice", mock_sd)
            adc = SoundCardADC()
            adc.configure(44100, 1)
            samples = adc.read_samples(1000)
        assert len(samples) == 1000
        mock_sd.rec.assert_called_once()
        mock_sd.wait.assert_called_once()

    def test_close(self):
        mock_sd = MagicMock()
        with pytest.MonkeyPatch.context() as mp:
            mp.setitem(sys.modules, "sounddevice", mock_sd)
            adc = SoundCardADC()
            adc.configure(44100, 1)
        adc.close()
        assert adc._configured is False

    def test_default_device_none(self):
        adc = SoundCardADC()
        assert adc._device is None

    def test_custom_device(self):
        adc = SoundCardADC(device=2, channels=2)
        assert adc._device == 2
        assert adc._channels == 2


class TestSymmetricResearchADC:
    def test_no_pyserial(self):
        orig = sys.modules.get("serial")
        sys.modules["serial"] = None  # type: ignore[assignment]
        try:
            adc = SymmetricResearchADC()
            with pytest.raises(RuntimeError, match=r"pyserial not available|Failed to open"):
                adc.configure(100, 1)
        finally:
            if orig is not None:
                sys.modules["serial"] = orig
            else:
                sys.modules.pop("serial", None)

    def test_configure_with_mock(self):
        mock_serial_mod = MagicMock()
        mock_conn = MagicMock()
        mock_serial_mod.Serial.return_value = mock_conn
        with pytest.MonkeyPatch.context() as mp:
            mp.setitem(sys.modules, "serial", mock_serial_mod)
            adc = SymmetricResearchADC(port="/dev/ttyUSB1")
            adc.configure(200, 1)
        assert adc._configured is True
        mock_serial_mod.Serial.assert_called_once_with("/dev/ttyUSB1", baudrate=115200, timeout=5.0)

    def test_read_not_configured(self):
        adc = SymmetricResearchADC()
        with pytest.raises(RuntimeError, match="ADC not configured"):
            adc.read_samples(100)

    def test_read_raises_not_implemented(self):
        mock_serial_mod = MagicMock()
        mock_serial_mod.Serial.return_value = MagicMock()
        with pytest.MonkeyPatch.context() as mp:
            mp.setitem(sys.modules, "serial", mock_serial_mod)
            adc = SymmetricResearchADC()
            adc.configure(100, 1)
        with pytest.raises(NotImplementedError, match="Symmetric Research"):
            adc.read_samples(100)

    def test_close(self):
        mock_serial_mod = MagicMock()
        mock_conn = MagicMock()
        mock_serial_mod.Serial.return_value = mock_conn
        with pytest.MonkeyPatch.context() as mp:
            mp.setitem(sys.modules, "serial", mock_serial_mod)
            adc = SymmetricResearchADC()
            adc.configure(100, 1)
        adc.close()
        mock_conn.close.assert_called_once()
        assert adc._configured is False

    def test_default_port(self):
        adc = SymmetricResearchADC()
        assert adc._port == "/dev/ttyUSB0"

    def test_bad_port(self):
        mock_serial_mod = MagicMock()
        mock_serial_mod.Serial.side_effect = OSError("No such device")
        with pytest.MonkeyPatch.context() as mp:
            mp.setitem(sys.modules, "serial", mock_serial_mod)
            adc = SymmetricResearchADC(port="/dev/nonexistent")
            with pytest.raises(RuntimeError, match="Failed to open"):
                adc.configure(100, 1)


class TestCreateADC:
    def test_create_mock(self, monkeypatch):
        monkeypatch.setenv("EARTHSYNC_STATION_STATION_ID", "t")
        monkeypatch.setenv("EARTHSYNC_STATION_API_KEY", "k")
        monkeypatch.setenv("EARTHSYNC_STATION_ADC_TYPE", "mock")
        from earthsync_station.config import StationSettings

        s = StationSettings()
        adc = create_adc(s)
        assert isinstance(adc, MockADC)

    def test_create_ads1256(self, monkeypatch):
        monkeypatch.setenv("EARTHSYNC_STATION_STATION_ID", "t")
        monkeypatch.setenv("EARTHSYNC_STATION_API_KEY", "k")
        monkeypatch.setenv("EARTHSYNC_STATION_ADC_TYPE", "ads1256")
        from earthsync_station.config import StationSettings

        s = StationSettings()
        adc = create_adc(s)
        assert isinstance(adc, ADS1256)

    def test_create_ads1263(self, monkeypatch):
        monkeypatch.setenv("EARTHSYNC_STATION_STATION_ID", "t")
        monkeypatch.setenv("EARTHSYNC_STATION_API_KEY", "k")
        monkeypatch.setenv("EARTHSYNC_STATION_ADC_TYPE", "ads1263")
        from earthsync_station.config import StationSettings

        s = StationSettings()
        adc = create_adc(s)
        assert isinstance(adc, ADS1263)

    def test_create_soundcard(self, monkeypatch):
        monkeypatch.setenv("EARTHSYNC_STATION_STATION_ID", "t")
        monkeypatch.setenv("EARTHSYNC_STATION_API_KEY", "k")
        monkeypatch.setenv("EARTHSYNC_STATION_ADC_TYPE", "soundcard")
        from earthsync_station.config import StationSettings

        s = StationSettings()
        adc = create_adc(s)
        assert isinstance(adc, SoundCardADC)

    def test_create_symmetric(self, monkeypatch):
        monkeypatch.setenv("EARTHSYNC_STATION_STATION_ID", "t")
        monkeypatch.setenv("EARTHSYNC_STATION_API_KEY", "k")
        monkeypatch.setenv("EARTHSYNC_STATION_ADC_TYPE", "symmetric_research")
        from earthsync_station.config import StationSettings

        s = StationSettings()
        adc = create_adc(s)
        assert isinstance(adc, SymmetricResearchADC)

    def test_create_unknown(self, monkeypatch):
        monkeypatch.setenv("EARTHSYNC_STATION_STATION_ID", "t")
        monkeypatch.setenv("EARTHSYNC_STATION_API_KEY", "k")
        monkeypatch.setenv("EARTHSYNC_STATION_ADC_TYPE", "nonexistent")
        from earthsync_station.config import StationSettings

        s = StationSettings()
        with pytest.raises(ValueError, match="Unknown ADC type"):
            create_adc(s)
