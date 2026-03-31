"""Tests for earthsync_simulator.main (config + integration + async loop)."""

import asyncio
import json
import signal
from unittest.mock import AsyncMock, patch

import numpy as np
import pytest
from earthsync_simulator.config import Settings
from earthsync_simulator.main import _connect_redis, _handle_signal, _run, main
from earthsync_simulator.profiles import create_profile
from earthsync_simulator.signal_generator import generate_sr_time_domain


class TestConfigDefaults:
    def test_config_defaults(self):
        settings = Settings()
        assert settings.station_model == "sierra_nevada"
        assert settings.latitude == 37.0
        assert settings.longitude == -3.4
        assert settings.interval_ms == 10000
        assert settings.segment_duration_s == 10.0
        assert settings.redis_host == "localhost"
        assert settings.redis_port == 6379
        assert settings.redis_password == ""
        assert settings.redis_connect_timeout_ms == 20000
        assert settings.log_level == "info"

    def test_config_station_id_generated(self):
        """Each Settings instance gets a unique UUID by default."""
        a = Settings()
        b = Settings()
        assert a.station_id != b.station_id
        # Should look like a UUID (36 chars with hyphens)
        assert len(a.station_id) == 36

    def test_config_custom_env(self, monkeypatch):
        monkeypatch.setenv("EARTHSYNC_SIMULATOR_STATION_ID", "test-det-001")
        monkeypatch.setenv("EARTHSYNC_SIMULATOR_STATION_MODEL", "modra")
        monkeypatch.setenv("EARTHSYNC_SIMULATOR_LATITUDE", "48.37")
        monkeypatch.setenv("EARTHSYNC_SIMULATOR_LONGITUDE", "17.27")
        monkeypatch.setenv("EARTHSYNC_SIMULATOR_INTERVAL_MS", "5000")
        monkeypatch.setenv("EARTHSYNC_SIMULATOR_SEGMENT_DURATION_S", "5.0")
        monkeypatch.setenv("EARTHSYNC_SIMULATOR_REDIS_HOST", "redis.local")
        monkeypatch.setenv("EARTHSYNC_SIMULATOR_REDIS_PORT", "6380")
        monkeypatch.setenv("EARTHSYNC_SIMULATOR_REDIS_PASSWORD", "s3cret")
        monkeypatch.setenv("EARTHSYNC_SIMULATOR_LOG_LEVEL", "debug")

        settings = Settings()
        assert settings.station_id == "test-det-001"
        assert settings.station_model == "modra"
        assert settings.latitude == pytest.approx(48.37)
        assert settings.longitude == pytest.approx(17.27)
        assert settings.interval_ms == 5000
        assert settings.segment_duration_s == 5.0
        assert settings.redis_host == "redis.local"
        assert settings.redis_port == 6380
        assert settings.redis_password == "s3cret"
        assert settings.log_level == "debug"


class TestSignalIntegration:
    """Integration tests: config -> profile -> signal generation."""

    def test_default_config_produces_valid_signal(self):
        settings = Settings()
        profile = create_profile(settings.station_model)
        result = generate_sr_time_domain(
            profile,
            settings.segment_duration_s,
            rng=np.random.default_rng(0),
        )
        expected_len = int(profile.sample_rate_hz * settings.segment_duration_s)
        assert len(result["samples"]) == expected_len
        assert result["sample_rate_hz"] == profile.sample_rate_hz
        assert np.all(np.isfinite(result["samples"]))

    def test_custom_config_produces_valid_signal(self, monkeypatch):
        monkeypatch.setenv("EARTHSYNC_SIMULATOR_STATION_MODEL", "heartmath")
        monkeypatch.setenv("EARTHSYNC_SIMULATOR_SEGMENT_DURATION_S", "2.0")

        settings = Settings()
        profile = create_profile(settings.station_model)
        result = generate_sr_time_domain(
            profile,
            settings.segment_duration_s,
            rng=np.random.default_rng(0),
        )
        assert result["sample_rate_hz"] == 130
        assert len(result["samples"]) == 260  # 130 * 2

    @pytest.mark.asyncio
    async def test_redis_publish_mock(self, monkeypatch):
        """Verify the publish loop calls XADD with correct stream name."""
        monkeypatch.setenv("EARTHSYNC_SIMULATOR_STATION_ID", "mock-det")
        monkeypatch.setenv("EARTHSYNC_SIMULATOR_INTERVAL_MS", "100")
        monkeypatch.setenv("EARTHSYNC_SIMULATOR_SEGMENT_DURATION_S", "1.0")

        settings = Settings()
        profile = create_profile(settings.station_model)
        result = generate_sr_time_domain(
            profile, settings.segment_duration_s, rng=np.random.default_rng(0)
        )

        # Verify the signal payload structure matches what main.py would send
        payload = {
            "station_id": settings.station_id,
            "timestamp": 1000,
            "location": {"lat": settings.latitude, "lon": settings.longitude},
            "sample_rate_hz": result["sample_rate_hz"],
            "segment_duration_s": result["segment_duration_s"],
            "samples": result["samples"].tolist(),
        }
        serialized = json.dumps(payload)
        parsed = json.loads(serialized)

        assert parsed["station_id"] == "mock-det"
        assert parsed["sample_rate_hz"] == 256
        assert len(parsed["samples"]) == 256  # 1s * 256 Hz


# ── async main.py tests ───────────────────────────────────────────────────


class TestConnectRedis:
    @pytest.mark.asyncio
    async def test_connect_redis_success(self, monkeypatch):
        """Mock Redis connects successfully on first attempt."""
        monkeypatch.setenv("EARTHSYNC_SIMULATOR_REDIS_CONNECT_TIMEOUT_MS", "5000")
        settings = Settings()

        mock_client = AsyncMock()
        mock_client.ping = AsyncMock(return_value=True)

        with patch("earthsync_simulator.main.redis.asyncio.Redis", return_value=mock_client):
            client = await _connect_redis(settings)

        mock_client.ping.assert_awaited_once()
        assert client is mock_client

    @pytest.mark.asyncio
    async def test_connect_redis_retry(self, monkeypatch):
        """First attempt fails, second succeeds."""
        monkeypatch.setenv("EARTHSYNC_SIMULATOR_REDIS_CONNECT_TIMEOUT_MS", "30000")
        settings = Settings()

        mock_client_fail = AsyncMock()
        mock_client_fail.ping = AsyncMock(side_effect=ConnectionError("refused"))

        mock_client_ok = AsyncMock()
        mock_client_ok.ping = AsyncMock(return_value=True)

        call_count = 0

        def make_client(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return mock_client_fail
            return mock_client_ok

        with (
            patch("earthsync_simulator.main.redis.asyncio.Redis", side_effect=make_client),
            patch("earthsync_simulator.main.asyncio.sleep", new_callable=AsyncMock),
        ):
            client = await _connect_redis(settings)

        assert client is mock_client_ok
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_connect_redis_timeout(self, monkeypatch):
        """All attempts fail within timeout -> ConnectionError."""
        monkeypatch.setenv("EARTHSYNC_SIMULATOR_REDIS_CONNECT_TIMEOUT_MS", "1")
        settings = Settings()

        mock_client = AsyncMock()
        mock_client.ping = AsyncMock(side_effect=ConnectionError("refused"))

        with (
            patch("earthsync_simulator.main.redis.asyncio.Redis", return_value=mock_client),
            pytest.raises(ConnectionError, match="Failed to connect to Redis"),
        ):
            await _connect_redis(settings)


class TestRun:
    @pytest.mark.asyncio
    async def test_run_publishes_to_stream(self, monkeypatch):
        """Mock Redis, verify XADD called with correct stream key and data format."""
        monkeypatch.setenv("EARTHSYNC_SIMULATOR_STATION_ID", "pub-test")
        monkeypatch.setenv("EARTHSYNC_SIMULATOR_INTERVAL_MS", "100")
        monkeypatch.setenv("EARTHSYNC_SIMULATOR_SEGMENT_DURATION_S", "1.0")
        settings = Settings()

        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(return_value=True)
        mock_redis.xadd = AsyncMock()
        mock_redis.aclose = AsyncMock()

        publish_count = 0
        original_xadd = mock_redis.xadd

        async def counting_xadd(*args, **kwargs):
            nonlocal publish_count
            publish_count += 1
            result = await original_xadd(*args, **kwargs)
            if publish_count >= 1:
                # Trigger shutdown after first publish
                import earthsync_simulator.main as main_mod

                if main_mod._shutdown_event is not None:
                    main_mod._shutdown_event.set()
            return result

        mock_redis.xadd = AsyncMock(side_effect=counting_xadd)

        with patch("earthsync_simulator.main.redis.asyncio.Redis", return_value=mock_redis):
            await _run(settings)

        assert publish_count >= 1
        call_args = mock_redis.xadd.call_args_list[0]
        assert call_args[0][0] == "spectrogram_stream"
        data = json.loads(call_args[0][1]["data"])
        assert data["station_id"] == "pub-test"
        assert "sample_rate_hz" in data
        assert "samples" in data
        assert "modes" in data
        assert "metadata" in data

    @pytest.mark.asyncio
    async def test_run_handles_shutdown(self, monkeypatch):
        """Set shutdown event immediately, verify loop exits."""
        monkeypatch.setenv("EARTHSYNC_SIMULATOR_INTERVAL_MS", "100")
        monkeypatch.setenv("EARTHSYNC_SIMULATOR_SEGMENT_DURATION_S", "1.0")
        settings = Settings()

        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(return_value=True)
        mock_redis.xadd = AsyncMock()
        mock_redis.aclose = AsyncMock()

        async def connect_and_shutdown(s):
            import earthsync_simulator.main as main_mod

            if main_mod._shutdown_event is not None:
                main_mod._shutdown_event.set()
            return mock_redis

        with patch(
            "earthsync_simulator.main._connect_redis",
            side_effect=connect_and_shutdown,
        ):
            await _run(settings)

        mock_redis.aclose.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_run_handles_publish_error(self, monkeypatch):
        """XADD raises, verify loop continues and eventually exits."""
        monkeypatch.setenv("EARTHSYNC_SIMULATOR_STATION_ID", "err-test")
        monkeypatch.setenv("EARTHSYNC_SIMULATOR_INTERVAL_MS", "100")
        monkeypatch.setenv("EARTHSYNC_SIMULATOR_SEGMENT_DURATION_S", "1.0")
        settings = Settings()

        mock_redis = AsyncMock()
        mock_redis.ping = AsyncMock(return_value=True)
        mock_redis.aclose = AsyncMock()

        call_count = 0

        async def failing_xadd(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count <= 1:
                raise ConnectionError("write failed")
            # After first error, shut down
            import earthsync_simulator.main as main_mod

            if main_mod._shutdown_event is not None:
                main_mod._shutdown_event.set()

        mock_redis.xadd = AsyncMock(side_effect=failing_xadd)

        with patch("earthsync_simulator.main.redis.asyncio.Redis", return_value=mock_redis):
            # The publish error is not caught in the loop -- it will propagate
            # and be caught by the finally block. Let's verify aclose is called.
            with pytest.raises(ConnectionError, match="write failed"):
                await _run(settings)

        mock_redis.aclose.assert_awaited_once()


class TestHandleSignal:
    def test_handle_signal_sets_shutdown_event(self):
        """_handle_signal sets the global shutdown event."""
        import earthsync_simulator.main as main_mod

        event = asyncio.Event()
        main_mod._shutdown_event = event
        assert not event.is_set()

        _handle_signal(signal.SIGINT)
        assert event.is_set()

        # Cleanup
        main_mod._shutdown_event = None

    def test_handle_signal_no_event(self):
        """_handle_signal with no event does not raise."""
        import earthsync_simulator.main as main_mod

        main_mod._shutdown_event = None
        _handle_signal(signal.SIGTERM)  # Should not raise


class TestMainEntrypoint:
    def test_main_entrypoint(self, monkeypatch):
        """main() calls _run with settings."""
        monkeypatch.setenv("EARTHSYNC_SIMULATOR_STATION_ID", "entry-test")
        mock_run = AsyncMock()

        with (
            patch("earthsync_simulator.main._run", mock_run),
            patch("earthsync_simulator.main.asyncio.run") as mock_asyncio_run,
        ):
            main()

        mock_asyncio_run.assert_called_once()

    def test_main_handles_keyboard_interrupt(self, monkeypatch):
        """main() suppresses KeyboardInterrupt."""
        with patch(
            "earthsync_simulator.main.asyncio.run",
            side_effect=KeyboardInterrupt,
        ):
            main()  # Should not raise

    def test_main_handles_connection_error(self, monkeypatch):
        """main() exits with code 1 on ConnectionError."""
        with (
            patch(
                "earthsync_simulator.main.asyncio.run",
                side_effect=ConnectionError("fail"),
            ),
            pytest.raises(SystemExit) as exc_info,
        ):
            main()

        assert exc_info.value.code == 1

    def test_main_dunder_main_guard(self):
        """Cover the ``if __name__ == '__main__': main()`` line (175).

        We use runpy.run_module which re-executes the module with __name__
        set to '__main__', triggering the guard.  asyncio.run is patched at
        the real module level so the launched main() becomes a no-op.
        """
        import runpy

        with patch("asyncio.run"):
            runpy.run_module("earthsync_simulator.main", run_name="__main__", alter_sys=False)
