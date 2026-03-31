"""Entry point — Redis publish loop for synthetic SR signals."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import signal
import sys
import time

import numpy as np
import redis.asyncio
import structlog

from earthsync_simulator.config import Settings
from earthsync_simulator.profiles import create_profile
from earthsync_simulator.signal_generator import generate_sr_time_domain

logger = structlog.get_logger()

# Global shutdown event
_shutdown_event: asyncio.Event | None = None


def _handle_signal(sig: int) -> None:
    """Request graceful shutdown."""
    logger.info("shutdown_signal_received", signal=sig)
    if _shutdown_event is not None:
        _shutdown_event.set()


async def _connect_redis(settings: Settings) -> redis.asyncio.Redis:
    """Connect to Redis with retry logic."""
    timeout_s = settings.redis_connect_timeout_ms / 1000.0
    deadline = time.monotonic() + timeout_s
    attempt = 0

    while True:
        attempt += 1
        try:
            client = redis.asyncio.Redis(
                host=settings.redis_host,
                port=settings.redis_port,
                password=settings.redis_password or None,
                decode_responses=True,
                socket_connect_timeout=5.0,
            )
            await client.ping()  # type: ignore[misc]  # redis-py async stubs
            logger.info(
                "redis_connected",
                host=settings.redis_host,
                port=settings.redis_port,
                attempt=attempt,
            )
            return client  # noqa: TRY300
        except Exception as exc:
            if time.monotonic() >= deadline:
                raise ConnectionError(
                    f"Failed to connect to Redis after {attempt} attempts"
                ) from exc
            wait = min(2.0**attempt, 10.0)
            logger.warning(
                "redis_connect_retry",
                attempt=attempt,
                wait_s=wait,
                error=str(exc),
            )
            await asyncio.sleep(wait)


async def _run(settings: Settings) -> None:
    """Main publish loop."""
    global _shutdown_event  # noqa: PLW0603
    _shutdown_event = asyncio.Event()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _handle_signal, sig)

    profile = create_profile(settings.station_model)
    logger.info(
        "simulator_starting",
        station_id=settings.station_id,
        model=settings.station_model,
        sample_rate_hz=profile.sample_rate_hz,
        interval_ms=settings.interval_ms,
        segment_duration_s=settings.segment_duration_s,
    )

    redis = await _connect_redis(settings)

    diurnal_phase = 0.0
    phase_increment = settings.interval_ms / 86_400_000.0
    rng = np.random.default_rng()

    try:
        while not _shutdown_event.is_set():
            result = generate_sr_time_domain(
                profile,
                settings.segment_duration_s,
                diurnal_phase=diurnal_phase,
                rng=rng,
            )

            payload = {
                "station_id": settings.station_id,
                "timestamp": int(time.time() * 1000),
                "location": {
                    "lat": settings.latitude,
                    "lon": settings.longitude,
                },
                "sample_rate_hz": result["sample_rate_hz"],
                "segment_duration_s": result["segment_duration_s"],
                "samples": result["samples"].tolist(),
                "metadata": {k: v for k, v in result["metadata"].items() if k != "modes"},
                "modes": result["metadata"]["modes"],
            }

            await redis.xadd(
                "spectrogram_stream",
                {"data": json.dumps(payload)},
            )

            logger.info(
                "signal_published",
                station_id=settings.station_id,
                diurnal_phase=round(diurnal_phase, 4),
                qburst=result["metadata"]["qburst_injected"],
                n_samples=len(result["samples"]),
            )

            diurnal_phase = (diurnal_phase + phase_increment) % 1.0

            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(
                    _shutdown_event.wait(),
                    timeout=settings.interval_ms / 1000.0,
                )

    finally:
        await redis.aclose()
        logger.info("simulator_stopped", station_id=settings.station_id)


def main() -> None:
    """CLI entry point."""
    settings = Settings()
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(
                logging,
                settings.log_level.upper(),
                logging.INFO,
            )
        ),
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.dev.ConsoleRenderer(),
        ],
    )

    try:
        asyncio.run(_run(settings))
    except KeyboardInterrupt:
        pass
    except ConnectionError:
        logger.exception("fatal_connection_error")
        sys.exit(1)


if __name__ == "__main__":
    main()
