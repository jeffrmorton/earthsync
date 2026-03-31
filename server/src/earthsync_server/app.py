"""FastAPI application factory."""

import asyncio
import contextlib
import json
import time
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
import structlog
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from earthsync_server.config import get_settings
from earthsync_server.db.pool import close_pool, create_pool
from earthsync_server.db.schema import initialize_schema
from earthsync_server.db.store import DatabaseStore, MemoryStore
from earthsync_server.models import DetectedPeak
from earthsync_server.routes import register_routes
from earthsync_server.services.archiver import Archiver
from earthsync_server.services.cross_validator import CrossValidator
from earthsync_server.services.stream_processor import StreamProcessor

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: PLR0915
    """Manage application lifecycle: DB pool, Redis, and stream consumer."""
    settings = get_settings()

    # Create asyncpg pool and initialize schema
    pool = await create_pool(
        host=settings.db_host,
        port=settings.db_port,
        user=settings.db_user,
        password=settings.db_password,
        database=settings.db_name,
    )
    await initialize_schema(pool)
    app.state.store = DatabaseStore(pool)
    app.state.db_pool = pool

    # Connect to Redis
    redis_client = aioredis.Redis(
        host=settings.redis_host,
        port=settings.redis_port,
        password=settings.redis_password or None,
        decode_responses=True,
    )
    await redis_client.ping()  # type: ignore[misc]  # redis-py async stubs
    logger.info("redis_connected", host=settings.redis_host, port=settings.redis_port)
    app.state.redis = redis_client
    app.state.ws_clients: set[WebSocket] = set()

    # Create consumer group (idempotent)
    with contextlib.suppress(Exception):
        await redis_client.xgroup_create(
            "spectrogram_stream", "earthsync_group", id="0", mkstream=True
        )
        logger.info("consumer_group_created", group="earthsync_group")

    # Start stream consumer background task
    processor = StreamProcessor(settings)

    async def consume_stream():
        while True:
            try:
                messages = await redis_client.xreadgroup(
                    "earthsync_group",
                    "server-1",
                    {"spectrogram_stream": ">"},
                    count=10,
                    block=3000,
                )
                for _stream_name, entries in messages:
                    for msg_id, fields in entries:
                        try:
                            data = json.loads(fields.get("data", "{}"))
                            result = processor.process_segment(data)
                            if result:
                                # Store in DataStore
                                store = app.state.store
                                record = {
                                    "station_id": result.station_id,
                                    "timestamp_ms": int(time.time() * 1000),
                                    "location": {
                                        "lat": result.location.lat,
                                        "lon": result.location.lon,
                                    },
                                    "spectrogram": result.spectrogram,
                                    "peaks": [p.model_dump() for p in result.detected_peaks],
                                    "algorithm_version": result.algorithm_version,
                                }
                                await store.add_spectrogram(result.station_id, record)
                                if result.detected_peaks:
                                    await store.add_peaks(
                                        result.station_id,
                                        record["timestamp_ms"],
                                        [p.model_dump() for p in result.detected_peaks],
                                    )

                                # Broadcast to WebSocket clients
                                payload_json = result.model_dump_json()
                                dead: set[WebSocket] = set()
                                for ws in app.state.ws_clients:
                                    try:
                                        await ws.send_text(payload_json)
                                    except Exception:
                                        dead.add(ws)
                                app.state.ws_clients -= dead

                                logger.debug(
                                    "segment_processed",
                                    station_id=result.station_id,
                                    peaks=len(result.detected_peaks),
                                    ws_clients=len(app.state.ws_clients),
                                )

                            await redis_client.xack("spectrogram_stream", "earthsync_group", msg_id)
                        except Exception:
                            logger.exception("process_error", msg_id=msg_id)
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("stream_consumer_error")
                await asyncio.sleep(1)

    task = asyncio.create_task(consume_stream())
    logger.info("stream_consumer_started")

    # Start archiver background task
    archiver = Archiver(
        store=app.state.store,
        retention_hours_spec=settings.redis_spec_retention_hours,
        retention_hours_peak=settings.redis_peak_retention_hours,
    )

    cross_validator = CrossValidator()

    async def run_archiver():
        while True:
            try:
                await asyncio.sleep(settings.cleanup_interval_s)
                trimmed = await archiver.archive_cycle()
                if trimmed > 0:
                    logger.info("archiver_trimmed", count=trimmed)
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("archiver_error")

    async def run_cross_validator():
        while True:
            try:
                await asyncio.sleep(settings.cross_validation_interval_s)
                # Cross-validate peaks from all stations
                for station_id, state in processor.tracked_stations.items():
                    if state:
                        peaks = [DetectedPeak(freq=s["freq"], amp=s["amp"]) for s in state]
                        result = cross_validator.validate_peaks(peaks)
                        await app.state.store.store_cross_validation(station_id, result)
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("cross_validator_error")

    archiver_task = asyncio.create_task(run_archiver())
    cross_validator_task = asyncio.create_task(run_cross_validator())
    logger.info("background_services_started")

    yield

    # Shutdown
    task.cancel()
    archiver_task.cancel()
    cross_validator_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    with contextlib.suppress(asyncio.CancelledError):
        await archiver_task
    with contextlib.suppress(asyncio.CancelledError):
        await cross_validator_task
    await redis_client.aclose()
    await close_pool(pool)
    logger.info("shutdown_complete")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="EarthSync Server",
        version="0.1.1",
        description="Schumann Resonance processing and visualization server",
        lifespan=lifespan,
    )
    app.state.store = MemoryStore()
    app.state.ws_clients = set()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    register_routes(app)

    @app.websocket("/ws/data")
    async def ws_data(websocket: WebSocket):
        # Optional auth: check query param ?token=<JWT>
        token = websocket.query_params.get("token")
        if token:
            try:
                from jwt import DecodeError, ExpiredSignatureError  # noqa: PLC0415
                from jwt import decode as jwt_decode  # noqa: PLC0415

                settings = get_settings()
                jwt_decode(token, settings.jwt_secret, algorithms=["HS256"])
            except (ExpiredSignatureError, DecodeError):
                await websocket.close(code=4001, reason="Invalid token")
                return
        # If no token provided, allow anonymous (backward compatible)
        await websocket.accept()
        app.state.ws_clients.add(websocket)
        logger.info("ws_client_connected", total=len(app.state.ws_clients))
        try:
            while True:
                await websocket.receive_text()  # Keep connection alive
        except WebSocketDisconnect:
            pass
        finally:
            app.state.ws_clients.discard(websocket)
            logger.info("ws_client_disconnected", total=len(app.state.ws_clients))

    return app
