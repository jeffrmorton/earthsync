"""Redis client management -- two async clients for different purposes."""

from __future__ import annotations

import redis.asyncio as aioredis
import structlog

logger = structlog.get_logger()


async def create_redis_client(
    host: str,
    port: int,
    password: str | None = None,
    key_prefix: str | None = None,
) -> aioredis.Redis:
    """Create an async Redis client."""
    client = aioredis.Redis(
        host=host,
        port=port,
        password=password or None,
        decode_responses=True,
        socket_connect_timeout=5.0,
    )
    await client.ping()  # type: ignore[misc]  # redis-py async stubs
    logger.info("redis_connected", host=host, port=port, prefix=key_prefix)
    return client


async def create_redis_clients(
    host: str,
    port: int,
    password: str | None = None,
) -> tuple[aioredis.Redis, aioredis.Redis]:
    """Create main + stream Redis clients.

    Main client: used for encryption keys, general operations.
    Stream client: used for XREADGROUP consumer, history lists, peak sorted sets.
    """
    main = await create_redis_client(host, port, password, key_prefix="main")
    stream = await create_redis_client(host, port, password, key_prefix="stream")
    return main, stream


async def close_redis_clients(*clients: aioredis.Redis) -> None:
    """Close one or more Redis clients."""
    for client in clients:
        await client.aclose()
    logger.info("redis_clients_closed", count=len(clients))
