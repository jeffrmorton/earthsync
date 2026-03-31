"""PostgreSQL connection pool management via asyncpg."""

from __future__ import annotations

import asyncpg
import structlog

logger = structlog.get_logger()


async def create_pool(  # noqa: PLR0913
    host: str,
    port: int,
    user: str,
    password: str,
    database: str,
    min_size: int = 2,
    max_size: int = 20,
) -> asyncpg.Pool:
    """Create and return an asyncpg connection pool."""
    pool = await asyncpg.create_pool(
        host=host,
        port=port,
        user=user,
        password=password,
        database=database,
        min_size=min_size,
        max_size=max_size,
        command_timeout=30,
    )
    logger.info("db_pool_created", host=host, database=database)
    return pool


async def close_pool(pool: asyncpg.Pool) -> None:
    """Close the connection pool."""
    await pool.close()
    logger.info("db_pool_closed")
