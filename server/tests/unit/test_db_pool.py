"""Tests for earthsync_server.db.pool — asyncpg connection pool management."""

from unittest.mock import AsyncMock, patch

import pytest
from earthsync_server.db.pool import close_pool, create_pool


@pytest.fixture
def mock_pool():
    pool = AsyncMock()
    pool.close = AsyncMock()
    return pool


class TestCreatePool:
    async def test_creates_pool_with_correct_params(self, mock_pool):
        with patch("earthsync_server.db.pool.asyncpg.create_pool", new_callable=AsyncMock) as m:
            m.return_value = mock_pool
            result = await create_pool(
                host="db.local",
                port=5432,
                user="testuser",
                password="testpass",
                database="testdb",
            )
            m.assert_awaited_once_with(
                host="db.local",
                port=5432,
                user="testuser",
                password="testpass",
                database="testdb",
                min_size=2,
                max_size=20,
                command_timeout=30,
            )
            assert result is mock_pool

    async def test_creates_pool_with_custom_sizes(self, mock_pool):
        with patch("earthsync_server.db.pool.asyncpg.create_pool", new_callable=AsyncMock) as m:
            m.return_value = mock_pool
            await create_pool(
                host="localhost",
                port=5432,
                user="u",
                password="p",
                database="d",
                min_size=5,
                max_size=50,
            )
            m.assert_awaited_once_with(
                host="localhost",
                port=5432,
                user="u",
                password="p",
                database="d",
                min_size=5,
                max_size=50,
                command_timeout=30,
            )

    async def test_returns_pool_object(self, mock_pool):
        with patch("earthsync_server.db.pool.asyncpg.create_pool", new_callable=AsyncMock) as m:
            m.return_value = mock_pool
            result = await create_pool("h", 5432, "u", "p", "d")
            assert result is mock_pool


class TestClosePool:
    async def test_close_pool_calls_close(self, mock_pool):
        await close_pool(mock_pool)
        mock_pool.close.assert_awaited_once()

    async def test_close_pool_completes(self, mock_pool):
        """Verify close_pool returns without error."""
        result = await close_pool(mock_pool)
        assert result is None
