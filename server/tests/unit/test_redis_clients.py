"""Tests for earthsync_server.redis.clients — Redis client management."""

from unittest.mock import AsyncMock, patch

import pytest
from earthsync_server.redis.clients import (
    close_redis_clients,
    create_redis_client,
    create_redis_clients,
)


@pytest.fixture
def mock_redis():
    client = AsyncMock()
    client.ping = AsyncMock(return_value=True)
    client.aclose = AsyncMock()
    return client


class TestCreateRedisClient:
    async def test_creates_client_and_pings(self, mock_redis):
        with patch("earthsync_server.redis.clients.aioredis.Redis", return_value=mock_redis):
            result = await create_redis_client("localhost", 6379)
            mock_redis.ping.assert_awaited_once()
            assert result is mock_redis

    async def test_creates_client_with_password(self, mock_redis):
        with patch("earthsync_server.redis.clients.aioredis.Redis", return_value=mock_redis) as m:
            await create_redis_client("localhost", 6379, password="secret")
            m.assert_called_once_with(
                host="localhost",
                port=6379,
                password="secret",
                decode_responses=True,
                socket_connect_timeout=5.0,
            )

    async def test_creates_client_without_password(self, mock_redis):
        with patch("earthsync_server.redis.clients.aioredis.Redis", return_value=mock_redis) as m:
            await create_redis_client("localhost", 6379, password=None)
            m.assert_called_once_with(
                host="localhost",
                port=6379,
                password=None,
                decode_responses=True,
                socket_connect_timeout=5.0,
            )

    async def test_empty_string_password_treated_as_none(self, mock_redis):
        with patch("earthsync_server.redis.clients.aioredis.Redis", return_value=mock_redis) as m:
            await create_redis_client("localhost", 6379, password="")
            m.assert_called_once_with(
                host="localhost",
                port=6379,
                password=None,
                decode_responses=True,
                socket_connect_timeout=5.0,
            )

    async def test_creates_client_with_key_prefix(self, mock_redis):
        with patch("earthsync_server.redis.clients.aioredis.Redis", return_value=mock_redis):
            with patch("earthsync_server.redis.clients.logger") as mock_logger:
                await create_redis_client("localhost", 6379, key_prefix="test")
                mock_logger.info.assert_called_once_with(
                    "redis_connected", host="localhost", port=6379, prefix="test"
                )

    async def test_ping_failure_raises(self):
        client = AsyncMock()
        client.ping = AsyncMock(side_effect=ConnectionError("Connection refused"))
        with patch("earthsync_server.redis.clients.aioredis.Redis", return_value=client):
            with pytest.raises(ConnectionError, match="Connection refused"):
                await create_redis_client("localhost", 6379)


class TestCreateRedisClients:
    async def test_creates_two_clients(self):
        clients = []
        for _ in range(2):
            c = AsyncMock()
            c.ping = AsyncMock(return_value=True)
            clients.append(c)

        with patch("earthsync_server.redis.clients.aioredis.Redis", side_effect=clients):
            main, stream = await create_redis_clients("localhost", 6379)
            assert main is clients[0]
            assert stream is clients[1]

    async def test_passes_password_to_both(self):
        clients = []
        for _ in range(2):
            c = AsyncMock()
            c.ping = AsyncMock(return_value=True)
            clients.append(c)

        with patch("earthsync_server.redis.clients.aioredis.Redis", side_effect=clients) as m:
            await create_redis_clients("redis.local", 6380, password="pw")
            assert m.call_count == 2
            for c in m.call_args_list:
                assert c.kwargs["password"] == "pw"
                assert c.kwargs["host"] == "redis.local"
                assert c.kwargs["port"] == 6380


class TestCloseRedisClients:
    async def test_closes_single_client(self, mock_redis):
        await close_redis_clients(mock_redis)
        mock_redis.aclose.assert_awaited_once()

    async def test_closes_multiple_clients(self):
        c1, c2, c3 = AsyncMock(), AsyncMock(), AsyncMock()
        c1.aclose, c2.aclose, c3.aclose = AsyncMock(), AsyncMock(), AsyncMock()
        await close_redis_clients(c1, c2, c3)
        c1.aclose.assert_awaited_once()
        c2.aclose.assert_awaited_once()
        c3.aclose.assert_awaited_once()

    async def test_closes_zero_clients(self):
        with patch("earthsync_server.redis.clients.logger") as mock_logger:
            await close_redis_clients()
            mock_logger.info.assert_called_once_with("redis_clients_closed", count=0)

    async def test_logs_correct_count(self, mock_redis):
        c2 = AsyncMock()
        c2.aclose = AsyncMock()
        with patch("earthsync_server.redis.clients.logger") as mock_logger:
            await close_redis_clients(mock_redis, c2)
            mock_logger.info.assert_called_once_with("redis_clients_closed", count=2)
