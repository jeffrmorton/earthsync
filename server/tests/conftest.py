"""Shared test fixtures."""

import os

import pytest
from httpx import ASGITransport, AsyncClient

# Set required env vars before importing anything that triggers Settings.
os.environ.setdefault("EARTHSYNC_JWT_SECRET", "test-jwt-secret-key")
os.environ.setdefault("EARTHSYNC_API_INGEST_KEY", "test-api-ingest-key")
os.environ.setdefault("EARTHSYNC_DB_PASSWORD", "test-db-password")

from earthsync_server.app import create_app
from earthsync_server.db.store import MemoryStore


@pytest.fixture
def app():
    application = create_app()
    application.state.store = MemoryStore()
    return application


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture(autouse=True)
def _clear_store(app):
    """Clear the MemoryStore between tests.

    MemoryStore.clear() is async but its internals are plain dict ops.
    We call the sync internals directly to avoid needing an event loop
    in this synchronous autouse fixture.
    """
    store = app.state.store
    store._users.clear()
    store._spectrograms.clear()
    store._peaks.clear()
    store._calibrations.clear()
    store._quality.clear()
    store._qbursts.clear()
    store._cross_validations.clear()
    yield
    store._users.clear()
    store._spectrograms.clear()
    store._peaks.clear()
    store._calibrations.clear()
    store._quality.clear()
    store._qbursts.clear()
    store._cross_validations.clear()
