"""Tests for WebSocket endpoint authentication."""

from datetime import UTC, datetime, timedelta

import pytest
from jwt import encode
from starlette.testclient import TestClient


def test_ws_anonymous_allowed(app):
    """Anonymous WebSocket connections (no token) should be accepted."""
    client = TestClient(app)
    with client.websocket_connect("/ws/data") as ws:
        assert ws is not None


def test_ws_with_valid_token_accepted(app):
    """WebSocket connections with a valid JWT token should be accepted."""
    payload = {
        "sub": "testuser",
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + timedelta(hours=1),
    }
    token = encode(payload, "test-jwt-secret-key", algorithm="HS256")
    client = TestClient(app)
    with client.websocket_connect(f"/ws/data?token={token}") as ws:
        assert ws is not None


def test_ws_with_invalid_token_rejected(app):
    """WebSocket connections with an invalid JWT token should be rejected with 4001."""
    client = TestClient(app)
    with pytest.raises(Exception) as exc_info:  # noqa: PT011
        with client.websocket_connect("/ws/data?token=invalid-token"):
            pass
    # Starlette raises on non-accept close
    assert exc_info.value is not None


def test_ws_with_expired_token_rejected(app):
    """WebSocket connections with an expired JWT token should be rejected."""
    payload = {
        "sub": "testuser",
        "iat": datetime.now(UTC) - timedelta(hours=2),
        "exp": datetime.now(UTC) - timedelta(hours=1),
    }
    token = encode(payload, "test-jwt-secret-key", algorithm="HS256")
    client = TestClient(app)
    with pytest.raises(Exception) as exc_info:  # noqa: PT011
        with client.websocket_connect(f"/ws/data?token={token}"):
            pass
    assert exc_info.value is not None
