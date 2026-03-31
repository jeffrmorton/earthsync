"""Tests for earthsync_server.middleware.auth and auth_service."""

import time
from unittest.mock import MagicMock

import jwt
import pytest
from earthsync_server.middleware.auth import require_api_key, require_jwt
from earthsync_server.middleware.auth_service import AuthService
from fastapi import HTTPException

SECRET = "test-secret-key-for-jwt-testing"


# ---- AuthService tests ----


@pytest.fixture
def auth_service():
    return AuthService(jwt_secret=SECRET, jwt_expiration_hours=1)


class TestAuthServiceCreateToken:
    def test_returns_tuple_of_token_and_expiry(self, auth_service):
        token, expires_in = auth_service.create_token("alice")
        assert isinstance(token, str)
        assert isinstance(expires_in, int)

    def test_expiry_matches_hours(self):
        service = AuthService(jwt_secret=SECRET, jwt_expiration_hours=2)
        _, expires_in = service.create_token("bob")
        assert expires_in == 7200

    def test_default_expiry_one_hour(self):
        service = AuthService(jwt_secret=SECRET)
        _, expires_in = service.create_token("charlie")
        assert expires_in == 3600

    def test_token_contains_subject(self, auth_service):
        token, _ = auth_service.create_token("alice")
        payload = jwt.decode(token, SECRET, algorithms=["HS256"])
        assert payload["sub"] == "alice"

    def test_token_contains_expiration(self, auth_service):
        token, _ = auth_service.create_token("alice")
        payload = jwt.decode(token, SECRET, algorithms=["HS256"])
        assert "exp" in payload

    def test_different_users_get_different_tokens(self, auth_service):
        t1, _ = auth_service.create_token("alice")
        t2, _ = auth_service.create_token("bob")
        assert t1 != t2


class TestAuthServiceVerifyToken:
    def test_valid_token_returns_username(self, auth_service):
        token, _ = auth_service.create_token("alice")
        username = auth_service.verify_token(token)
        assert username == "alice"

    def test_expired_token_raises_401(self):
        service = AuthService(jwt_secret=SECRET, jwt_expiration_hours=0)
        payload = {"sub": "alice", "exp": int(time.time()) - 10}
        token = jwt.encode(payload, SECRET, algorithm="HS256")
        with pytest.raises(HTTPException) as exc_info:
            service.verify_token(token)
        assert exc_info.value.status_code == 401
        assert "expired" in exc_info.value.detail.lower()

    def test_invalid_token_raises_401(self, auth_service):
        with pytest.raises(HTTPException) as exc_info:
            auth_service.verify_token("not-a-valid-token")
        assert exc_info.value.status_code == 401
        assert "Invalid token" in exc_info.value.detail

    def test_wrong_secret_raises_401(self, auth_service):
        wrong = "a-definitely-wrong-secret-key-thats-long-enough"
        token = jwt.encode({"sub": "alice", "exp": int(time.time()) + 3600}, wrong)
        with pytest.raises(HTTPException) as exc_info:
            auth_service.verify_token(token)
        assert exc_info.value.status_code == 401

    def test_token_without_subject_raises_401(self, auth_service):
        token = jwt.encode({"exp": int(time.time()) + 3600}, SECRET)
        with pytest.raises(HTTPException) as exc_info:
            auth_service.verify_token(token)
        assert exc_info.value.status_code == 401
        assert "no subject" in exc_info.value.detail.lower()


# ---- FastAPI dependency function tests ----


@pytest.fixture
def mock_settings():
    settings = MagicMock()
    settings.jwt_secret = SECRET
    settings.api_ingest_key = "my-ingest-key"
    return settings


class TestRequireJwtDependency:
    async def test_valid_bearer_token(self, mock_settings):
        payload = {"sub": "alice", "exp": int(time.time()) + 3600}
        token = jwt.encode(payload, SECRET, algorithm="HS256")
        result = await require_jwt(authorization=f"Bearer {token}", settings=mock_settings)
        assert result["sub"] == "alice"

    async def test_missing_bearer_prefix_raises_401(self, mock_settings):
        with pytest.raises(HTTPException) as exc_info:
            await require_jwt(authorization="Token abc123", settings=mock_settings)
        assert exc_info.value.status_code == 401
        assert "authorization header" in exc_info.value.detail.lower()

    async def test_empty_authorization_raises_401(self, mock_settings):
        with pytest.raises(HTTPException) as exc_info:
            await require_jwt(authorization="", settings=mock_settings)
        assert exc_info.value.status_code == 401

    async def test_expired_token_raises_401(self, mock_settings):
        payload = {"sub": "alice", "exp": int(time.time()) - 10}
        token = jwt.encode(payload, SECRET, algorithm="HS256")
        with pytest.raises(HTTPException) as exc_info:
            await require_jwt(authorization=f"Bearer {token}", settings=mock_settings)
        assert exc_info.value.status_code == 401
        assert "expired" in exc_info.value.detail.lower()

    async def test_invalid_token_raises_401(self, mock_settings):
        with pytest.raises(HTTPException) as exc_info:
            await require_jwt(authorization="Bearer garbage-token", settings=mock_settings)
        assert exc_info.value.status_code == 401
        assert "Invalid token" in exc_info.value.detail


class TestRequireApiKeyDependency:
    async def test_valid_api_key(self, mock_settings):
        result = await require_api_key(x_api_key="my-ingest-key", settings=mock_settings)
        assert result == "my-ingest-key"

    async def test_wrong_api_key_raises_403(self, mock_settings):
        with pytest.raises(HTTPException) as exc_info:
            await require_api_key(x_api_key="wrong-key", settings=mock_settings)
        assert exc_info.value.status_code == 403
        assert "Invalid API key" in exc_info.value.detail

    async def test_empty_api_key_raises_403(self, mock_settings):
        with pytest.raises(HTTPException) as exc_info:
            await require_api_key(x_api_key="", settings=mock_settings)
        assert exc_info.value.status_code == 403
