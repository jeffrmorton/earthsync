"""AuthService -- JWT token creation and verification for services."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
import structlog
from fastapi import HTTPException

logger = structlog.get_logger()


class AuthService:
    """JWT token creation and verification.

    Used by background services and WebSocket handlers that need
    to create or verify tokens outside of FastAPI dependency injection.
    """

    def __init__(self, jwt_secret: str, jwt_expiration_hours: int = 1):
        self._secret = jwt_secret
        self._expiration_hours = jwt_expiration_hours

    def create_token(self, username: str) -> tuple[str, int]:
        """Create a JWT token. Returns (token, expires_in_seconds)."""
        expires = datetime.now(UTC) + timedelta(hours=self._expiration_hours)
        payload = {"sub": username, "exp": expires}
        token = jwt.encode(payload, self._secret, algorithm="HS256")
        return token, self._expiration_hours * 3600

    def verify_token(self, token: str) -> str:
        """Verify JWT token and return username. Raises HTTPException on failure."""
        try:
            payload = jwt.decode(token, self._secret, algorithms=["HS256"])
            username = payload.get("sub")
            if username is None:
                raise HTTPException(status_code=401, detail="Invalid token: no subject")
        except jwt.ExpiredSignatureError as exc:
            raise HTTPException(status_code=401, detail="Token expired") from exc
        except jwt.InvalidTokenError as exc:
            raise HTTPException(status_code=401, detail="Invalid token") from exc
        else:
            return username
