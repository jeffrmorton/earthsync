"""Authentication dependencies for FastAPI route handlers."""

from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from jwt import DecodeError, ExpiredSignatureError, decode

from earthsync_server.config import Settings, get_settings


async def require_jwt(
    authorization: Annotated[str, Header()],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict:
    """Validate JWT Bearer token and return decoded payload.

    Raises 401 on missing/invalid/expired token.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header",
        )
    token = authorization.removeprefix("Bearer ")
    try:
        return decode(token, settings.jwt_secret, algorithms=["HS256"])
    except ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
        ) from exc
    except DecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        ) from exc


async def require_api_key(
    x_api_key: Annotated[str, Header()],
    settings: Annotated[Settings, Depends(get_settings)],
) -> str:
    """Validate X-API-Key header against configured ingest key.

    Raises 403 on mismatch, 422 on missing header.
    """
    if x_api_key != settings.api_ingest_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key",
        )
    return x_api_key
