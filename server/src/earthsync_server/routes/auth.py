"""Authentication endpoints -- registration and login."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from jwt import encode
from pwdlib import PasswordHash

from earthsync_server.config import Settings, get_settings
from earthsync_server.middleware.rate_limiter import auth_limiter
from earthsync_server.models import LoginResponse, RegisterRequest

router = APIRouter()

ph = PasswordHash.recommended()


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    body: RegisterRequest,
    request: Request,
) -> dict:
    """Register a new user."""
    auth_limiter.check(request)
    store = request.app.state.store
    hashed = ph.hash(body.password)
    if not await store.create_user(body.username, hashed):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already taken",
        )
    return {"username": body.username}


@router.post("/login")
async def login(
    body: RegisterRequest,
    request: Request,
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> LoginResponse:
    """Authenticate user and return JWT token."""
    auth_limiter.check(request)
    store = request.app.state.store
    hashed = await store.get_user(body.username)
    if hashed is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    if not ph.verify(body.password, hashed):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    now = datetime.now(UTC)
    payload = {
        "sub": body.username,
        "iat": now,
        "exp": now + timedelta(hours=settings.jwt_expiration_hours),
    }
    token = encode(payload, settings.jwt_secret, algorithm="HS256")
    return LoginResponse(
        token=token,
        expires_in=settings.jwt_expiration_hours * 3600,
    )
