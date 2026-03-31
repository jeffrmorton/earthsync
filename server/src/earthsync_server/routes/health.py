"""Health check and metrics endpoints."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
async def health_check() -> dict:
    """Health check -- returns server status."""
    return {"status": "ok", "version": "0.1.1"}
