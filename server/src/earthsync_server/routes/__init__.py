"""Route registration."""

from fastapi import FastAPI

from earthsync_server.routes import auth, calibration, export, health, history, ingest, public


def register_routes(app: FastAPI) -> None:
    """Register all route handlers."""
    app.include_router(health.router, tags=["health"])
    app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
    app.include_router(ingest.router, tags=["ingest"])
    app.include_router(history.router, prefix="/api/history", tags=["history"])
    app.include_router(calibration.router, prefix="/api/stations", tags=["calibration"])
    app.include_router(export.router, prefix="/api/export", tags=["export"])
    app.include_router(public.router, prefix="/api/public", tags=["public"])
