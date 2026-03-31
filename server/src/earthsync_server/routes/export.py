"""Data export endpoints."""

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import PlainTextResponse, Response

from earthsync_server.middleware.auth import require_jwt
from earthsync_server.middleware.rate_limiter import export_limiter
from earthsync_server.services.export_formats import (
    export_peaks_csv,
    export_peaks_json,
    export_spectra_csv,
)

router = APIRouter()


@router.get("/peaks")
async def export_peaks(
    request: Request,
    _claims: dict = Depends(require_jwt),  # noqa: B008
    station: str | None = Query(default=None),
    from_time: str | None = Query(default=None, alias="from"),
    to_time: str | None = Query(default=None, alias="to"),
    fmt: str | None = Query(default=None, alias="format"),
) -> Response:
    """Export peak data in requested format (json or csv)."""
    export_limiter.check(request)
    _ = (from_time, to_time)  # reserved for future filtering
    store = request.app.state.store
    peaks = await store.get_peaks(station_id=station)

    if fmt == "csv":
        csv_content = export_peaks_csv(peaks)
        return PlainTextResponse(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="peaks.csv"'},
        )

    json_content = export_peaks_json(peaks)
    return PlainTextResponse(
        content=json_content,
        media_type="application/json",
    )


@router.get("/spectra")
async def export_spectra(
    request: Request,
    _claims: dict = Depends(require_jwt),  # noqa: B008
    fmt: str | None = Query(default=None, alias="format"),
) -> Response:
    """Export spectral data in requested format (json or csv)."""
    export_limiter.check(request)
    store = request.app.state.store
    spectrograms = await store.get_spectrograms()

    if fmt == "csv":
        csv_content = export_spectra_csv(spectrograms)
        return PlainTextResponse(
            content=csv_content,
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="spectra.csv"'},
        )

    json_content = export_peaks_json(spectrograms)
    return PlainTextResponse(
        content=json_content,
        media_type="application/json",
    )
