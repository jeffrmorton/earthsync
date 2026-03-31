"""EarthSync Server entry point."""

import uvicorn

from earthsync_server.app import create_app
from earthsync_server.config import get_settings

app = create_app()

if __name__ == "__main__":
    settings = get_settings()
    uvicorn.run("earthsync_server.main:app", host="0.0.0.0", port=settings.port, reload=True)  # noqa: S104
