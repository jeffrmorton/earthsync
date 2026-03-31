"""Upload time-domain samples to EarthSync server."""

import asyncio

import httpx
import structlog

logger = structlog.get_logger()


class Uploader:
    """Uploads acquisition segments to the EarthSync backend via HTTP."""

    def __init__(
        self,
        server_url: str,
        api_key: str,
        max_retries: int = 3,
        retry_delay_s: float = 5.0,
    ):
        self._server_url = server_url.rstrip("/")
        self._api_key = api_key
        self._max_retries = max_retries
        self._retry_delay_s = retry_delay_s

    async def upload(self, payload: dict) -> bool:
        """Upload a time-domain segment to the server. Returns True on success."""
        url = f"{self._server_url}/api/data-ingest"
        headers = {
            "X-API-Key": self._api_key,
            "Content-Type": "application/json",
        }

        for attempt in range(1, self._max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.post(url, json=payload, headers=headers)
                if response.status_code == 202:
                    logger.info("upload_success", attempt=attempt)
                    return True
                logger.warning(
                    "upload_rejected",
                    status=response.status_code,
                    attempt=attempt,
                )
            except httpx.HTTPError as e:
                logger.warning("upload_error", error=str(e), attempt=attempt)

            if attempt < self._max_retries:
                await asyncio.sleep(self._retry_delay_s * attempt)

        logger.error("upload_failed", max_retries=self._max_retries)
        return False
