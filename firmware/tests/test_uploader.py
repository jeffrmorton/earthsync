"""Tests for the HTTP uploader."""

from unittest.mock import AsyncMock, patch

import httpx
import pytest
from earthsync_station.uploader import Uploader


@pytest.fixture
def uploader():
    return Uploader(
        server_url="http://localhost:3000",
        api_key="test-key",
        max_retries=3,
        retry_delay_s=0.01,  # Fast retries for tests
    )


@pytest.fixture
def sample_payload():
    return {
        "station_id": "test-station",
        "timestamp": "2026-03-28T00:00:00+00:00",
        "location": {"lat": 37.0, "lon": -119.0},
        "samples": [0.001, -0.002, 0.003],
        "sample_rate_hz": 256,
        "segment_duration_s": 10.0,
        "sensor_type": "induction_coil",
        "metadata": {"adc_gain": 1},
    }


class TestUploadSuccess:
    @pytest.mark.asyncio
    async def test_upload_success(self, uploader, sample_payload):
        mock_response = httpx.Response(202, request=httpx.Request("POST", "http://test"))
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
            result = await uploader.upload(sample_payload)
        assert result is True


class TestUploadRetry:
    @pytest.mark.asyncio
    async def test_upload_retry_on_error(self, uploader, sample_payload):
        mock_success = httpx.Response(202, request=httpx.Request("POST", "http://test"))
        mock_post = AsyncMock(side_effect=[httpx.ConnectError("refused"), mock_success])
        with patch("httpx.AsyncClient.post", mock_post):
            result = await uploader.upload(sample_payload)
        assert result is True
        assert mock_post.call_count == 2

    @pytest.mark.asyncio
    async def test_upload_all_retries_exhausted(self, uploader, sample_payload):
        mock_post = AsyncMock(side_effect=httpx.ConnectError("refused"))
        with patch("httpx.AsyncClient.post", mock_post):
            result = await uploader.upload(sample_payload)
        assert result is False
        assert mock_post.call_count == 3

    @pytest.mark.asyncio
    async def test_upload_rejected_status(self, uploader, sample_payload):
        mock_response = httpx.Response(400, request=httpx.Request("POST", "http://test"))
        mock_post = AsyncMock(return_value=mock_response)
        with patch("httpx.AsyncClient.post", mock_post):
            result = await uploader.upload(sample_payload)
        assert result is False
        assert mock_post.call_count == 3
