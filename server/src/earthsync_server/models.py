"""Pydantic v2 models for EarthSync data structures."""

from typing import Literal

from pydantic import BaseModel, Field


class Location(BaseModel):
    """Geographic coordinates of a station."""

    lat: float
    lon: float


class DetectedPeak(BaseModel):
    """A peak detected in the Schumann Resonance spectrum."""

    freq: float
    amp: float
    q_factor: float | None = None
    freq_err: float | None = None
    amp_err: float | None = None
    q_err: float | None = None
    snr: float | None = None


class TrackedPeak(DetectedPeak):
    """A detected peak with temporal tracking information."""

    track_status: Literal["new", "continuing"]
    track_id: str


class LorentzianMode(BaseModel):
    """A single Lorentzian mode from the fit."""

    freq: float
    amp: float
    q_factor: float
    freq_err: float | None = None
    amp_err: float | None = None
    q_err: float | None = None


class LorentzianFitResult(BaseModel):
    """Result of a multi-Lorentzian curve fit."""

    modes: list[LorentzianMode]
    background: dict
    chi_squared: float | None = None
    degrees_of_freedom: int
    converged: bool


class NoiseFloor(BaseModel):
    """Noise floor statistics."""

    median: float
    std: float


class TimeDomainQuality(BaseModel):
    """Time-domain signal quality assessment."""

    is_usable: bool
    flags: list[str]


class QBurstResult(BaseModel):
    """Q-burst detection result."""

    detected: bool
    peak_amplitude: float | None = None
    duration_ms: float | None = None


class TransientInfo(BaseModel):
    """Transient event classification."""

    type: Literal["none", "broadband", "narrowband", "error"]
    details: str | None = None


class WSPayload(BaseModel):
    """WebSocket broadcast payload for processed station data."""

    station_id: str
    timestamp: str
    location: Location
    spectrogram: list[float]
    lorentzian_fit: LorentzianFitResult | None = None
    detected_peaks: list[TrackedPeak]
    transient_info: TransientInfo
    noise_floor: NoiseFloor | None = None
    quality_flags: list[str]
    algorithm_version: str
    calibration_status: str
    sample_rate_hz: int
    frequency_resolution_hz: float | None = None


class IngestRequest(BaseModel):
    """Incoming raw data from a station."""

    station_id: str
    timestamp: str
    location: Location
    samples: list[float]
    sample_rate_hz: int = Field(ge=90, le=10000)
    segment_duration_s: float = Field(ge=1, le=600)
    sensor_type: str | None = None
    metadata: dict | None = None


class RegisterRequest(BaseModel):
    """User registration request."""

    username: str = Field(min_length=3, max_length=30, pattern=r"^[a-zA-Z0-9_]+$")
    password: str = Field(min_length=8)


class LoginResponse(BaseModel):
    """Authentication response with JWT token."""

    token: str
    expires_in: int
