"""
Schema definitions for login events, evaluation requests, and API responses.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

LOGIN_COLUMNS = ["user_id", "login_ts", "lat", "lon", "city", "country", "device_id", "ip"]


class LoginEvent(BaseModel):
    user_id: str = Field(
        ..., description="Unique identifier for the user", json_schema_extra={"example": "usr_1001"}
    )
    login_ts: str = Field(
        ...,
        description="ISO-8601 timestamp of login attempt",
        json_schema_extra={"example": "2026-08-02T15:30:00Z"},
    )
    lat: float = Field(..., description="Latitude of login IP", json_schema_extra={"example": 40.7128})
    lon: float = Field(..., description="Longitude of login IP", json_schema_extra={"example": -74.0060})
    city: str | None = Field(None, description="City name", json_schema_extra={"example": "New York"})
    country: str | None = Field(None, description="Country code", json_schema_extra={"example": "US"})
    device_id: str = Field(
        ..., description="Unique device fingerprint", json_schema_extra={"example": "dev-macbook-pro"}
    )
    ip: str = Field(..., description="IPv4 or IPv6 address", json_schema_extra={"example": "198.51.100.45"})


class EvaluationResult(BaseModel):
    user_id: str
    is_anomaly: bool
    risk_score: float = Field(..., description="Risk score between 0.0 and 100.0")
    risk_tier: str = Field(..., description="LOW, MEDIUM, HIGH, or CRITICAL")
    reasons: list[str]
    velocity_kmph: float
    distance_km: float
    time_delta_hours: float
    previous_location: dict | None = None
    current_location: dict
    timestamp: str


class APIKeyCreate(BaseModel):
    name: str = Field(..., description="Name for the API key owner/app")


class APIKeyResponse(BaseModel):
    name: str
    api_key: str
    created_at: str
