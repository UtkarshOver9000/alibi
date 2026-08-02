"""
Schema definitions for login events, evaluation requests, and API responses.
"""

from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field


LOGIN_COLUMNS = ["user_id", "login_ts", "lat", "lon", "city", "country", "device_id", "ip"]


class LoginEvent(BaseModel):
    user_id: str = Field(..., description="Unique identifier for the user", example="usr_1001")
    login_ts: str = Field(..., description="ISO-8601 timestamp of login attempt", example="2026-08-02T15:30:00Z")
    lat: float = Field(..., description="Latitude of login IP", example="40.7128")
    lon: float = Field(..., description="Longitude of login IP", example="-74.0060")
    city: Optional[str] = Field(None, description="City name", example="New York")
    country: Optional[str] = Field(None, description="Country code", example="US")
    device_id: str = Field(..., description="Unique device fingerprint", example="dev-macbook-pro")
    ip: str = Field(..., description="IPv4 or IPv6 address", example="198.51.100.45")


class EvaluationResult(BaseModel):
    user_id: str
    is_anomaly: bool
    risk_score: float = Field(..., description="Risk score between 0.0 and 100.0")
    risk_tier: str = Field(..., description="LOW, MEDIUM, HIGH, or CRITICAL")
    reasons: List[str]
    velocity_kmph: float
    distance_km: float
    time_delta_hours: float
    previous_location: Optional[dict] = None
    current_location: dict
    timestamp: str


class APIKeyCreate(BaseModel):
    name: str = Field(..., description="Name for the API key owner/app")


class APIKeyResponse(BaseModel):
    name: str
    api_key: str
    created_at: str
