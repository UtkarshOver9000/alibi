"""
Schema for login events and derived impossible-travel signals.
"""

from __future__ import annotations

LOGIN_COLUMNS = [
    "user_id",
    "login_ts",
    "lat",
    "lon",
    "city",
    "country",
    "device_id",
    "ip",
]

DERIVED_COLUMNS = [
    "prev_login_ts",
    "prev_lat",
    "prev_lon",
    "time_delta_hours",
    "distance_km",
    "required_speed_kmph",
    "is_impossible_travel",
]
