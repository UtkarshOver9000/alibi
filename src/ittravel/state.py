"""
In-memory state store for user login history and API keys.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone


class UserState:
    def __init__(self, user_id: str):
        self.user_id = user_id
        self.last_ts: datetime | None = None
        self.last_lat: float | None = None
        self.last_lon: float | None = None
        self.last_city: str | None = None
        self.last_country: str | None = None
        self.last_device_id: str | None = None
        self.last_ip: str | None = None
        self.known_devices: set[str] = set()
        self.login_history: list[dict] = []

    def update(
        self,
        ts: datetime,
        lat: float,
        lon: float,
        city: str | None,
        country: str | None,
        device_id: str,
        ip: str,
    ):
        self.last_ts = ts
        self.last_lat = lat
        self.last_lon = lon
        self.last_city = city
        self.last_country = country
        self.last_device_id = device_id
        self.last_ip = ip
        self.known_devices.add(device_id)
        self.login_history.append({
            "ts": ts.isoformat(),
            "lat": lat,
            "lon": lon,
            "city": city,
            "country": country,
            "device_id": device_id,
            "ip": ip,
        })
        if len(self.login_history) > 50:
            self.login_history.pop(0)


class StateStore:
    def __init__(self):
        self.users: dict[str, UserState] = {}
        self.api_keys: dict[str, dict] = {
            "demo-master-key-9000": {
                "name": "Default Admin Key",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        }
        self.anomaly_logs: list[dict] = []

    def get_user(self, user_id: str) -> UserState:
        if user_id not in self.users:
            self.users[user_id] = UserState(user_id)
        return self.users[user_id]

    def create_api_key(self, name: str) -> dict:
        key = f"sk_live_{secrets.token_hex(16)}"
        created_at = datetime.now(timezone.utc).isoformat()
        info = {"name": name, "api_key": key, "created_at": created_at}
        self.api_keys[key] = info
        return info

    def is_valid_api_key(self, key: str) -> bool:
        return key in self.api_keys

    def log_anomaly(self, anomaly: dict):
        self.anomaly_logs.insert(0, anomaly)
        if len(self.anomaly_logs) > 200:
            self.anomaly_logs.pop()

    def get_anomalies(self, limit: int = 50) -> list[dict]:
        return self.anomaly_logs[:limit]


# Global singleton instance for app state
store = StateStore()
