"""
In-memory state: per-user login history and issued API keys.

State lives in process memory. On a serverless deployment it resets whenever
a new instance starts, so treat the live demo as a sandbox, not a system of
record.
"""

from __future__ import annotations

import secrets
from collections import OrderedDict, deque
from datetime import UTC, datetime

from . import settings

HISTORY_LIMIT = 50
MAX_USERS = 100_000  # beyond this the least recently seen users are forgotten, so memory stays bounded


def master_key() -> str | None:
    """The admin key, from ALIBI_API_KEY on the server. Unset means the keyed endpoints are switched off."""
    return settings.api_key()


class UserState:
    def __init__(self, user_id: str):
        self.user_id = user_id
        self.login_count = 0
        self.last_ts: datetime | None = None
        self.last_lat: float | None = None
        self.last_lon: float | None = None
        self.last_city: str | None = None
        self.last_country: str | None = None
        self.last_success: bool | None = None
        self.recent_outcomes: deque[bool] = deque(maxlen=10)
        self.seen: dict[str, set] = {k: set() for k in ("country", "asn", "ip", "ua", "browser", "os", "device")}
        self.login_history: deque[dict] = deque(maxlen=HISTORY_LIMIT)

    @property
    def known_devices(self) -> set:
        return self.seen["ua"]

    def record(self, event, ts: datetime) -> None:
        self.login_count += 1
        self.last_ts = ts
        self.last_lat, self.last_lon = event.lat, event.lon
        self.last_city, self.last_country = event.city, event.country
        self.last_success = event.success
        self.recent_outcomes.append(event.success)
        for key, value in (
            ("country", event.country),
            ("asn", event.asn),
            ("ip", event.ip),
            ("ua", event.user_agent or event.device_id),
            ("browser", event.browser),
            ("os", event.os),
            ("device", event.device_type),
        ):
            self.seen[key].add(value)
        self.login_history.append(
            {"ts": ts.isoformat(), "country": event.country, "ip": event.ip, "success": event.success}
        )


class StateStore:
    def __init__(self, max_users: int = MAX_USERS):
        self.users: OrderedDict[str, UserState] = OrderedDict()  # least recently seen first
        self.max_users = max_users
        self.api_keys: dict[str, dict] = {}
        self.anomaly_logs: list[dict] = []

    def get_user(self, user_id: str) -> UserState:
        user = self.users.get(user_id)
        if user is None:
            user = self.users[user_id] = UserState(user_id)
            while len(self.users) > self.max_users:
                self.users.popitem(last=False)  # a forgotten user starts again with no history
        else:
            self.users.move_to_end(user_id)
        return user

    def create_api_key(self, name: str) -> dict:
        key = f"alibi_{secrets.token_hex(16)}"
        info = {"name": name, "api_key": key, "created_at": datetime.now(UTC).isoformat()}
        self.api_keys[key] = info
        return info

    def is_master_key(self, key: str) -> bool:
        admin = master_key()
        return admin is not None and secrets.compare_digest(key, admin)

    def is_valid_api_key(self, key: str) -> bool:
        return self.is_master_key(key) or key in self.api_keys

    def log_anomaly(self, anomaly: dict) -> None:
        self.anomaly_logs.insert(0, anomaly)
        del self.anomaly_logs[200:]

    def get_anomalies(self, limit: int = 50) -> list[dict]:
        return self.anomaly_logs[:limit]


store = StateStore()
