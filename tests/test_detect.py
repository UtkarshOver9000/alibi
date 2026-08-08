"""
Unit tests for the offline geometric reference detector (detect.py).
"""

import pandas as pd

from ittravel.detect import detect_impossible_travel


def _events(rows):
    return pd.DataFrame(rows, columns=["user_id", "login_ts", "lat", "lon"])


def test_flags_impossible_velocity_between_consecutive_logins():
    # 20 min gap (above the 15 min min_time_hours floor) but NYC -> Tokyo
    # is physically impossible in that window.
    df = _events([
        {"user_id": "u1", "login_ts": "2026-08-02T12:00:00Z", "lat": 40.7128, "lon": -74.0060},
        {"user_id": "u1", "login_ts": "2026-08-02T12:20:00Z", "lat": 35.6762, "lon": 139.6503},
    ])
    out = detect_impossible_travel(df)
    flagged = out.sort_values("login_ts")["is_impossible_travel"].tolist()
    assert flagged == [0, 1]


def test_does_not_flag_realistic_travel_speed():
    df = _events([
        {"user_id": "u1", "login_ts": "2026-08-02T12:00:00Z", "lat": 40.7128, "lon": -74.0060},
        {"user_id": "u1", "login_ts": "2026-08-02T22:00:00Z", "lat": 51.5074, "lon": -0.1278},
    ])
    out = detect_impossible_travel(df)
    assert out.sort_values("login_ts")["is_impossible_travel"].tolist() == [0, 0]


def test_first_login_per_user_is_never_flagged():
    df = _events([
        {"user_id": "u1", "login_ts": "2026-08-02T12:00:00Z", "lat": 40.7128, "lon": -74.0060},
        {"user_id": "u2", "login_ts": "2026-08-02T12:00:00Z", "lat": 1.3521, "lon": 103.8198},
    ])
    out = detect_impossible_travel(df)
    assert out["is_impossible_travel"].tolist() == [0, 0]


def test_users_are_evaluated_independently():
    df = _events([
        {"user_id": "u1", "login_ts": "2026-08-02T12:00:00Z", "lat": 40.7128, "lon": -74.0060},
        {"user_id": "u2", "login_ts": "2026-08-02T12:00:00Z", "lat": 51.5074, "lon": -0.1278},
        {"user_id": "u1", "login_ts": "2026-08-02T12:20:00Z", "lat": 40.7500, "lon": -74.0100},
        {"user_id": "u2", "login_ts": "2026-08-02T12:20:00Z", "lat": 35.6762, "lon": 139.6503},
    ])
    out = detect_impossible_travel(df).sort_values(["user_id", "login_ts"])
    assert out[out["user_id"] == "u1"]["is_impossible_travel"].tolist() == [0, 0]
    assert out[out["user_id"] == "u2"]["is_impossible_travel"].tolist() == [0, 1]
