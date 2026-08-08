"""
Unit tests for AI Anomaly Engine & Geo-Physics Calculations.
"""

from ittravel.ml_engine import AIAnomalyEngine
from ittravel.schema import LoginEvent


def test_first_login_is_low_risk():
    engine = AIAnomalyEngine()
    event = LoginEvent(
        user_id="test_usr_1",
        login_ts="2026-08-02T12:00:00Z",
        lat=40.7128,
        lon=-74.0060,
        city="New York",
        country="US",
        device_id="dev_1",
        ip="198.51.100.1",
    )
    result = engine.evaluate_event(event)
    assert result.is_anomaly is False
    assert result.risk_tier == "LOW"
    assert result.velocity_kmph == 0.0


def test_impossible_travel_triggers_critical_anomaly():
    engine = AIAnomalyEngine()
    
    # NYC Login
    event1 = LoginEvent(
        user_id="test_usr_2",
        login_ts="2026-08-02T12:00:00Z",
        lat=40.7128,
        lon=-74.0060,
        city="New York",
        country="US",
        device_id="dev_1",
        ip="198.51.100.1",
    )
    engine.evaluate_event(event1)

    # Tokyo Login 5 minutes later -> ~10,800 km in 0.083 hrs = ~130,000 km/h impossible speed
    event2 = LoginEvent(
        user_id="test_usr_2",
        login_ts="2026-08-02T12:05:00Z",
        lat=35.6762,
        lon=139.6503,
        city="Tokyo",
        country="JP",
        device_id="dev_2",
        ip="203.0.113.5",
    )
    result2 = engine.evaluate_event(event2)
    assert result2.is_anomaly is True
    assert result2.risk_score >= 60.0
    assert any("Impossible physical travel" in r for r in result2.reasons)


def test_normal_travel_is_low_risk():
    engine = AIAnomalyEngine()

    # NYC Login
    event1 = LoginEvent(
        user_id="test_usr_3",
        login_ts="2026-08-02T12:00:00Z",
        lat=40.7128,
        lon=-74.0060,
        city="New York",
        country="US",
        device_id="dev_1",
        ip="198.51.100.1",
    )
    engine.evaluate_event(event1)

    # London Login 10 hours later -> 5,500 km in 10 hrs = 550 km/h (Realistic flight speed)
    event2 = LoginEvent(
        user_id="test_usr_3",
        login_ts="2026-08-02T22:00:00Z",
        lat=51.5074,
        lon=-0.1278,
        city="London",
        country="GB",
        device_id="dev_1",
        ip="198.51.100.1",
    )
    result2 = engine.evaluate_event(event2)
    assert result2.is_anomaly is False
    assert result2.velocity_kmph < 900.0
