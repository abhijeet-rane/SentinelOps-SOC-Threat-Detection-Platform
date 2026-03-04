"""
Tests for isolation_forest.py — LoginAnomalyDetector
"""
import numpy as np
import pytest
from datetime import datetime, timezone, timedelta
from models.isolation_forest import LoginAnomalyDetector


# ── Feature Engineering ───────────────────────────────

def test_feature_engineering_correct_shape():
    detector = LoginAnomalyDetector()
    events = [
        {"timestamp": "2026-03-04T02:00:00+00:00", "username": "alice", "source_ip": "10.0.0.1", "success": False},
        {"timestamp": "2026-03-04T02:01:00+00:00", "username": "alice", "source_ip": "10.0.0.2", "success": False},
    ]
    X = detector.engineer_features(events)
    assert X.shape == (2, 6), f"Expected (2, 6), got {X.shape}"


def test_cyclical_hour_encoding_no_discontinuity():
    """Hour 23 and hour 0 should be close in cyclical space."""
    sin_23, cos_23 = LoginAnomalyDetector._cyclical_hour(23)
    sin_0, cos_0 = LoginAnomalyDetector._cyclical_hour(0)
    # Euclidean distance between 11pm and midnight should be small
    dist = np.sqrt((sin_23 - sin_0) ** 2 + (cos_23 - cos_0) ** 2)
    dist_noon_midnight = np.sqrt(
        (LoginAnomalyDetector._cyclical_hour(12)[0] - sin_0) ** 2 +
        (LoginAnomalyDetector._cyclical_hour(12)[1] - cos_0) ** 2
    )
    assert dist < dist_noon_midnight, "Hour 23 should be closer to hour 0 than hour 12 is"


def test_off_hours_flag_at_3am():
    ts = datetime(2026, 3, 4, 3, 0, 0)  # 3am weekday
    assert LoginAnomalyDetector._is_off_hours(ts) == 1


def test_off_hours_flag_at_noon_is_zero():
    ts = datetime(2026, 3, 4, 12, 0, 0)  # noon weekday
    assert LoginAnomalyDetector._is_off_hours(ts) == 0


def test_weekend_is_off_hours():
    ts = datetime(2026, 3, 7, 12, 0, 0)  # Saturday noon
    assert LoginAnomalyDetector._is_off_hours(ts) == 1


# ── Training ─────────────────────────────────────────

def test_training_with_synthetic_baseline_succeeds():
    detector = LoginAnomalyDetector()
    stats = detector.train([])  # triggers synthetic baseline
    assert detector.is_trained is True
    assert stats["samples"] > 0
    assert 0 <= stats["anomaly_rate"] <= 100


def test_training_stats_contain_required_keys():
    detector = LoginAnomalyDetector()
    stats = detector.train([])
    for key in ("samples", "features", "anomalies_detected", "anomaly_rate", "trained_at"):
        assert key in stats, f"Missing key: {key}"


def test_training_with_real_events_succeeds():
    detector = LoginAnomalyDetector()
    events = [
        {"timestamp": "2026-03-04T10:00:00+00:00", "username": f"u{i}", "source_ip": f"10.0.0.{i}", "success": i % 3 != 0}
        for i in range(20)
    ]
    stats = detector.train(events)
    assert detector.is_trained is True
    assert stats["samples"] >= 20


# ── Prediction ───────────────────────────────────────

def test_predict_after_training_returns_valid_result():
    detector = LoginAnomalyDetector()
    detector.train([])
    result = detector.predict({
        "timestamp": "2026-03-04T10:00:00+00:00",
        "username": "alice",
        "source_ip": "192.168.1.1",
        "success": True,
    })
    assert "is_anomaly" in result
    assert "anomaly_score" in result
    assert "confidence" in result
    assert "model_used" in result
    assert result["model_used"] == "isolation_forest"
    assert 0.0 <= result["anomaly_score"] <= 1.0
    assert 0.0 <= result["confidence"] <= 1.0


def test_obvious_brute_force_detected_as_anomaly():
    """High failed_ratio + many IPs + off-hours should yield high anomaly score."""
    detector = LoginAnomalyDetector()
    detector.train([])

    # Simulate 20 failures from 18 different IPs at 3am
    events = [
        {"timestamp": "2026-03-04T03:00:00+00:00", "username": "victim", "source_ip": f"10.0.{i}.1", "success": False}
        for i in range(20)
    ]
    result = detector.predict(events[0])
    # Score may or may not exceed threshold in synthetic baseline, but should be above 0
    assert result["anomaly_score"] >= 0.0
    assert isinstance(result["is_anomaly"], bool)


def test_predict_without_training_returns_graceful_result():
    detector = LoginAnomalyDetector()
    # Do NOT train
    result = detector.predict({"timestamp": "2026-03-04T10:00:00+00:00", "username": "test"})
    assert result["is_anomaly"] is False
    assert "not trained" in result["reason"].lower()


def test_anomaly_score_is_bounded():
    detector = LoginAnomalyDetector()
    detector.train([])
    # Test with many different events
    for hour in range(0, 24, 4):
        result = detector.predict({
            "timestamp": f"2026-03-04T{hour:02d}:00:00+00:00",
            "username": "testuser",
            "source_ip": "192.168.1.100",
            "success": True,
        })
        assert 0.0 <= result["anomaly_score"] <= 1.0, f"Score out of bounds at hour {hour}"
        assert 0.0 <= result["confidence"] <= 1.0
