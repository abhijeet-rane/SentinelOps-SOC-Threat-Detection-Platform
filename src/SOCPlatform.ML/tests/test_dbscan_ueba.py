"""
Tests for dbscan_ueba.py — UEBADetector
"""
import numpy as np
import pytest
from models.dbscan_ueba import UEBADetector


# ── Feature Engineering ───────────────────────────────

def test_user_profile_feature_shape():
    detector = UEBADetector()
    events = [
        {"timestamp": "2026-03-04T10:00:00+00:00", "username": "alice", "event_type": "login", "resource": "/app"},
        {"timestamp": "2026-03-04T11:00:00+00:00", "username": "alice", "event_type": "view", "resource": "/dashboard"},
        {"timestamp": "2026-03-04T22:00:00+00:00", "username": "bob", "event_type": "login", "resource": "/admin"},
    ]
    names, X = detector.build_user_profiles(events)
    assert X.shape[1] == 5, f"Expected 5 features, got {X.shape[1]}"
    assert len(names) == 2  # alice, bob
    assert "alice" in names and "bob" in names


def test_empty_events_returns_empty_profile():
    detector = UEBADetector()
    names, X = detector.build_user_profiles([])
    assert len(names) == 0
    assert X.shape == (0, 5)


def test_weekend_ratio_computed_correctly():
    """Events exclusively on weekends should give weekend_ratio=1.0."""
    detector = UEBADetector()
    events = [
        # Saturday 2026-03-07 and Sunday 2026-03-08
        {"timestamp": "2026-03-07T10:00:00+00:00", "username": "weekend_user", "event_type": "login", "resource": "/x"},
        {"timestamp": "2026-03-08T10:00:00+00:00", "username": "weekend_user", "event_type": "view", "resource": "/y"},
    ]
    names, X = detector.build_user_profiles(events)
    idx = names.index("weekend_user")
    weekend_ratio = X[idx, 4]
    assert weekend_ratio == 1.0, f"Expected 1.0, got {weekend_ratio}"


# ── Auto-tune eps ─────────────────────────────────────

def test_auto_eps_returns_positive_value():
    X = np.random.default_rng(42).random((30, 5))
    eps = UEBADetector._auto_eps(X, min_samples=3)
    assert eps > 0


def test_auto_eps_with_minimal_data():
    X = np.array([[0.1, 0.2, 0.3, 0.4, 0.5]])
    eps = UEBADetector._auto_eps(X, min_samples=1)
    assert eps >= 0.1  # Should return minimum safe value


# ── Training ─────────────────────────────────────────

def test_training_with_synthetic_data_succeeds():
    detector = UEBADetector()
    stats = detector.train([])
    assert detector.is_trained is True
    assert stats["users_profiled"] > 0
    assert "clusters" in stats
    assert "eps" in stats


def test_training_creates_cluster_centers():
    detector = UEBADetector()
    detector.train([])
    assert len(detector._cluster_centers) > 0
    for label, center in detector._cluster_centers.items():
        assert label != -1, "Cluster centers should not include noise label"
        assert len(center) == 5, "Each center should have 5 coordinates"


def test_training_builds_user_profile_dict():
    detector = UEBADetector()
    events = [
        {"timestamp": f"2026-03-04T{h:02d}:00:00+00:00", "username": f"u{h % 5}", "event_type": "login", "resource": "/x"}
        for h in range(24)
    ]
    detector.train(events)
    assert len(detector._user_profiles) > 0


# ── Prediction ───────────────────────────────────────

def test_predict_after_training_returns_valid_structure():
    detector = UEBADetector()
    detector.train([])
    result = detector.predict({"username": "testuser", "timestamp": "2026-03-04T10:00:00+00:00"})
    assert "is_anomaly" in result
    assert "anomaly_score" in result
    assert "confidence" in result
    assert result["model_used"] == "dbscan_ueba"
    assert 0.0 <= result["anomaly_score"] <= 1.0


def test_noise_user_flagged_as_anomaly():
    """A user previously labelled as noise (-1) should get high anomaly score."""
    detector = UEBADetector()
    detector.train([])
    # Inject a "noise" user into profiles
    detector._user_profiles["noise_user"] = -1
    result = detector.predict({"username": "noise_user", "timestamp": "2026-03-04T03:00:00+00:00"})
    assert result["is_anomaly"] is True
    assert result["anomaly_score"] >= 0.5


def test_predict_without_training_returns_graceful_result():
    detector = UEBADetector()
    result = detector.predict({"username": "unknown", "timestamp": "2026-03-04T10:00:00+00:00"})
    assert result["is_anomaly"] is False
    assert "not trained" in result["reason"].lower()
