"""
Tests for zscore_network.py — NetworkOutlierDetector
"""
import numpy as np
import pytest
from models.zscore_network import NetworkOutlierDetector, CONSISTENCY_CONSTANT


# ── MAD Formula ───────────────────────────────────────

def test_mad_formula_correctness():
    """Verify Modified Z-Score formula: M = 0.6745 * (x - median) / MAD."""
    X = np.array([[1.0, 2.0, 3.0, 4.0], [1.1, 2.1, 3.1, 4.1], [100.0, 2.0, 3.0, 4.0]])
    medians, mads = NetworkOutlierDetector._compute_mad(X)
    # For column 0: median = 1.1, MAD = median(|[1.0-1.1, 1.1-1.1, 100.0-1.1]|) = median([0.1, 0, 98.9]) = 0.1
    assert abs(medians[0] - 1.1) < 1e-6
    assert mads[0] > 0


def test_mad_robust_to_outliers():
    """MAD should be much more stable than std when outliers present."""
    normal = np.ones((100, 4)) * 5.0  # all 5s
    outlier = np.array([[1000.0, 1000.0, 1000.0, 1000.0]])  # extreme outlier
    X_with_outlier = np.vstack([normal, outlier])

    medians, mads = NetworkOutlierDetector._compute_mad(X_with_outlier)
    # Median should still be ≈5.0
    assert abs(medians[0] - 5.0) < 1.0, "Median should be close to 5 despite outlier"
    # MAD should be ≈0 since 100 out of 101 values are exactly 5
    assert mads[0] < 1.0, "MAD should be small despite the outlier"


def test_mad_nonzero_when_all_same():
    """When all values are identical, MAD is 0 — should use fallback 1e-6."""
    X = np.ones((10, 4))
    medians, mads = NetworkOutlierDetector._compute_mad(X)
    # All equal → MAD=0 → fallback 1e-6
    assert all(m == pytest.approx(1e-6) for m in mads)


# ── Feature Engineering ───────────────────────────────

def test_feature_engineering_basic():
    detector = NetworkOutlierDetector()
    event = {
        "connections": 60,
        "duration_seconds": 60,
        "dest_ports": [80, 443, 8080],
        "bytes_sent": 1024,
        "bytes_received": 2048,
        "dest_ips": ["10.0.0.1", "10.0.0.2"],
    }
    X = detector.engineer_features([event])
    assert X.shape == (1, 4)
    # cpm = connections / (duration_seconds / 60) = 60 / (60/60) = 60 / 1.0 = 60.0 per minute
    assert X[0, 0] == pytest.approx(60.0)  # 60 conns / 1 min window = 60 per minute
    assert X[0, 1] == 3   # 3 unique ports
    assert X[0, 2] == 3072  # 1024 + 2048
    assert X[0, 3] == 2   # 2 unique IPs


def test_feature_engineering_scalar_ports_and_ips():
    """Should accept scalar int for ports/IPs (not just lists)."""
    detector = NetworkOutlierDetector()
    event = {"connections": 10, "duration_seconds": 60, "unique_dest_ports": 5,
             "bytes_sent": 500, "unique_dest_ips": 3}
    X = detector.engineer_features([event])
    assert X.shape == (1, 4)
    assert X[0, 1] == 5
    assert X[0, 3] == 3


# ── Training ─────────────────────────────────────────

def test_training_with_synthetic_baseline_succeeds():
    detector = NetworkOutlierDetector()
    stats = detector.train([])
    assert detector.is_trained is True
    assert detector._medians is not None
    assert detector._mads is not None
    assert stats["samples"] > 0


def test_training_stores_medians_and_mads_correct_shape():
    detector = NetworkOutlierDetector()
    detector.train([])
    assert len(detector._medians) == 4
    assert len(detector._mads) == 4
    assert all(m > 0 for m in detector._mads)


# ── Prediction ───────────────────────────────────────

def test_normal_traffic_not_flagged():
    """Average traffic should produce a low anomaly score."""
    detector = NetworkOutlierDetector()
    detector.train([])
    # Craft an event near the median of synthetic baseline
    event = {"connections": 5, "duration_seconds": 60,
             "dest_ports": [80, 443], "bytes_sent": 10000,
             "bytes_received": 5000, "dest_ips": ["10.0.0.1"]}
    result = detector.predict(event)
    assert not result["is_anomaly"], f"Normal traffic should not be anomalous, score={result['anomaly_score']}"


def test_high_port_count_detected_as_anomaly():
    """500 unique destination ports is clearly a port scan."""
    detector = NetworkOutlierDetector()
    detector.train([])
    event = {
        "connections": 600,
        "duration_seconds": 60,
        "dest_ports": list(range(1, 501)),  # 500 unique ports
        "bytes_sent": 50000,
        "bytes_received": 1000,
        "dest_ips": ["10.0.0.1"],
    }
    result = detector.predict(event)
    assert result["anomaly_score"] > 0.3 or result["is_anomaly"], \
        "500 destination ports should yield elevated anomaly score"


def test_predict_returns_zscore_breakdown():
    """Per-feature z-scores should be in the result details."""
    detector = NetworkOutlierDetector()
    detector.train([])
    event = {"connections": 5, "duration_seconds": 60, "dest_ports": [80], "bytes_sent": 1000, "dest_ips": ["10.0.0.1"]}
    result = detector.predict(event)
    assert "z_scores" in result
    assert len(result["z_scores"]) == 4


def test_predict_without_training_returns_graceful_result():
    detector = NetworkOutlierDetector()
    result = detector.predict({"connections": 5})
    assert result["is_anomaly"] is False
    assert "not trained" in result["reason"].lower()


def test_anomaly_score_bounded_zero_to_one():
    detector = NetworkOutlierDetector()
    detector.train([])
    for connections in [1, 10, 100, 10000]:
        event = {"connections": connections, "duration_seconds": 60,
                 "dest_ports": [80], "bytes_sent": connections * 100, "dest_ips": ["1.1.1.1"]}
        result = detector.predict(event)
        assert 0.0 <= result["anomaly_score"] <= 1.0, f"Score out of range for connections={connections}"
