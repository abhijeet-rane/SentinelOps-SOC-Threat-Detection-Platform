"""
Modified Z-Score – Network Activity Outlier Detection
======================================================
Detects unusual network traffic patterns using the Modified Z-Score
(Median Absolute Deviation), which is robust against outliers unlike
the standard mean/std-based Z-score.

Features (4-dimensional):
  - connections_per_minute : TCP connection rate
  - unique_dest_ports     : distinct destination ports (high = scan)
  - bytes_transferred     : data volume (high = exfiltration)
  - unique_dest_ips       : distinct destination IPs

Modified Z-Score formula:
  M_i = 0.6745 * (x_i - median) / MAD
  where MAD = median(|x_i - median(x)|)
  Threshold: |M_i| > 3.5 (Iglewicz & Hoaglin recommendation)
"""

import numpy as np
import pandas as pd
import joblib
import os
import logging
from datetime import datetime
from typing import Optional

logger = logging.getLogger("soc_ml.zscore_network")

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "trained_models")

# The constant 0.6745 is the 0.75th quartile of the standard normal distribution
# It makes the MAD consistent with the standard deviation for normal data
CONSISTENCY_CONSTANT = 0.6745


class NetworkOutlierDetector:
    """Modified Z-Score based network activity outlier detector."""

    def __init__(self, threshold: float = 3.5):
        self.threshold = threshold
        self.is_trained = False
        self.training_stats: dict = {}
        self._medians: Optional[np.ndarray] = None
        self._mads: Optional[np.ndarray] = None
        self._feature_names = [
            "connections_per_minute", "unique_dest_ports",
            "bytes_transferred", "unique_dest_ips"
        ]

    # ── Feature Engineering ──────────────────────────

    def engineer_features(self, events: list[dict]) -> np.ndarray:
        """
        Extract network features from raw events.

        Each event dict should have:
          - connections (int): number of connections in the window
          - duration_seconds (float): time window duration
          - dest_ports (list[int] or int): destination ports
          - bytes_sent (int): bytes transferred
          - bytes_received (int): bytes received
          - dest_ips (list[str] or int): destination IPs
        """
        if not events:
            return np.empty((0, 4))

        features = []
        for ev in events:
            # Connections per minute
            conns = ev.get("connections", ev.get("connection_count", 1))
            duration = max(ev.get("duration_seconds", 60), 1)
            cpm = conns / (duration / 60.0)

            # Unique destination ports
            ports = ev.get("dest_ports", ev.get("unique_dest_ports", 1))
            if isinstance(ports, list):
                unique_ports = len(set(ports))
            else:
                unique_ports = int(ports)

            # Bytes transferred
            bytes_sent = ev.get("bytes_sent", ev.get("bytes_transferred", 0))
            bytes_recv = ev.get("bytes_received", 0)
            total_bytes = bytes_sent + bytes_recv

            # Unique destination IPs
            ips = ev.get("dest_ips", ev.get("unique_dest_ips", 1))
            if isinstance(ips, list):
                unique_ips = len(set(ips))
            else:
                unique_ips = int(ips)

            features.append([cpm, unique_ports, total_bytes, unique_ips])

        return np.array(features, dtype=np.float64)

    def engineer_single_event(self, event: dict) -> np.ndarray:
        """Engineer features for a single network event."""
        return self.engineer_features([event])

    # ── Modified Z-Score ─────────────────────────────

    @staticmethod
    def _compute_mad(X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """Compute Median Absolute Deviation for each feature."""
        medians = np.median(X, axis=0)
        abs_deviations = np.abs(X - medians)
        mads = np.median(abs_deviations, axis=0)
        # Prevent division by zero — use a small value if MAD is 0
        mads = np.where(mads == 0, 1e-6, mads)
        return medians, mads

    def modified_zscore(self, X: np.ndarray) -> np.ndarray:
        """
        Compute Modified Z-Scores for each sample.
        Returns a matrix of z-scores (samples x features).
        """
        if self._medians is None or self._mads is None:
            raise ValueError("Model not trained — no baseline statistics available.")

        return CONSISTENCY_CONSTANT * (X - self._medians) / self._mads

    # ── Training ─────────────────────────────────────

    def train(self, events: list[dict]) -> dict:
        """
        Train the Z-Score detector: learn baseline median and MAD statistics.
        """
        logger.info(f"Training Z-Score Network detector on {len(events)} events...")

        X = self.engineer_features(events)
        if X.shape[0] < 10:
            X = self._generate_synthetic_baseline()
            logger.info(f"Insufficient data, using synthetic baseline ({X.shape[0]} samples)")

        self._medians, self._mads = self._compute_mad(X)
        self.is_trained = True

        # Compute scores on training data for stats
        z_scores = self.modified_zscore(X)
        combined_scores = np.max(np.abs(z_scores), axis=1)  # Max across features
        anomaly_mask = combined_scores > self.threshold
        anomaly_count = int(np.sum(anomaly_mask))

        self.training_stats = {
            "samples": int(X.shape[0]),
            "features": int(X.shape[1]),
            "threshold": self.threshold,
            "anomalies_detected": anomaly_count,
            "anomaly_rate": round(anomaly_count / X.shape[0] * 100, 2),
            "medians": self._medians.tolist(),
            "mads": self._mads.tolist(),
            "max_zscore": round(float(np.max(combined_scores)), 4),
            "trained_at": datetime.utcnow().isoformat(),
        }

        self._save_model()
        logger.info(f"Z-Score training complete: {self.training_stats}")
        return self.training_stats

    def predict(self, event: dict) -> dict:
        """
        Score a single network event against the baseline.
        """
        if not self.is_trained:
            self._load_model()

        if not self.is_trained:
            return {
                "is_anomaly": False, "anomaly_score": 0.0,
                "confidence": 0.0, "reason": "Model not trained",
                "model_used": "zscore_network",
            }

        X = self.engineer_single_event(event)
        if X.shape[0] == 0:
            return {
                "is_anomaly": False, "anomaly_score": 0.0,
                "confidence": 0.0, "reason": "Invalid event data",
                "model_used": "zscore_network",
            }

        z_scores = self.modified_zscore(X)[0]  # Shape: (4,)
        abs_z = np.abs(z_scores)
        max_z = float(np.max(abs_z))
        mean_z = float(np.mean(abs_z))

        is_anomaly = max_z > self.threshold

        # Normalize anomaly score to 0-1 range
        anomaly_score = round(max(0.0, min(1.0, max_z / (self.threshold * 2))), 4)
        confidence = round(min(1.0, max_z / self.threshold), 4)

        # Identify which features are anomalous
        reason = self._explain(z_scores, event)

        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": anomaly_score,
            "confidence": confidence,
            "reason": reason,
            "model_used": "zscore_network",
            "z_scores": {name: round(float(z), 4) for name, z in zip(self._feature_names, z_scores)},
            "max_zscore": round(max_z, 4),
        }

    # ── Explanation ──────────────────────────────────

    def _explain(self, z_scores: np.ndarray, event: dict) -> str:
        """Generate explanation based on which features have high z-scores."""
        explanations = {
            0: "abnormal connection rate",
            1: "unusually many destination ports (possible port scan)",
            2: "abnormal data transfer volume (possible exfiltration)",
            3: "unusually many destination IPs (possible lateral movement)",
        }

        anomalous_features = []
        for i, z in enumerate(z_scores):
            if abs(z) > self.threshold:
                direction = "high" if z > 0 else "low"
                anomalous_features.append(
                    f"{direction} {explanations.get(i, self._feature_names[i])} (z={z:.2f})"
                )

        if not anomalous_features:
            if np.max(np.abs(z_scores)) > self.threshold * 0.7:
                return "borderline anomalous network activity"
            return "network activity within normal baseline"

        return "; ".join(anomalous_features)

    # ── Synthetic Baseline ───────────────────────────

    def _generate_synthetic_baseline(self, n_samples: int = 500) -> np.ndarray:
        """Generate realistic synthetic network baseline data."""
        rng = np.random.default_rng(42)

        # Normal traffic (~90%)
        n_normal = int(n_samples * 0.9)
        normal = np.column_stack([
            rng.lognormal(1.5, 0.8, n_normal),          # connections/min: ~4-10
            rng.poisson(3, n_normal) + 1,                # dest ports: 1-6 typical
            rng.lognormal(10, 1.5, n_normal),            # bytes: ~20KB typical
            rng.poisson(5, n_normal) + 1,                # dest IPs: 2-8 typical
        ])

        # Anomalous traffic (~10%)
        n_anom = n_samples - n_normal
        anomalous = np.column_stack([
            rng.lognormal(4, 1, n_anom),                 # high connection rate
            rng.poisson(50, n_anom) + 20,                # many ports (scan)
            rng.lognormal(16, 2, n_anom),                # large data transfer
            rng.poisson(30, n_anom) + 15,                # many dest IPs
        ])

        return np.vstack([normal, anomalous])

    # ── Persistence ──────────────────────────────────

    def _save_model(self):
        os.makedirs(MODEL_DIR, exist_ok=True)
        joblib.dump({
            "medians": self._medians,
            "mads": self._mads,
            "threshold": self.threshold,
            "stats": self.training_stats,
        }, os.path.join(MODEL_DIR, "zscore_network.joblib"))
        logger.info("Z-Score Network model saved.")

    def _load_model(self):
        path = os.path.join(MODEL_DIR, "zscore_network.joblib")
        if os.path.exists(path):
            data = joblib.load(path)
            self._medians = data["medians"]
            self._mads = data["mads"]
            self.threshold = data["threshold"]
            self.training_stats = data["stats"]
            self.is_trained = True
            logger.info("Z-Score Network model loaded from disk.")
