"""
Isolation Forest – Login Pattern Anomaly Detection
===================================================
Detects abnormal authentication patterns: brute-force attempts, credential
stuffing, impossible travel, and after-hours access.

Features (6-dimensional):
  - hour_sin / hour_cos : cyclical time encoding (no midnight discontinuity)
  - failed_ratio        : failed / total logins per user in the window
  - login_frequency     : logins per hour for this user
  - unique_ips          : distinct source IPs per user in the window
  - is_off_hours        : binary flag for outside 08:00-18:00 on weekdays
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os
import logging
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger("soc_ml.isolation_forest")

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "trained_models")


class LoginAnomalyDetector:
    """Isolation Forest model for login anomaly detection."""

    def __init__(self):
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self.is_trained = False
        self.training_stats: dict = {}
        self._feature_names = [
            "hour_sin", "hour_cos", "failed_ratio",
            "login_frequency", "unique_ips", "is_off_hours"
        ]

    # ── Feature Engineering ──────────────────────────

    @staticmethod
    def _cyclical_hour(hour: float) -> tuple[float, float]:
        """Encode hour as sin/cos to avoid midnight discontinuity."""
        rad = 2 * np.pi * hour / 24.0
        return np.sin(rad), np.cos(rad)

    @staticmethod
    def _is_off_hours(timestamp: datetime) -> int:
        """Return 1 if outside business hours (08-18 weekdays)."""
        if timestamp.weekday() >= 5:  # Weekend
            return 1
        return 0 if 8 <= timestamp.hour < 18 else 1

    def engineer_features(self, events: list[dict]) -> np.ndarray:
        """
        Transform raw login events into a 6-dimensional feature matrix.

        Each event dict should have:
          - timestamp (datetime or ISO string)
          - username (str)
          - source_ip (str, optional)
          - success (bool)
        """
        if not events:
            return np.empty((0, 6))

        df = pd.DataFrame(events)
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
        else:
            df["timestamp"] = datetime.utcnow()

        df["success"] = df.get("success", pd.Series([True] * len(df))).astype(bool)
        df["username"] = df.get("username", pd.Series(["unknown"] * len(df)))
        df["source_ip"] = df.get("source_ip", pd.Series(["0.0.0.0"] * len(df)))

        features = []
        for _, row in df.iterrows():
            ts = row["timestamp"]
            user = row["username"]

            # Cyclical hour encoding
            hour_sin, hour_cos = self._cyclical_hour(ts.hour + ts.minute / 60.0)

            # Window-based user stats (from the batch)
            user_events = df[df["username"] == user]
            total = len(user_events)
            failed = len(user_events[~user_events["success"]])
            failed_ratio = failed / max(total, 1)

            # Login frequency (events per hour in the window)
            time_range = (user_events["timestamp"].max() - user_events["timestamp"].min())
            hours = max(time_range.total_seconds() / 3600, 1.0)
            login_frequency = total / hours

            # Unique IPs
            unique_ips = user_events["source_ip"].nunique()

            # Off-hours
            off_hours = self._is_off_hours(ts)

            features.append([
                hour_sin, hour_cos, failed_ratio,
                login_frequency, unique_ips, off_hours
            ])

        return np.array(features, dtype=np.float64)

    # ── Training ─────────────────────────────────────

    def train(self, events: list[dict]) -> dict:
        """
        Train the Isolation Forest on historical login events.
        Returns training statistics.
        """
        logger.info(f"Training Isolation Forest on {len(events)} events...")

        X = self.engineer_features(events)
        if X.shape[0] < 10:
            # Not enough data — generate synthetic baseline
            X = self._generate_synthetic_baseline()
            logger.info(f"Insufficient data, using synthetic baseline ({X.shape[0]} samples)")

        # Scale features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        # Train model
        self.model = IsolationForest(
            n_estimators=200,
            max_features=0.8,
            contamination=0.05,
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X_scaled)
        self.is_trained = True

        # Training stats
        scores = self.model.decision_function(X_scaled)
        predictions = self.model.predict(X_scaled)
        anomaly_count = int(np.sum(predictions == -1))

        self.training_stats = {
            "samples": int(X.shape[0]),
            "features": int(X.shape[1]),
            "anomalies_detected": anomaly_count,
            "anomaly_rate": round(anomaly_count / X.shape[0] * 100, 2),
            "score_mean": round(float(np.mean(scores)), 4),
            "score_std": round(float(np.std(scores)), 4),
            "trained_at": datetime.utcnow().isoformat(),
        }

        self._save_model()
        logger.info(f"Training complete: {self.training_stats}")
        return self.training_stats

    def predict(self, event: dict) -> dict:
        """
        Predict whether a single login event is anomalous.
        Returns anomaly score, is_anomaly flag, confidence, and reason.
        """
        if not self.is_trained:
            self._load_model()

        if not self.is_trained:
            return {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "confidence": 0.0,
                "reason": "Model not trained",
                "model_used": "isolation_forest",
            }

        X = self.engineer_features([event])
        if X.shape[0] == 0:
            return {
                "is_anomaly": False, "anomaly_score": 0.0,
                "confidence": 0.0, "reason": "Invalid event data",
                "model_used": "isolation_forest",
            }

        X_scaled = self.scaler.transform(X)

        # decision_function: negative = more anomalous
        raw_score = float(self.model.decision_function(X_scaled)[0])
        prediction = int(self.model.predict(X_scaled)[0])  # 1=normal, -1=anomaly
        is_anomaly = prediction == -1

        # Normalize score to 0-1 range (higher = more anomalous)
        anomaly_score = round(max(0.0, min(1.0, 0.5 - raw_score)), 4)

        # Confidence based on how far from the decision boundary
        confidence = round(min(1.0, abs(raw_score) * 2), 4)

        # Generate human-readable reason
        reason = self._explain_anomaly(event, X[0], anomaly_score)

        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": anomaly_score,
            "confidence": confidence,
            "reason": reason,
            "model_used": "isolation_forest",
            "raw_score": round(raw_score, 4),
        }

    # ── Explanation ──────────────────────────────────

    def _explain_anomaly(self, event: dict, features: np.ndarray, score: float) -> str:
        """Generate a human-readable explanation of why the event is anomalous."""
        reasons = []

        if features[2] > 0.5:  # failed_ratio
            reasons.append(f"high login failure rate ({features[2]:.0%})")
        if features[3] > 10:   # login_frequency
            reasons.append(f"unusually high login frequency ({features[3]:.1f}/hr)")
        if features[4] > 5:    # unique_ips
            reasons.append(f"many distinct source IPs ({int(features[4])})")
        if features[5] == 1:   # is_off_hours
            reasons.append("activity outside business hours")

        if not reasons:
            reasons.append("unusual combination of login patterns")

        return "; ".join(reasons)

    # ── Synthetic Baseline ───────────────────────────

    def _generate_synthetic_baseline(self, n_samples: int = 500) -> np.ndarray:
        """Generate realistic synthetic login data for initial training."""
        rng = np.random.default_rng(42)

        # Normal business-hours logins (~80%)
        n_normal = int(n_samples * 0.8)
        normal_hours = rng.normal(13, 3, n_normal).clip(8, 18)  # 8-18 range
        normal_features = np.column_stack([
            np.sin(2 * np.pi * normal_hours / 24),
            np.cos(2 * np.pi * normal_hours / 24),
            rng.beta(1, 20, n_normal),           # low failed_ratio
            rng.lognormal(0.5, 0.5, n_normal),   # moderate frequency
            rng.poisson(1.5, n_normal) + 1,      # 1-3 IPs typical
            np.zeros(n_normal),                   # business hours
        ])

        # Anomalous patterns (~20%)
        n_anom = n_samples - n_normal
        anom_hours = rng.uniform(0, 6, n_anom)  # late night
        anom_features = np.column_stack([
            np.sin(2 * np.pi * anom_hours / 24),
            np.cos(2 * np.pi * anom_hours / 24),
            rng.beta(5, 3, n_anom),              # high failed_ratio
            rng.lognormal(2, 1, n_anom),         # very high frequency
            rng.poisson(8, n_anom) + 3,          # many IPs
            np.ones(n_anom),                     # off-hours
        ])

        return np.vstack([normal_features, anom_features])

    # ── Persistence ──────────────────────────────────

    def _save_model(self):
        os.makedirs(MODEL_DIR, exist_ok=True)
        joblib.dump(self.model, os.path.join(MODEL_DIR, "isolation_forest.joblib"))
        joblib.dump(self.scaler, os.path.join(MODEL_DIR, "isolation_forest_scaler.joblib"))
        logger.info("Isolation Forest model saved.")

    def _load_model(self):
        model_path = os.path.join(MODEL_DIR, "isolation_forest.joblib")
        scaler_path = os.path.join(MODEL_DIR, "isolation_forest_scaler.joblib")
        if os.path.exists(model_path) and os.path.exists(scaler_path):
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            self.is_trained = True
            logger.info("Isolation Forest model loaded from disk.")
