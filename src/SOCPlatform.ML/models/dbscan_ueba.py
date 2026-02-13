"""
DBSCAN – User and Entity Behavioral Analytics (UEBA)
=====================================================
Clusters users by behavioral patterns and flags those who deviate from
their established baseline cluster. Noise points (label=-1) are
automatically flagged as anomalous.

Features (5-dimensional):
  - avg_events_per_day   : mean daily event count per user
  - distinct_event_types : number of unique event categories
  - avg_session_hour     : mean hour of activity (weighted)
  - resource_diversity   : distinct resources/endpoints accessed
  - weekend_ratio        : fraction of events occurring on weekends
"""

import numpy as np
import pandas as pd
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import NearestNeighbors
import joblib
import os
import logging
from datetime import datetime
from typing import Optional

logger = logging.getLogger("soc_ml.dbscan_ueba")

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "trained_models")


class UEBADetector:
    """DBSCAN-based User and Entity Behavioral Analytics detector."""

    def __init__(self):
        self.model: Optional[DBSCAN] = None
        self.scaler: Optional[StandardScaler] = None
        self.is_trained = False
        self.training_stats: dict = {}
        self._user_profiles: dict = {}  # username -> cluster label
        self._cluster_centers: dict = {}  # cluster_label -> mean feature vector
        self._trained_features: Optional[np.ndarray] = None
        self._trained_labels: Optional[np.ndarray] = None
        self._feature_names = [
            "avg_events_per_day", "distinct_event_types",
            "avg_session_hour", "resource_diversity", "weekend_ratio"
        ]

    # ── Feature Engineering ──────────────────────────

    def build_user_profiles(self, events: list[dict]) -> tuple[list[str], np.ndarray]:
        """
        Aggregate raw events into per-user behavioral profiles.

        Each event dict should have:
          - timestamp (datetime or ISO string)
          - username (str)
          - event_type (str)
          - resource (str, optional, e.g. endpoint or file path)
        """
        if not events:
            return [], np.empty((0, 5))

        df = pd.DataFrame(events)
        df["timestamp"] = pd.to_datetime(df.get("timestamp", datetime.utcnow()), utc=True, errors="coerce")
        df["username"] = df.get("username", "unknown")
        df["event_type"] = df.get("event_type", "unknown")
        df["resource"] = df.get("resource", "default")

        df["date"] = df["timestamp"].dt.date
        df["hour"] = df["timestamp"].dt.hour
        df["is_weekend"] = df["timestamp"].dt.weekday.isin([5, 6]).astype(int)

        usernames = []
        features = []

        for user, group in df.groupby("username"):
            days_active = max(group["date"].nunique(), 1)
            avg_events = len(group) / days_active
            distinct_types = group["event_type"].nunique()
            avg_hour = group["hour"].mean()
            resource_diversity = group["resource"].nunique()
            weekend_ratio = group["is_weekend"].mean()

            usernames.append(user)
            features.append([
                avg_events, distinct_types, avg_hour,
                resource_diversity, weekend_ratio
            ])

        return usernames, np.array(features, dtype=np.float64)

    def engineer_single_event(self, event: dict) -> np.ndarray:
        """Engineer features for a single event for real-time classification."""
        ts = pd.to_datetime(event.get("timestamp", datetime.utcnow()), utc=True)

        # Create a simple profile from the single event
        features = np.array([[
            1.0,  # avg_events_per_day (single event — will be compared to baseline)
            1,    # distinct_event_types
            ts.hour + ts.minute / 60.0,
            1,    # resource_diversity
            1.0 if ts.weekday() >= 5 else 0.0,
        ]], dtype=np.float64)

        return features

    # ── Auto-tune eps via k-distance ─────────────────

    @staticmethod
    def _auto_eps(X: np.ndarray, min_samples: int = 3) -> float:
        """Estimate DBSCAN eps using the k-distance elbow method."""
        k = min(min_samples, X.shape[0] - 1)
        if k < 1:
            return 0.5

        nn = NearestNeighbors(n_neighbors=k)
        nn.fit(X)
        distances, _ = nn.kneighbors(X)
        k_distances = np.sort(distances[:, -1])

        # Find the "elbow" — point of maximum curvature
        if len(k_distances) < 3:
            return float(np.mean(k_distances)) if len(k_distances) > 0 else 0.5

        # Use second derivative to find elbow
        d1 = np.diff(k_distances)
        d2 = np.diff(d1)
        if len(d2) > 0:
            elbow_idx = np.argmax(d2) + 1
            eps = float(k_distances[min(elbow_idx, len(k_distances) - 1)])
        else:
            eps = float(np.median(k_distances))

        return max(eps, 0.1)  # Minimum eps to avoid trivial clusters

    # ── Training ─────────────────────────────────────

    def train(self, events: list[dict]) -> dict:
        """
        Train DBSCAN on user behavioral profiles.
        Returns training statistics including cluster info.
        """
        logger.info(f"Training DBSCAN UEBA on {len(events)} events...")

        usernames, X = self.build_user_profiles(events)
        if X.shape[0] < 5:
            # Not enough users — generate synthetic profiles
            usernames, X = self._generate_synthetic_profiles()
            logger.info(f"Insufficient data, using synthetic profiles ({X.shape[0]} users)")

        # Scale features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        # Auto-tune eps
        min_samples = max(2, min(3, X_scaled.shape[0] // 5))
        eps = self._auto_eps(X_scaled, min_samples)
        logger.info(f"Auto-tuned eps={eps:.3f}, min_samples={min_samples}")

        # Train DBSCAN
        self.model = DBSCAN(eps=eps, min_samples=min_samples, metric="euclidean")
        labels = self.model.fit_predict(X_scaled)

        self._trained_features = X_scaled
        self._trained_labels = labels
        self.is_trained = True

        # Store user profiles and cluster centers
        self._user_profiles = {}
        for i, user in enumerate(usernames):
            self._user_profiles[user] = int(labels[i])

        self._cluster_centers = {}
        for label in set(labels):
            if label == -1:
                continue
            mask = labels == label
            self._cluster_centers[int(label)] = X_scaled[mask].mean(axis=0).tolist()

        n_clusters = len(set(labels) - {-1})
        n_noise = int(np.sum(labels == -1))

        self.training_stats = {
            "users_profiled": int(X.shape[0]),
            "features": int(X.shape[1]),
            "clusters": n_clusters,
            "noise_points": n_noise,
            "eps": round(eps, 4),
            "min_samples": min_samples,
            "anomaly_rate": round(n_noise / max(X.shape[0], 1) * 100, 2),
            "trained_at": datetime.utcnow().isoformat(),
        }

        self._save_model()
        logger.info(f"DBSCAN training complete: {self.training_stats}")
        return self.training_stats

    def predict(self, event: dict) -> dict:
        """
        Classify a single event: find closest cluster, compute distance-based score.
        """
        if not self.is_trained:
            self._load_model()

        if not self.is_trained:
            return {
                "is_anomaly": False, "anomaly_score": 0.0,
                "confidence": 0.0, "reason": "Model not trained",
                "model_used": "dbscan_ueba",
            }

        username = event.get("username", "unknown")

        # Check if user has a known profile
        if username in self._user_profiles:
            cluster = self._user_profiles[username]
            if cluster == -1:
                return {
                    "is_anomaly": True, "anomaly_score": 0.8,
                    "confidence": 0.85,
                    "reason": f"user '{username}' is classified as noise (no behavioral cluster)",
                    "model_used": "dbscan_ueba",
                }

        # Engineer features for the event
        X = self.engineer_single_event(event)
        X_scaled = self.scaler.transform(X)

        # Find distance to nearest cluster center
        min_dist = float("inf")
        nearest_cluster = -1
        for label, center in self._cluster_centers.items():
            dist = float(np.linalg.norm(X_scaled[0] - np.array(center)))
            if dist < min_dist:
                min_dist = dist
                nearest_cluster = label

        # Score: higher distance = more anomalous
        # Normalize using training data distances
        if self._trained_features is not None and len(self._cluster_centers) > 0:
            all_dists = []
            for feat, lab in zip(self._trained_features, self._trained_labels):
                if lab != -1 and lab in self._cluster_centers:
                    c = np.array(self._cluster_centers[lab])
                    all_dists.append(float(np.linalg.norm(feat - c)))
            if all_dists:
                mean_dist = np.mean(all_dists)
                std_dist = max(np.std(all_dists), 0.01)
                z = (min_dist - mean_dist) / std_dist
                anomaly_score = round(max(0.0, min(1.0, 0.5 + z * 0.2)), 4)
            else:
                anomaly_score = 0.5
        else:
            anomaly_score = 0.5

        is_anomaly = anomaly_score > 0.65
        confidence = round(min(1.0, abs(anomaly_score - 0.5) * 3), 4)

        reason = self._explain(event, min_dist, nearest_cluster, is_anomaly)

        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": anomaly_score,
            "confidence": confidence,
            "reason": reason,
            "model_used": "dbscan_ueba",
            "nearest_cluster": nearest_cluster,
        }

    def _explain(self, event: dict, dist: float, cluster: int, is_anomaly: bool) -> str:
        username = event.get("username", "unknown")
        if is_anomaly:
            return (f"user '{username}' behavior deviates significantly from cluster {cluster} "
                    f"(distance={dist:.2f})")
        return f"user '{username}' behavior is consistent with cluster {cluster}"

    # ── Synthetic Profiles ───────────────────────────

    def _generate_synthetic_profiles(self, n_users: int = 60) -> tuple[list[str], np.ndarray]:
        """Generate realistic synthetic user behavioral profiles."""
        rng = np.random.default_rng(42)

        # Cluster 1: Regular analysts (high activity, business hours)
        n1 = n_users // 3
        c1 = np.column_stack([
            rng.normal(50, 10, n1).clip(10),     # avg events/day
            rng.poisson(5, n1) + 2,              # event types
            rng.normal(13, 2, n1).clip(8, 18),   # avg hour
            rng.poisson(8, n1) + 3,              # resource diversity
            rng.beta(1, 8, n1),                  # low weekend ratio
        ])

        # Cluster 2: Managers (less activity, meetings)
        n2 = n_users // 3
        c2 = np.column_stack([
            rng.normal(15, 5, n2).clip(5),
            rng.poisson(3, n2) + 1,
            rng.normal(11, 1.5, n2).clip(9, 17),
            rng.poisson(4, n2) + 2,
            rng.beta(1, 10, n2),
        ])

        # Cluster 3: Off-hours / suspect users
        n3 = n_users - n1 - n2
        c3 = np.column_stack([
            rng.normal(100, 30, n3).clip(20),    # very high activity
            rng.poisson(10, n3) + 5,             # many event types
            rng.normal(3, 2, n3).clip(0, 6),     # late night
            rng.poisson(15, n3) + 8,             # high resource diversity
            rng.beta(4, 2, n3),                  # high weekend ratio
        ])

        X = np.vstack([c1, c2, c3])
        names = [f"user_{i}" for i in range(n_users)]
        return names, X

    # ── Persistence ──────────────────────────────────

    def _save_model(self):
        os.makedirs(MODEL_DIR, exist_ok=True)
        joblib.dump({
            "model": self.model,
            "scaler": self.scaler,
            "user_profiles": self._user_profiles,
            "cluster_centers": self._cluster_centers,
            "trained_features": self._trained_features,
            "trained_labels": self._trained_labels,
            "stats": self.training_stats,
        }, os.path.join(MODEL_DIR, "dbscan_ueba.joblib"))
        logger.info("DBSCAN UEBA model saved.")

    def _load_model(self):
        path = os.path.join(MODEL_DIR, "dbscan_ueba.joblib")
        if os.path.exists(path):
            data = joblib.load(path)
            self.model = data["model"]
            self.scaler = data["scaler"]
            self._user_profiles = data["user_profiles"]
            self._cluster_centers = data["cluster_centers"]
            self._trained_features = data["trained_features"]
            self._trained_labels = data["trained_labels"]
            self.training_stats = data["stats"]
            self.is_trained = True
            logger.info("DBSCAN UEBA model loaded from disk.")
