"""
Ensemble anomaly detection using multiple algorithms.
"""

from typing import Dict, List, Tuple
import numpy as np

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.cluster import DBSCAN
    from sklearn.neighbors import LocalOutlierFactor, NearestNeighbors
    from sklearn.preprocessing import StandardScaler
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

try:
    from scipy import stats
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False


class AdvancedAnomalyDetector:
    """
    Ensemble anomaly detection using multiple algorithms.
    Combines Isolation Forest, DBSCAN, LOF, and statistical methods.
    """

    def __init__(self, contamination: float = 0.1):
        self.contamination = contamination
        self.scaler = StandardScaler() if HAS_SKLEARN else None
        self.isolation_forest = None
        self.lof = None
        self.dbscan = None

    def detect_ensemble(self, features: np.ndarray) -> Tuple[np.ndarray, Dict]:
        """
        Ensemble anomaly detection - combines multiple methods for robust detection.
        Returns: (anomaly_labels, method_scores)
        """
        if not HAS_SKLEARN or len(features) < 10:
            return np.zeros(len(features)), {}

        scaled = self.scaler.fit_transform(features)
        n_samples = len(features)
        votes = np.zeros(n_samples)
        method_scores = {}

        # 1. Isolation Forest
        self.isolation_forest = IsolationForest(
            contamination=self.contamination, random_state=42, n_estimators=100
        )
        if_labels = self.isolation_forest.fit_predict(scaled)
        if_anomalies = (if_labels == -1).astype(int)
        votes += if_anomalies
        method_scores['isolation_forest'] = if_anomalies

        # 2. Local Outlier Factor
        self.lof = LocalOutlierFactor(
            n_neighbors=min(20, n_samples - 1), contamination=self.contamination
        )
        lof_labels = self.lof.fit_predict(scaled)
        lof_anomalies = (lof_labels == -1).astype(int)
        votes += lof_anomalies
        method_scores['lof'] = lof_anomalies

        # 3. DBSCAN (outliers are labeled -1)
        # Automatically find eps using k-distance
        k = min(5, n_samples - 1)
        nn = NearestNeighbors(n_neighbors=k)
        nn.fit(scaled)
        distances, _ = nn.kneighbors(scaled)
        k_distances = np.sort(distances[:, -1])
        eps = np.percentile(k_distances, 90)  # Use 90th percentile as eps

        self.dbscan = DBSCAN(eps=eps, min_samples=3)
        db_labels = self.dbscan.fit_predict(scaled)
        db_anomalies = (db_labels == -1).astype(int)
        votes += db_anomalies
        method_scores['dbscan'] = db_anomalies

        # 4. Statistical (Z-score)
        z_scores = np.abs(stats.zscore(features, axis=0)) if HAS_SCIPY else np.zeros_like(features)
        stat_anomalies = (np.max(z_scores, axis=1) > 3).astype(int)
        votes += stat_anomalies
        method_scores['statistical'] = stat_anomalies

        # Ensemble: anomaly if >= 2 methods agree
        ensemble_labels = (votes >= 2).astype(int) * -1  # -1 for anomaly
        ensemble_labels[ensemble_labels == 0] = 1  # 1 for normal

        method_scores['votes'] = votes
        method_scores['ensemble'] = (ensemble_labels == -1).astype(int)

        return ensemble_labels, method_scores

    def detect_change_points(self, time_series: np.ndarray, threshold: float = 2.0) -> List[int]:
        """
        Detect change points in time series using CUSUM algorithm.
        Returns indices where significant changes occur.
        """
        if len(time_series) < 10:
            return []

        mean = np.mean(time_series)
        std = np.std(time_series) or 1

        # CUSUM
        s_pos = np.zeros(len(time_series))
        s_neg = np.zeros(len(time_series))

        for i in range(1, len(time_series)):
            s_pos[i] = max(0, s_pos[i-1] + (time_series[i] - mean) / std - 0.5)
            s_neg[i] = max(0, s_neg[i-1] - (time_series[i] - mean) / std - 0.5)

        # Find points exceeding threshold
        change_points = []
        for i in range(1, len(time_series)):
            if s_pos[i] > threshold or s_neg[i] > threshold:
                if not change_points or i - change_points[-1] > 3:  # Min gap
                    change_points.append(i)
                    s_pos[i] = 0
                    s_neg[i] = 0

        return change_points
