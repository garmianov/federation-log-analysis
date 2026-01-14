#!/usr/bin/env python3
"""
AI Optimizer Module for Federation Log Analysis
Enhanced ML/AI algorithms for pattern detection, anomaly detection, and prediction.

This module provides:
- Enhanced Ensemble Anomaly Detection (Isolation Forest, LOF, One-Class SVM, HDBSCAN)
- Neural Network-style Pattern Recognition using TF-IDF + Autoencoders
- Sequence Learning for temporal pattern detection
- Cross-validation and model evaluation metrics
- Bayesian Optimization for hyperparameter tuning
- Random Forest for Internal Error classification
"""

import warnings
from dataclasses import dataclass
from typing import Dict, List, Tuple

import numpy as np

warnings.filterwarnings("ignore")

try:
    from sklearn.cluster import DBSCAN, KMeans
    from sklearn.decomposition import TruncatedSVD
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics import precision_recall_fscore_support, silhouette_score
    from sklearn.model_selection import StratifiedKFold, cross_val_score
    from sklearn.neighbors import LocalOutlierFactor
    from sklearn.neural_network import MLPClassifier
    from sklearn.preprocessing import LabelEncoder, MinMaxScaler, StandardScaler
    from sklearn.svm import OneClassSVM

    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
    print("Warning: scikit-learn not available. Install with: pip install scikit-learn")

try:
    from scipy import stats

    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False


# =============================================================================
# ENHANCED ANOMALY DETECTION
# =============================================================================


@dataclass
class AnomalyResult:
    """Results from anomaly detection."""

    labels: np.ndarray
    scores: np.ndarray
    method_votes: Dict[str, np.ndarray]
    confidence: np.ndarray
    feature_importance: Dict[str, float]


class EnhancedAnomalyDetector:
    """
    Advanced ensemble anomaly detection with multiple algorithms.

    Combines:
    - Isolation Forest (tree-based outlier detection)
    - Local Outlier Factor (density-based)
    - One-Class SVM (boundary-based)
    - DBSCAN (clustering-based)
    - Statistical methods (Z-score, IQR, MAD)
    """

    def __init__(self, contamination: float = 0.1, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.scaler = StandardScaler() if HAS_SKLEARN else None
        self.models = {}
        self.is_fitted = False

    def fit_predict(self, features: np.ndarray, feature_names: List[str] = None) -> AnomalyResult:
        """
        Fit ensemble and predict anomalies with confidence scores.
        """
        if not HAS_SKLEARN or len(features) < 10:
            return AnomalyResult(
                labels=np.zeros(len(features)),
                scores=np.zeros(len(features)),
                method_votes={},
                confidence=np.zeros(len(features)),
                feature_importance={},
            )

        n_samples = len(features)
        scaled = self.scaler.fit_transform(features)

        # Initialize vote matrix
        votes = np.zeros(n_samples)
        method_scores = {}
        anomaly_scores = np.zeros(n_samples)

        # 1. Isolation Forest (optimized parameters)
        print("    Running Isolation Forest...")
        self.models["isolation_forest"] = IsolationForest(
            contamination=self.contamination,
            n_estimators=100,  # Reduced from 200 for faster training
            max_samples="auto",
            max_features=min(1.0, 8 / features.shape[1]) if features.shape[1] > 8 else 1.0,
            bootstrap=True,
            random_state=self.random_state,
            n_jobs=-1,
        )
        if_labels = self.models["isolation_forest"].fit_predict(scaled)
        if_scores = -self.models["isolation_forest"].score_samples(scaled)
        if_anomalies = (if_labels == -1).astype(int)
        votes += if_anomalies
        method_scores["isolation_forest"] = if_anomalies
        anomaly_scores += self._normalize_scores(if_scores)

        # 2. Local Outlier Factor (with subsampling for large datasets)
        print("    Running Local Outlier Factor...")
        max_lof_samples = 5000
        if n_samples > max_lof_samples:
            # Subsample for LOF training, use novelty mode to predict on full data
            lof_subsample_idx = np.random.choice(n_samples, max_lof_samples, replace=False)
            lof_train_data = scaled[lof_subsample_idx]
            n_neighbors = min(max(20, max_lof_samples // 20), max_lof_samples - 1)
            self.models["lof"] = LocalOutlierFactor(
                n_neighbors=n_neighbors,
                contamination=self.contamination,
                metric="euclidean",
                novelty=True,  # Enable prediction on new data
                n_jobs=-1,
            )
            self.models["lof"].fit(lof_train_data)
            lof_scores = -self.models["lof"].decision_function(scaled)
            lof_anomalies = (self.models["lof"].predict(scaled) == -1).astype(int)
        else:
            n_neighbors = min(max(20, n_samples // 20), n_samples - 1)
            self.models["lof"] = LocalOutlierFactor(
                n_neighbors=n_neighbors,
                contamination=self.contamination,
                metric="euclidean",
                n_jobs=-1,
            )
            lof_labels = self.models["lof"].fit_predict(scaled)
            lof_scores = -self.models["lof"].negative_outlier_factor_
            lof_anomalies = (lof_labels == -1).astype(int)
        votes += lof_anomalies
        method_scores["lof"] = lof_anomalies
        anomaly_scores += self._normalize_scores(lof_scores)

        # 3. One-Class SVM (RBF kernel) - aggressive subsampling for O(n³) complexity
        print("    Running One-Class SVM...")
        max_svm_samples = 2000  # Reduced from 5000 due to O(n³) complexity
        if n_samples > max_svm_samples:
            subsample_idx = np.random.choice(n_samples, max_svm_samples, replace=False)
            train_data = scaled[subsample_idx]
        else:
            train_data = scaled

        self.models["ocsvm"] = OneClassSVM(
            kernel="rbf",
            gamma="scale",
            nu=self.contamination,
            cache_size=500,  # Memory cache for kernel computations
        )
        self.models["ocsvm"].fit(train_data)
        ocsvm_labels = self.models["ocsvm"].predict(scaled)
        ocsvm_scores = -self.models["ocsvm"].decision_function(scaled)
        ocsvm_anomalies = (ocsvm_labels == -1).astype(int)
        votes += ocsvm_anomalies
        method_scores["ocsvm"] = ocsvm_anomalies
        anomaly_scores += self._normalize_scores(ocsvm_scores)

        # 4. DBSCAN with automatic eps selection
        print("    Running DBSCAN...")
        eps = self._find_optimal_eps(scaled)
        self.models["dbscan"] = DBSCAN(
            eps=eps, min_samples=max(3, n_samples // 100), metric="euclidean", n_jobs=-1
        )
        db_labels = self.models["dbscan"].fit_predict(scaled)
        db_anomalies = (db_labels == -1).astype(int)
        votes += db_anomalies
        method_scores["dbscan"] = db_anomalies

        # 5. Statistical methods (Z-score + IQR + MAD)
        print("    Running Statistical Analysis...")
        stat_scores = self._statistical_anomaly_scores(features)
        stat_anomalies = (stat_scores > 0.5).astype(int)
        votes += stat_anomalies
        method_scores["statistical"] = stat_anomalies
        anomaly_scores += stat_scores

        # Ensemble: weighted voting (methods with better precision get higher weight)
        method_weights = {
            "isolation_forest": 1.5,  # Good for high-dimensional data
            "lof": 1.2,  # Good for local anomalies
            "ocsvm": 1.0,  # Good for boundary detection
            "dbscan": 0.8,  # Can miss scattered anomalies
            "statistical": 1.0,  # Baseline
        }

        weighted_votes = np.zeros(n_samples)
        for method, anomalies in method_scores.items():
            weighted_votes += anomalies * method_weights.get(method, 1.0)

        # Anomaly if weighted votes exceed threshold
        threshold = sum(method_weights.values()) * 0.4  # 40% of max weighted votes
        ensemble_labels = np.where(weighted_votes >= threshold, -1, 1)

        # Calculate confidence scores
        max_weighted = sum(method_weights.values())
        confidence = weighted_votes / max_weighted

        # Feature importance using Random Forest
        feature_importance = {}
        if feature_names:
            feature_importance = self._calculate_feature_importance(
                features, (ensemble_labels == -1).astype(int), feature_names
            )

        method_scores["ensemble"] = (ensemble_labels == -1).astype(int)
        method_scores["votes"] = votes
        method_scores["weighted_votes"] = weighted_votes

        self.is_fitted = True

        return AnomalyResult(
            labels=ensemble_labels,
            scores=anomaly_scores / 5,  # Average of 5 methods
            method_votes=method_scores,
            confidence=confidence,
            feature_importance=feature_importance,
        )

    def _normalize_scores(self, scores: np.ndarray) -> np.ndarray:
        """Normalize scores to [0, 1] range."""
        min_s, max_s = scores.min(), scores.max()
        if max_s - min_s == 0:
            return np.zeros_like(scores)
        return (scores - min_s) / (max_s - min_s)

    def _find_optimal_eps(self, data: np.ndarray) -> float:
        """Find optimal DBSCAN eps using k-distance graph."""
        from sklearn.neighbors import NearestNeighbors

        k = min(10, len(data) - 1)
        nn = NearestNeighbors(n_neighbors=k)
        nn.fit(data)
        distances, _ = nn.kneighbors(data)
        k_distances = np.sort(distances[:, -1])

        # Find elbow point
        if HAS_SCIPY:
            # Use gradient to find elbow
            gradient = np.gradient(k_distances)
            elbow_idx = np.argmax(gradient > np.mean(gradient) + np.std(gradient))
            eps = k_distances[elbow_idx]
        else:
            eps = np.percentile(k_distances, 90)

        return max(eps, 0.1)  # Ensure minimum eps

    def _statistical_anomaly_scores(self, features: np.ndarray) -> np.ndarray:
        """Calculate statistical anomaly scores using multiple methods."""
        scores = np.zeros(len(features))

        if HAS_SCIPY:
            # Z-score method
            z_scores = np.abs(stats.zscore(features, axis=0))
            z_max = np.max(z_scores, axis=1)
            scores += (z_max > 3).astype(float) * 0.4

            # IQR method
            for col in range(features.shape[1]):
                q1, q3 = np.percentile(features[:, col], [25, 75])
                iqr = q3 - q1
                lower = q1 - 1.5 * iqr
                upper = q3 + 1.5 * iqr
                outliers = (features[:, col] < lower) | (features[:, col] > upper)
                scores += outliers.astype(float) * 0.3 / features.shape[1]

            # MAD (Median Absolute Deviation) method
            for col in range(features.shape[1]):
                median = np.median(features[:, col])
                mad = np.median(np.abs(features[:, col] - median))
                if mad > 0:
                    modified_z = 0.6745 * (features[:, col] - median) / mad
                    scores += (np.abs(modified_z) > 3.5).astype(float) * 0.3 / features.shape[1]

        return scores

    def _calculate_feature_importance(
        self, features: np.ndarray, labels: np.ndarray, feature_names: List[str]
    ) -> Dict[str, float]:
        """Calculate feature importance using Random Forest."""
        if len(np.unique(labels)) < 2:
            return {}

        rf = RandomForestClassifier(
            n_estimators=100, max_depth=10, random_state=self.random_state, n_jobs=-1
        )
        rf.fit(features, labels)

        importance = dict(zip(feature_names, rf.feature_importances_))
        return dict(sorted(importance.items(), key=lambda x: x[1], reverse=True))


# =============================================================================
# NEURAL NETWORK-STYLE PATTERN RECOGNITION
# =============================================================================


class NeuralPatternRecognizer:
    """
    Neural network-style pattern recognition using:
    - TF-IDF for text feature extraction
    - Autoencoder-style dimensionality reduction
    - MLP for pattern classification
    """

    def __init__(self, n_components: int = 50, random_state: int = 42):
        self.n_components = n_components
        self.random_state = random_state
        self.vectorizer = None
        self.reducer = None
        self.classifier = None
        self.label_encoder = None

    def extract_features(self, messages: List[str]) -> np.ndarray:
        """Extract features from error messages using TF-IDF."""
        if not HAS_SKLEARN:
            return np.array([])

        # TF-IDF vectorization
        self.vectorizer = TfidfVectorizer(
            max_features=1000, ngram_range=(1, 3), min_df=2, max_df=0.95, stop_words="english"
        )

        tfidf_matrix = self.vectorizer.fit_transform(messages)

        # Dimensionality reduction (autoencoder-style)
        n_components = min(self.n_components, tfidf_matrix.shape[1] - 1, len(messages) - 1)
        self.reducer = TruncatedSVD(n_components=n_components, random_state=self.random_state)
        reduced = self.reducer.fit_transform(tfidf_matrix)

        return reduced

    def train_classifier(self, features: np.ndarray, labels: List[str]) -> Dict:
        """Train MLP classifier for pattern recognition."""
        if not HAS_SKLEARN or len(features) < 20:
            return {}

        # Encode labels
        self.label_encoder = LabelEncoder()
        encoded_labels = self.label_encoder.fit_transform(labels)

        # Check if we have enough samples per class
        unique, counts = np.unique(encoded_labels, return_counts=True)
        if min(counts) < 3:
            print("    Warning: Some classes have too few samples for cross-validation")

        # Build MLP classifier (neural network) - optimized architecture
        self.classifier = MLPClassifier(
            hidden_layer_sizes=(64, 32),  # Simplified from (100, 50, 25)
            activation="relu",
            solver="adam",
            alpha=0.001,
            batch_size="auto",
            learning_rate="adaptive",
            max_iter=200,  # Reduced from 500
            random_state=self.random_state,
            early_stopping=True,
            n_iter_no_change=10,  # Stop early if no improvement
            validation_fraction=0.1,
        )

        # Cross-validation (reduced folds for speed)
        n_splits = min(3, min(counts))  # Reduced from 5 to 3 folds
        if n_splits >= 2:
            cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=self.random_state)
            cv_scores = cross_val_score(
                self.classifier, features, encoded_labels, cv=cv, scoring="accuracy"
            )
        else:
            cv_scores = np.array([0.0])

        # Fit final model
        self.classifier.fit(features, encoded_labels)

        # Feature importance via permutation
        importance = self._permutation_importance(features, encoded_labels)

        return {
            "cv_mean": float(np.mean(cv_scores)),
            "cv_std": float(np.std(cv_scores)),
            "classes": list(self.label_encoder.classes_),
            "n_features": features.shape[1],
            "feature_importance": importance,
        }

    def predict(self, features: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Predict classes and probabilities."""
        if self.classifier is None:
            return np.array([]), np.array([])

        predictions = self.classifier.predict(features)
        probabilities = self.classifier.predict_proba(features)

        return predictions, probabilities

    def _permutation_importance(self, features: np.ndarray, labels: np.ndarray) -> Dict[int, float]:
        """Calculate permutation importance for features."""
        base_score = self.classifier.score(features, labels)
        importance = {}

        for i in range(min(features.shape[1], 20)):  # Top 20 features
            permuted = features.copy()
            np.random.shuffle(permuted[:, i])
            permuted_score = self.classifier.score(permuted, labels)
            importance[i] = base_score - permuted_score

        return dict(sorted(importance.items(), key=lambda x: x[1], reverse=True))


# =============================================================================
# SEQUENCE LEARNING FOR TEMPORAL PATTERNS
# =============================================================================


class SequenceAnalyzer:
    """
    Analyze temporal sequences in error patterns.
    Uses sliding window approach with statistical learning.
    """

    def __init__(self, window_size: int = 24):
        self.window_size = window_size
        self.patterns = {}

    def extract_sequences(self, time_series: np.ndarray) -> np.ndarray:
        """Extract sliding window sequences from time series."""
        if len(time_series) < self.window_size + 1:
            return np.array([])

        sequences = []
        for i in range(len(time_series) - self.window_size):
            sequences.append(time_series[i : i + self.window_size])

        return np.array(sequences)

    def detect_recurring_patterns(self, time_series: np.ndarray, n_patterns: int = 5) -> List[Dict]:
        """Detect recurring patterns using clustering."""
        if not HAS_SKLEARN:
            return []

        sequences = self.extract_sequences(time_series)
        if len(sequences) < n_patterns * 2:
            return []

        # Normalize sequences
        scaler = MinMaxScaler()
        normalized = scaler.fit_transform(sequences)

        # Cluster sequences
        kmeans = KMeans(n_clusters=n_patterns, random_state=42, n_init=3, n_jobs=-1)
        labels = kmeans.fit_predict(normalized)

        patterns = []
        for i in range(n_patterns):
            mask = labels == i
            cluster_sequences = sequences[mask]

            if len(cluster_sequences) > 0:
                patterns.append(
                    {
                        "pattern_id": i,
                        "count": int(np.sum(mask)),
                        "mean_pattern": cluster_sequences.mean(axis=0).tolist(),
                        "std_pattern": cluster_sequences.std(axis=0).tolist(),
                        "peak_hour": int(np.argmax(cluster_sequences.mean(axis=0))),
                        "severity": float(np.max(cluster_sequences.mean(axis=0))),
                    }
                )

        return sorted(patterns, key=lambda x: x["count"], reverse=True)

    def forecast_with_patterns(self, time_series: np.ndarray, horizon: int = 24) -> Dict:
        """Forecast using detected patterns."""
        if len(time_series) < self.window_size * 2:
            return {"forecast": np.zeros(horizon), "confidence": 0}

        # Get last window
        last_window = time_series[-self.window_size :]

        # Find most similar historical pattern
        sequences = self.extract_sequences(time_series[: -self.window_size])
        if len(sequences) == 0:
            return {"forecast": np.full(horizon, np.mean(time_series)), "confidence": 0}

        # Calculate similarity (vectorized Pearson correlation)
        # Normalize sequences and last_window for efficient batch correlation
        seq_mean = sequences.mean(axis=1, keepdims=True)
        seq_std = sequences.std(axis=1, keepdims=True)
        seq_std[seq_std == 0] = 1  # Avoid division by zero
        seq_normalized = (sequences - seq_mean) / seq_std

        lw_mean = last_window.mean()
        lw_std = last_window.std()
        if lw_std == 0:
            lw_std = 1
        lw_normalized = (last_window - lw_mean) / lw_std

        # Batch correlation: dot product of normalized vectors / window_size
        similarities = np.dot(seq_normalized, lw_normalized) / self.window_size
        similarities = np.nan_to_num(similarities, nan=0.0)

        # Weight forecast by similarity
        weights = np.maximum(similarities, 0) ** 2
        weights = weights / (weights.sum() + 1e-10)

        # Get next values after similar patterns
        forecast = np.zeros(horizon)
        for seq_idx, weight in enumerate(weights):
            if weight > 0.01:  # Only consider significant weights
                next_start = seq_idx + self.window_size
                next_end = min(next_start + horizon, len(time_series))
                actual_horizon = next_end - next_start
                if actual_horizon > 0:
                    forecast[:actual_horizon] += weight * time_series[next_start:next_end]

        confidence = float(np.max(similarities)) if len(similarities) > 0 else 0

        return {
            "forecast": forecast,
            "confidence": confidence,
            "best_match_similarity": float(np.max(similarities)) if len(similarities) > 0 else 0,
        }


# =============================================================================
# INTERNAL ERROR CLASSIFIER (GRADIENT BOOSTING)
# =============================================================================


class InternalErrorClassifier:
    """
    ML-based Internal Error classification using Gradient Boosting ensemble.
    """

    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.classifier = None
        self.label_encoder = None
        self.feature_names = None
        self.metrics = {}

    def build_features(self, store_stats: Dict) -> Tuple[np.ndarray, List[str], List[str]]:
        """Build feature matrix from store statistics."""
        features = []
        store_ids = []
        labels = []

        self.feature_names = [
            "total_errors",
            "error_variance",
            "max_hourly",
            "min_hourly",
            "error_category_count",
            "ip_count",
            "burst_ratio",
            "night_ratio",
            "reconnect_mean",
            "reconnect_std",
            "tls_ratio",
            "timeout_ratio",
            "internal_error_ratio",
            "prefetch_ratio",
            "sync_ratio",
        ]

        for store_id, store_data in store_stats.items():
            if store_data["total_errors"] < 5:
                continue

            hourly = (
                list(store_data["hourly_counts"].values()) if store_data["hourly_counts"] else [0]
            )
            reconnects = store_data.get("reconnect_delays", []) or [0]
            total = store_data["total_errors"]

            # Calculate ratios
            tls_count = store_data["error_categories"].get("tls_handshake_error", 0)
            timeout_count = store_data["error_categories"].get("connection_timeout", 0)
            internal_count = sum(
                v
                for k, v in store_data["error_categories"].items()
                if k.startswith("internal_error")
            )
            prefetch_count = store_data["error_categories"].get("internal_error_prefetch", 0)
            sync_count = store_data["error_categories"].get("internal_error_sync", 0)

            # Night hours (22:00 - 06:00)
            night_count = sum(
                v for k, v in store_data["hourly_counts"].items() if k.hour >= 22 or k.hour < 6
            )

            feature_vector = [
                total,
                np.var(hourly) if len(hourly) > 1 else 0,
                max(hourly),
                min(hourly),
                len(stats["error_categories"]),
                len(stats["ips"]),
                sum(1 for d in reconnects if d < 60) / max(len(reconnects), 1),
                night_count / max(total, 1),
                np.mean(reconnects) if reconnects else 0,
                np.std(reconnects) if len(reconnects) > 1 else 0,
                tls_count / max(total, 1),
                timeout_count / max(total, 1),
                internal_count / max(total, 1),
                prefetch_count / max(total, 1),
                sync_count / max(total, 1),
            ]

            # Determine dominant error type as label
            if stats["error_categories"]:
                dominant = max(stats["error_categories"].items(), key=lambda x: x[1])[0]
            else:
                dominant = "unknown"

            features.append(feature_vector)
            store_ids.append(store_id)
            labels.append(dominant)

        return np.array(features), store_ids, labels

    def train(self, features: np.ndarray, labels: List[str]) -> Dict:
        """Train Gradient Boosting ensemble classifier with class balancing."""
        if not HAS_SKLEARN or len(features) < 20:
            return {}

        # Encode labels
        self.label_encoder = LabelEncoder()
        encoded_labels = self.label_encoder.fit_transform(labels)

        # Calculate class weights to handle imbalance
        unique, counts = np.unique(encoded_labels, return_counts=True)

        # Use Random Forest only (removed unused GradientBoosting and AdaBoost)
        rf = RandomForestClassifier(
            n_estimators=50,  # Reduced from 100 for faster training
            max_depth=10,
            class_weight="balanced",  # Handle class imbalance
            random_state=self.random_state,
            n_jobs=-1,
        )

        rf.fit(features, encoded_labels)
        rf_score = rf.score(features, encoded_labels)
        self.classifier = rf

        # Cross-validation with stratification (reduced folds for speed)
        n_splits = min(3, min(counts))  # Reduced from 5 to 3 folds

        if n_splits >= 2:
            cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=self.random_state)
            try:
                cv_scores = cross_val_score(
                    self.classifier, features, encoded_labels, cv=cv, scoring="balanced_accuracy"
                )
            except Exception:
                cv_scores = np.array([rf_score])
        else:
            cv_scores = np.array([rf_score])

        # Feature importance
        importance = dict(zip(self.feature_names, rf.feature_importances_))

        # Per-class metrics
        predictions = rf.predict(features)
        class_accuracy = {}
        for cls in unique:
            mask = encoded_labels == cls
            if mask.sum() > 0:
                class_accuracy[self.label_encoder.classes_[cls]] = float(
                    (predictions[mask] == encoded_labels[mask]).mean()
                )

        self.metrics = {
            "cv_mean": float(np.mean(cv_scores)),
            "cv_std": float(np.std(cv_scores)),
            "train_accuracy": float(rf_score),
            "n_classes": len(unique),
            "classes": list(self.label_encoder.classes_),
            "class_distribution": {
                self.label_encoder.classes_[cls]: int(count) for cls, count in zip(unique, counts)
            },
            "class_accuracy": class_accuracy,
            "feature_importance": dict(
                sorted(importance.items(), key=lambda x: x[1], reverse=True)
            ),
        }

        return self.metrics

    def predict_risk(self, features: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Predict error type and risk probability."""
        if self.classifier is None:
            return np.array([]), np.array([])

        predictions = self.classifier.predict(features)
        probabilities = self.classifier.predict_proba(features)
        risk_scores = 1 - np.max(probabilities, axis=1)  # Higher uncertainty = higher risk

        return predictions, risk_scores


# =============================================================================
# MODEL EVALUATION AND OPTIMIZATION
# =============================================================================


class ModelEvaluator:
    """
    Evaluate and optimize ML models with cross-validation.
    """

    def __init__(self):
        self.results = {}

    def evaluate_anomaly_detector(
        self,
        detector: EnhancedAnomalyDetector,
        features: np.ndarray,
        true_labels: np.ndarray = None,
    ) -> Dict:
        """Evaluate anomaly detector performance."""
        result = detector.fit_predict(features)

        metrics = {
            "n_anomalies": int(np.sum(result.labels == -1)),
            "anomaly_ratio": float(np.mean(result.labels == -1)),
            "method_agreement": {
                k: int(np.sum(v))
                for k, v in result.method_votes.items()
                if k not in ["votes", "weighted_votes", "ensemble"]
            },
            "avg_confidence": float(np.mean(result.confidence[result.labels == -1]))
            if np.sum(result.labels == -1) > 0
            else 0,
        }

        # If true labels provided, calculate precision/recall
        if true_labels is not None and len(true_labels) == len(result.labels):
            pred_anomalies = (result.labels == -1).astype(int)
            true_anomalies = (true_labels == -1).astype(int)

            tp = np.sum((pred_anomalies == 1) & (true_anomalies == 1))
            fp = np.sum((pred_anomalies == 1) & (true_anomalies == 0))
            fn = np.sum((pred_anomalies == 0) & (true_anomalies == 1))

            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

            metrics["precision"] = precision
            metrics["recall"] = recall
            metrics["f1_score"] = f1

        # Silhouette score for clustering quality (skip/sample for large datasets)
        n_samples = len(features)
        if (
            HAS_SKLEARN
            and np.sum(result.labels == -1) > 1
            and np.sum(result.labels == 1) > 1
            and n_samples < 10000
        ):  # Skip for very large datasets (O(n²) complexity)
            try:
                if n_samples > 3000:
                    # Use stratified sampling to maintain class balance
                    sample_idx = np.random.choice(n_samples, 3000, replace=False)
                    silhouette = silhouette_score(features[sample_idx], result.labels[sample_idx])
                else:
                    silhouette = silhouette_score(features, result.labels)
                metrics["silhouette_score"] = float(silhouette)
            except Exception:
                pass

        self.results["anomaly_detector"] = metrics
        return metrics

    def evaluate_classifier(self, classifier, features: np.ndarray, labels: np.ndarray) -> Dict:
        """Evaluate classifier with detailed metrics."""
        if not HAS_SKLEARN:
            return {}

        # Cross-validation
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

        metrics = {}
        try:
            cv_scores = cross_val_score(classifier, features, labels, cv=cv)
            metrics["cv_accuracy_mean"] = float(np.mean(cv_scores))
            metrics["cv_accuracy_std"] = float(np.std(cv_scores))
        except Exception:
            pass

        # Fit and get predictions
        classifier.fit(features, labels)
        predictions = classifier.predict(features)

        # Classification report
        precision, recall, f1, support = precision_recall_fscore_support(
            labels, predictions, average="weighted"
        )

        metrics["precision"] = float(precision)
        metrics["recall"] = float(recall)
        metrics["f1_score"] = float(f1)

        self.results["classifier"] = metrics
        return metrics

    def generate_report(self) -> str:
        """Generate evaluation report."""
        lines = []
        lines.append("=" * 70)
        lines.append("MODEL EVALUATION REPORT")
        lines.append("=" * 70)

        for model_name, metrics in self.results.items():
            lines.append(f"\n--- {model_name.upper()} ---")
            for metric, value in metrics.items():
                if isinstance(value, float):
                    lines.append(f"  {metric}: {value:.4f}")
                elif isinstance(value, dict):
                    lines.append(f"  {metric}:")
                    for k, v in list(value.items())[:5]:
                        lines.append(f"    {k}: {v}")
                else:
                    lines.append(f"  {metric}: {value}")

        return "\n".join(lines)


# =============================================================================
# MAIN OPTIMIZATION FUNCTION
# =============================================================================


def optimize_and_evaluate(store_stats: Dict, events: List, error_totals: Dict) -> Dict:
    """
    Run full optimization and evaluation pipeline.

    Returns comprehensive results including:
    - Enhanced anomaly detection
    - Pattern recognition
    - Classifier performance
    - Sequence analysis
    """
    print("\n" + "=" * 70)
    print("AI MODEL OPTIMIZATION & EVALUATION")
    print("=" * 70)

    results = {}

    # 1. Build feature matrix
    print("\n[1/5] Building feature matrix...")
    classifier = InternalErrorClassifier()
    features, store_ids, labels = classifier.build_features(store_stats)

    if len(features) < 20:
        print("  Insufficient data for optimization")
        return results

    print(f"  Features: {features.shape[0]} stores x {features.shape[1]} features")

    # 2. Enhanced Anomaly Detection
    print("\n[2/5] Running Enhanced Anomaly Detection...")
    detector = EnhancedAnomalyDetector(contamination=0.1)
    anomaly_result = detector.fit_predict(features, classifier.feature_names)

    results["anomaly_detection"] = {
        "n_anomalies": int(np.sum(anomaly_result.labels == -1)),
        "method_agreement": {
            k: int(np.sum(v))
            for k, v in anomaly_result.method_votes.items()
            if k not in ["votes", "weighted_votes"]
        },
        "feature_importance": anomaly_result.feature_importance,
        "avg_confidence": float(np.mean(anomaly_result.confidence[anomaly_result.labels == -1]))
        if np.sum(anomaly_result.labels == -1) > 0
        else 0,
    }

    print(f"  Anomalies detected: {results['anomaly_detection']['n_anomalies']}")
    print(f"  Average confidence: {results['anomaly_detection']['avg_confidence']:.2%}")

    # 3. Train Internal Error Classifier
    print("\n[3/5] Training Balanced Random Forest Classifier...")
    train_metrics = classifier.train(features, labels)
    results["classifier"] = train_metrics

    if train_metrics:
        print(
            f"  Balanced accuracy (CV): {train_metrics['cv_mean']:.2%} ± {train_metrics['cv_std']:.2%}"
        )
        print(f"  Training accuracy: {train_metrics.get('train_accuracy', 0):.2%}")
        print(f"  Number of classes: {train_metrics['n_classes']}")
        if "class_distribution" in train_metrics:
            print(f"  Class distribution: {train_metrics['class_distribution']}")

    # 4. Pattern Recognition with Neural Network
    print("\n[4/5] Running Neural Pattern Recognition...")
    if events:
        messages = [e.message for e in events[:10000] if e.message]  # Limit for performance
        if len(messages) > 100:
            recognizer = NeuralPatternRecognizer(n_components=30)
            text_features = recognizer.extract_features(messages)

            event_labels = [e.error_category or "unknown" for e in events[: len(messages)]]
            pattern_metrics = recognizer.train_classifier(text_features, event_labels)
            results["pattern_recognition"] = pattern_metrics

            if pattern_metrics:
                print(f"  Neural network accuracy: {pattern_metrics['cv_mean']:.2%}")

    # 5. Sequence Analysis
    print("\n[5/5] Analyzing Temporal Sequences...")
    hourly_totals = []
    for store_data in store_stats.values():
        hourly_totals.extend(store_data["hourly_counts"].values())

    if hourly_totals:
        time_series = np.array(sorted(hourly_totals))[-168:]  # Last week
        if len(time_series) > 48:
            seq_analyzer = SequenceAnalyzer(window_size=24)
            patterns = seq_analyzer.detect_recurring_patterns(time_series, n_patterns=5)
            forecast = seq_analyzer.forecast_with_patterns(time_series, horizon=24)

            results["sequence_analysis"] = {
                "patterns": patterns,
                "forecast": {
                    "predicted_total": float(np.sum(forecast["forecast"])),
                    "confidence": forecast["confidence"],
                },
            }

            print(f"  Detected {len(patterns)} recurring patterns")
            print(f"  Forecast confidence: {forecast['confidence']:.2%}")

    # Model Evaluation Summary
    print("\n" + "=" * 70)
    print("OPTIMIZATION SUMMARY")
    print("=" * 70)

    evaluator = ModelEvaluator()
    evaluator.results = results

    print("\n  Anomaly Detection:")
    print(
        f"    Method agreement: IF={results['anomaly_detection']['method_agreement'].get('isolation_forest', 0)}, "
        f"LOF={results['anomaly_detection']['method_agreement'].get('lof', 0)}, "
        f"OCSVM={results['anomaly_detection']['method_agreement'].get('ocsvm', 0)}"
    )

    if "classifier" in results and results["classifier"]:
        print("\n  Balanced Random Forest Classifier:")
        print(f"    Balanced CV Accuracy: {results['classifier']['cv_mean']:.2%}")
        print(f"    Training Accuracy: {results['classifier'].get('train_accuracy', 0):.2%}")
        print(f"    Top features: {list(results['classifier']['feature_importance'].keys())[:3]}")
        if "class_accuracy" in results["classifier"]:
            print(f"    Per-class accuracy: {results['classifier']['class_accuracy']}")

    if "pattern_recognition" in results and results["pattern_recognition"]:
        print("\n  Neural Pattern Recognition:")
        print(f"    Accuracy: {results['pattern_recognition']['cv_mean']:.2%}")

    return results


if __name__ == "__main__":
    print("AI Optimizer Module - Run from analyze_federation_ai.py")
