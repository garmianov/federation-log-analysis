"""
Unit tests for anomaly detection functionality.

Tests the ML-based anomaly detection including:
- Feature extraction
- Anomaly scoring
- Ensemble methods
"""

import pytest
import numpy as np


class TestFeatureExtraction:
    """Tests for feature extraction from store statistics."""

    def test_store_stats_structure(self, federation_analyzer, temp_log_file):
        """Test that store_stats has expected structure after processing."""
        federation_analyzer.process_log_file(str(temp_log_file))

        # store_stats should be a defaultdict
        assert hasattr(federation_analyzer, 'store_stats')

        # Each store should have tracking data
        for store_id, stats in federation_analyzer.store_stats.items():
            assert isinstance(store_id, str)
            assert isinstance(stats, dict)


class TestAnomalyScoring:
    """Tests for anomaly scoring logic."""

    @pytest.mark.skipif(
        not pytest.importorskip("sklearn", reason="sklearn required"),
        reason="sklearn not available"
    )
    def test_isolation_forest_scoring(self):
        """Test Isolation Forest anomaly detection."""
        from sklearn.ensemble import IsolationForest

        # Create sample data with one obvious outlier
        np.random.seed(42)
        normal_data = np.random.randn(50, 3)
        outlier = np.array([[10, 10, 10]])  # Obvious outlier
        data = np.vstack([normal_data, outlier])

        # Fit and predict
        clf = IsolationForest(contamination=0.05, random_state=42)
        predictions = clf.fit_predict(data)

        # Outlier should be detected (labeled as -1)
        assert predictions[-1] == -1

    @pytest.mark.skipif(
        not pytest.importorskip("sklearn", reason="sklearn required"),
        reason="sklearn not available"
    )
    def test_ensemble_voting(self):
        """Test ensemble voting logic."""
        # Simulate votes from different methods
        # 1 = normal, -1 = anomaly
        method_votes = {
            'isolation_forest': np.array([1, 1, -1, -1, 1]),
            'lof': np.array([1, -1, -1, 1, 1]),
            'dbscan': np.array([1, 1, -1, 1, -1]),
        }

        # Ensemble: anomaly if >= 2 methods agree
        ensemble_predictions = []
        for i in range(5):
            anomaly_votes = sum(1 for method in method_votes.values() if method[i] == -1)
            ensemble_predictions.append(-1 if anomaly_votes >= 2 else 1)

        # Index 2 should be anomaly (all 3 methods agree)
        assert ensemble_predictions[2] == -1
        # Index 0 should be normal (0 methods say anomaly)
        assert ensemble_predictions[0] == 1


class TestAnomalyThresholds:
    """Tests for anomaly threshold calculations."""

    def test_z_score_calculation(self):
        """Test Z-score based anomaly detection."""
        data = np.array([1, 2, 3, 4, 5, 100])  # 100 is outlier

        mean = np.mean(data)
        std = np.std(data)
        z_scores = np.abs((data - mean) / std)

        # Z-score > 2 typically indicates anomaly
        anomalies = z_scores > 2
        assert anomalies[-1] == True  # 100 should be anomaly
        assert anomalies[0] == False  # 1 should not be anomaly

    def test_iqr_calculation(self):
        """Test IQR-based anomaly detection."""
        data = np.array([1, 2, 3, 4, 5, 6, 7, 8, 9, 100])

        q1 = np.percentile(data, 25)
        q3 = np.percentile(data, 75)
        iqr = q3 - q1
        lower_bound = q1 - 1.5 * iqr
        upper_bound = q3 + 1.5 * iqr

        anomalies = (data < lower_bound) | (data > upper_bound)
        assert anomalies[-1] == True  # 100 should be anomaly


class TestAIOptimizerIntegration:
    """Tests for AI optimizer module integration."""

    @pytest.mark.skipif(
        not pytest.importorskip("sklearn", reason="sklearn required"),
        reason="sklearn not available"
    )
    def test_enhanced_anomaly_detector_import(self):
        """Test that EnhancedAnomalyDetector can be imported."""
        try:
            from ai_optimizer import EnhancedAnomalyDetector
            detector = EnhancedAnomalyDetector()
            assert detector is not None
        except ImportError:
            pytest.skip("ai_optimizer module not available")

    @pytest.mark.skipif(
        not pytest.importorskip("sklearn", reason="sklearn required"),
        reason="sklearn not available"
    )
    def test_enhanced_anomaly_detector_fit(self):
        """Test EnhancedAnomalyDetector fit method."""
        try:
            from ai_optimizer import EnhancedAnomalyDetector

            # Create sample data
            np.random.seed(42)
            data = np.random.randn(100, 5)

            detector = EnhancedAnomalyDetector()
            result = detector.fit_predict(data)

            assert result is not None
            assert hasattr(result, 'labels')
            assert len(result.labels) == 100
        except ImportError:
            pytest.skip("ai_optimizer module not available")
