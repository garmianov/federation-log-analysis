#!/usr/bin/env python3
"""
AI-Powered Federation Log Analyzer for Genetec Security Center
Enhanced with Advanced ML Algorithms for Pattern Detection and Prediction.

Features:
- Advanced Anomaly Detection: Isolation Forest, DBSCAN, LOF, Ensemble methods
- Predictive Analytics: ARIMA-style forecasting, trend extrapolation
- Root Cause Inference: Feature importance, causal analysis, Bayesian inference
- Cascade Failure Detection: Temporal correlation, propagation analysis
- Actionable Recommendations: Priority-scored remediation steps

Supports:
- Nested ZIP files containing .log files
- SBUXSCRoleGroup and Federation role logs
- Connection timeout, TLS errors, socket exceptions detection
"""

import os
import re
import sys
import zipfile
import io
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Optional, Set
import warnings
import numpy as np
from dataclasses import dataclass, field

warnings.filterwarnings('ignore')

try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingClassifier
    from sklearn.cluster import KMeans, DBSCAN
    from sklearn.neighbors import LocalOutlierFactor
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.decomposition import PCA
    from sklearn.model_selection import cross_val_score
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
    print("Note: Install scikit-learn for advanced ML features: pip install scikit-learn")

try:
    from scipy import stats
    from scipy.signal import find_peaks
    from scipy.ndimage import uniform_filter1d
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False

# Import AI optimizer module
try:
    from ai_optimizer import (
        EnhancedAnomalyDetector, NeuralPatternRecognizer,
        SequenceAnalyzer, InternalErrorClassifier,
        ModelEvaluator, optimize_and_evaluate
    )
    HAS_AI_OPTIMIZER = True
except ImportError:
    HAS_AI_OPTIMIZER = False
    print("Note: AI optimizer module not found. Run from project directory.")

# =============================================================================
# PATTERNS FOR FEDERATION LOG PARSING
# =============================================================================

# Timestamp pattern: 2026-01-04T21:06:38.339-08:00
TIMESTAMP_PATTERN = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})')

# Store pattern: Store 51389 (vNVR) or Store_51389
STORE_PATTERN = re.compile(r'Store[\s_](\d{4,5})(?:\s*\([^)]*\))?')

# IP and Port pattern
IP_PORT_PATTERN = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)')

# Federation group pattern
FED_GROUP_PATTERN = re.compile(r'(SBUXSCRoleGroup\d+)')

# Error classification patterns
ERROR_PATTERNS = {
    'tls_handshake_error': [
        'TlsConnectionException',
        'error completing the handshake',
        'SSL handshake',
        'TLS handshake'
    ],
    'connection_timeout': [
        'did not properly respond after a period of time',
        'connection attempt failed',
        'timed out',
        'timeout'
    ],
    'connection_refused': [
        'connection was forcibly closed',
        'actively refused',
        'Connection refused',
        'target machine actively refused'
    ],
    'host_unreachable': [
        'host has failed to respond',
        'No route to host',
        'network is unreachable',
        'host is down'
    ],
    'socket_exception': [
        'SocketException',
        'socket error',
        'WSAECONNRESET'
    ],
    'proxy_disconnect': [
        'logged off',
        'federated proxy',
        'Initial sync context is null',
        'proxy connection lost'
    ],
    'sql_connection': [
        'SqlException',
        'SQL Server',
        'database connection'
    ],
    'certificate_error': [
        'certificate',
        'cert validation',
        'trust relationship'
    ],
    'scheduling_reconnect': [
        'Scheduling reconnection',
        'reconnect attempt',
        'startDelay'
    ],
    # Internal Error patterns - application-layer failures
    'internal_error_logon': [
        'result Failure () while at step Waiting for message',
        'LogonFailedEventArgs.FailureCode=Failure',
        'OnFederatedProxy_LogonFailed'
    ],
    'internal_error_prefetch': [
        'prefetch failed',
        'Prefetch query failed',
        'The prefetch failed (Base)',
        'The prefetch failed (DirectoryRole)',
        'The prefetch failed (DirectoryServers)'
    ],
    'internal_error_directory': [
        'not currently connected to the Directory',
        'Directory and cannot handle your request'
    ],
    'internal_error_sync': [
        'Entity synchronization failed',
        'Aborting synchronization',
        'Failed to map local and remote custom fields'
    ],
    'internal_error_tls_auth': [
        'TLS authentication failed',
        'TLS authentication failed when connecting'
    ]
}

# Internal Error sub-type patterns for detailed classification
INTERNAL_ERROR_SUBTYPES = {
    'empty_redirection': re.compile(r'result Failure \(\) while at step Waiting for message: RedirectionResponseMessage'),
    'empty_logon': re.compile(r'result Failure \(\) while at step Waiting for message: LogOnResultMessage'),
    'prefetch_base': re.compile(r'prefetch failed \(Base\)', re.I),
    'prefetch_directory_role': re.compile(r'prefetch failed \(DirectoryRole\)', re.I),
    'prefetch_directory_servers': re.compile(r'prefetch failed \(DirectoryServers\)', re.I),
    'directory_disconnected': re.compile(r'not currently connected to the Directory'),
    'tls_auth_failed': re.compile(r'TLS authentication failed'),
    'handshake_error': re.compile(r'error completing the handshake'),
    'read_timeout': re.compile(r'Read timeout occured'),
    'transport_read_error': re.compile(r'Unable to read data from the transport connection'),
    'sync_aborted': re.compile(r'Aborting synchronization'),
    'entity_sync_failed': re.compile(r'Entity synchronization failed'),
    'custom_fields_failed': re.compile(r'Failed to map local and remote custom fields'),
    'logon_failed_event': re.compile(r'OnFederatedProxy_LogonFailed.*FailureCode=Failure'),
    'security_token_error': re.compile(r'Raising WFSecurityTokensManager')
}

# Severity indicators
SEVERITY_PATTERNS = {
    'fatal': re.compile(r'\(Fatal\)', re.I),
    'error': re.compile(r'\(Error\)', re.I),
    'warning': re.compile(r'\(Warning\)', re.I),
    'exception': re.compile(r'Exception', re.I)
}


# =============================================================================
# ADVANCED AI ALGORITHMS
# =============================================================================

@dataclass
class Recommendation:
    """Actionable recommendation with priority scoring."""
    priority: int  # 1-5, 1 being highest
    category: str  # 'immediate', 'short_term', 'preventive'
    target: str  # store_id, machine, or 'system'
    action: str  # specific action to take
    reason: str  # why this action is recommended
    estimated_impact: str  # expected improvement
    confidence: float  # 0-1 confidence score


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
        from sklearn.neighbors import NearestNeighbors
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


class PredictiveAnalytics:
    """
    Forecasting and trend prediction using statistical methods.
    Implements ARIMA-style forecasting without external dependencies.
    """

    def __init__(self):
        self.seasonal_pattern = None
        self.trend_slope = None
        self.base_level = None

    def decompose_time_series(self, data: np.ndarray, period: int = 24) -> Dict:
        """
        Decompose time series into trend, seasonal, and residual components.
        Uses STL-like decomposition.
        """
        if len(data) < period * 2:
            return {'trend': data, 'seasonal': np.zeros_like(data),
                    'residual': np.zeros_like(data)}

        # Trend: Moving average
        if HAS_SCIPY:
            trend = uniform_filter1d(data.astype(float), size=period, mode='nearest')
        else:
            trend = np.convolve(data, np.ones(period)/period, mode='same')

        # Seasonal: Average deviation by position in cycle
        detrended = data - trend
        seasonal = np.zeros_like(data, dtype=float)
        for i in range(period):
            mask = np.arange(len(data)) % period == i
            seasonal[mask] = np.mean(detrended[mask])

        # Residual
        residual = data - trend - seasonal

        self.seasonal_pattern = seasonal[:period]
        self.trend_slope = (trend[-1] - trend[0]) / len(trend) if len(trend) > 1 else 0
        self.base_level = trend[-1] if len(trend) > 0 else np.mean(data)

        return {'trend': trend, 'seasonal': seasonal, 'residual': residual}

    def forecast(self, data: np.ndarray, horizon: int = 24,
                 confidence_level: float = 0.95) -> Dict:
        """
        Forecast future values with confidence intervals.
        Uses exponential smoothing with seasonal adjustment.
        """
        if len(data) < 48:
            mean_val = np.mean(data)
            return {
                'forecast': np.full(horizon, mean_val),
                'lower_bound': np.full(horizon, mean_val * 0.5),
                'upper_bound': np.full(horizon, mean_val * 1.5)
            }

        decomp = self.decompose_time_series(data)

        # Holt-Winters style forecasting
        alpha = 0.3  # Level smoothing
        beta = 0.1   # Trend smoothing

        level = decomp['trend'][-1]
        trend = self.trend_slope

        forecast = []
        for h in range(horizon):
            # Project level and trend
            projected_level = level + trend * (h + 1)

            # Add seasonal component
            seasonal_idx = (len(data) + h) % len(self.seasonal_pattern)
            seasonal = self.seasonal_pattern[seasonal_idx] if self.seasonal_pattern is not None else 0

            forecast.append(max(0, projected_level + seasonal))

        forecast = np.array(forecast)

        # Confidence intervals based on residual variance
        residual_std = np.std(decomp['residual'])
        z_score = stats.norm.ppf((1 + confidence_level) / 2) if HAS_SCIPY else 1.96

        # Wider intervals for further predictions
        interval_width = residual_std * z_score * np.sqrt(np.arange(1, horizon + 1))

        return {
            'forecast': forecast,
            'lower_bound': np.maximum(0, forecast - interval_width),
            'upper_bound': forecast + interval_width,
            'trend_direction': 'increasing' if trend > 0.1 else 'decreasing' if trend < -0.1 else 'stable'
        }

    def predict_failure_probability(self, store_features: Dict) -> float:
        """
        Predict probability of failure in next period based on historical patterns.
        Uses logistic-style calculation.
        """
        # Risk factors with weights
        risk_score = 0
        max_score = 0

        # Recent failure rate (normalized)
        if 'recent_errors' in store_features:
            risk_score += min(store_features['recent_errors'] / 100, 1) * 30
            max_score += 30

        # Error variance (high variance = unpredictable = risky)
        if 'error_variance' in store_features:
            risk_score += min(store_features['error_variance'] / 50, 1) * 20
            max_score += 20

        # Number of distinct error types
        if 'error_types' in store_features:
            risk_score += min(store_features['error_types'] / 5, 1) * 15
            max_score += 15

        # Recent trend
        if 'trend' in store_features:
            if store_features['trend'] == 'increasing':
                risk_score += 20
            elif store_features['trend'] == 'stable':
                risk_score += 5
            max_score += 20

        # Burst frequency
        if 'burst_count' in store_features:
            risk_score += min(store_features['burst_count'] / 10, 1) * 15
            max_score += 15

        # Convert to probability using sigmoid-like function
        if max_score > 0:
            normalized = risk_score / max_score
            probability = 1 / (1 + np.exp(-5 * (normalized - 0.5)))
            return probability
        return 0.5


class CausalAnalyzer:
    """
    Root cause analysis using feature importance and causal inference.
    """

    def __init__(self):
        self.feature_importance = {}
        self.correlation_matrix = None
        self.causal_graph = {}

    def calculate_feature_importance(self, features: np.ndarray,
                                     labels: np.ndarray,
                                     feature_names: List[str]) -> Dict[str, float]:
        """
        Calculate feature importance using Random Forest.
        """
        if not HAS_SKLEARN or len(features) < 20:
            return {}

        # Handle binary classification for anomaly detection
        rf = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
        try:
            rf.fit(features, labels)
            importance = rf.feature_importances_

            self.feature_importance = {
                name: float(imp) for name, imp in zip(feature_names, importance)
            }

            return dict(sorted(self.feature_importance.items(),
                             key=lambda x: x[1], reverse=True))
        except Exception:
            return {}

    def build_correlation_matrix(self, features: np.ndarray,
                                 feature_names: List[str]) -> np.ndarray:
        """
        Build correlation matrix between features.
        """
        if len(features) < 10:
            return np.array([])

        self.correlation_matrix = np.corrcoef(features.T)
        return self.correlation_matrix

    def granger_causality_test(self, series1: np.ndarray, series2: np.ndarray,
                               max_lag: int = 5) -> Dict:
        """
        Simplified Granger causality test.
        Tests if series1 helps predict series2.
        """
        if len(series1) < max_lag * 3:
            return {'causal': False, 'p_value': 1.0}

        # Build lagged features
        X = []
        y = series2[max_lag:]

        for i in range(max_lag, len(series2)):
            row = list(series2[i-max_lag:i]) + list(series1[i-max_lag:i])
            X.append(row)

        X = np.array(X)

        # Restricted model (only series2 lags)
        X_restricted = X[:, :max_lag]

        # Compare R-squared
        if HAS_SKLEARN:
            from sklearn.linear_model import LinearRegression
            model_full = LinearRegression().fit(X, y)
            model_restricted = LinearRegression().fit(X_restricted, y)

            r2_full = model_full.score(X, y)
            r2_restricted = model_restricted.score(X_restricted, y)

            # F-test approximation
            improvement = r2_full - r2_restricted
            is_causal = improvement > 0.05  # 5% improvement threshold

            return {
                'causal': is_causal,
                'improvement': improvement,
                'r2_full': r2_full,
                'r2_restricted': r2_restricted
            }

        return {'causal': False, 'p_value': 1.0}

    def infer_root_causes(self, store_stats: Dict, machine_stats: Dict,
                          error_totals: Dict) -> List[Dict]:
        """
        Infer likely root causes from observed patterns.
        Uses Bayesian-style reasoning.
        """
        causes = []

        # Prior probabilities of different root causes
        priors = {
            'network_issue': 0.3,
            'store_hardware': 0.25,
            'server_overload': 0.2,
            'certificate_expiry': 0.1,
            'configuration_error': 0.1,
            'external_dependency': 0.05
        }

        # Calculate evidence updates based on error patterns
        total_errors = sum(error_totals.values())
        if total_errors == 0:
            return causes

        # Network issues evidence
        network_evidence = (
            error_totals.get('connection_timeout', 0) +
            error_totals.get('host_unreachable', 0) +
            error_totals.get('socket_exception', 0)
        ) / total_errors

        # Hardware evidence
        hardware_evidence = error_totals.get('connection_refused', 0) / total_errors

        # TLS/Certificate evidence
        cert_evidence = (
            error_totals.get('tls_handshake_error', 0) +
            error_totals.get('certificate_error', 0)
        ) / total_errors

        # Server overload evidence (many stores on same machine)
        overload_evidence = 0
        if machine_stats:
            max_stores_per_machine = max(
                len(m.get('stores', set())) for m in machine_stats.values()
            )
            if max_stores_per_machine > 200:
                overload_evidence = 0.5

        # Update posteriors (simplified Bayesian update)
        posteriors = {}
        posteriors['network_issue'] = priors['network_issue'] * (1 + 3 * network_evidence)
        posteriors['store_hardware'] = priors['store_hardware'] * (1 + 3 * hardware_evidence)
        posteriors['certificate_expiry'] = priors['certificate_expiry'] * (1 + 5 * cert_evidence)
        posteriors['server_overload'] = priors['server_overload'] * (1 + 2 * overload_evidence)

        # Normalize
        total_posterior = sum(posteriors.values())
        for cause, prob in sorted(posteriors.items(), key=lambda x: x[1], reverse=True):
            normalized_prob = prob / total_posterior if total_posterior > 0 else 0
            if normalized_prob > 0.1:  # Only report significant causes
                causes.append({
                    'cause': cause,
                    'probability': normalized_prob,
                    'evidence': self._get_evidence_description(cause, error_totals)
                })

        return causes

    def _get_evidence_description(self, cause: str, error_totals: Dict) -> str:
        """Get human-readable evidence for a root cause."""
        descriptions = {
            'network_issue': f"High timeout/socket errors ({error_totals.get('connection_timeout', 0):,})",
            'store_hardware': f"Connection refused errors ({error_totals.get('connection_refused', 0):,})",
            'certificate_expiry': f"TLS errors ({error_totals.get('tls_handshake_error', 0):,})",
            'server_overload': "High store density on federation servers",
            'configuration_error': "Inconsistent error patterns across stores",
            'external_dependency': "Correlated failures across multiple stores"
        }
        return descriptions.get(cause, "Pattern analysis")


class CascadeDetector:
    """
    Detect cascading failures where one store's failure triggers others.
    """

    def __init__(self, time_window_seconds: int = 60):
        self.time_window = time_window_seconds
        self.cascade_events = []

    def detect_cascades(self, events: List, min_stores: int = 3) -> List[Dict]:
        """
        Detect cascade events where multiple stores fail within time window.
        """
        if not events:
            return []

        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp if e.timestamp else datetime.min)

        cascades = []
        i = 0

        while i < len(sorted_events):
            if sorted_events[i].timestamp is None:
                i += 1
                continue

            # Find all events within time window
            window_end = sorted_events[i].timestamp + timedelta(seconds=self.time_window)
            stores_in_window = set()
            events_in_window = []

            j = i
            while j < len(sorted_events) and sorted_events[j].timestamp and sorted_events[j].timestamp <= window_end:
                if sorted_events[j].store_id:
                    stores_in_window.add(sorted_events[j].store_id)
                    events_in_window.append(sorted_events[j])
                j += 1

            # Check if this is a cascade
            if len(stores_in_window) >= min_stores:
                # Determine cascade characteristics
                error_types = defaultdict(int)
                machines = set()
                for e in events_in_window:
                    if e.error_category:
                        error_types[e.error_category] += 1
                    if e.machine:
                        machines.add(e.machine)

                cascades.append({
                    'start_time': sorted_events[i].timestamp,
                    'end_time': events_in_window[-1].timestamp if events_in_window else sorted_events[i].timestamp,
                    'store_count': len(stores_in_window),
                    'stores': list(stores_in_window)[:10],  # Limit for display
                    'event_count': len(events_in_window),
                    'dominant_error': max(error_types.items(), key=lambda x: x[1])[0] if error_types else 'unknown',
                    'machines_affected': len(machines),
                    'is_server_wide': len(machines) == 1 and len(stores_in_window) > 10
                })

                i = j  # Skip past this cascade
            else:
                i += 1

        self.cascade_events = cascades
        return cascades

    def analyze_propagation(self, cascades: List[Dict]) -> Dict:
        """
        Analyze cascade propagation patterns.
        """
        if not cascades:
            return {}

        # Statistics
        avg_stores = np.mean([c['store_count'] for c in cascades])
        max_stores = max(c['store_count'] for c in cascades)
        server_wide_count = sum(1 for c in cascades if c['is_server_wide'])

        # Error type analysis
        error_counts = defaultdict(int)
        for c in cascades:
            error_counts[c['dominant_error']] += 1

        return {
            'total_cascades': len(cascades),
            'avg_stores_affected': avg_stores,
            'max_stores_in_cascade': max_stores,
            'server_wide_cascades': server_wide_count,
            'common_error_types': dict(error_counts)
        }


class RecommendationEngine:
    """
    Generate actionable recommendations with priority scoring.
    """

    def __init__(self):
        self.recommendations = []

    def generate_recommendations(self, analysis_results: Dict) -> List[Recommendation]:
        """
        Generate prioritized recommendations based on analysis results.
        """
        self.recommendations = []

        # Check anomaly detection results
        if 'anomalies' in analysis_results:
            anomalies = analysis_results['anomalies']
            if anomalies.get('anomalous_stores'):
                top_anomalies = anomalies['anomalous_stores'][:5]
                for store in top_anomalies:
                    self.recommendations.append(Recommendation(
                        priority=1,
                        category='immediate',
                        target=f"Store {store['store_id']}",
                        action=f"Investigate connectivity to store {store['store_id']}",
                        reason=f"Anomalous behavior detected: {store['total_errors']:,} errors",
                        estimated_impact=f"Reduce ~{store['total_errors']//2:,} errors",
                        confidence=0.85
                    ))

        # Check cascade detection
        if 'cascades' in analysis_results:
            cascades = analysis_results['cascades']
            if cascades.get('server_wide_cascades', 0) > 0:
                self.recommendations.append(Recommendation(
                    priority=1,
                    category='immediate',
                    target='Federation Servers',
                    action='Review federation server load balancing and health',
                    reason=f"{cascades['server_wide_cascades']} server-wide cascade events detected",
                    estimated_impact='Prevent mass disconnections',
                    confidence=0.9
                ))

        # Check root causes
        if 'root_causes' in analysis_results:
            for cause in analysis_results['root_causes'][:3]:
                if cause['probability'] > 0.2:
                    action = self._get_action_for_cause(cause['cause'])
                    self.recommendations.append(Recommendation(
                        priority=2 if cause['probability'] > 0.3 else 3,
                        category='short_term',
                        target='System',
                        action=action,
                        reason=f"Root cause analysis: {cause['cause']} ({cause['probability']:.0%} probability)",
                        estimated_impact='Address underlying issue',
                        confidence=cause['probability']
                    ))

        # Check predictions
        if 'predictions' in analysis_results:
            pred = analysis_results['predictions']
            if pred.get('trend_direction') == 'increasing':
                self.recommendations.append(Recommendation(
                    priority=2,
                    category='preventive',
                    target='System',
                    action='Scale up monitoring and prepare incident response',
                    reason='Error trend is increasing',
                    estimated_impact='Faster response to incidents',
                    confidence=0.7
                ))

        # Check machine health
        if 'machine_health' in analysis_results:
            for machine, health in analysis_results['machine_health'].items():
                if health.get('score', 100) < 40:
                    self.recommendations.append(Recommendation(
                        priority=1,
                        category='immediate',
                        target=machine,
                        action=f'Review and potentially restart federation services on {machine}',
                        reason=f"Low health score ({health['score']:.0f}/100)",
                        estimated_impact=f"Improve {len(health.get('stores', []))} store connections",
                        confidence=0.8
                    ))

        # Sort by priority
        self.recommendations.sort(key=lambda r: (r.priority, -r.confidence))

        return self.recommendations

    def _get_action_for_cause(self, cause: str) -> str:
        """Get specific action for a root cause."""
        actions = {
            'network_issue': 'Review network routes and firewall rules for store connectivity',
            'store_hardware': 'Schedule maintenance check for affected store vNVR hardware',
            'certificate_expiry': 'Audit and renew TLS certificates across federation',
            'server_overload': 'Rebalance store distribution across federation servers',
            'configuration_error': 'Review recent configuration changes and federation settings',
            'external_dependency': 'Check external service dependencies (DNS, proxy, etc.)'
        }
        return actions.get(cause, 'Investigate further')

    def format_report(self) -> str:
        """Format recommendations as a text report."""
        if not self.recommendations:
            return "No critical recommendations at this time."

        lines = []
        lines.append("=" * 70)
        lines.append("ACTIONABLE RECOMMENDATIONS")
        lines.append("=" * 70)

        current_priority = None
        for rec in self.recommendations:
            if rec.priority != current_priority:
                current_priority = rec.priority
                priority_labels = {1: 'CRITICAL', 2: 'HIGH', 3: 'MEDIUM', 4: 'LOW', 5: 'INFO'}
                lines.append(f"\n[{priority_labels.get(rec.priority, 'OTHER')} PRIORITY]")
                lines.append("-" * 40)

            lines.append(f"\n  Target: {rec.target}")
            lines.append(f"  Action: {rec.action}")
            lines.append(f"  Reason: {rec.reason}")
            lines.append(f"  Impact: {rec.estimated_impact}")
            lines.append(f"  Confidence: {rec.confidence:.0%}")

        return "\n".join(lines)


class FederationEvent:
    """Represents a single federation event."""
    __slots__ = ('timestamp', 'store_id', 'fed_group', 'machine', 'event_type',
                 'error_category', 'severity', 'ip', 'port', 'message', 'internal_error_subtype')

    def __init__(self):
        self.timestamp = None
        self.store_id = None
        self.fed_group = None
        self.machine = None
        self.event_type = None
        self.error_category = None
        self.severity = None
        self.ip = None
        self.port = None
        self.message = None
        self.internal_error_subtype = None


class OnlineStats:
    """Welford's algorithm for streaming statistics."""
    __slots__ = ('n', 'mean', 'M2', 'min_val', 'max_val', 'samples')

    def __init__(self):
        self.n = 0
        self.mean = 0.0
        self.M2 = 0.0
        self.min_val = float('inf')
        self.max_val = float('-inf')
        self.samples = []

    def update(self, x):
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        self.M2 += delta * (x - self.mean)
        if x < self.min_val:
            self.min_val = x
        if x > self.max_val:
            self.max_val = x
        if self.n % 100 == 0:
            self.samples.append(x)

    def get_stats(self):
        if self.n < 1:
            return None
        std = (self.M2 / self.n) ** 0.5 if self.n > 1 else 0
        median = sorted(self.samples)[len(self.samples)//2] if self.samples else self.mean
        return {'count': self.n, 'mean': self.mean, 'std': std,
                'min': self.min_val, 'max': self.max_val, 'median': median}


class FederationLogAnalyzer:
    """Specialized analyzer for Genetec federation logs."""

    def __init__(self):
        # Data structures
        self.events = []
        self.store_stats = defaultdict(lambda: {
            'total_errors': 0,
            'error_categories': defaultdict(int),
            'internal_error_subtypes': defaultdict(int),
            'timestamps': [],
            'ips': set(),
            'fed_groups': set(),
            'machines': set(),
            'hourly_counts': defaultdict(int),
            'reconnect_delays': []
        })
        self.internal_error_totals = defaultdict(int)
        self.machine_stats = defaultdict(lambda: {
            'total_errors': 0,
            'stores': set(),
            'error_categories': defaultdict(int)
        })
        self.hourly_errors = defaultdict(lambda: defaultdict(int))
        self.error_category_totals = defaultdict(int)
        self.ip_stats = defaultdict(lambda: {'stores': set(), 'errors': 0})

        self.seen_hashes = set()
        self.files_processed = 0
        self.lines_processed = 0
        self.current_machine = None
        self.min_ts = None
        self.max_ts = None

    def parse_timestamp(self, line: str) -> Optional[datetime]:
        """Fast timestamp extraction."""
        if len(line) < 20 or line[4] != '-':
            return None
        try:
            return datetime.strptime(line[:19], '%Y-%m-%dT%H:%M:%S')
        except ValueError:
            return None

    def classify_error(self, line: str) -> Tuple[Optional[str], Optional[str]]:
        """Classify error type and severity."""
        line_lower = line.lower()

        # Find error category
        error_category = None
        for category, patterns in ERROR_PATTERNS.items():
            if any(p.lower() in line_lower for p in patterns):
                error_category = category
                break

        # Find severity
        severity = None
        for sev, pattern in SEVERITY_PATTERNS.items():
            if pattern.search(line):
                severity = sev
                break

        return error_category, severity

    def classify_internal_error(self, line: str) -> Optional[str]:
        """Classify internal error subtype for detailed analysis."""
        for subtype, pattern in INTERNAL_ERROR_SUBTYPES.items():
            if pattern.search(line):
                return subtype
        return None

    def process_line(self, line: str, fed_group: str = None) -> Optional[str]:
        """Process a single log line."""
        line = line.strip()
        if not line:
            return fed_group

        # Check for header/fed group info
        if line.startswith('*'):
            match = FED_GROUP_PATTERN.search(line)
            if match:
                return match.group(1)
            if 'MachineName=' in line:
                m = re.search(r'MachineName=(\S+)', line)
                if m:
                    self.current_machine = m.group(1)
            return fed_group

        # Skip duplicates
        line_hash = hash(line)
        if line_hash in self.seen_hashes:
            return fed_group
        self.seen_hashes.add(line_hash)
        self.lines_processed += 1

        # Parse timestamp
        timestamp = self.parse_timestamp(line)
        if not timestamp:
            return fed_group

        # Update time range
        if self.min_ts is None or timestamp < self.min_ts:
            self.min_ts = timestamp
        if self.max_ts is None or timestamp > self.max_ts:
            self.max_ts = timestamp

        # Classify error
        error_category, severity = self.classify_error(line)
        if not error_category and not severity:
            return fed_group

        # Extract store ID
        store_match = STORE_PATTERN.search(line)
        store_id = store_match.group(1).zfill(5) if store_match else None

        # Extract IP/Port
        ip_match = IP_PORT_PATTERN.search(line)
        ip = ip_match.group(1) if ip_match else None
        port = ip_match.group(2) if ip_match else None

        # Extract fed group from line
        fg_match = FED_GROUP_PATTERN.search(line)
        if fg_match:
            fed_group = fg_match.group(1)

        # Classify internal error subtype if applicable
        internal_subtype = None
        if error_category and error_category.startswith('internal_error'):
            internal_subtype = self.classify_internal_error(line)

        # Build event
        event = FederationEvent()
        event.timestamp = timestamp
        event.store_id = store_id
        event.fed_group = fed_group
        event.machine = self.current_machine
        event.error_category = error_category
        event.severity = severity
        event.ip = ip
        event.port = port
        event.message = line[:300]
        event.internal_error_subtype = internal_subtype

        self.events.append(event)

        # Track internal error subtypes
        if internal_subtype:
            self.internal_error_totals[internal_subtype] += 1

        # Calculate hour key for time-based statistics
        hour_key = timestamp.replace(minute=0, second=0, microsecond=0)

        # Update statistics
        if error_category:
            self.error_category_totals[error_category] += 1
            self.hourly_errors[hour_key][error_category] += 1

        if store_id:
            stats = self.store_stats[store_id]
            stats['total_errors'] += 1
            stats['timestamps'].append(timestamp)
            if error_category:
                stats['error_categories'][error_category] += 1
            if internal_subtype:
                stats['internal_error_subtypes'][internal_subtype] += 1
            if ip:
                stats['ips'].add(ip)
            if fed_group:
                stats['fed_groups'].add(fed_group)
            if self.current_machine:
                stats['machines'].add(self.current_machine)
            stats['hourly_counts'][hour_key] += 1

            # Extract reconnect delay if present
            delay_match = re.search(r'startDelay\s*=\s*(\d+)', line)
            if delay_match:
                stats['reconnect_delays'].append(int(delay_match.group(1)))

        if self.current_machine:
            mstats = self.machine_stats[self.current_machine]
            mstats['total_errors'] += 1
            if store_id:
                mstats['stores'].add(store_id)
            if error_category:
                mstats['error_categories'][error_category] += 1

        if ip:
            self.ip_stats[ip]['errors'] += 1
            if store_id:
                self.ip_stats[ip]['stores'].add(store_id)

        return fed_group

    def process_log_content(self, content: str, fed_group: str = None) -> str:
        """Process log file content."""
        for line in content.split('\n'):
            fed_group = self.process_line(line, fed_group)
        return fed_group

    def process_nested_zip(self, zip_path: str):
        """Process a ZIP file that may contain nested ZIPs with logs."""
        print(f"\nProcessing: {os.path.basename(zip_path)}")

        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                # Find relevant log files
                log_files = [n for n in zf.namelist()
                            if ('SBUXSCRoleGroup' in n or 'Federation' in n)
                            and (n.endswith('.log') or n.endswith('.zip'))]

                print(f"  Found {len(log_files)} relevant files")

                for name in sorted(log_files):
                    try:
                        if name.endswith('.zip'):
                            # Nested ZIP - extract and process
                            with zf.open(name) as nested_file:
                                nested_data = nested_file.read()
                                with zipfile.ZipFile(io.BytesIO(nested_data), 'r') as nested_zf:
                                    for inner_name in nested_zf.namelist():
                                        if inner_name.endswith('.log'):
                                            content = nested_zf.read(inner_name).decode('utf-8-sig', errors='replace')
                                            self.process_log_content(content)
                                            self.files_processed += 1
                        else:
                            # Direct log file
                            content = zf.read(name).decode('utf-8-sig', errors='replace')
                            self.process_log_content(content)
                            self.files_processed += 1

                    except Exception as e:
                        print(f"    Error processing {name}: {e}")

        except Exception as e:
            print(f"  Error opening zip: {e}")

        print(f"  Processed {self.files_processed} files, {self.lines_processed:,} lines")

    def process_log_file(self, log_path: str):
        """Process a single .log file directly (unzipped)."""
        print(f"\nProcessing: {os.path.basename(log_path)}")

        try:
            with open(log_path, 'r', encoding='utf-8-sig', errors='replace') as f:
                content = f.read()
                self.process_log_content(content)
                self.files_processed += 1
            print(f"  Processed {self.lines_processed:,} lines")
        except Exception as e:
            print(f"  Error processing file: {e}")

    def process_log_directory(self, dir_path: str):
        """Process all .log files in a directory."""
        print(f"\nProcessing directory: {dir_path}")

        log_files = []
        for root, dirs, files in os.walk(dir_path):
            for f in files:
                if f.endswith('.log') and ('SBUXSCRoleGroup' in f or 'Federation' in f):
                    log_files.append(os.path.join(root, f))

        if not log_files:
            # If no specific federation logs found, try all .log files
            for root, dirs, files in os.walk(dir_path):
                for f in files:
                    if f.endswith('.log'):
                        log_files.append(os.path.join(root, f))

        print(f"  Found {len(log_files)} log files")

        for log_file in sorted(log_files):
            try:
                with open(log_file, 'r', encoding='utf-8-sig', errors='replace') as f:
                    content = f.read()
                    self.process_log_content(content)
                    self.files_processed += 1
            except Exception as e:
                print(f"    Error processing {os.path.basename(log_file)}: {e}")

        print(f"  Processed {self.files_processed} files, {self.lines_processed:,} lines")

    def analyze_anomalies(self) -> Dict:
        """Use ensemble ML methods to detect anomalous stores."""
        if not HAS_SKLEARN or len(self.store_stats) < 10:
            return {'anomalous_stores': [], 'method_agreement': {}}

        print("\n" + "=" * 70)
        print("ADVANCED ANOMALY DETECTION (Ensemble Methods)")
        print("=" * 70)

        # Build feature matrix
        store_ids = []
        features = []
        feature_names = ['total_errors', 'variance', 'max_hourly', 'category_count',
                         'ip_count', 'avg_interval_hours', 'min_interval', 'burst_score']

        for store_id, stats in self.store_stats.items():
            if stats['total_errors'] < 3:
                continue

            # Calculate features
            hourly_values = list(stats['hourly_counts'].values())
            variance = np.var(hourly_values) if len(hourly_values) > 1 else 0
            max_hourly = max(hourly_values) if hourly_values else 0

            # Error category diversity
            category_count = len(stats['error_categories'])

            # Time pattern features
            timestamps = stats['timestamps']
            if len(timestamps) > 1:
                deltas = [(timestamps[i+1] - timestamps[i]).total_seconds()
                         for i in range(len(timestamps)-1)]
                avg_delta = np.mean(deltas)
                min_delta = min(deltas)
                # Burst score: how many consecutive short intervals
                burst_score = sum(1 for d in deltas if d < 60) / len(deltas)
            else:
                avg_delta = 0
                min_delta = 0
                burst_score = 0

            feature_vector = [
                stats['total_errors'],
                variance,
                max_hourly,
                category_count,
                len(stats['ips']),
                avg_delta / 3600 if avg_delta > 0 else 0,
                min_delta,
                burst_score,
            ]

            store_ids.append(store_id)
            features.append(feature_vector)

        if len(features) < 10:
            print("Insufficient data for anomaly detection")
            return {'anomalous_stores': [], 'method_agreement': {}}

        features = np.array(features)

        # Use advanced ensemble anomaly detection
        detector = AdvancedAnomalyDetector(contamination=0.1)
        labels, method_scores = detector.detect_ensemble(features)

        # Calculate method agreement statistics
        method_agreement = {
            'isolation_forest': int(np.sum(method_scores.get('isolation_forest', []))),
            'lof': int(np.sum(method_scores.get('lof', []))),
            'dbscan': int(np.sum(method_scores.get('dbscan', []))),
            'statistical': int(np.sum(method_scores.get('statistical', []))),
            'ensemble_total': int(np.sum(method_scores.get('ensemble', [])))
        }

        print(f"\nMethod Agreement (anomalies detected):")
        print(f"  Isolation Forest: {method_agreement['isolation_forest']}")
        print(f"  Local Outlier Factor: {method_agreement['lof']}")
        print(f"  DBSCAN: {method_agreement['dbscan']}")
        print(f"  Statistical (Z-score): {method_agreement['statistical']}")
        print(f"  Ensemble (>=2 agree): {method_agreement['ensemble_total']}")

        anomalous = []
        votes = method_scores.get('votes', np.zeros(len(features)))

        for i, (store_id, label, feat) in enumerate(zip(store_ids, labels, features)):
            if label == -1:
                anomalous.append({
                    'store_id': store_id,
                    'total_errors': int(feat[0]),
                    'max_hourly': int(feat[2]),
                    'categories': len(self.store_stats[store_id]['error_categories']),
                    'ips': list(self.store_stats[store_id]['ips'])[:3],
                    'confidence': int(votes[i]) / 4,  # 4 methods total
                    'dominant_error': max(
                        self.store_stats[store_id]['error_categories'].items(),
                        key=lambda x: x[1]
                    )[0] if self.store_stats[store_id]['error_categories'] else 'unknown'
                })

        anomalous.sort(key=lambda x: (x['confidence'], x['total_errors']), reverse=True)

        print(f"\nFound {len(anomalous)} anomalous stores (ensemble):")
        print(f"{'Store':<10}{'Errors':<10}{'Max/Hr':<8}{'Conf':<8}{'Dominant Error':<25}{'IPs'}")
        print("-" * 80)
        for s in anomalous[:20]:
            ips_str = ', '.join(s['ips']) if s['ips'] else 'N/A'
            print(f"{s['store_id']:<10}{s['total_errors']:<10}{s['max_hourly']:<8}"
                  f"{s['confidence']:.0%}    {s['dominant_error']:<25}{ips_str[:20]}")

        # Feature importance analysis
        print("\n--- Feature Importance (what drives anomalies) ---")
        causal = CausalAnalyzer()
        anomaly_labels = (labels == -1).astype(int)
        importance = causal.calculate_feature_importance(features, anomaly_labels, feature_names)
        for name, imp in list(importance.items())[:5]:
            bar = '█' * int(imp * 40)
            print(f"  {name:<20}: {bar} {imp:.2%}")

        return {
            'anomalous_stores': anomalous,
            'method_agreement': method_agreement,
            'feature_importance': importance
        }

    def analyze_error_patterns(self) -> Dict:
        """Analyze error patterns using TF-IDF and clustering."""
        if not HAS_SKLEARN or len(self.events) < 100:
            return {}

        print("\n" + "=" * 70)
        print("ERROR PATTERN ANALYSIS")
        print("=" * 70)

        # Group errors by category
        print(f"\nError Category Distribution:")
        print(f"{'Category':<25}{'Count':<12}{'%':<10}{'Bar'}")
        print("-" * 60)

        total = sum(self.error_category_totals.values())
        for cat, count in sorted(self.error_category_totals.items(),
                                 key=lambda x: x[1], reverse=True):
            pct = 100 * count / total if total > 0 else 0
            bar = '█' * int(pct / 2.5)
            print(f"{cat:<25}{count:<12}{pct:.1f}%     {bar}")

        # Analyze hourly patterns per error type
        print(f"\nHourly Pattern by Error Type:")

        hourly_by_type = defaultdict(lambda: defaultdict(int))
        for hour, categories in self.hourly_errors.items():
            hour_of_day = hour.hour
            for cat, count in categories.items():
                hourly_by_type[cat][hour_of_day] += count

        for cat in list(self.error_category_totals.keys())[:5]:
            hourly = hourly_by_type[cat]
            if hourly:
                peak_hour = max(hourly, key=hourly.get)
                total_cat = sum(hourly.values())
                print(f"  {cat}: Peak at {peak_hour:02d}:00, "
                      f"Total: {total_cat:,}")

        return {'category_totals': dict(self.error_category_totals)}

    def analyze_internal_errors(self) -> Dict:
        """Analyze Internal Errors in detail - application-layer failures."""
        print("\n" + "=" * 70)
        print("INTERNAL ERROR ANALYSIS (Application-Layer Failures)")
        print("=" * 70)

        if not self.internal_error_totals:
            print("\nNo Internal Errors detected in the logs.")
            return {}

        # Calculate total internal errors
        total_internal = sum(self.internal_error_totals.values())
        total_all = sum(self.error_category_totals.values())
        internal_pct = 100 * total_internal / total_all if total_all > 0 else 0

        print(f"\nInternal Error Summary:")
        print(f"  Total Internal Errors: {total_internal:,} ({internal_pct:.1f}% of all errors)")

        # Sub-type breakdown
        print(f"\n{'Sub-Type':<30}{'Count':<12}{'%':<10}{'Bar'}")
        print("-" * 65)

        subtype_descriptions = {
            'empty_redirection': 'vNVR not responding (RedirectionResponseMessage)',
            'empty_logon': 'vNVR not responding (LogOnResultMessage)',
            'prefetch_base': 'Base entity prefetch failed',
            'prefetch_directory_role': 'DirectoryRole prefetch failed',
            'prefetch_directory_servers': 'DirectoryServers prefetch failed',
            'directory_disconnected': 'vNVR not connected to Directory',
            'tls_auth_failed': 'TLS authentication failed',
            'handshake_error': 'TLS handshake error',
            'read_timeout': 'Read timeout on connection',
            'transport_read_error': 'Transport connection read error',
            'sync_aborted': 'Synchronization aborted',
            'entity_sync_failed': 'Entity synchronization failed',
            'custom_fields_failed': 'Custom fields mapping failed',
            'logon_failed_event': 'Logon failed event triggered',
            'security_token_error': 'Security token manager error'
        }

        for subtype, count in sorted(self.internal_error_totals.items(),
                                     key=lambda x: x[1], reverse=True):
            pct = 100 * count / total_internal if total_internal > 0 else 0
            bar = '█' * int(pct / 2.5)
            desc = subtype_descriptions.get(subtype, subtype)
            print(f"{desc[:30]:<30}{count:<12}{pct:.1f}%     {bar}")

        # Group subtypes into categories for diagnosis
        print(f"\n--- INTERNAL ERROR DIAGNOSIS GROUPS ---")

        unresponsive_count = sum(self.internal_error_totals.get(s, 0)
                                 for s in ['empty_redirection', 'empty_logon'])
        prefetch_count = sum(self.internal_error_totals.get(s, 0)
                            for s in ['prefetch_base', 'prefetch_directory_role', 'prefetch_directory_servers'])
        tls_count = sum(self.internal_error_totals.get(s, 0)
                       for s in ['tls_auth_failed', 'handshake_error'])
        network_count = sum(self.internal_error_totals.get(s, 0)
                           for s in ['read_timeout', 'transport_read_error'])
        sync_count = sum(self.internal_error_totals.get(s, 0)
                        for s in ['sync_aborted', 'entity_sync_failed', 'custom_fields_failed'])

        print(f"\n{'Diagnosis Group':<35}{'Count':<10}{'%':<10}{'Action'}")
        print("-" * 80)

        groups = [
            ('vNVR Unresponsive', unresponsive_count, 'Restart vNVR service'),
            ('Data Prefetch Failures', prefetch_count, 'Check vNVR database/resources'),
            ('TLS/Certificate Issues', tls_count, 'Verify certificates'),
            ('Network Transport Issues', network_count, 'Check network connectivity'),
            ('Sync/Data Issues', sync_count, 'Review entity configuration'),
        ]

        for group, count, action in groups:
            if count > 0:
                pct = 100 * count / total_internal if total_internal > 0 else 0
                bar = '█' * int(pct / 5)
                print(f"{group:<35}{count:<10}{pct:.1f}%     {bar}  → {action}")

        # Stores most affected by internal errors
        print(f"\n--- TOP STORES WITH INTERNAL ERRORS ---")
        print(f"{'Store':<10}{'Total IE':<12}{'Dominant Sub-Type':<35}{'IPs'}")
        print("-" * 80)

        stores_with_internal = []
        for store_id, stats in self.store_stats.items():
            ie_total = sum(stats['internal_error_subtypes'].values())
            if ie_total > 0:
                dominant = max(stats['internal_error_subtypes'].items(),
                              key=lambda x: x[1])[0] if stats['internal_error_subtypes'] else 'unknown'
                stores_with_internal.append({
                    'store_id': store_id,
                    'internal_errors': ie_total,
                    'dominant_subtype': dominant,
                    'ips': list(stats['ips'])[:2]
                })

        stores_with_internal.sort(key=lambda x: x['internal_errors'], reverse=True)

        for store in stores_with_internal[:20]:
            desc = subtype_descriptions.get(store['dominant_subtype'], store['dominant_subtype'])[:35]
            ips = ', '.join(store['ips']) if store['ips'] else 'N/A'
            print(f"{store['store_id']:<10}{store['internal_errors']:<12}{desc:<35}{ips[:20]}")

        # Generate recommendations based on internal error patterns
        print(f"\n--- INTERNAL ERROR RECOMMENDATIONS ---")

        if unresponsive_count > total_internal * 0.3:
            print(f"\n⚠️  HIGH UNRESPONSIVE vNVR RATE ({unresponsive_count:,} events)")
            print(f"   → Schedule vNVR service restarts for affected stores")
            print(f"   → Check vNVR CPU/Memory utilization")
            print(f"   → Review vNVR logs on store systems")

        if prefetch_count > total_internal * 0.2:
            print(f"\n⚠️  DATA PREFETCH FAILURES ({prefetch_count:,} events)")
            print(f"   → Check vNVR database health and disk space")
            print(f"   → Review entity counts in affected stores")
            print(f"   → Consider increasing prefetch timeout settings")

        if tls_count > total_internal * 0.1:
            print(f"\n⚠️  TLS/CERTIFICATE ISSUES ({tls_count:,} events)")
            print(f"   → Audit certificate expiration dates")
            print(f"   → Verify TLS version compatibility")
            print(f"   → Check certificate chain validity")

        return {
            'total_internal_errors': total_internal,
            'percentage_of_all': internal_pct,
            'subtypes': dict(self.internal_error_totals),
            'stores_affected': stores_with_internal,
            'diagnosis_groups': {
                'unresponsive': unresponsive_count,
                'prefetch': prefetch_count,
                'tls': tls_count,
                'network': network_count,
                'sync': sync_count
            }
        }

    def analyze_store_clusters(self) -> Dict:
        """Cluster stores by error behavior."""
        if not HAS_SKLEARN or len(self.store_stats) < 20:
            return {}

        print("\n" + "=" * 70)
        print("STORE CLUSTERING")
        print("=" * 70)

        # Build feature matrix
        store_ids = []
        features = []

        for store_id, stats in self.store_stats.items():
            if stats['total_errors'] < 5:
                continue

            # Category ratios
            total = stats['total_errors']
            cat_vector = []
            for cat in ['tls_handshake_error', 'connection_timeout',
                       'connection_refused', 'host_unreachable',
                       'socket_exception', 'proxy_disconnect']:
                cat_vector.append(stats['error_categories'].get(cat, 0) / total)

            features.append(cat_vector + [
                total,
                len(stats['ips']),
            ])
            store_ids.append(store_id)

        if len(features) < 20:
            print("Insufficient data for clustering")
            return {}

        features = np.array(features)
        scaler = StandardScaler()
        scaled = scaler.fit_transform(features)

        # Determine number of clusters
        n_clusters = min(5, len(features) // 50)
        n_clusters = max(2, n_clusters)

        kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
        labels = kmeans.fit_predict(scaled)

        # Analyze clusters
        clusters = defaultdict(list)
        for store_id, label, feat in zip(store_ids, labels, features):
            clusters[label].append({
                'store_id': store_id,
                'total_errors': int(feat[-2]),
                'dominant_category': max(
                    self.store_stats[store_id]['error_categories'].items(),
                    key=lambda x: x[1]
                )[0] if self.store_stats[store_id]['error_categories'] else 'unknown'
            })

        print(f"\nIdentified {n_clusters} behavior clusters:\n")

        cluster_profiles = {}
        for cluster_id, stores in sorted(clusters.items()):
            # Find dominant error type
            all_cats = defaultdict(int)
            for s in stores:
                for cat, cnt in self.store_stats[s['store_id']]['error_categories'].items():
                    all_cats[cat] += cnt

            dominant = max(all_cats.items(), key=lambda x: x[1])[0] if all_cats else 'unknown'
            total_errors = sum(s['total_errors'] for s in stores)

            profile = {
                'dominant_error': dominant,
                'store_count': len(stores),
                'total_errors': total_errors
            }
            cluster_profiles[cluster_id] = profile

            print(f"CLUSTER {cluster_id}: {dominant.replace('_', ' ').title()}")
            print(f"  Stores: {len(stores)}, Total Errors: {total_errors:,}")
            top_stores = sorted(stores, key=lambda x: x['total_errors'], reverse=True)[:5]
            print(f"  Top stores: {', '.join(s['store_id'] for s in top_stores)}")
            print()

        return {'clusters': dict(clusters), 'profiles': cluster_profiles}

    def analyze_time_series(self) -> Dict:
        """Analyze temporal patterns with advanced forecasting."""
        print("\n" + "=" * 70)
        print("TIME SERIES ANALYSIS & FORECASTING")
        print("=" * 70)

        if not self.hourly_errors:
            print("No hourly data available")
            return {}

        # Aggregate hourly errors
        hours = sorted(self.hourly_errors.keys())
        hourly_totals = [sum(self.hourly_errors[h].values()) for h in hours]

        if len(hourly_totals) < 24:
            print("Insufficient time series data")
            return {}

        hourly_array = np.array(hourly_totals)

        # Use PredictiveAnalytics for advanced analysis
        predictor = PredictiveAnalytics()

        # Decompose time series
        decomposed = predictor.decompose_time_series(hourly_array, period=24)

        # Trend analysis
        first_half = np.mean(hourly_array[:len(hourly_array)//2])
        second_half = np.mean(hourly_array[len(hourly_array)//2:])
        change_pct = (second_half - first_half) / first_half * 100 if first_half > 0 else 0

        if change_pct > 20:
            trend = f"INCREASING (+{change_pct:.1f}%)"
            trend_direction = 'increasing'
        elif change_pct < -20:
            trend = f"DECREASING ({change_pct:.1f}%)"
            trend_direction = 'decreasing'
        else:
            trend = "STABLE"
            trend_direction = 'stable'

        print(f"\nCurrent Trend: {trend}")
        print(f"Average errors/hour: {np.mean(hourly_array):.1f}")
        print(f"Max errors/hour: {np.max(hourly_array):,}")
        print(f"Std deviation: {np.std(hourly_array):.1f}")

        # Change point detection
        detector = AdvancedAnomalyDetector()
        change_points = detector.detect_change_points(hourly_array)
        if change_points:
            print(f"\nChange Points Detected: {len(change_points)}")
            for cp in change_points[:5]:
                if cp < len(hours):
                    print(f"  - {hours[cp]}: Error rate changed significantly")

        # Forecast next 24 hours
        forecast_result = predictor.forecast(hourly_array, horizon=24)
        print(f"\n--- 24-HOUR FORECAST ---")
        print(f"Predicted total errors: {int(sum(forecast_result['forecast'])):,}")
        print(f"Trend direction: {forecast_result['trend_direction']}")
        print(f"Peak forecast hour: {np.argmax(forecast_result['forecast'])}:00 "
              f"({int(max(forecast_result['forecast']))} errors)")
        print(f"Low forecast hour: {np.argmin(forecast_result['forecast'])}:00 "
              f"({int(min(forecast_result['forecast']))} errors)")

        # Display forecast with confidence intervals
        print(f"\n{'Hour':<6}{'Forecast':<12}{'95% CI':<20}")
        print("-" * 40)
        for i in range(0, 24, 3):  # Show every 3 hours
            fc = forecast_result['forecast'][i]
            lb = forecast_result['lower_bound'][i]
            ub = forecast_result['upper_bound'][i]
            print(f"{i:02d}:00  {fc:<12.0f}[{lb:.0f} - {ub:.0f}]")

        # Hour of day pattern
        hour_of_day_counts = defaultdict(int)
        for h in hours:
            hour_of_day_counts[h.hour] += sum(self.hourly_errors[h].values())

        print(f"\nHour of Day Pattern:")
        print(f"{'Hour':<8}{'Errors':<12}{'Bar'}")
        print("-" * 50)

        max_hourly = max(hour_of_day_counts.values()) if hour_of_day_counts else 1
        for hour in range(24):
            count = hour_of_day_counts.get(hour, 0)
            bar = '█' * int(35 * count / max_hourly)
            print(f"{hour:02d}:00   {count:<12,}{bar}")

        # Find peak periods
        print(f"\nTop 10 Peak Hours:")
        print(f"{'Time':<25}{'Errors':<12}{'Dominant Error'}")
        print("-" * 55)

        sorted_hours = sorted(self.hourly_errors.items(),
                             key=lambda x: sum(x[1].values()), reverse=True)[:10]
        for hour, cats in sorted_hours:
            total = sum(cats.values())
            dominant = max(cats.items(), key=lambda x: x[1])[0]
            print(f"{str(hour):<25}{total:<12,}{dominant}")

        return {
            'trend': trend,
            'trend_direction': trend_direction,
            'avg_hourly': float(np.mean(hourly_array)),
            'max_hourly': int(np.max(hourly_array)),
            'forecast': forecast_result,
            'change_points': change_points
        }

    def analyze_cascades(self) -> Dict:
        """Detect and analyze cascading failures."""
        print("\n" + "=" * 70)
        print("CASCADE FAILURE DETECTION")
        print("=" * 70)

        if len(self.events) < 100:
            print("Insufficient events for cascade detection")
            return {}

        # Detect cascades
        cascade_detector = CascadeDetector(time_window_seconds=60)
        cascades = cascade_detector.detect_cascades(self.events, min_stores=5)

        if not cascades:
            print("\nNo significant cascade events detected")
            return {'cascades': [], 'propagation': {}}

        # Analyze propagation patterns
        propagation = cascade_detector.analyze_propagation(cascades)

        print(f"\nCascade Statistics:")
        print(f"  Total cascade events: {propagation['total_cascades']}")
        print(f"  Average stores affected: {propagation['avg_stores_affected']:.1f}")
        print(f"  Max stores in single cascade: {propagation['max_stores_in_cascade']}")
        print(f"  Server-wide cascades: {propagation['server_wide_cascades']}")

        print(f"\nCascade Error Types:")
        for error_type, count in sorted(propagation['common_error_types'].items(),
                                        key=lambda x: x[1], reverse=True):
            print(f"  {error_type}: {count}")

        print(f"\nTop 10 Cascade Events:")
        print(f"{'Start Time':<22}{'Stores':<10}{'Events':<10}{'Error Type':<25}{'Server-wide'}")
        print("-" * 80)

        for cascade in sorted(cascades, key=lambda c: c['store_count'], reverse=True)[:10]:
            server_wide = "YES" if cascade['is_server_wide'] else "No"
            print(f"{str(cascade['start_time']):<22}{cascade['store_count']:<10}"
                  f"{cascade['event_count']:<10}{cascade['dominant_error']:<25}{server_wide}")

        return {
            'cascades': cascades,
            'propagation': propagation,
            'server_wide_cascades': propagation['server_wide_cascades']
        }

    def analyze_root_causes(self) -> Dict:
        """Perform advanced root cause analysis with Bayesian inference."""
        print("\n" + "=" * 70)
        print("ROOT CAUSE ANALYSIS (AI-Powered)")
        print("=" * 70)

        # Initialize causal analyzer
        causal = CausalAnalyzer()

        # Machine health analysis
        print(f"\nMachine Health Scores:")
        print(f"{'Machine':<15}{'Errors':<12}{'Stores':<10}{'Errors/Store':<15}{'Health':<12}{'Status'}")
        print("-" * 75)

        machine_health = {}
        for machine, stats in sorted(self.machine_stats.items(),
                                    key=lambda x: x[1]['total_errors'], reverse=True):
            errors = stats['total_errors']
            stores = len(stats['stores'])
            ratio = errors / stores if stores > 0 else 0

            # Calculate health score (0-100, higher is better)
            health_score = max(0, 100 - min(100, ratio * 2 + errors / 1000))

            if health_score < 30:
                status = "CRITICAL"
            elif health_score < 50:
                status = "WARNING"
            elif health_score < 70:
                status = "FAIR"
            else:
                status = "GOOD"

            machine_health[machine] = {
                'score': health_score,
                'errors': errors,
                'stores': list(stats['stores']),
                'ratio': ratio
            }

            health_bar = '█' * int(health_score / 10) + '░' * (10 - int(health_score / 10))
            print(f"{machine:<15}{errors:<12,}{stores:<10}{ratio:<15.1f}{health_bar} {health_score:.0f}  {status}")

        # Bayesian root cause inference
        print(f"\n--- PROBABILISTIC ROOT CAUSE ANALYSIS ---")
        root_causes = causal.infer_root_causes(
            self.store_stats,
            self.machine_stats,
            self.error_category_totals
        )

        print(f"\nInferred Root Causes (Bayesian Analysis):")
        print(f"{'Cause':<25}{'Probability':<15}{'Evidence'}")
        print("-" * 70)
        for cause in root_causes:
            prob_bar = '█' * int(cause['probability'] * 20)
            print(f"{cause['cause']:<25}{prob_bar} {cause['probability']:.0%}    {cause['evidence']}")

        # IP analysis - find problematic endpoints
        print(f"\nTop Problem IPs (potential bottlenecks):")
        print(f"{'IP Address':<20}{'Errors':<12}{'Stores':<10}{'Errors/Store'}")
        print("-" * 55)

        top_ips = sorted(self.ip_stats.items(),
                        key=lambda x: x[1]['errors'], reverse=True)[:15]
        for ip, stats in top_ips:
            stores_count = len(stats['stores'])
            ratio = stats['errors'] / stores_count if stores_count > 0 else 0
            print(f"{ip:<20}{stats['errors']:<12,}{stores_count:<10}{ratio:.1f}")

        # Store risk analysis
        print(f"\n--- STORE RISK ANALYSIS ---")
        predictor = PredictiveAnalytics()

        high_risk_stores = []
        for store_id, stats in self.store_stats.items():
            if stats['total_errors'] < 10:
                continue

            # Calculate failure probability
            hourly_values = list(stats['hourly_counts'].values())
            features = {
                'recent_errors': stats['total_errors'],
                'error_variance': np.var(hourly_values) if len(hourly_values) > 1 else 0,
                'error_types': len(stats['error_categories']),
                'trend': 'increasing' if len(hourly_values) > 2 and hourly_values[-1] > np.mean(hourly_values) else 'stable',
                'burst_count': len([d for d in stats.get('reconnect_delays', []) if d < 60])
            }

            prob = predictor.predict_failure_probability(features)
            if prob > 0.6:
                high_risk_stores.append({
                    'store_id': store_id,
                    'probability': prob,
                    'total_errors': stats['total_errors']
                })

        if high_risk_stores:
            print(f"\nHigh-Risk Stores (>60% failure probability):")
            print(f"{'Store':<12}{'Risk':<12}{'Current Errors'}")
            print("-" * 40)
            for store in sorted(high_risk_stores, key=lambda x: x['probability'], reverse=True)[:15]:
                risk_bar = '█' * int(store['probability'] * 10)
                print(f"{store['store_id']:<12}{risk_bar} {store['probability']:.0%}    {store['total_errors']:,}")

        return {
            'machine_health': machine_health,
            'root_causes': root_causes,
            'high_risk_stores': high_risk_stores
        }

    def generate_report(self):
        """Generate comprehensive AI-powered analysis report with recommendations."""
        print("\n" + "=" * 70)
        print("FEDERATION LOG AI ANALYSIS REPORT")
        print("Advanced ML Analysis with Predictive Analytics")
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)

        print(f"\nDataset Summary:")
        print(f"  Files processed: {self.files_processed:,}")
        print(f"  Lines processed: {self.lines_processed:,}")
        print(f"  Unique stores: {len(self.store_stats):,}")
        print(f"  Unique machines: {len(self.machine_stats)}")
        print(f"  Total events: {len(self.events):,}")

        if self.min_ts and self.max_ts:
            duration = self.max_ts - self.min_ts
            print(f"  Time range: {self.min_ts} to {self.max_ts}")
            print(f"  Duration: {duration}")

        # Collect all analysis results
        results = {}

        # Run all analyses
        print("\n[1/8] Analyzing error patterns...")
        self.analyze_error_patterns()

        print("\n[2/8] Analyzing Internal Errors...")
        results['internal_errors'] = self.analyze_internal_errors()

        print("\n[3/8] Running ensemble anomaly detection...")
        results['anomalies'] = self.analyze_anomalies()

        print("\n[4/8] Clustering stores by behavior...")
        results['clusters'] = self.analyze_store_clusters()

        print("\n[5/8] Analyzing time series and forecasting...")
        results['time_series'] = self.analyze_time_series()

        print("\n[6/8] Detecting cascade failures...")
        results['cascades'] = self.analyze_cascades()

        print("\n[7/8] Performing root cause analysis...")
        root_cause = self.analyze_root_causes()
        results['root_causes'] = root_cause.get('root_causes', [])
        results['machine_health'] = root_cause.get('machine_health', {})
        results['predictions'] = results['time_series']

        # Run AI Optimization if available
        if HAS_AI_OPTIMIZER:
            print("\n[8/8] Running AI Model Optimization...")
            results['ai_optimization'] = optimize_and_evaluate(
                self.store_stats, self.events, self.error_category_totals
            )
        else:
            print("\n[8/8] AI Optimizer not available - skipping advanced ML")
            results['ai_optimization'] = {}

        # Generate actionable recommendations
        print("\n" + "=" * 70)
        rec_engine = RecommendationEngine()
        recommendations = rec_engine.generate_recommendations(results)

        print(rec_engine.format_report())

        # Executive Summary
        print("\n" + "=" * 70)
        print("EXECUTIVE SUMMARY")
        print("=" * 70)

        # Key metrics
        total_errors = sum(self.error_category_totals.values())
        anomalous_count = len(results['anomalies'].get('anomalous_stores', []))
        cascade_count = len(results['cascades'].get('cascades', []))

        print(f"\nKey Metrics:")
        print(f"  Total Errors Analyzed: {total_errors:,}")
        print(f"  Anomalous Stores Detected: {anomalous_count}")
        print(f"  Cascade Events Detected: {cascade_count}")

        if results['time_series']:
            trend = results['time_series'].get('trend_direction', 'unknown')
            print(f"  Error Trend: {trend.upper()}")

            forecast = results['time_series'].get('forecast', {})
            if forecast:
                next_24h = sum(forecast.get('forecast', []))
                print(f"  24-Hour Forecast: {int(next_24h):,} errors expected")

        # Top root cause
        if results['root_causes']:
            top_cause = results['root_causes'][0]
            print(f"  Most Likely Root Cause: {top_cause['cause']} ({top_cause['probability']:.0%})")

        # Critical actions
        critical_recs = [r for r in recommendations if r.priority == 1]
        if critical_recs:
            print(f"\nCritical Actions Required: {len(critical_recs)}")
            for rec in critical_recs[:3]:
                print(f"  → {rec.action}")

        print("\n" + "=" * 70)
        print("END OF AI ANALYSIS REPORT")
        print("=" * 70)

        return {
            'anomalies': results['anomalies'],
            'clusters': results['clusters'],
            'time_series': results['time_series'],
            'cascades': results['cascades'],
            'root_causes': results['root_causes'],
            'recommendations': [
                {
                    'priority': r.priority,
                    'action': r.action,
                    'target': r.target,
                    'reason': r.reason,
                    'confidence': r.confidence
                }
                for r in recommendations
            ]
        }


def main():
    """Main entry point."""
    print("Federation Log AI Analyzer")
    print("=" * 50)

    analyzer = FederationLogAnalyzer()

    # Check for command line arguments
    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            path = os.path.expanduser(arg)
            if os.path.isfile(path):
                if path.endswith('.zip'):
                    analyzer.process_nested_zip(path)
                elif path.endswith('.log'):
                    analyzer.process_log_file(path)
                else:
                    print(f"Unsupported file type: {path}")
            elif os.path.isdir(path):
                analyzer.process_log_directory(path)
            else:
                print(f"Path not found: {path}")
    else:
        # Auto-discover files in Downloads
        downloads = os.path.expanduser("~/Downloads")
        zip_files = []
        log_files = []

        for f in os.listdir(downloads):
            full_path = os.path.join(downloads, f)
            if f.endswith('.zip') and ('Fed' in f or 'Base' in f):
                zip_files.append(full_path)
            elif f.endswith('.log') and ('SBUXSCRoleGroup' in f or 'Federation' in f):
                log_files.append(full_path)

        if not zip_files and not log_files:
            print("No federation log files found in ~/Downloads")
            print("Looking for: *Fed*.zip, *Base*.zip, *SBUXSCRoleGroup*.log, *Federation*.log")
            print("\nUsage: python analyze_federation_ai.py [file.zip|file.log|directory] ...")
            sys.exit(1)

        # Sort by modification time (newest first)
        zip_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
        log_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)

        if zip_files:
            print(f"\nFound {len(zip_files)} ZIP files:")
            for f in zip_files:
                size_mb = os.path.getsize(f) / (1024 * 1024)
                print(f"  {os.path.basename(f)} ({size_mb:.1f} MB)")

        if log_files:
            print(f"\nFound {len(log_files)} log files:")
            for f in log_files:
                size_mb = os.path.getsize(f) / (1024 * 1024)
                print(f"  {os.path.basename(f)} ({size_mb:.1f} MB)")

        for zip_file in zip_files:
            analyzer.process_nested_zip(zip_file)

        for log_file in log_files:
            analyzer.process_log_file(log_file)

    if analyzer.events:
        analyzer.generate_report()
    else:
        print("\nNo federation events found in the log files.")


if __name__ == "__main__":
    main()
