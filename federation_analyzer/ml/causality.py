"""
Root cause analysis using feature importance and causal inference.
"""

from typing import Dict, List

import numpy as np

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LinearRegression

    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False


class CausalAnalyzer:
    """
    Root cause analysis using feature importance and causal inference.
    """

    def __init__(self):
        self.feature_importance = {}
        self.correlation_matrix = None
        self.causal_graph = {}

    def calculate_feature_importance(
        self, features: np.ndarray, labels: np.ndarray, feature_names: List[str]
    ) -> Dict[str, float]:
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

            return dict(sorted(self.feature_importance.items(), key=lambda x: x[1], reverse=True))
        except Exception:
            return {}

    def build_correlation_matrix(
        self, features: np.ndarray, feature_names: List[str]
    ) -> np.ndarray:
        """
        Build correlation matrix between features.
        """
        if len(features) < 10:
            return np.array([])

        self.correlation_matrix = np.corrcoef(features.T)
        return self.correlation_matrix

    def granger_causality_test(
        self, series1: np.ndarray, series2: np.ndarray, max_lag: int = 5
    ) -> Dict:
        """
        Simplified Granger causality test.
        Tests if series1 helps predict series2.
        """
        if len(series1) < max_lag * 3:
            return {"causal": False, "p_value": 1.0}

        # Build lagged features
        X = []
        y = series2[max_lag:]

        for i in range(max_lag, len(series2)):
            row = list(series2[i - max_lag : i]) + list(series1[i - max_lag : i])
            X.append(row)

        X = np.array(X)

        # Restricted model (only series2 lags)
        X_restricted = X[:, :max_lag]

        # Compare R-squared
        if HAS_SKLEARN:
            model_full = LinearRegression().fit(X, y)
            model_restricted = LinearRegression().fit(X_restricted, y)

            r2_full = model_full.score(X, y)
            r2_restricted = model_restricted.score(X_restricted, y)

            # F-test approximation
            improvement = r2_full - r2_restricted
            is_causal = improvement > 0.05  # 5% improvement threshold

            return {
                "causal": is_causal,
                "improvement": improvement,
                "r2_full": r2_full,
                "r2_restricted": r2_restricted,
            }

        return {"causal": False, "p_value": 1.0}

    def infer_root_causes(
        self, store_stats: Dict, machine_stats: Dict, error_totals: Dict
    ) -> List[Dict]:
        """
        Infer likely root causes from observed patterns.
        Uses Bayesian-style reasoning.
        """
        causes = []

        # Prior probabilities of different root causes
        priors = {
            "network_issue": 0.3,
            "store_hardware": 0.25,
            "server_overload": 0.2,
            "certificate_expiry": 0.1,
            "configuration_error": 0.1,
            "external_dependency": 0.05,
        }

        # Calculate evidence updates based on error patterns
        total_errors = sum(error_totals.values())
        if total_errors == 0:
            return causes

        # Network issues evidence
        network_evidence = (
            error_totals.get("connection_timeout", 0)
            + error_totals.get("host_unreachable", 0)
            + error_totals.get("socket_exception", 0)
        ) / total_errors

        # Hardware evidence
        hardware_evidence = error_totals.get("connection_refused", 0) / total_errors

        # TLS/Certificate evidence
        cert_evidence = (
            error_totals.get("tls_handshake_error", 0) + error_totals.get("certificate_error", 0)
        ) / total_errors

        # Server overload evidence (many stores on same machine)
        overload_evidence = 0
        if machine_stats:
            max_stores_per_machine = max(
                len(m.get("stores", set())) for m in machine_stats.values()
            )
            if max_stores_per_machine > 200:
                overload_evidence = 0.5

        # Update posteriors (simplified Bayesian update)
        posteriors = {}
        posteriors["network_issue"] = priors["network_issue"] * (1 + 3 * network_evidence)
        posteriors["store_hardware"] = priors["store_hardware"] * (1 + 3 * hardware_evidence)
        posteriors["certificate_expiry"] = priors["certificate_expiry"] * (1 + 5 * cert_evidence)
        posteriors["server_overload"] = priors["server_overload"] * (1 + 2 * overload_evidence)

        # Normalize
        total_posterior = sum(posteriors.values())
        for cause, prob in sorted(posteriors.items(), key=lambda x: x[1], reverse=True):
            normalized_prob = prob / total_posterior if total_posterior > 0 else 0
            if normalized_prob > 0.1:  # Only report significant causes
                causes.append(
                    {
                        "cause": cause,
                        "probability": normalized_prob,
                        "evidence": self._get_evidence_description(cause, error_totals),
                    }
                )

        return causes

    def _get_evidence_description(self, cause: str, error_totals: Dict) -> str:
        """Get human-readable evidence for a root cause."""
        descriptions = {
            "network_issue": f"High timeout/socket errors ({error_totals.get('connection_timeout', 0):,})",
            "store_hardware": f"Connection refused errors ({error_totals.get('connection_refused', 0):,})",
            "certificate_expiry": f"TLS errors ({error_totals.get('tls_handshake_error', 0):,})",
            "server_overload": "High store density on federation servers",
            "configuration_error": "Inconsistent error patterns across stores",
            "external_dependency": "Correlated failures across multiple stores",
        }
        return descriptions.get(cause, "Pattern analysis")
