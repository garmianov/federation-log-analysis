"""
Forecasting and trend prediction using statistical methods.
"""

from typing import Dict

import numpy as np

try:
    from scipy import stats
    from scipy.ndimage import uniform_filter1d

    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False


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
            return {"trend": data, "seasonal": np.zeros_like(data), "residual": np.zeros_like(data)}

        # Trend: Moving average
        if HAS_SCIPY:
            trend = uniform_filter1d(data.astype(float), size=period, mode="nearest")
        else:
            trend = np.convolve(data, np.ones(period) / period, mode="same")

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

        return {"trend": trend, "seasonal": seasonal, "residual": residual}

    def forecast(self, data: np.ndarray, horizon: int = 24, confidence_level: float = 0.95) -> Dict:
        """
        Forecast future values with confidence intervals.
        Uses exponential smoothing with seasonal adjustment.
        """
        if len(data) < 48:
            mean_val = np.mean(data)
            return {
                "forecast": np.full(horizon, mean_val),
                "lower_bound": np.full(horizon, mean_val * 0.5),
                "upper_bound": np.full(horizon, mean_val * 1.5),
            }

        decomp = self.decompose_time_series(data)

        # Holt-Winters style forecasting
        # Note: alpha (0.3) and beta (0.1) smoothing constants reserved for future use
        level = decomp["trend"][-1]
        trend = self.trend_slope

        forecast = []
        for h in range(horizon):
            # Project level and trend
            projected_level = level + trend * (h + 1)

            # Add seasonal component
            seasonal_idx = (len(data) + h) % len(self.seasonal_pattern)
            seasonal = (
                self.seasonal_pattern[seasonal_idx] if self.seasonal_pattern is not None else 0
            )

            forecast.append(max(0, projected_level + seasonal))

        forecast = np.array(forecast)

        # Confidence intervals based on residual variance
        residual_std = np.std(decomp["residual"])
        z_score = stats.norm.ppf((1 + confidence_level) / 2) if HAS_SCIPY else 1.96

        # Wider intervals for further predictions
        interval_width = residual_std * z_score * np.sqrt(np.arange(1, horizon + 1))

        return {
            "forecast": forecast,
            "lower_bound": np.maximum(0, forecast - interval_width),
            "upper_bound": forecast + interval_width,
            "trend_direction": "increasing"
            if trend > 0.1
            else "decreasing"
            if trend < -0.1
            else "stable",
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
        if "recent_errors" in store_features:
            risk_score += min(store_features["recent_errors"] / 100, 1) * 30
            max_score += 30

        # Error variance (high variance = unpredictable = risky)
        if "error_variance" in store_features:
            risk_score += min(store_features["error_variance"] / 50, 1) * 20
            max_score += 20

        # Number of distinct error types
        if "error_types" in store_features:
            risk_score += min(store_features["error_types"] / 5, 1) * 15
            max_score += 15

        # Recent trend
        if "trend" in store_features:
            if store_features["trend"] == "increasing":
                risk_score += 20
            elif store_features["trend"] == "stable":
                risk_score += 5
            max_score += 20

        # Burst frequency
        if "burst_count" in store_features:
            risk_score += min(store_features["burst_count"] / 10, 1) * 15
            max_score += 15

        # Convert to probability using sigmoid-like function
        if max_score > 0:
            normalized = risk_score / max_score
            probability = 1 / (1 + np.exp(-5 * (normalized - 0.5)))
            return probability
        return 0.5
