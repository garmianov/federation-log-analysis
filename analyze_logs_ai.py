#!/usr/bin/env python3
"""
AI-Powered Federation Log Analyzer
Uses machine learning algorithms for advanced pattern detection and prediction.

Features:
- Anomaly Detection: Identify unusual failure patterns using Isolation Forest
- Store Clustering: Group stores with similar behavior using K-Means
- Time Series Forecasting: Predict future failure rates
- Pattern Recognition: Detect recurring failure sequences
- Correlation Analysis: Find relationships between stores, machines, and time
"""

import os
import re
import sys
import warnings
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Tuple, Optional
import numpy as np

warnings.filterwarnings('ignore')

# Optional imports with fallbacks
try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False
    print("Warning: pandas not installed. Install with: pip install pandas")

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.cluster import KMeans, DBSCAN
    from sklearn.preprocessing import StandardScaler
    from sklearn.decomposition import PCA
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
    print("Warning: scikit-learn not installed. Install with: pip install scikit-learn")

try:
    from scipy import stats
    from scipy.signal import find_peaks
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False


class AnomalyDetector:
    """Detect anomalous patterns in log data using multiple methods."""

    def __init__(self, contamination: float = 0.1):
        self.contamination = contamination
        self.isolation_forest = None
        self.scaler = StandardScaler() if HAS_SKLEARN else None

    def fit_isolation_forest(self, features: np.ndarray) -> np.ndarray:
        """
        Use Isolation Forest to detect anomalies.
        Returns: Array of -1 (anomaly) or 1 (normal) for each sample.
        """
        if not HAS_SKLEARN:
            return np.ones(len(features))

        scaled_features = self.scaler.fit_transform(features)
        self.isolation_forest = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100
        )
        return self.isolation_forest.fit_predict(scaled_features)

    def detect_statistical_anomalies(self, values: np.ndarray, threshold: float = 3.0) -> np.ndarray:
        """
        Detect anomalies using Z-score method.
        Returns: Boolean array where True indicates anomaly.
        """
        if len(values) < 2:
            return np.zeros(len(values), dtype=bool)

        mean = np.mean(values)
        std = np.std(values)
        if std == 0:
            return np.zeros(len(values), dtype=bool)

        z_scores = np.abs((values - mean) / std)
        return z_scores > threshold

    def detect_iqr_anomalies(self, values: np.ndarray, k: float = 1.5) -> np.ndarray:
        """
        Detect anomalies using Interquartile Range (IQR) method.
        More robust to extreme outliers than Z-score.
        """
        q1 = np.percentile(values, 25)
        q3 = np.percentile(values, 75)
        iqr = q3 - q1
        lower_bound = q1 - k * iqr
        upper_bound = q3 + k * iqr
        return (values < lower_bound) | (values > upper_bound)


class StoreClustering:
    """Cluster stores based on their failure patterns."""

    def __init__(self, n_clusters: int = 5):
        self.n_clusters = n_clusters
        self.kmeans = None
        self.scaler = StandardScaler() if HAS_SKLEARN else None
        self.labels_ = None
        self.cluster_centers_ = None

    def build_store_features(self, store_data: Dict) -> Tuple[np.ndarray, List[str]]:
        """
        Build feature matrix for stores.
        Features: failure_count, avg_failures_per_day, failure_variance,
                  peak_hour_failures, night_failures_ratio, weekend_ratio
        """
        store_ids = []
        features = []

        for store_id, data in store_data.items():
            if data['total_failures'] < 5:  # Skip stores with too few events
                continue

            feature_vector = [
                data['total_failures'],
                data['avg_daily_failures'],
                data['failure_variance'],
                data['peak_hour_failures'],
                data['night_ratio'],
                data['weekend_ratio'],
                data['max_hourly_failures'],
                data['failure_burst_count']
            ]
            store_ids.append(store_id)
            features.append(feature_vector)

        return np.array(features), store_ids

    def fit_predict(self, features: np.ndarray) -> np.ndarray:
        """Cluster stores using K-Means."""
        if not HAS_SKLEARN or len(features) < self.n_clusters:
            return np.zeros(len(features), dtype=int)

        scaled_features = self.scaler.fit_transform(features)
        self.kmeans = KMeans(n_clusters=self.n_clusters, random_state=42, n_init=10)
        self.labels_ = self.kmeans.fit_predict(scaled_features)
        self.cluster_centers_ = self.scaler.inverse_transform(self.kmeans.cluster_centers_)
        return self.labels_

    def get_cluster_profiles(self) -> Dict:
        """Generate human-readable profiles for each cluster."""
        if self.cluster_centers_ is None:
            return {}

        profiles = {}
        feature_names = ['total_failures', 'avg_daily', 'variance', 'peak_hour',
                        'night_ratio', 'weekend_ratio', 'max_hourly', 'burst_count']

        for i, center in enumerate(self.cluster_centers_):
            profile = {}
            for j, name in enumerate(feature_names):
                profile[name] = center[j]

            # Generate description
            if center[0] > 100:  # high failure count
                if center[4] > 0.4:  # high night ratio
                    desc = "High-failure nocturnal pattern"
                elif center[7] > 5:  # high burst count
                    desc = "High-failure bursty pattern"
                else:
                    desc = "Consistently problematic"
            elif center[2] > 50:  # high variance
                desc = "Intermittent issues"
            elif center[5] > 0.4:  # high weekend ratio
                desc = "Weekend-heavy failures"
            else:
                desc = "Normal/stable pattern"

            profile['description'] = desc
            profiles[i] = profile

        return profiles


class TimeSeriesAnalyzer:
    """Analyze and forecast time series patterns in failure data."""

    def __init__(self):
        self.hourly_pattern = None
        self.daily_pattern = None
        self.trend = None

    def decompose(self, hourly_counts: np.ndarray) -> Dict:
        """
        Decompose time series into trend, seasonality, and residual.
        Uses simple moving average method.
        """
        if len(hourly_counts) < 48:  # Need at least 2 days
            return {'trend': hourly_counts, 'seasonal': np.zeros_like(hourly_counts),
                    'residual': np.zeros_like(hourly_counts)}

        # Calculate trend using 24-hour moving average
        window = 24
        trend = np.convolve(hourly_counts, np.ones(window)/window, mode='same')

        # Calculate seasonal pattern (average by hour of day)
        detrended = hourly_counts - trend
        seasonal = np.zeros_like(hourly_counts, dtype=float)
        for h in range(24):
            mask = np.arange(len(hourly_counts)) % 24 == h
            seasonal[mask] = np.mean(detrended[mask])

        # Residual
        residual = hourly_counts - trend - seasonal

        self.trend = trend
        self.hourly_pattern = seasonal[:24]

        return {'trend': trend, 'seasonal': seasonal, 'residual': residual}

    def forecast_next_hours(self, hourly_counts: np.ndarray, hours_ahead: int = 24) -> np.ndarray:
        """
        Simple forecast using trend + seasonal pattern.
        """
        if len(hourly_counts) < 48:
            return np.full(hours_ahead, np.mean(hourly_counts))

        decomposed = self.decompose(hourly_counts)

        # Project trend
        trend_slope = (decomposed['trend'][-1] - decomposed['trend'][-24]) / 24
        last_trend = decomposed['trend'][-1]

        forecast = []
        last_hour = len(hourly_counts) % 24

        for i in range(hours_ahead):
            hour = (last_hour + i + 1) % 24
            trend_value = last_trend + trend_slope * (i + 1)
            seasonal_value = self.hourly_pattern[hour] if self.hourly_pattern is not None else 0
            forecast.append(max(0, trend_value + seasonal_value))

        return np.array(forecast)

    def detect_trend(self, hourly_counts: np.ndarray) -> str:
        """Detect if failures are trending up, down, or stable."""
        if len(hourly_counts) < 48:
            return "insufficient_data"

        first_half = np.mean(hourly_counts[:len(hourly_counts)//2])
        second_half = np.mean(hourly_counts[len(hourly_counts)//2:])

        change_pct = (second_half - first_half) / first_half * 100 if first_half > 0 else 0

        if change_pct > 20:
            return f"increasing (+{change_pct:.1f}%)"
        elif change_pct < -20:
            return f"decreasing ({change_pct:.1f}%)"
        else:
            return "stable"


class PatternRecognizer:
    """Recognize recurring patterns and sequences in failures."""

    def __init__(self):
        self.common_sequences = []
        self.failure_correlations = {}

    def find_failure_bursts(self, timestamps: List[datetime],
                           window_minutes: int = 10,
                           min_count: int = 5) -> List[Dict]:
        """
        Identify bursts of failures (many failures in short time).
        """
        if not timestamps:
            return []

        sorted_ts = sorted(timestamps)
        bursts = []
        i = 0

        while i < len(sorted_ts):
            window_end = sorted_ts[i] + timedelta(minutes=window_minutes)
            count = 1
            j = i + 1

            while j < len(sorted_ts) and sorted_ts[j] <= window_end:
                count += 1
                j += 1

            if count >= min_count:
                bursts.append({
                    'start': sorted_ts[i],
                    'end': sorted_ts[j-1] if j > i else sorted_ts[i],
                    'count': count,
                    'duration_minutes': (sorted_ts[j-1] - sorted_ts[i]).total_seconds() / 60
                })
                i = j
            else:
                i += 1

        return bursts

    def find_correlated_stores(self, store_failures: Dict[str, List[datetime]],
                               time_window_minutes: int = 5) -> List[Tuple[str, str, float]]:
        """
        Find stores that tend to fail together (within time window).
        Returns list of (store1, store2, correlation_score) tuples.
        """
        correlations = []
        stores = list(store_failures.keys())

        for i, store1 in enumerate(stores):
            for store2 in stores[i+1:]:
                ts1 = set(t.replace(second=0, microsecond=0) for t in store_failures[store1])
                ts2 = set(t.replace(second=0, microsecond=0) for t in store_failures[store2])

                # Count co-occurrences within window
                co_occur = 0
                for t1 in ts1:
                    for delta in range(-time_window_minutes, time_window_minutes + 1):
                        if t1 + timedelta(minutes=delta) in ts2:
                            co_occur += 1
                            break

                # Calculate Jaccard similarity
                union = len(ts1 | ts2)
                if union > 0:
                    similarity = co_occur / min(len(ts1), len(ts2))
                    if similarity > 0.3:  # Only report significant correlations
                        correlations.append((store1, store2, similarity))

        return sorted(correlations, key=lambda x: x[2], reverse=True)

    def detect_periodic_failures(self, hourly_counts: np.ndarray) -> Dict:
        """
        Detect if failures follow a periodic pattern (daily, etc.)
        using autocorrelation.
        """
        if len(hourly_counts) < 48:
            return {'periodic': False, 'period': None}

        # Calculate autocorrelation
        n = len(hourly_counts)
        mean = np.mean(hourly_counts)
        var = np.var(hourly_counts)

        if var == 0:
            return {'periodic': False, 'period': None}

        autocorr = []
        for lag in range(1, min(49, n//2)):
            c = np.sum((hourly_counts[:-lag] - mean) * (hourly_counts[lag:] - mean)) / (n * var)
            autocorr.append(c)

        autocorr = np.array(autocorr)

        # Find peaks in autocorrelation
        if HAS_SCIPY:
            peaks, _ = find_peaks(autocorr, height=0.3)
            if len(peaks) > 0:
                period = peaks[0] + 1
                return {'periodic': True, 'period': period, 'strength': autocorr[peaks[0]]}

        # Fallback: check 24-hour period manually
        if len(autocorr) >= 24 and autocorr[23] > 0.3:
            return {'periodic': True, 'period': 24, 'strength': autocorr[23]}

        return {'periodic': False, 'period': None}


class AILogAnalyzer:
    """Main class that orchestrates all AI analysis components."""

    def __init__(self):
        self.anomaly_detector = AnomalyDetector()
        self.clustering = StoreClustering()
        self.time_series = TimeSeriesAnalyzer()
        self.pattern_recognizer = PatternRecognizer()

        self.store_data = {}
        self.machine_data = {}
        self.hourly_failures = []
        self.raw_failures = []

    def load_excel(self, filepath: str) -> bool:
        """Load health history from Excel file."""
        if not HAS_PANDAS:
            print("Error: pandas required for Excel loading")
            return False

        try:
            df = pd.read_excel(filepath, sheet_name='Sheet1')
            print(f"Loaded {len(df):,} events from {os.path.basename(filepath)}")
            self._process_dataframe(df)
            return True
        except Exception as e:
            print(f"Error loading file: {e}")
            return False

    def _process_dataframe(self, df: pd.DataFrame):
        """Process loaded dataframe into analysis structures."""

        def extract_store_id(entity):
            if pd.isna(entity):
                return None
            match = re.search(r'Store[\s_](\d{4,5})', str(entity))
            return match.group(1).zfill(5) if match else None

        df['store_id'] = df['Source entity'].apply(extract_store_id)
        df['hour'] = df['Event timestamp'].dt.floor('h')
        df['hour_of_day'] = df['Event timestamp'].dt.hour
        df['day_of_week'] = df['Event timestamp'].dt.dayofweek

        failures = df[df['Health event'] == 'Connection failed'].copy()

        # Build hourly failure counts
        hourly = failures.groupby('hour').size()
        self.hourly_failures = hourly.values
        self.hourly_index = hourly.index.tolist()

        # Build store-level statistics
        for store_id in failures['store_id'].dropna().unique():
            store_failures = failures[failures['store_id'] == store_id]

            timestamps = store_failures['Event timestamp'].tolist()
            hours = store_failures['hour_of_day'].values
            days = store_failures['day_of_week'].values

            daily_counts = store_failures.groupby(store_failures['Event timestamp'].dt.date).size()
            hourly_counts = store_failures.groupby('hour').size()

            self.store_data[store_id] = {
                'total_failures': len(store_failures),
                'avg_daily_failures': daily_counts.mean() if len(daily_counts) > 0 else 0,
                'failure_variance': daily_counts.var() if len(daily_counts) > 1 else 0,
                'peak_hour_failures': hourly_counts.max() if len(hourly_counts) > 0 else 0,
                'night_ratio': np.sum((hours >= 22) | (hours < 6)) / len(hours) if len(hours) > 0 else 0,
                'weekend_ratio': np.sum(days >= 5) / len(days) if len(days) > 0 else 0,
                'max_hourly_failures': hourly_counts.max() if len(hourly_counts) > 0 else 0,
                'failure_burst_count': 0,  # Will be calculated later
                'timestamps': timestamps,
                'machine': store_failures['Machine'].mode().iloc[0] if len(store_failures) > 0 else None
            }

        # Build machine-level statistics
        for machine in failures['Machine'].unique():
            machine_failures = failures[failures['Machine'] == machine]
            self.machine_data[machine] = {
                'total_failures': len(machine_failures),
                'unique_stores': machine_failures['store_id'].nunique(),
                'timestamps': machine_failures['Event timestamp'].tolist()
            }

        # Store raw failure data
        self.raw_failures = failures[['Event timestamp', 'store_id', 'Machine']].to_dict('records')

        print(f"Processed {len(self.store_data)} stores, {len(self.machine_data)} machines")

    def run_anomaly_detection(self) -> Dict:
        """Run anomaly detection on stores and time periods."""
        print("\n" + "=" * 70)
        print("ANOMALY DETECTION")
        print("=" * 70)

        results = {'stores': [], 'time_periods': []}

        # Build feature matrix for stores
        features, store_ids = self.clustering.build_store_features(self.store_data)

        if len(features) > 10:
            # Isolation Forest anomaly detection
            anomaly_labels = self.anomaly_detector.fit_isolation_forest(features)

            anomalous_stores = []
            for i, (store_id, label) in enumerate(zip(store_ids, anomaly_labels)):
                if label == -1:  # Anomaly
                    anomalous_stores.append({
                        'store_id': store_id,
                        'failures': self.store_data[store_id]['total_failures'],
                        'avg_daily': self.store_data[store_id]['avg_daily_failures'],
                        'machine': self.store_data[store_id]['machine']
                    })

            results['stores'] = sorted(anomalous_stores,
                                       key=lambda x: x['failures'], reverse=True)

            print(f"\nFound {len(anomalous_stores)} anomalous stores (Isolation Forest)")
            print(f"{'Store':<12}{'Failures':<12}{'Avg Daily':<12}{'Machine':<12}")
            print("-" * 48)
            for s in results['stores'][:15]:
                print(f"{s['store_id']:<12}{s['failures']:<12}{s['avg_daily']:<12.1f}{s['machine'] or 'N/A':<12}")

        # Time-based anomaly detection
        if len(self.hourly_failures) > 0:
            z_anomalies = self.anomaly_detector.detect_statistical_anomalies(
                self.hourly_failures, threshold=2.5
            )
            iqr_anomalies = self.anomaly_detector.detect_iqr_anomalies(
                self.hourly_failures, k=1.5
            )

            combined_anomalies = z_anomalies | iqr_anomalies

            print(f"\nFound {np.sum(combined_anomalies)} anomalous time periods")
            print(f"{'Time Period':<25}{'Failures':<12}{'Method'}")
            print("-" * 50)

            for i, is_anomaly in enumerate(combined_anomalies):
                if is_anomaly and i < len(self.hourly_index):
                    method = []
                    if z_anomalies[i]:
                        method.append("Z-score")
                    if iqr_anomalies[i]:
                        method.append("IQR")
                    results['time_periods'].append({
                        'time': self.hourly_index[i],
                        'failures': int(self.hourly_failures[i]),
                        'method': '+'.join(method)
                    })

            for tp in sorted(results['time_periods'],
                           key=lambda x: x['failures'], reverse=True)[:10]:
                print(f"{str(tp['time']):<25}{tp['failures']:<12}{tp['method']}")

        return results

    def run_clustering(self) -> Dict:
        """Cluster stores by failure patterns."""
        print("\n" + "=" * 70)
        print("STORE CLUSTERING")
        print("=" * 70)

        features, store_ids = self.clustering.build_store_features(self.store_data)

        if len(features) < 10:
            print("Insufficient data for clustering")
            return {}

        # Determine optimal number of clusters (simplified elbow method)
        n_clusters = min(5, len(features) // 20)
        n_clusters = max(2, n_clusters)
        self.clustering.n_clusters = n_clusters

        labels = self.clustering.fit_predict(features)
        profiles = self.clustering.get_cluster_profiles()

        # Group stores by cluster
        clusters = defaultdict(list)
        for store_id, label in zip(store_ids, labels):
            clusters[label].append({
                'store_id': store_id,
                'failures': self.store_data[store_id]['total_failures']
            })

        print(f"\nIdentified {n_clusters} store behavior clusters:\n")

        for cluster_id, stores in sorted(clusters.items()):
            profile = profiles.get(cluster_id, {})
            desc = profile.get('description', 'Unknown pattern')
            total_failures = sum(s['failures'] for s in stores)

            print(f"CLUSTER {cluster_id}: {desc}")
            print(f"  Stores: {len(stores)}, Total Failures: {total_failures:,}")
            print(f"  Avg failures/store: {profile.get('total_failures', 0):.1f}")
            print(f"  Night ratio: {profile.get('night_ratio', 0):.1%}")
            print(f"  Weekend ratio: {profile.get('weekend_ratio', 0):.1%}")

            # Show top stores in cluster
            top_stores = sorted(stores, key=lambda x: x['failures'], reverse=True)[:5]
            print(f"  Top stores: {', '.join(s['store_id'] for s in top_stores)}")
            print()

        return {'clusters': dict(clusters), 'profiles': profiles}

    def run_time_series_analysis(self) -> Dict:
        """Analyze time series patterns and forecast."""
        print("\n" + "=" * 70)
        print("TIME SERIES ANALYSIS")
        print("=" * 70)

        if len(self.hourly_failures) < 24:
            print("Insufficient data for time series analysis")
            return {}

        # Decompose
        decomposed = self.time_series.decompose(self.hourly_failures)

        # Detect trend
        trend = self.time_series.detect_trend(self.hourly_failures)
        print(f"\nOverall Trend: {trend}")

        # Detect periodicity
        periodicity = self.pattern_recognizer.detect_periodic_failures(self.hourly_failures)
        if periodicity['periodic']:
            print(f"Periodic Pattern: Yes, {periodicity['period']}-hour cycle "
                  f"(strength: {periodicity.get('strength', 0):.2f})")
        else:
            print("Periodic Pattern: No clear periodicity detected")

        # Hourly pattern
        if self.time_series.hourly_pattern is not None:
            print("\nHourly Pattern (deviation from trend):")
            print(f"{'Hour':<8}{'Deviation':<12}{'Bar'}")
            print("-" * 50)

            pattern = self.time_series.hourly_pattern
            max_abs = max(abs(pattern.min()), abs(pattern.max())) or 1

            for hour, dev in enumerate(pattern):
                bar_len = int(20 * abs(dev) / max_abs)
                bar_char = '█' if dev >= 0 else '░'
                direction = '+' if dev >= 0 else ''
                print(f"{hour:02d}:00   {direction}{dev:<11.1f}{bar_char * bar_len}")

        # Forecast
        forecast = self.time_series.forecast_next_hours(self.hourly_failures, hours_ahead=24)
        print(f"\n24-Hour Forecast:")
        print(f"  Expected failures: {int(forecast.sum()):,}")
        print(f"  Peak hour: {np.argmax(forecast):02d}:00 ({int(forecast.max())} failures)")
        print(f"  Low hour: {np.argmin(forecast):02d}:00 ({int(forecast.min())} failures)")

        return {
            'trend': trend,
            'periodicity': periodicity,
            'forecast': forecast.tolist()
        }

    def run_pattern_recognition(self) -> Dict:
        """Detect patterns and correlations."""
        print("\n" + "=" * 70)
        print("PATTERN RECOGNITION")
        print("=" * 70)

        results = {'bursts': [], 'correlations': [], 'cascades': []}

        # Find failure bursts for each store
        print("\nFailure Bursts (>5 failures in 10 minutes):")
        print(f"{'Store':<12}{'Start Time':<22}{'Count':<10}{'Duration'}")
        print("-" * 60)

        all_bursts = []
        for store_id, data in self.store_data.items():
            bursts = self.pattern_recognizer.find_failure_bursts(
                data['timestamps'], window_minutes=10, min_count=5
            )
            for burst in bursts:
                burst['store_id'] = store_id
                all_bursts.append(burst)

            # Update burst count in store data
            self.store_data[store_id]['failure_burst_count'] = len(bursts)

        # Sort by count and show top bursts
        all_bursts.sort(key=lambda x: x['count'], reverse=True)
        for burst in all_bursts[:15]:
            print(f"{burst['store_id']:<12}{str(burst['start']):<22}"
                  f"{burst['count']:<10}{burst['duration_minutes']:.1f} min")

        results['bursts'] = all_bursts[:50]

        # Find correlated stores (stores that fail together)
        print("\nCorrelated Stores (fail within 5 minutes of each other):")

        # Sample stores for correlation analysis (top 100 by failures)
        top_stores = sorted(self.store_data.items(),
                           key=lambda x: x[1]['total_failures'], reverse=True)[:100]
        store_timestamps = {s[0]: s[1]['timestamps'] for s in top_stores}

        if len(store_timestamps) >= 2:
            correlations = self.pattern_recognizer.find_correlated_stores(
                store_timestamps, time_window_minutes=5
            )

            print(f"{'Store 1':<12}{'Store 2':<12}{'Correlation':<12}{'Same Machine?'}")
            print("-" * 50)

            for store1, store2, corr in correlations[:15]:
                machine1 = self.store_data[store1]['machine']
                machine2 = self.store_data[store2]['machine']
                same_machine = "Yes" if machine1 == machine2 else "No"
                print(f"{store1:<12}{store2:<12}{corr:<12.2%}{same_machine}")

            results['correlations'] = correlations[:50]

        return results

    def run_root_cause_analysis(self) -> Dict:
        """Attempt to identify root causes of failures."""
        print("\n" + "=" * 70)
        print("ROOT CAUSE ANALYSIS")
        print("=" * 70)

        results = {'machine_issues': [], 'time_based': [], 'recommendations': []}

        # Machine analysis
        print("\nMachine Health Score:")
        print(f"{'Machine':<12}{'Failures':<12}{'Stores':<10}{'Failures/Store':<15}{'Score'}")
        print("-" * 60)

        machine_scores = []
        for machine, data in sorted(self.machine_data.items(),
                                   key=lambda x: x[1]['total_failures'], reverse=True):
            failures_per_store = data['total_failures'] / max(data['unique_stores'], 1)

            # Health score: lower is worse
            # Based on failures per store (normalized) and total failure count
            score = 100 - min(100, failures_per_store * 2 + data['total_failures'] / 100)
            score = max(0, score)

            machine_scores.append({
                'machine': machine,
                'failures': data['total_failures'],
                'stores': data['unique_stores'],
                'failures_per_store': failures_per_store,
                'score': score
            })

            score_bar = '█' * int(score / 10) + '░' * (10 - int(score / 10))
            print(f"{machine:<12}{data['total_failures']:<12,}{data['unique_stores']:<10}"
                  f"{failures_per_store:<15.1f}{score_bar} {score:.0f}")

        results['machine_issues'] = machine_scores

        # Generate recommendations
        print("\nRecommendations:")
        recommendations = []

        # Check for problem machines
        worst_machine = min(machine_scores, key=lambda x: x['score'])
        if worst_machine['score'] < 50:
            rec = f"Investigate {worst_machine['machine']} - lowest health score ({worst_machine['score']:.0f})"
            recommendations.append(rec)
            print(f"  1. {rec}")

        # Check for problem stores
        problem_stores = [s for s, d in self.store_data.items() if d['total_failures'] > 500]
        if problem_stores:
            rec = f"Priority attention needed for {len(problem_stores)} stores with >500 failures"
            recommendations.append(rec)
            print(f"  2. {rec}")

        # Check for time-based patterns
        if hasattr(self.time_series, 'hourly_pattern') and self.time_series.hourly_pattern is not None:
            peak_hour = np.argmax(self.time_series.hourly_pattern)
            rec = f"Peak failure hour is {peak_hour:02d}:00 - consider maintenance window adjustment"
            recommendations.append(rec)
            print(f"  3. {rec}")

        results['recommendations'] = recommendations

        return results

    def generate_report(self):
        """Run all analyses and generate comprehensive report."""
        print("\n" + "=" * 70)
        print("AI-POWERED LOG ANALYSIS REPORT")
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)

        print(f"\nDataset Summary:")
        print(f"  Total stores analyzed: {len(self.store_data):,}")
        print(f"  Total machines: {len(self.machine_data)}")
        print(f"  Time periods: {len(self.hourly_failures)} hours")
        print(f"  Total failures: {sum(d['total_failures'] for d in self.store_data.values()):,}")

        # Run all analyses
        anomalies = self.run_anomaly_detection()
        clusters = self.run_clustering()
        time_series = self.run_time_series_analysis()
        patterns = self.run_pattern_recognition()
        root_cause = self.run_root_cause_analysis()

        print("\n" + "=" * 70)
        print("END OF AI ANALYSIS REPORT")
        print("=" * 70)

        return {
            'anomalies': anomalies,
            'clusters': clusters,
            'time_series': time_series,
            'patterns': patterns,
            'root_cause': root_cause
        }


def main():
    """Main entry point."""
    print("AI-Powered Federation Log Analyzer")
    print("=" * 50)

    if len(sys.argv) < 2:
        # Default to latest health history file
        downloads = os.path.expanduser("~/Downloads")
        health_files = [f for f in os.listdir(downloads)
                       if f.startswith("Health history") and f.endswith(".xlsx")]
        if health_files:
            health_files.sort(key=lambda f: os.path.getmtime(os.path.join(downloads, f)), reverse=True)
            filepath = os.path.join(downloads, health_files[0])
            print(f"Using latest health file: {health_files[0]}")
        else:
            print("Usage: python analyze_logs_ai.py <health_history.xlsx>")
            print("Or place a 'Health history*.xlsx' file in ~/Downloads")
            sys.exit(1)
    else:
        filepath = sys.argv[1]

    analyzer = AILogAnalyzer()
    if analyzer.load_excel(filepath):
        results = analyzer.generate_report()


if __name__ == "__main__":
    main()
