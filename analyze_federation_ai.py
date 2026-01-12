#!/usr/bin/env python3
"""
AI-Powered Federation Log Analyzer for Genetec Security Center
Specialized for analyzing federation reconnection issues from raw log files.

Supports:
- Nested ZIP files containing .log files
- SBUXSCRoleGroup and Federation role logs
- Connection timeout, TLS errors, socket exceptions detection
- Machine learning for pattern detection and root cause analysis
"""

import os
import re
import sys
import zipfile
import tempfile
import io
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Tuple, Optional
import warnings
import numpy as np

warnings.filterwarnings('ignore')

try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.cluster import KMeans, DBSCAN
    from sklearn.preprocessing import StandardScaler
    from sklearn.feature_extraction.text import TfidfVectorizer
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
    print("Note: Install scikit-learn for advanced ML features: pip install scikit-learn")

try:
    from scipy import stats
    from scipy.signal import find_peaks
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False

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
    ]
}

# Severity indicators
SEVERITY_PATTERNS = {
    'fatal': re.compile(r'\(Fatal\)', re.I),
    'error': re.compile(r'\(Error\)', re.I),
    'warning': re.compile(r'\(Warning\)', re.I),
    'exception': re.compile(r'Exception', re.I)
}


class FederationEvent:
    """Represents a single federation event."""
    __slots__ = ('timestamp', 'store_id', 'fed_group', 'machine', 'event_type',
                 'error_category', 'severity', 'ip', 'port', 'message')

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
            'timestamps': [],
            'ips': set(),
            'fed_groups': set(),
            'machines': set(),
            'hourly_counts': defaultdict(int),
            'reconnect_delays': []
        })
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

        self.events.append(event)

        # Update statistics
        if error_category:
            self.error_category_totals[error_category] += 1

            hour_key = timestamp.replace(minute=0, second=0, microsecond=0)
            self.hourly_errors[hour_key][error_category] += 1

        if store_id:
            stats = self.store_stats[store_id]
            stats['total_errors'] += 1
            stats['timestamps'].append(timestamp)
            if error_category:
                stats['error_categories'][error_category] += 1
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

    def analyze_anomalies(self) -> Dict:
        """Use ML to detect anomalous stores."""
        if not HAS_SKLEARN or len(self.store_stats) < 10:
            return {'anomalous_stores': []}

        print("\n" + "=" * 70)
        print("ANOMALY DETECTION (Isolation Forest)")
        print("=" * 70)

        # Build feature matrix
        store_ids = []
        features = []

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
            else:
                avg_delta = 0
                min_delta = 0

            feature_vector = [
                stats['total_errors'],
                variance,
                max_hourly,
                category_count,
                len(stats['ips']),
                avg_delta / 3600 if avg_delta > 0 else 0,  # Hours between errors
                min_delta,  # Burst indicator
            ]

            store_ids.append(store_id)
            features.append(feature_vector)

        if len(features) < 10:
            print("Insufficient data for anomaly detection")
            return {'anomalous_stores': []}

        features = np.array(features)
        scaler = StandardScaler()
        scaled = scaler.fit_transform(features)

        iso_forest = IsolationForest(contamination=0.1, random_state=42)
        labels = iso_forest.fit_predict(scaled)

        anomalous = []
        for store_id, label, feat in zip(store_ids, labels, features):
            if label == -1:
                anomalous.append({
                    'store_id': store_id,
                    'total_errors': int(feat[0]),
                    'max_hourly': int(feat[2]),
                    'categories': len(self.store_stats[store_id]['error_categories']),
                    'ips': list(self.store_stats[store_id]['ips'])[:3]
                })

        anomalous.sort(key=lambda x: x['total_errors'], reverse=True)

        print(f"\nFound {len(anomalous)} anomalous stores:")
        print(f"{'Store':<10}{'Errors':<10}{'Max/Hour':<10}{'Categories':<12}{'IPs'}")
        print("-" * 60)
        for s in anomalous[:20]:
            ips_str = ', '.join(s['ips']) if s['ips'] else 'N/A'
            print(f"{s['store_id']:<10}{s['total_errors']:<10}{s['max_hourly']:<10}"
                  f"{s['categories']:<12}{ips_str}")

        return {'anomalous_stores': anomalous}

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
        """Analyze temporal patterns."""
        print("\n" + "=" * 70)
        print("TIME SERIES ANALYSIS")
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

        # Trend analysis
        first_half = np.mean(hourly_array[:len(hourly_array)//2])
        second_half = np.mean(hourly_array[len(hourly_array)//2:])
        change_pct = (second_half - first_half) / first_half * 100 if first_half > 0 else 0

        if change_pct > 20:
            trend = f"INCREASING (+{change_pct:.1f}%)"
        elif change_pct < -20:
            trend = f"DECREASING ({change_pct:.1f}%)"
        else:
            trend = "STABLE"

        print(f"\nTrend: {trend}")
        print(f"Average errors/hour: {np.mean(hourly_array):.1f}")
        print(f"Max errors/hour: {np.max(hourly_array):,}")
        print(f"Std deviation: {np.std(hourly_array):.1f}")

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
            'avg_hourly': np.mean(hourly_array),
            'max_hourly': np.max(hourly_array)
        }

    def analyze_root_causes(self) -> Dict:
        """Perform root cause analysis."""
        print("\n" + "=" * 70)
        print("ROOT CAUSE ANALYSIS")
        print("=" * 70)

        recommendations = []

        # Machine analysis
        print(f"\nMachine Health:")
        print(f"{'Machine':<15}{'Errors':<12}{'Stores':<10}{'Errors/Store':<15}{'Status'}")
        print("-" * 62)

        for machine, stats in sorted(self.machine_stats.items(),
                                    key=lambda x: x[1]['total_errors'], reverse=True):
            errors = stats['total_errors']
            stores = len(stats['stores'])
            ratio = errors / stores if stores > 0 else 0

            if ratio > 50:
                status = "⚠ HIGH"
            elif ratio > 20:
                status = "⚡ ELEVATED"
            else:
                status = "✓ NORMAL"

            print(f"{machine:<15}{errors:<12,}{stores:<10}{ratio:<15.1f}{status}")

            if ratio > 50:
                recommendations.append(f"Investigate {machine} - high error rate per store")

        # IP analysis - find problematic endpoints
        print(f"\nTop Problem IPs:")
        print(f"{'IP Address':<20}{'Errors':<12}{'Stores':<10}")
        print("-" * 42)

        top_ips = sorted(self.ip_stats.items(),
                        key=lambda x: x[1]['errors'], reverse=True)[:15]
        for ip, stats in top_ips:
            print(f"{ip:<20}{stats['errors']:<12,}{len(stats['stores']):<10}")

        # Store analysis
        problem_stores = [(s, d['total_errors']) for s, d in self.store_stats.items()
                         if d['total_errors'] > 100]
        if problem_stores:
            recommendations.append(
                f"{len(problem_stores)} stores have >100 errors - prioritize investigation"
            )

        # Error category recommendations
        for cat, count in sorted(self.error_category_totals.items(),
                                key=lambda x: x[1], reverse=True)[:3]:
            if cat == 'connection_timeout':
                recommendations.append(
                    f"High timeout errors ({count:,}) - check network latency and store connectivity"
                )
            elif cat == 'tls_handshake_error':
                recommendations.append(
                    f"TLS errors ({count:,}) - verify certificates and TLS versions"
                )
            elif cat == 'host_unreachable':
                recommendations.append(
                    f"Host unreachable ({count:,}) - check store network/VPN connectivity"
                )

        print(f"\nRecommendations:")
        for i, rec in enumerate(recommendations[:10], 1):
            print(f"  {i}. {rec}")

        return {'recommendations': recommendations}

    def generate_report(self):
        """Generate comprehensive analysis report."""
        print("\n" + "=" * 70)
        print("FEDERATION LOG AI ANALYSIS REPORT")
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

        # Run all analyses
        self.analyze_error_patterns()
        anomalies = self.analyze_anomalies()
        clusters = self.analyze_store_clusters()
        time_series = self.analyze_time_series()
        root_cause = self.analyze_root_causes()

        print("\n" + "=" * 70)
        print("END OF AI ANALYSIS REPORT")
        print("=" * 70)

        return {
            'anomalies': anomalies,
            'clusters': clusters,
            'time_series': time_series,
            'root_cause': root_cause
        }


def main():
    """Main entry point."""
    print("Federation Log AI Analyzer")
    print("=" * 50)

    # Find ZIP files in Downloads
    downloads = os.path.expanduser("~/Downloads")
    zip_files = []

    for f in os.listdir(downloads):
        if f.endswith('.zip') and ('Fed' in f or 'Base' in f):
            zip_files.append(os.path.join(downloads, f))

    if not zip_files:
        print("No federation log ZIP files found in ~/Downloads")
        print("Looking for files matching: *Fed*.zip or *Base*.zip")
        sys.exit(1)

    # Sort by modification time (newest first)
    zip_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)

    print(f"\nFound {len(zip_files)} federation log files:")
    for f in zip_files:
        size_mb = os.path.getsize(f) / (1024 * 1024)
        print(f"  {os.path.basename(f)} ({size_mb:.1f} MB)")

    analyzer = FederationLogAnalyzer()

    for zip_file in zip_files:
        analyzer.process_nested_zip(zip_file)

    if analyzer.events:
        analyzer.generate_report()
    else:
        print("\nNo federation events found in the log files.")


if __name__ == "__main__":
    main()
