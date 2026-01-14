"""
Main FederationLogAnalyzer class for parsing and analyzing federation logs.
"""

import os
import re
import zipfile
import io
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Tuple, Optional
import warnings
import numpy as np

warnings.filterwarnings('ignore')

try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.cluster import KMeans, DBSCAN
    from sklearn.neighbors import LocalOutlierFactor
    from sklearn.preprocessing import StandardScaler
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

try:
    from scipy import stats
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False

# Import from local modules
from .patterns import (
    TIMESTAMP_PATTERN, STORE_PATTERN, IP_PORT_PATTERN, FED_GROUP_PATTERN,
    ERROR_PATTERNS, INTERNAL_ERROR_SUBTYPES, SEVERITY_PATTERNS
)
from .events import FederationEvent, OnlineStats
from .ml.anomaly import AdvancedAnomalyDetector
from .ml.forecasting import PredictiveAnalytics
from .ml.causality import CausalAnalyzer
from .ml.cascades import CascadeDetector
from .ml.recommendations import Recommendation, RecommendationEngine

# Import AI optimizer module if available
try:
    from ai_optimizer import (
        EnhancedAnomalyDetector, NeuralPatternRecognizer,
        SequenceAnalyzer, InternalErrorClassifier,
        ModelEvaluator, optimize_and_evaluate
    )
    HAS_AI_OPTIMIZER = True
except ImportError:
    HAS_AI_OPTIMIZER = False


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
