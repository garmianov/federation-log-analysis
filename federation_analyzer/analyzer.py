"""
Main FederationLogAnalyzer class for parsing and analyzing federation logs.
"""

import io
import os
import re
import warnings
import zipfile
from collections import defaultdict
from datetime import datetime
from typing import Dict, Optional, Tuple

import numpy as np

warnings.filterwarnings("ignore")

try:
    from sklearn.cluster import DBSCAN, KMeans
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
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
from .events import FederationEvent
from .logging_config import get_logger
from .patterns import (
    ERROR_PATTERNS,
    FED_GROUP_PATTERN,
    INTERNAL_ERROR_SUBTYPES,
    IP_PORT_PATTERN,
    SEVERITY_PATTERNS,
    STORE_PATTERN,
)

# Module logger
logger = get_logger(__name__)
from .ml.anomaly import AdvancedAnomalyDetector
from .ml.cascades import CascadeDetector
from .ml.causality import CausalAnalyzer
from .ml.forecasting import PredictiveAnalytics
from .ml.recommendations import RecommendationEngine

# Import AI optimizer module if available
try:
    from ai_optimizer import (
        EnhancedAnomalyDetector,
        InternalErrorClassifier,
        ModelEvaluator,
        NeuralPatternRecognizer,
        SequenceAnalyzer,
        optimize_and_evaluate,
    )

    HAS_AI_OPTIMIZER = True
except ImportError:
    HAS_AI_OPTIMIZER = False


class FederationLogAnalyzer:
    """Specialized analyzer for Genetec federation logs."""

    def __init__(self):
        # Data structures
        self.events = []
        self.store_stats = defaultdict(
            lambda: {
                "total_errors": 0,
                "error_categories": defaultdict(int),
                "internal_error_subtypes": defaultdict(int),
                "timestamps": [],
                "ips": set(),
                "fed_groups": set(),
                "machines": set(),
                "hourly_counts": defaultdict(int),
                "reconnect_delays": [],
            }
        )
        self.internal_error_totals = defaultdict(int)
        self.machine_stats = defaultdict(
            lambda: {"total_errors": 0, "stores": set(), "error_categories": defaultdict(int)}
        )
        self.hourly_errors = defaultdict(lambda: defaultdict(int))
        self.error_category_totals = defaultdict(int)
        self.ip_stats = defaultdict(lambda: {"stores": set(), "errors": 0})

        self.seen_hashes = set()
        self.files_processed = 0
        self.lines_processed = 0
        self.current_machine = None
        self.min_ts = None
        self.max_ts = None

    def parse_timestamp(self, line: str) -> Optional[datetime]:
        """Fast timestamp extraction."""
        if len(line) < 20 or line[4] != "-":
            return None
        try:
            return datetime.strptime(line[:19], "%Y-%m-%dT%H:%M:%S")
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
        if line.startswith("*"):
            match = FED_GROUP_PATTERN.search(line)
            if match:
                return match.group(1)
            if "MachineName=" in line:
                m = re.search(r"MachineName=(\S+)", line)
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
        if error_category and error_category.startswith("internal_error"):
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
            stats["total_errors"] += 1
            stats["timestamps"].append(timestamp)
            if error_category:
                stats["error_categories"][error_category] += 1
            if internal_subtype:
                stats["internal_error_subtypes"][internal_subtype] += 1
            if ip:
                stats["ips"].add(ip)
            if fed_group:
                stats["fed_groups"].add(fed_group)
            if self.current_machine:
                stats["machines"].add(self.current_machine)
            stats["hourly_counts"][hour_key] += 1

            # Extract reconnect delay if present
            delay_match = re.search(r"startDelay\s*=\s*(\d+)", line)
            if delay_match:
                stats["reconnect_delays"].append(int(delay_match.group(1)))

        if self.current_machine:
            mstats = self.machine_stats[self.current_machine]
            mstats["total_errors"] += 1
            if store_id:
                mstats["stores"].add(store_id)
            if error_category:
                mstats["error_categories"][error_category] += 1

        if ip:
            self.ip_stats[ip]["errors"] += 1
            if store_id:
                self.ip_stats[ip]["stores"].add(store_id)

        return fed_group

    def process_log_content(self, content: str, fed_group: str = None) -> str:
        """Process log file content."""
        for line in content.split("\n"):
            fed_group = self.process_line(line, fed_group)
        return fed_group

    def process_nested_zip(self, zip_path: str):
        """Process a ZIP file that may contain nested ZIPs with logs."""
        logger.info("\nProcessing: %s", os.path.basename(zip_path))

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                # Find relevant log files
                log_files = [
                    n
                    for n in zf.namelist()
                    if ("SBUXSCRoleGroup" in n or "Federation" in n)
                    and (n.endswith(".log") or n.endswith(".zip"))
                ]

                logger.info("  Found %d relevant files", len(log_files))

                for name in sorted(log_files):
                    try:
                        if name.endswith(".zip"):
                            # Nested ZIP - extract and process
                            with zf.open(name) as nested_file:
                                nested_data = nested_file.read()
                                with zipfile.ZipFile(io.BytesIO(nested_data), "r") as nested_zf:
                                    for inner_name in nested_zf.namelist():
                                        if inner_name.endswith(".log"):
                                            content = nested_zf.read(inner_name).decode(
                                                "utf-8-sig", errors="replace"
                                            )
                                            self.process_log_content(content)
                                            self.files_processed += 1
                        else:
                            # Direct log file
                            content = zf.read(name).decode("utf-8-sig", errors="replace")
                            self.process_log_content(content)
                            self.files_processed += 1

                    except Exception as e:
                        logger.error("    Error processing %s: %s", name, e)

        except Exception as e:
            logger.error("  Error opening zip: %s", e)

        logger.info(
            "  Processed %d files, %s lines", self.files_processed, f"{self.lines_processed:,}"
        )

    def process_log_file(self, log_path: str):
        """Process a single .log file directly (unzipped)."""
        logger.info("\nProcessing: %s", os.path.basename(log_path))

        try:
            with open(log_path, encoding="utf-8-sig", errors="replace") as f:
                content = f.read()
                self.process_log_content(content)
                self.files_processed += 1
            logger.info("  Processed %s lines", f"{self.lines_processed:,}")
        except Exception as e:
            logger.error("  Error processing file: %s", e)

    def process_log_directory(self, dir_path: str):
        """Process all .log files in a directory."""
        logger.info("\nProcessing directory: %s", dir_path)

        log_files = []
        for root, _dirs, files in os.walk(dir_path):
            for f in files:
                if f.endswith(".log") and ("SBUXSCRoleGroup" in f or "Federation" in f):
                    log_files.append(os.path.join(root, f))

        if not log_files:
            # If no specific federation logs found, try all .log files
            for root, _dirs, files in os.walk(dir_path):
                for f in files:
                    if f.endswith(".log"):
                        log_files.append(os.path.join(root, f))

        logger.info("  Found %d log files", len(log_files))

        for log_file in sorted(log_files):
            try:
                with open(log_file, encoding="utf-8-sig", errors="replace") as f:
                    content = f.read()
                    self.process_log_content(content)
                    self.files_processed += 1
            except Exception as e:
                logger.error("    Error processing %s: %s", os.path.basename(log_file), e)

        logger.info(
            "  Processed %d files, %s lines", self.files_processed, f"{self.lines_processed:,}"
        )

    def analyze_anomalies(self) -> Dict:
        """Use ensemble ML methods to detect anomalous stores."""
        if not HAS_SKLEARN or len(self.store_stats) < 10:
            return {"anomalous_stores": [], "method_agreement": {}}

        logger.info("\n" + "=" * 70)
        logger.info("ADVANCED ANOMALY DETECTION (Ensemble Methods)")
        logger.info("=" * 70)

        # Build feature matrix
        store_ids = []
        features = []
        feature_names = [
            "total_errors",
            "variance",
            "max_hourly",
            "category_count",
            "ip_count",
            "avg_interval_hours",
            "min_interval",
            "burst_score",
        ]

        for store_id, store_data in self.store_stats.items():
            if store_data["total_errors"] < 3:
                continue

            # Calculate features
            hourly_values = list(store_data["hourly_counts"].values())
            variance = np.var(hourly_values) if len(hourly_values) > 1 else 0
            max_hourly = max(hourly_values) if hourly_values else 0

            # Error category diversity
            category_count = len(store_data["error_categories"])

            # Time pattern features
            timestamps = store_data["timestamps"]
            if len(timestamps) > 1:
                deltas = [
                    (timestamps[i + 1] - timestamps[i]).total_seconds()
                    for i in range(len(timestamps) - 1)
                ]
                avg_delta = np.mean(deltas)
                min_delta = min(deltas)
                # Burst score: how many consecutive short intervals
                burst_score = sum(1 for d in deltas if d < 60) / len(deltas)
            else:
                avg_delta = 0
                min_delta = 0
                burst_score = 0

            feature_vector = [
                stats["total_errors"],
                variance,
                max_hourly,
                category_count,
                len(stats["ips"]),
                avg_delta / 3600 if avg_delta > 0 else 0,
                min_delta,
                burst_score,
            ]

            store_ids.append(store_id)
            features.append(feature_vector)

        if len(features) < 10:
            logger.info("Insufficient data for anomaly detection")
            return {"anomalous_stores": [], "method_agreement": {}}

        features = np.array(features)

        # Use advanced ensemble anomaly detection
        detector = AdvancedAnomalyDetector(contamination=0.1)
        labels, method_scores = detector.detect_ensemble(features)

        # Calculate method agreement statistics
        method_agreement = {
            "isolation_forest": int(np.sum(method_scores.get("isolation_forest", []))),
            "lof": int(np.sum(method_scores.get("lof", []))),
            "dbscan": int(np.sum(method_scores.get("dbscan", []))),
            "statistical": int(np.sum(method_scores.get("statistical", []))),
            "ensemble_total": int(np.sum(method_scores.get("ensemble", []))),
        }

        logger.info("\nMethod Agreement (anomalies detected):")
        logger.info("  Isolation Forest: %d", method_agreement["isolation_forest"])
        logger.info("  Local Outlier Factor: %d", method_agreement["lof"])
        logger.info("  DBSCAN: %d", method_agreement["dbscan"])
        logger.info("  Statistical (Z-score): %d", method_agreement["statistical"])
        logger.info("  Ensemble (>=2 agree): %d", method_agreement["ensemble_total"])

        anomalous = []
        votes = method_scores.get("votes", np.zeros(len(features)))

        for i, (store_id, label, feat) in enumerate(zip(store_ids, labels, features)):
            if label == -1:
                anomalous.append(
                    {
                        "store_id": store_id,
                        "total_errors": int(feat[0]),
                        "max_hourly": int(feat[2]),
                        "categories": len(self.store_stats[store_id]["error_categories"]),
                        "ips": list(self.store_stats[store_id]["ips"])[:3],
                        "confidence": int(votes[i]) / 4,  # 4 methods total
                        "dominant_error": max(
                            self.store_stats[store_id]["error_categories"].items(),
                            key=lambda x: x[1],
                        )[0]
                        if self.store_stats[store_id]["error_categories"]
                        else "unknown",
                    }
                )

        anomalous.sort(key=lambda x: (x["confidence"], x["total_errors"]), reverse=True)

        logger.info("\nFound %d anomalous stores (ensemble):", len(anomalous))
        logger.info(
            "%-10s%-10s%-8s%-8s%-25s%s",
            "Store",
            "Errors",
            "Max/Hr",
            "Conf",
            "Dominant Error",
            "IPs",
        )
        logger.info("-" * 80)
        for s in anomalous[:20]:
            ips_str = ", ".join(s["ips"]) if s["ips"] else "N/A"
            logger.info(
                "%-10s%-10d%-8d%.0f%%    %-25s%s",
                s["store_id"],
                s["total_errors"],
                s["max_hourly"],
                s["confidence"] * 100,
                s["dominant_error"],
                ips_str[:20],
            )

        # Feature importance analysis
        logger.info("\n--- Feature Importance (what drives anomalies) ---")
        causal = CausalAnalyzer()
        anomaly_labels = (labels == -1).astype(int)
        importance = causal.calculate_feature_importance(features, anomaly_labels, feature_names)
        for name, imp in list(importance.items())[:5]:
            bar = "█" * int(imp * 40)
            logger.info("  %-20s: %s %.2f%%", name, bar, imp * 100)

        return {
            "anomalous_stores": anomalous,
            "method_agreement": method_agreement,
            "feature_importance": importance,
        }

    def analyze_error_patterns(self) -> Dict:
        """Analyze error patterns using TF-IDF and clustering."""
        if not HAS_SKLEARN or len(self.events) < 100:
            return {}

        logger.info("\n" + "=" * 70)
        logger.info("ERROR PATTERN ANALYSIS")
        logger.info("=" * 70)

        # Group errors by category
        logger.info("\nError Category Distribution:")
        logger.info("%-25s%-12s%-10s%s", "Category", "Count", "%", "Bar")
        logger.info("-" * 60)

        total = sum(self.error_category_totals.values())
        for cat, count in sorted(
            self.error_category_totals.items(), key=lambda x: x[1], reverse=True
        ):
            pct = 100 * count / total if total > 0 else 0
            bar = "█" * int(pct / 2.5)
            logger.info("%-25s%-12d%.1f%%     %s", cat, count, pct, bar)

        # Analyze hourly patterns per error type
        logger.info("\nHourly Pattern by Error Type:")

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
                logger.info("  %s: Peak at %02d:00, Total: %s", cat, peak_hour, f"{total_cat:,}")

        return {"category_totals": dict(self.error_category_totals)}

    def analyze_internal_errors(self) -> Dict:
        """Analyze Internal Errors in detail - application-layer failures."""
        logger.info("\n" + "=" * 70)
        logger.info("INTERNAL ERROR ANALYSIS (Application-Layer Failures)")
        logger.info("=" * 70)

        if not self.internal_error_totals:
            logger.info("\nNo Internal Errors detected in the logs.")
            return {}

        # Calculate total internal errors
        total_internal = sum(self.internal_error_totals.values())
        total_all = sum(self.error_category_totals.values())
        internal_pct = 100 * total_internal / total_all if total_all > 0 else 0

        logger.info("\nInternal Error Summary:")
        logger.info(
            "  Total Internal Errors: %s (%.1f%% of all errors)",
            f"{total_internal:,}",
            internal_pct,
        )

        # Sub-type breakdown
        logger.info("\n%-30s%-12s%-10s%s", "Sub-Type", "Count", "%", "Bar")
        logger.info("-" * 65)

        subtype_descriptions = {
            "empty_redirection": "vNVR not responding (RedirectionResponseMessage)",
            "empty_logon": "vNVR not responding (LogOnResultMessage)",
            "prefetch_base": "Base entity prefetch failed",
            "prefetch_directory_role": "DirectoryRole prefetch failed",
            "prefetch_directory_servers": "DirectoryServers prefetch failed",
            "directory_disconnected": "vNVR not connected to Directory",
            "tls_auth_failed": "TLS authentication failed",
            "handshake_error": "TLS handshake error",
            "read_timeout": "Read timeout on connection",
            "transport_read_error": "Transport connection read error",
            "sync_aborted": "Synchronization aborted",
            "entity_sync_failed": "Entity synchronization failed",
            "custom_fields_failed": "Custom fields mapping failed",
            "logon_failed_event": "Logon failed event triggered",
            "security_token_error": "Security token manager error",
        }

        for subtype, count in sorted(
            self.internal_error_totals.items(), key=lambda x: x[1], reverse=True
        ):
            pct = 100 * count / total_internal if total_internal > 0 else 0
            bar = "█" * int(pct / 2.5)
            desc = subtype_descriptions.get(subtype, subtype)
            logger.info("%-30s%-12d%.1f%%     %s", desc[:30], count, pct, bar)

        # Group subtypes into categories for diagnosis
        logger.info("\n--- INTERNAL ERROR DIAGNOSIS GROUPS ---")

        unresponsive_count = sum(
            self.internal_error_totals.get(s, 0) for s in ["empty_redirection", "empty_logon"]
        )
        prefetch_count = sum(
            self.internal_error_totals.get(s, 0)
            for s in ["prefetch_base", "prefetch_directory_role", "prefetch_directory_servers"]
        )
        tls_count = sum(
            self.internal_error_totals.get(s, 0) for s in ["tls_auth_failed", "handshake_error"]
        )
        network_count = sum(
            self.internal_error_totals.get(s, 0) for s in ["read_timeout", "transport_read_error"]
        )
        sync_count = sum(
            self.internal_error_totals.get(s, 0)
            for s in ["sync_aborted", "entity_sync_failed", "custom_fields_failed"]
        )

        logger.info("\n%-35s%-10s%-10s%s", "Diagnosis Group", "Count", "%", "Action")
        logger.info("-" * 80)

        groups = [
            ("vNVR Unresponsive", unresponsive_count, "Restart vNVR service"),
            ("Data Prefetch Failures", prefetch_count, "Check vNVR database/resources"),
            ("TLS/Certificate Issues", tls_count, "Verify certificates"),
            ("Network Transport Issues", network_count, "Check network connectivity"),
            ("Sync/Data Issues", sync_count, "Review entity configuration"),
        ]

        for group, count, action in groups:
            if count > 0:
                pct = 100 * count / total_internal if total_internal > 0 else 0
                bar = "█" * int(pct / 5)
                logger.info("%-35s%-10d%.1f%%     %s  → %s", group, count, pct, bar, action)

        # Stores most affected by internal errors
        logger.info("\n--- TOP STORES WITH INTERNAL ERRORS ---")
        logger.info("%-10s%-12s%-35s%s", "Store", "Total IE", "Dominant Sub-Type", "IPs")
        logger.info("-" * 80)

        stores_with_internal = []
        for store_id, store_data in self.store_stats.items():
            ie_total = sum(store_data["internal_error_subtypes"].values())
            if ie_total > 0:
                dominant = (
                    max(store_data["internal_error_subtypes"].items(), key=lambda x: x[1])[0]
                    if store_data["internal_error_subtypes"]
                    else "unknown"
                )
                stores_with_internal.append(
                    {
                        "store_id": store_id,
                        "internal_errors": ie_total,
                        "dominant_subtype": dominant,
                        "ips": list(store_data["ips"])[:2],
                    }
                )

        stores_with_internal.sort(key=lambda x: x["internal_errors"], reverse=True)

        for store in stores_with_internal[:20]:
            desc = subtype_descriptions.get(store["dominant_subtype"], store["dominant_subtype"])[
                :35
            ]
            ips = ", ".join(store["ips"]) if store["ips"] else "N/A"
            logger.info(
                "%-10s%-12d%-35s%s", store["store_id"], store["internal_errors"], desc, ips[:20]
            )

        # Generate recommendations based on internal error patterns
        logger.info("\n--- INTERNAL ERROR RECOMMENDATIONS ---")

        if unresponsive_count > total_internal * 0.3:
            logger.info("\n⚠️  HIGH UNRESPONSIVE vNVR RATE (%s events)", f"{unresponsive_count:,}")
            logger.info("   → Schedule vNVR service restarts for affected stores")
            logger.info("   → Check vNVR CPU/Memory utilization")
            logger.info("   → Review vNVR logs on store systems")

        if prefetch_count > total_internal * 0.2:
            logger.info("\n⚠️  DATA PREFETCH FAILURES (%s events)", f"{prefetch_count:,}")
            logger.info("   → Check vNVR database health and disk space")
            logger.info("   → Review entity counts in affected stores")
            logger.info("   → Consider increasing prefetch timeout settings")

        if tls_count > total_internal * 0.1:
            logger.info("\n⚠️  TLS/CERTIFICATE ISSUES (%s events)", f"{tls_count:,}")
            logger.info("   → Audit certificate expiration dates")
            logger.info("   → Verify TLS version compatibility")
            logger.info("   → Check certificate chain validity")

        return {
            "total_internal_errors": total_internal,
            "percentage_of_all": internal_pct,
            "subtypes": dict(self.internal_error_totals),
            "stores_affected": stores_with_internal,
            "diagnosis_groups": {
                "unresponsive": unresponsive_count,
                "prefetch": prefetch_count,
                "tls": tls_count,
                "network": network_count,
                "sync": sync_count,
            },
        }

    def analyze_store_clusters(self) -> Dict:
        """Cluster stores by error behavior."""
        if not HAS_SKLEARN or len(self.store_stats) < 20:
            return {}

        logger.info("\n" + "=" * 70)
        logger.info("STORE CLUSTERING")
        logger.info("=" * 70)

        # Build feature matrix
        store_ids = []
        features = []

        for store_id, store_data in self.store_stats.items():
            if store_data["total_errors"] < 5:
                continue

            # Category ratios
            total = store_data["total_errors"]
            cat_vector = []
            for cat in [
                "tls_handshake_error",
                "connection_timeout",
                "connection_refused",
                "host_unreachable",
                "socket_exception",
                "proxy_disconnect",
            ]:
                cat_vector.append(store_data["error_categories"].get(cat, 0) / total)

            features.append(
                cat_vector
                + [
                    total,
                    len(store_data["ips"]),
                ]
            )
            store_ids.append(store_id)

        if len(features) < 20:
            logger.info("Insufficient data for clustering")
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
            clusters[label].append(
                {
                    "store_id": store_id,
                    "total_errors": int(feat[-2]),
                    "dominant_category": max(
                        self.store_stats[store_id]["error_categories"].items(), key=lambda x: x[1]
                    )[0]
                    if self.store_stats[store_id]["error_categories"]
                    else "unknown",
                }
            )

        logger.info("\nIdentified %d behavior clusters:\n", n_clusters)

        cluster_profiles = {}
        for cluster_id, stores in sorted(clusters.items()):
            # Find dominant error type
            all_cats = defaultdict(int)
            for s in stores:
                for cat, cnt in self.store_stats[s["store_id"]]["error_categories"].items():
                    all_cats[cat] += cnt

            dominant = max(all_cats.items(), key=lambda x: x[1])[0] if all_cats else "unknown"
            total_errors = sum(s["total_errors"] for s in stores)

            profile = {
                "dominant_error": dominant,
                "store_count": len(stores),
                "total_errors": total_errors,
            }
            cluster_profiles[cluster_id] = profile

            logger.info("CLUSTER %d: %s", cluster_id, dominant.replace("_", " ").title())
            logger.info("  Stores: %d, Total Errors: %s", len(stores), f"{total_errors:,}")
            top_stores = sorted(stores, key=lambda x: x["total_errors"], reverse=True)[:5]
            logger.info("  Top stores: %s", ", ".join(s["store_id"] for s in top_stores))
            logger.info("")

        return {"clusters": dict(clusters), "profiles": cluster_profiles}

    def analyze_time_series(self) -> Dict:
        """Analyze temporal patterns with advanced forecasting."""
        logger.info("\n" + "=" * 70)
        logger.info("TIME SERIES ANALYSIS & FORECASTING")
        logger.info("=" * 70)

        if not self.hourly_errors:
            logger.info("No hourly data available")
            return {}

        # Aggregate hourly errors
        hours = sorted(self.hourly_errors.keys())
        hourly_totals = [sum(self.hourly_errors[h].values()) for h in hours]

        if len(hourly_totals) < 24:
            logger.info("Insufficient time series data")
            return {}

        hourly_array = np.array(hourly_totals)

        # Use PredictiveAnalytics for advanced analysis
        predictor = PredictiveAnalytics()

        # Decompose time series (used internally by predictor for trend analysis)
        predictor.decompose_time_series(hourly_array, period=24)

        # Trend analysis
        first_half = np.mean(hourly_array[: len(hourly_array) // 2])
        second_half = np.mean(hourly_array[len(hourly_array) // 2 :])
        change_pct = (second_half - first_half) / first_half * 100 if first_half > 0 else 0

        if change_pct > 20:
            trend = f"INCREASING (+{change_pct:.1f}%)"
            trend_direction = "increasing"
        elif change_pct < -20:
            trend = f"DECREASING ({change_pct:.1f}%)"
            trend_direction = "decreasing"
        else:
            trend = "STABLE"
            trend_direction = "stable"

        logger.info("\nCurrent Trend: %s", trend)
        logger.info("Average errors/hour: %.1f", np.mean(hourly_array))
        logger.info("Max errors/hour: %s", f"{int(np.max(hourly_array)):,}")
        logger.info("Std deviation: %.1f", np.std(hourly_array))

        # Change point detection
        detector = AdvancedAnomalyDetector()
        change_points = detector.detect_change_points(hourly_array)
        if change_points:
            logger.info("\nChange Points Detected: %d", len(change_points))
            for cp in change_points[:5]:
                if cp < len(hours):
                    logger.info("  - %s: Error rate changed significantly", hours[cp])

        # Forecast next 24 hours
        forecast_result = predictor.forecast(hourly_array, horizon=24)
        logger.info("\n--- 24-HOUR FORECAST ---")
        logger.info("Predicted total errors: %s", f"{int(sum(forecast_result['forecast'])):,}")
        logger.info("Trend direction: %s", forecast_result["trend_direction"])
        logger.info(
            "Peak forecast hour: %d:00 (%d errors)",
            np.argmax(forecast_result["forecast"]),
            int(max(forecast_result["forecast"])),
        )
        logger.info(
            "Low forecast hour: %d:00 (%d errors)",
            np.argmin(forecast_result["forecast"]),
            int(min(forecast_result["forecast"])),
        )

        # Display forecast with confidence intervals
        logger.info("\n%-6s%-12s%-20s", "Hour", "Forecast", "95% CI")
        logger.info("-" * 40)
        for i in range(0, 24, 3):  # Show every 3 hours
            fc = forecast_result["forecast"][i]
            lb = forecast_result["lower_bound"][i]
            ub = forecast_result["upper_bound"][i]
            logger.info("%02d:00  %-12.0f[%.0f - %.0f]", i, fc, lb, ub)

        # Hour of day pattern
        hour_of_day_counts = defaultdict(int)
        for h in hours:
            hour_of_day_counts[h.hour] += sum(self.hourly_errors[h].values())

        logger.info("\nHour of Day Pattern:")
        logger.info("%-8s%-12s%s", "Hour", "Errors", "Bar")
        logger.info("-" * 50)

        max_hourly = max(hour_of_day_counts.values()) if hour_of_day_counts else 1
        for hour in range(24):
            count = hour_of_day_counts.get(hour, 0)
            bar = "█" * int(35 * count / max_hourly)
            logger.info("%02d:00   %-12s%s", hour, f"{count:,}", bar)

        # Find peak periods
        logger.info("\nTop 10 Peak Hours:")
        logger.info("%-25s%-12s%s", "Time", "Errors", "Dominant Error")
        logger.info("-" * 55)

        sorted_hours = sorted(
            self.hourly_errors.items(), key=lambda x: sum(x[1].values()), reverse=True
        )[:10]
        for hour, cats in sorted_hours:
            total = sum(cats.values())
            dominant = max(cats.items(), key=lambda x: x[1])[0]
            logger.info("%-25s%-12s%s", str(hour), f"{total:,}", dominant)

        return {
            "trend": trend,
            "trend_direction": trend_direction,
            "avg_hourly": float(np.mean(hourly_array)),
            "max_hourly": int(np.max(hourly_array)),
            "forecast": forecast_result,
            "change_points": change_points,
        }

    def analyze_cascades(self) -> Dict:
        """Detect and analyze cascading failures."""
        logger.info("\n" + "=" * 70)
        logger.info("CASCADE FAILURE DETECTION")
        logger.info("=" * 70)

        if len(self.events) < 100:
            logger.info("Insufficient events for cascade detection")
            return {}

        # Detect cascades
        cascade_detector = CascadeDetector(time_window_seconds=60)
        cascades = cascade_detector.detect_cascades(self.events, min_stores=5)

        if not cascades:
            logger.info("\nNo significant cascade events detected")
            return {"cascades": [], "propagation": {}}

        # Analyze propagation patterns
        propagation = cascade_detector.analyze_propagation(cascades)

        logger.info("\nCascade Statistics:")
        logger.info("  Total cascade events: %d", propagation["total_cascades"])
        logger.info("  Average stores affected: %.1f", propagation["avg_stores_affected"])
        logger.info("  Max stores in single cascade: %d", propagation["max_stores_in_cascade"])
        logger.info("  Server-wide cascades: %d", propagation["server_wide_cascades"])

        logger.info("\nCascade Error Types:")
        for error_type, count in sorted(
            propagation["common_error_types"].items(), key=lambda x: x[1], reverse=True
        ):
            logger.info("  %s: %d", error_type, count)

        logger.info("\nTop 10 Cascade Events:")
        logger.info(
            "%-22s%-10s%-10s%-25s%s", "Start Time", "Stores", "Events", "Error Type", "Server-wide"
        )
        logger.info("-" * 80)

        for cascade in sorted(cascades, key=lambda c: c["store_count"], reverse=True)[:10]:
            server_wide = "YES" if cascade["is_server_wide"] else "No"
            logger.info(
                "%-22s%-10d%-10d%-25s%s",
                str(cascade["start_time"]),
                cascade["store_count"],
                cascade["event_count"],
                cascade["dominant_error"],
                server_wide,
            )

        return {
            "cascades": cascades,
            "propagation": propagation,
            "server_wide_cascades": propagation["server_wide_cascades"],
        }

    def analyze_root_causes(self) -> Dict:
        """Perform advanced root cause analysis with Bayesian inference."""
        logger.info("\n" + "=" * 70)
        logger.info("ROOT CAUSE ANALYSIS (AI-Powered)")
        logger.info("=" * 70)

        # Initialize causal analyzer
        causal = CausalAnalyzer()

        # Machine health analysis
        logger.info("\nMachine Health Scores:")
        logger.info(
            "%-15s%-12s%-10s%-15s%-12s%s",
            "Machine",
            "Errors",
            "Stores",
            "Errors/Store",
            "Health",
            "Status",
        )
        logger.info("-" * 75)

        machine_health = {}
        for machine, machine_data in sorted(
            self.machine_stats.items(), key=lambda x: x[1]["total_errors"], reverse=True
        ):
            errors = machine_data["total_errors"]
            stores = len(machine_data["stores"])
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
                "score": health_score,
                "errors": errors,
                "stores": list(machine_data["stores"]),
                "ratio": ratio,
            }

            health_bar = "█" * int(health_score / 10) + "░" * (10 - int(health_score / 10))
            logger.info(
                "%-15s%-12s%-10d%-15.1f%s %.0f  %s",
                machine,
                f"{errors:,}",
                stores,
                ratio,
                health_bar,
                health_score,
                status,
            )

        # Bayesian root cause inference
        logger.info("\n--- PROBABILISTIC ROOT CAUSE ANALYSIS ---")
        root_causes = causal.infer_root_causes(
            self.store_stats, self.machine_stats, self.error_category_totals
        )

        logger.info("\nInferred Root Causes (Bayesian Analysis):")
        logger.info("%-25s%-15s%s", "Cause", "Probability", "Evidence")
        logger.info("-" * 70)
        for cause in root_causes:
            prob_bar = "█" * int(cause["probability"] * 20)
            logger.info(
                "%-25s%s %.0f%%    %s",
                cause["cause"],
                prob_bar,
                cause["probability"] * 100,
                cause["evidence"],
            )

        # IP analysis - find problematic endpoints
        logger.info("\nTop Problem IPs (potential bottlenecks):")
        logger.info("%-20s%-12s%-10s%s", "IP Address", "Errors", "Stores", "Errors/Store")
        logger.info("-" * 55)

        top_ips = sorted(self.ip_stats.items(), key=lambda x: x[1]["errors"], reverse=True)[:15]
        for ip, ip_data in top_ips:
            stores_count = len(ip_data["stores"])
            ratio = ip_data["errors"] / stores_count if stores_count > 0 else 0
            logger.info("%-20s%-12s%-10d%.1f", ip, f"{ip_data['errors']:,}", stores_count, ratio)

        # Store risk analysis
        logger.info("\n--- STORE RISK ANALYSIS ---")
        predictor = PredictiveAnalytics()

        high_risk_stores = []
        for store_id, store_data in self.store_stats.items():
            if store_data["total_errors"] < 10:
                continue

            # Calculate failure probability
            hourly_values = list(store_data["hourly_counts"].values())
            features = {
                "recent_errors": store_data["total_errors"],
                "error_variance": np.var(hourly_values) if len(hourly_values) > 1 else 0,
                "error_types": len(store_data["error_categories"]),
                "trend": "increasing"
                if len(hourly_values) > 2 and hourly_values[-1] > np.mean(hourly_values)
                else "stable",
                "burst_count": len([d for d in store_data.get("reconnect_delays", []) if d < 60]),
            }

            prob = predictor.predict_failure_probability(features)
            if prob > 0.6:
                high_risk_stores.append(
                    {
                        "store_id": store_id,
                        "probability": prob,
                        "total_errors": stats["total_errors"],
                    }
                )

        if high_risk_stores:
            logger.info("\nHigh-Risk Stores (>60%% failure probability):")
            logger.info("%-12s%-12s%s", "Store", "Risk", "Current Errors")
            logger.info("-" * 40)
            for store in sorted(high_risk_stores, key=lambda x: x["probability"], reverse=True)[
                :15
            ]:
                risk_bar = "█" * int(store["probability"] * 10)
                logger.info(
                    "%-12s%s %.0f%%    %s",
                    store["store_id"],
                    risk_bar,
                    store["probability"] * 100,
                    f"{store['total_errors']:,}",
                )

        return {
            "machine_health": machine_health,
            "root_causes": root_causes,
            "high_risk_stores": high_risk_stores,
        }

    def generate_report(self):
        """Generate comprehensive AI-powered analysis report with recommendations."""
        logger.info("\n" + "=" * 70)
        logger.info("FEDERATION LOG AI ANALYSIS REPORT")
        logger.info("Advanced ML Analysis with Predictive Analytics")
        logger.info("Generated: %s", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        logger.info("=" * 70)

        logger.info("\nDataset Summary:")
        logger.info("  Files processed: %s", f"{self.files_processed:,}")
        logger.info("  Lines processed: %s", f"{self.lines_processed:,}")
        logger.info("  Unique stores: %s", f"{len(self.store_stats):,}")
        logger.info("  Unique machines: %d", len(self.machine_stats))
        logger.info("  Total events: %s", f"{len(self.events):,}")

        if self.min_ts and self.max_ts:
            duration = self.max_ts - self.min_ts
            logger.info("  Time range: %s to %s", self.min_ts, self.max_ts)
            logger.info("  Duration: %s", duration)

        # Collect all analysis results
        results = {}

        # Run all analyses
        logger.info("\n[1/8] Analyzing error patterns...")
        self.analyze_error_patterns()

        logger.info("\n[2/8] Analyzing Internal Errors...")
        results["internal_errors"] = self.analyze_internal_errors()

        logger.info("\n[3/8] Running ensemble anomaly detection...")
        results["anomalies"] = self.analyze_anomalies()

        logger.info("\n[4/8] Clustering stores by behavior...")
        results["clusters"] = self.analyze_store_clusters()

        logger.info("\n[5/8] Analyzing time series and forecasting...")
        results["time_series"] = self.analyze_time_series()

        logger.info("\n[6/8] Detecting cascade failures...")
        results["cascades"] = self.analyze_cascades()

        logger.info("\n[7/8] Performing root cause analysis...")
        root_cause = self.analyze_root_causes()
        results["root_causes"] = root_cause.get("root_causes", [])
        results["machine_health"] = root_cause.get("machine_health", {})
        results["predictions"] = results["time_series"]

        # Run AI Optimization if available
        if HAS_AI_OPTIMIZER:
            logger.info("\n[8/8] Running AI Model Optimization...")
            results["ai_optimization"] = optimize_and_evaluate(
                self.store_stats, self.events, self.error_category_totals
            )
        else:
            logger.info("\n[8/8] AI Optimizer not available - skipping advanced ML")
            results["ai_optimization"] = {}

        # Generate actionable recommendations
        logger.info("\n" + "=" * 70)
        rec_engine = RecommendationEngine()
        recommendations = rec_engine.generate_recommendations(results)

        logger.info(rec_engine.format_report())

        # Executive Summary
        logger.info("\n" + "=" * 70)
        logger.info("EXECUTIVE SUMMARY")
        logger.info("=" * 70)

        # Key metrics
        total_errors = sum(self.error_category_totals.values())
        anomalous_count = len(results["anomalies"].get("anomalous_stores", []))
        cascade_count = len(results["cascades"].get("cascades", []))

        logger.info("\nKey Metrics:")
        logger.info("  Total Errors Analyzed: %s", f"{total_errors:,}")
        logger.info("  Anomalous Stores Detected: %d", anomalous_count)
        logger.info("  Cascade Events Detected: %d", cascade_count)

        if results["time_series"]:
            trend = results["time_series"].get("trend_direction", "unknown")
            logger.info("  Error Trend: %s", trend.upper())

            forecast = results["time_series"].get("forecast", {})
            if forecast:
                next_24h = sum(forecast.get("forecast", []))
                logger.info("  24-Hour Forecast: %s errors expected", f"{int(next_24h):,}")

        # Top root cause
        if results["root_causes"]:
            top_cause = results["root_causes"][0]
            logger.info(
                "  Most Likely Root Cause: %s (%.0f%%)",
                top_cause["cause"],
                top_cause["probability"] * 100,
            )

        # Critical actions
        critical_recs = [r for r in recommendations if r.priority == 1]
        if critical_recs:
            logger.info("\nCritical Actions Required: %d", len(critical_recs))
            for rec in critical_recs[:3]:
                logger.info("  → %s", rec.action)

        logger.info("\n" + "=" * 70)
        logger.info("END OF AI ANALYSIS REPORT")
        logger.info("=" * 70)

        return {
            "anomalies": results["anomalies"],
            "clusters": results["clusters"],
            "time_series": results["time_series"],
            "cascades": results["cascades"],
            "root_causes": results["root_causes"],
            "recommendations": [
                {
                    "priority": r.priority,
                    "action": r.action,
                    "target": r.target,
                    "reason": r.reason,
                    "confidence": r.confidence,
                }
                for r in recommendations
            ],
        }
