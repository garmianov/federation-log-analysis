#!/usr/bin/env python3
"""
Security Center Federation Log Analyzer v2 - Optimized for large log sets
Analyzes federation reconnection patterns and outages from Genetec Security Center logs.
Now with TRUE multiprocessing for parallel CPU utilization.
"""

import multiprocessing
import os
import re
import statistics
import sys
import tempfile
import zipfile
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime

# Compiled patterns (module level for multiprocessing)
STORE_PATTERN = re.compile(r"Store[\s_](\d{4,5})(?:\s*\([^)]*\))?")
TIMESTAMP_PATTERN = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")
FED_GROUP_PATTERN = re.compile(r"(SBUXSCRoleGroup\d+)")

# Connection event patterns
DISCONNECT_INDICATORS = [
    "logged off",
    "Initial sync context is null",
    "disconnect",
    "offline",
    "connection failed",
    "connection attempt failed",
]
RECONNECT_INDICATORS = [
    "logon",
    "sync complete",
    "connected successfully",
    "Scheduling reconnection",
]

# Error/warning patterns
ERROR_PATTERN = re.compile(r"\((Error|Warning|Fatal)\)", re.IGNORECASE)
EXCEPTION_PATTERN = re.compile(r"Exception", re.IGNORECASE)


def process_file_worker(filepath):  # noqa: C901
    """
    Worker function to process a single log file.
    Must be at module level for multiprocessing pickle.
    Returns a dictionary with extracted data.
    """
    result = {
        "store_disconnects": {},  # store_id -> list of (timestamp, event_type, line)
        "store_fed_groups": {},
        "timeline": {},  # hour_key -> {'disconnects': int, 'reconnects': int, 'stores': set}
        "errors_by_type": {},  # error_type -> list of dicts
        "lines_processed": 0,
        "seen_hashes": set(),
    }

    current_fed_group = None

    try:
        with open(filepath, encoding="utf-8-sig", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("*"):
                    # Check for fed group in header
                    match = FED_GROUP_PATTERN.search(line)
                    if match:
                        current_fed_group = match.group(1)
                    continue

                # Skip duplicates
                line_hash = hash(line)
                if line_hash in result["seen_hashes"]:
                    continue
                result["seen_hashes"].add(line_hash)
                result["lines_processed"] += 1

                # Parse timestamp (fast early bailout)
                if len(line) < 20 or line[4] != "-":
                    continue
                try:
                    timestamp = datetime.strptime(line[:19], "%Y-%m-%dT%H:%M:%S")
                except ValueError:
                    continue

                # Extract store ID
                store_match = STORE_PATTERN.search(line)
                if not store_match:
                    continue

                store_id = store_match.group(1).zfill(5)
                line_lower = line.lower()

                # Extract fed group from line if present
                fed_match = FED_GROUP_PATTERN.search(line)
                if fed_match:
                    current_fed_group = fed_match.group(1)
                    result["store_fed_groups"][store_id] = current_fed_group
                elif current_fed_group and store_id not in result["store_fed_groups"]:
                    result["store_fed_groups"][store_id] = current_fed_group

                # Check for disconnect/reconnect events
                has_null_sync = "initial sync context is null" in line_lower
                is_disconnect = (
                    has_null_sync
                    or "logged off" in line_lower
                    or "disconnect" in line_lower
                    or "offline" in line_lower
                    or "connection failed" in line_lower
                    or "connection attempt failed" in line_lower
                )

                is_reconnect = not has_null_sync and (
                    "logon" in line_lower
                    or "sync complete" in line_lower
                    or "connected successfully" in line_lower
                    or "scheduling reconnection" in line_lower
                )

                # Determine error type
                error_type = None
                if "(Warning)" in line:
                    error_type = "warning"
                elif "(Fatal)" in line:
                    error_type = "fatal"
                elif "(Error)" in line:
                    error_type = "error"
                elif "Exception" in line:
                    error_type = "exception"

                hour_key = timestamp.replace(minute=0, second=0, microsecond=0).isoformat()

                if is_disconnect:
                    if store_id not in result["store_disconnects"]:
                        result["store_disconnects"][store_id] = []
                    result["store_disconnects"][store_id].append(
                        (timestamp.isoformat(), "disconnect", line[:200])
                    )

                    if hour_key not in result["timeline"]:
                        result["timeline"][hour_key] = {
                            "disconnects": 0,
                            "reconnects": 0,
                            "stores": set(),
                        }
                    result["timeline"][hour_key]["disconnects"] += 1
                    result["timeline"][hour_key]["stores"].add(store_id)

                if is_reconnect and not is_disconnect:
                    if store_id not in result["store_disconnects"]:
                        result["store_disconnects"][store_id] = []
                    result["store_disconnects"][store_id].append(
                        (timestamp.isoformat(), "reconnect", line[:200])
                    )

                    if hour_key not in result["timeline"]:
                        result["timeline"][hour_key] = {
                            "disconnects": 0,
                            "reconnects": 0,
                            "stores": set(),
                        }
                    result["timeline"][hour_key]["reconnects"] += 1

                if error_type:
                    if error_type not in result["errors_by_type"]:
                        result["errors_by_type"][error_type] = []
                    # Limit samples per file
                    if len(result["errors_by_type"][error_type]) < 20:
                        result["errors_by_type"][error_type].append(
                            {
                                "timestamp": timestamp.isoformat(),
                                "store": store_id,
                                "line": line[:300],
                            }
                        )

        # Convert sets to lists for serialization
        for hour_key in result["timeline"]:
            result["timeline"][hour_key]["stores"] = list(result["timeline"][hour_key]["stores"])

        # Clear seen_hashes to reduce memory
        result["seen_hashes"] = set()

        return {"success": True, "filepath": filepath, "data": result}

    except Exception as e:
        return {"success": False, "filepath": filepath, "error": str(e)}


class FastLogAnalyzer:
    def __init__(self):
        self.seen_hashes = set()
        self.store_disconnects = defaultdict(list)  # store_id -> [(timestamp, event_type)]
        self.store_fed_groups = {}
        self.timeline = defaultdict(lambda: {"disconnects": 0, "reconnects": 0, "stores": set()})
        self.errors_by_type = defaultdict(list)
        self.files_processed = 0
        self.lines_processed = 0

    def merge_result(self, result_data):
        """Merge results from a worker process."""
        data = result_data

        # Merge store disconnects
        for store_id, events in data["store_disconnects"].items():
            for ts_str, event_type, line in events:
                timestamp = datetime.fromisoformat(ts_str)
                self.store_disconnects[store_id].append((timestamp, event_type, line))

        # Merge fed groups
        self.store_fed_groups.update(data["store_fed_groups"])

        # Merge timeline
        for hour_key_str, tdata in data["timeline"].items():
            hour_key = datetime.fromisoformat(hour_key_str)
            self.timeline[hour_key]["disconnects"] += tdata["disconnects"]
            self.timeline[hour_key]["reconnects"] += tdata["reconnects"]
            self.timeline[hour_key]["stores"].update(tdata["stores"])

        # Merge errors
        for error_type, errors in data["errors_by_type"].items():
            for err in errors:
                err["timestamp"] = datetime.fromisoformat(err["timestamp"])
                if len(self.errors_by_type[error_type]) < 500:
                    self.errors_by_type[error_type].append(err)

        self.lines_processed += data["lines_processed"]

    def process_zip(self, zip_path, temp_dir):
        """Process logs from a zip file."""
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                for name in zf.namelist():
                    if name.endswith(".log"):
                        extracted = os.path.join(temp_dir, os.path.basename(name))
                        with zf.open(name) as src, open(extracted, "wb") as dst:
                            dst.write(src.read())
                        result = process_file_worker(extracted)
                        if result["success"]:
                            self.merge_result(result["data"])
                            self.files_processed += 1
                        os.remove(extracted)
        except Exception as e:
            print(f"  Error processing zip {os.path.basename(zip_path)}: {e}", file=sys.stderr)

    def scan_all(self, log_dirs, max_workers=None):
        """Scan all log directories with TRUE parallel multiprocessing."""
        if max_workers is None:
            max_workers = multiprocessing.cpu_count()

        print("=" * 80, flush=True)
        print(f"SCANNING LOG DIRECTORIES (Multiprocessing: {max_workers} workers)", flush=True)
        print("=" * 80, flush=True)

        with tempfile.TemporaryDirectory() as temp_dir:
            for log_dir in log_dirs:
                if not os.path.exists(log_dir):
                    print(f"Warning: {log_dir} not found", flush=True)
                    continue

                print(f"\nScanning: {os.path.basename(log_dir)}", flush=True)

                files = sorted(os.listdir(log_dir))
                log_files = [os.path.join(log_dir, f) for f in files if f.endswith(".log")]
                zip_files = [os.path.join(log_dir, f) for f in files if f.endswith(".zip")]

                print(f"  {len(log_files)} .log files, {len(zip_files)} .zip files", flush=True)
                print(f"  Using {max_workers} CPU cores for parallel processing", flush=True)

                # Process .log files in TRUE parallel with multiprocessing
                processed = 0
                errors = 0

                with ProcessPoolExecutor(max_workers=max_workers) as executor:
                    futures = {executor.submit(process_file_worker, fp): fp for fp in log_files}
                    for future in as_completed(futures):
                        processed += 1
                        try:
                            result = future.result()
                            if result["success"]:
                                self.merge_result(result["data"])
                                self.files_processed += 1
                            else:
                                errors += 1
                                if errors <= 5:
                                    print(
                                        f"    Error: {os.path.basename(result['filepath'])}: {result['error']}",
                                        file=sys.stderr,
                                        flush=True,
                                    )
                        except Exception as e:
                            errors += 1
                            if errors <= 5:
                                print(f"    Worker error: {e}", file=sys.stderr, flush=True)

                        if processed % 200 == 0:
                            print(
                                f"    {processed}/{len(log_files)} logs... ({self.lines_processed:,} lines)",
                                flush=True,
                            )

                print(f"    Completed {len(log_files)} log files ({errors} errors)", flush=True)

                # Process .zip files (sequential due to temp file handling)
                if zip_files:
                    print(f"  Processing {len(zip_files)} zip files...", flush=True)
                    for i, filepath in enumerate(zip_files):
                        self.process_zip(filepath, temp_dir)
                        if (i + 1) % 20 == 0:
                            print(f"    {i+1}/{len(zip_files)} zips...", flush=True)
                    print(f"    Completed {len(zip_files)} zip files", flush=True)

        print(f"\nTotal files processed: {self.files_processed}", flush=True)
        print(f"Total unique lines: {self.lines_processed:,}", flush=True)
        print(f"Unique stores found: {len(self.store_disconnects)}", flush=True)

    def calculate_stats(self):
        """Calculate disconnection statistics for each store."""
        store_stats = {}

        for store_id, events in self.store_disconnects.items():
            sorted_events = sorted(events, key=lambda x: x[0])

            disconnect_count = sum(1 for e in sorted_events if e[1] == "disconnect")
            durations = []
            last_disconnect = None

            for ts, event_type, _ in sorted_events:
                if event_type == "disconnect":
                    last_disconnect = ts
                elif event_type == "reconnect" and last_disconnect:
                    duration = (ts - last_disconnect).total_seconds()
                    if 0 < duration < 86400 * 7:  # Valid duration < 7 days
                        durations.append(duration)
                    last_disconnect = None

            store_stats[store_id] = {
                "disconnect_count": disconnect_count,
                "durations": durations,
                "fed_group": self.store_fed_groups.get(store_id, "Unknown"),
            }

        return store_stats

    def generate_report(self):  # noqa: C901
        """Generate the final report."""
        print("\n" + "=" * 80, flush=True)
        print("FEDERATION LOG ANALYSIS REPORT", flush=True)
        print("=" * 80, flush=True)

        store_stats = self.calculate_stats()

        if not store_stats:
            print("\nNo store events found!", flush=True)
            return

        # Find and exclude store with highest reconnects
        disconnect_counts = {s: stats["disconnect_count"] for s, stats in store_stats.items()}
        max_store = max(disconnect_counts, key=disconnect_counts.get)
        max_count = disconnect_counts[max_store]

        print(f"\n>>> EXCLUDING STORE {max_store} (highest reconnects: {max_count})", flush=True)

        # Remove max store
        del store_stats[max_store]
        del disconnect_counts[max_store]

        # ========== SUMMARY ==========
        print("\n" + "-" * 80, flush=True)
        print("SUMMARY", flush=True)
        print("-" * 80, flush=True)

        total_stores = len(store_stats)
        total_disconnects = sum(disconnect_counts.values())
        total_errors = sum(len(v) for v in self.errors_by_type.values())

        print(f"Total stores analyzed: {total_stores}", flush=True)
        print(f"Total disconnect events: {total_disconnects:,}", flush=True)
        print(f"Total errors/warnings: {total_errors:,}", flush=True)

        # Time range
        all_times = []
        for s, _stats in store_stats.items():
            for ts, _, _ in self.store_disconnects.get(s, []):
                all_times.append(ts)
        if all_times:
            print(
                f"Time range: {min(all_times).strftime('%Y-%m-%d %H:%M')} to {max(all_times).strftime('%Y-%m-%d %H:%M')}",
                flush=True,
            )

        # ========== TOP STORES ==========
        print("\n" + "-" * 80, flush=True)
        print("TOP 20 STORES BY DISCONNECT COUNT", flush=True)
        print("-" * 80, flush=True)

        sorted_stores = sorted(disconnect_counts.items(), key=lambda x: x[1], reverse=True)[:20]

        print(f"\n{'Rank':<6}{'Store':<12}{'Disconnects':<14}{'Federation Group':<25}", flush=True)
        print("-" * 55, flush=True)

        for rank, (store_id, count) in enumerate(sorted_stores, 1):
            fed_group = store_stats[store_id]["fed_group"]
            print(f"{rank:<6}{store_id:<12}{count:<14,}{fed_group:<25}", flush=True)

        # ========== DISCONNECTION DURATION STATS ==========
        print("\n" + "-" * 80, flush=True)
        print("DISCONNECTION DURATION STATISTICS", flush=True)
        print("-" * 80, flush=True)

        all_durations = []
        stores_with_durations = {}
        for store_id, stats in store_stats.items():
            if stats["durations"]:
                all_durations.extend(stats["durations"])
                stores_with_durations[store_id] = {
                    "max": max(stats["durations"]),
                    "avg": statistics.mean(stats["durations"]),
                    "median": statistics.median(stats["durations"]),
                    "count": len(stats["durations"]),
                    "fed_group": stats["fed_group"],
                }

        def fmt_dur(sec):
            if sec < 60:
                return f"{sec:.0f}s"
            elif sec < 3600:
                return f"{sec/60:.1f}m"
            else:
                return f"{sec/3600:.1f}h"

        if all_durations:
            print("\nOVERALL STATISTICS:", flush=True)
            print(f"  Maximum disconnection: {fmt_dur(max(all_durations))}", flush=True)
            print(f"  Average disconnection: {fmt_dur(statistics.mean(all_durations))}", flush=True)
            print(
                f"  Median disconnection:  {fmt_dur(statistics.median(all_durations))}", flush=True
            )
            print(f"  Total measurements:    {len(all_durations):,}", flush=True)

            print("\nTOP 10 STORES BY MAXIMUM DISCONNECTION TIME:", flush=True)
            print(
                f"{'Store':<10}{'Max':<12}{'Avg':<12}{'Median':<12}{'Count':<8}{'Fed Group':<20}",
                flush=True,
            )
            print("-" * 74, flush=True)

            for store_id, stats in sorted(
                stores_with_durations.items(), key=lambda x: x[1]["max"], reverse=True
            )[:10]:
                print(
                    f"{store_id:<10}{fmt_dur(stats['max']):<12}{fmt_dur(stats['avg']):<12}{fmt_dur(stats['median']):<12}{stats['count']:<8}{stats['fed_group']:<20}",
                    flush=True,
                )

        # ========== FEDERATION GROUPS ==========
        print("\n" + "-" * 80, flush=True)
        print("RECONNECTS BY FEDERATION GROUP", flush=True)
        print("-" * 80, flush=True)

        fed_stats = defaultdict(lambda: {"stores": set(), "disconnects": 0})
        for store_id, count in disconnect_counts.items():
            fed_group = store_stats[store_id]["fed_group"]
            fed_stats[fed_group]["stores"].add(store_id)
            fed_stats[fed_group]["disconnects"] += count

        print(
            f"\n{'Federation Group':<25}{'Stores':<10}{'Disconnects':<15}{'Avg/Store':<12}",
            flush=True,
        )
        print("-" * 62, flush=True)

        for fg, stats in sorted(fed_stats.items(), key=lambda x: x[1]["disconnects"], reverse=True):
            avg = stats["disconnects"] / len(stats["stores"]) if stats["stores"] else 0
            print(
                f"{fg:<25}{len(stats['stores']):<10}{stats['disconnects']:<15,}{avg:<12.1f}",
                flush=True,
            )

        # ========== TIMELINE / OUTAGES ==========
        print("\n" + "-" * 80, flush=True)
        print("HOURLY TIMELINE (HIGH ACTIVITY PERIODS)", flush=True)
        print("-" * 80, flush=True)

        timeline_data = [
            (k, v["disconnects"], len(v["stores"]))
            for k, v in self.timeline.items()
            if k != max_store
        ]

        if timeline_data:
            avg_disc = statistics.mean([t[1] for t in timeline_data])
            std_disc = (
                statistics.stdev([t[1] for t in timeline_data]) if len(timeline_data) > 1 else 0
            )
            threshold = avg_disc + 2 * std_disc

            print(f"\nAverage disconnects/hour: {avg_disc:.1f}", flush=True)
            print(f"High activity threshold:  {threshold:.1f}", flush=True)

            print("\nHOURS WITH ELEVATED ACTIVITY (>threshold or >50):", flush=True)
            print(f"{'Hour':<22}{'Disconnects':<14}{'Stores Affected':<18}", flush=True)
            print("-" * 54, flush=True)

            for hour, disc_count, store_count in sorted(
                timeline_data, key=lambda x: x[1], reverse=True
            )[:25]:
                if disc_count > threshold or disc_count > 50:
                    print(
                        f"{hour.strftime('%Y-%m-%d %H:00'):<22}{disc_count:<14,}{store_count:<18}",
                        flush=True,
                    )

        # ========== ERROR ANALYSIS ==========
        print("\n" + "-" * 80, flush=True)
        print("ERROR ANALYSIS", flush=True)
        print("-" * 80, flush=True)

        print("\nError counts by type:", flush=True)
        for etype, errors in sorted(
            self.errors_by_type.items(), key=lambda x: len(x[1]), reverse=True
        ):
            print(f"  {etype.capitalize()}: {len(errors):,}", flush=True)

        # Categorize errors
        error_categories = defaultdict(int)
        for _etype, errors in self.errors_by_type.items():
            for err in errors:
                line = err["line"].lower()
                if "timeout" in line or "timed out" in line:
                    error_categories["Connection Timeout"] += 1
                elif "connection attempt failed" in line:
                    error_categories["Connection Failed"] += 1
                elif "socketexception" in line or "socket" in line:
                    error_categories["Socket Error"] += 1
                elif "tls" in line or "ssl" in line:
                    error_categories["TLS/SSL Error"] += 1
                elif "refused" in line:
                    error_categories["Connection Refused"] += 1

        if error_categories:
            print("\nCommon error patterns:", flush=True)
            for cat, count in sorted(error_categories.items(), key=lambda x: x[1], reverse=True):
                print(f"  {cat}: {count:,}", flush=True)

        # ========== VISUALS ==========
        self.print_visuals(
            sorted_stores, store_stats, stores_with_durations, fed_stats, timeline_data
        )

    def print_visuals(  # noqa: C901
        self, top_stores, store_stats, duration_stats, fed_stats, timeline_data
    ):
        """Print ASCII visualizations."""
        print("\n" + "=" * 80, flush=True)
        print("VISUAL CHARTS", flush=True)
        print("=" * 80, flush=True)

        # Bar chart: Top stores
        print("\n--- TOP 15 STORES BY DISCONNECTS ---", flush=True)
        if top_stores:
            max_val = top_stores[0][1]
            for store_id, count in top_stores[:15]:
                bar_len = int(45 * count / max_val) if max_val > 0 else 0
                fed = store_stats[store_id]["fed_group"][:12]
                print(f"Store {store_id} ({fed:>12}): {'█' * bar_len} {count:,}", flush=True)

        # Timeline heatmap
        print("\n--- DISCONNECT TIMELINE (daily) ---", flush=True)
        if timeline_data:
            daily = defaultdict(int)
            for hour, disc, _ in timeline_data:
                daily[hour.date()] += disc

            max_daily = max(daily.values()) if daily else 1
            print(
                f"Legend: · <10%, ░ <25%, ▒ <50%, ▓ <75%, █ >=75% of max ({max_daily:,})",
                flush=True,
            )

            for date in sorted(daily.keys()):
                count = daily[date]
                pct = count / max_daily if max_daily > 0 else 0
                if pct < 0.1:
                    bar = "·" * 40
                elif pct < 0.25:
                    bar = "░" * int(40 * pct / 0.25)
                elif pct < 0.5:
                    bar = "▒" * int(40 * (pct - 0.25) / 0.25)
                elif pct < 0.75:
                    bar = "▓" * int(40 * (pct - 0.5) / 0.25)
                else:
                    bar = "█" * int(40 * pct)
                print(f"{date} |{bar:<40}| {count:>7,}", flush=True)

        # Federation group chart
        print("\n--- DISCONNECTS BY FEDERATION GROUP ---", flush=True)
        if fed_stats:
            max_fed = max(s["disconnects"] for s in fed_stats.values())
            for fg, stats in sorted(
                fed_stats.items(), key=lambda x: x[1]["disconnects"], reverse=True
            ):
                bar_len = int(35 * stats["disconnects"] / max_fed) if max_fed > 0 else 0
                print(
                    f"{fg:>20}: {'█' * bar_len} {stats['disconnects']:,} ({len(stats['stores'])} stores)",
                    flush=True,
                )

        # Duration distribution
        print("\n--- MEDIAN DISCONNECTION TIME DISTRIBUTION ---", flush=True)
        if duration_stats:
            buckets = {"<1m": 0, "1-5m": 0, "5-15m": 0, "15-60m": 0, "1-4h": 0, ">4h": 0}
            for _store_id, dur_stats in duration_stats.items():
                med = dur_stats["median"]
                if med < 60:
                    buckets["<1m"] += 1
                elif med < 300:
                    buckets["1-5m"] += 1
                elif med < 900:
                    buckets["5-15m"] += 1
                elif med < 3600:
                    buckets["15-60m"] += 1
                elif med < 14400:
                    buckets["1-4h"] += 1
                else:
                    buckets[">4h"] += 1

            max_bucket = max(buckets.values()) if buckets.values() else 1
            for bucket, count in buckets.items():
                bar_len = int(35 * count / max_bucket) if max_bucket > 0 else 0
                print(f"{bucket:>8}: {'█' * bar_len} {count} stores", flush=True)

        print("\n" + "=" * 80, flush=True)
        print("END OF REPORT", flush=True)
        print("=" * 80, flush=True)


def find_log_paths():
    """Auto-discover federation log files/directories in ~/Downloads."""
    downloads = os.path.expanduser("~/Downloads")
    paths = []

    if not os.path.exists(downloads):
        return paths

    for item in os.listdir(downloads):
        full_path = os.path.join(downloads, item)

        # Check ZIP files
        if item.endswith(".zip") and ("Fed" in item or "Base" in item or "Log" in item):
            paths.append(full_path)
        # Check directories containing .log files
        elif os.path.isdir(full_path):
            try:
                log_files = [f for f in os.listdir(full_path) if f.endswith(".log")]
                if log_files:
                    paths.append(full_path)
            except (PermissionError, OSError):
                continue

    # Sort by modification time (newest first)
    paths.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return paths


def main():
    print("Security Center Federation Log Analyzer v2", flush=True)
    print("Optimized for large log sets with MULTIPROCESSING", flush=True)
    print(f"CPU cores available: {multiprocessing.cpu_count()}\n", flush=True)

    # Handle command-line arguments
    if len(sys.argv) > 1:
        log_dirs = [os.path.expanduser(arg) for arg in sys.argv[1:]]
        # Validate paths
        for path in log_dirs:
            if not os.path.exists(path):
                print(f"Error: Path not found: {path}")
                sys.exit(1)
    else:
        # Auto-discover in ~/Downloads
        log_dirs = find_log_paths()
        if not log_dirs:
            print("Usage: python analyze_federation_logs_v2.py <path1> [path2] ...")
            print("\nNo federation log files found in ~/Downloads.")
            print("Please specify directories or ZIP files containing logs.")
            sys.exit(1)
        print(f"Auto-discovered {len(log_dirs)} path(s):")
        for p in log_dirs[:5]:
            print(f"  - {p}")
        if len(log_dirs) > 5:
            print(f"  ... and {len(log_dirs) - 5} more")
        print()

    analyzer = FastLogAnalyzer()
    analyzer.scan_all(log_dirs)
    analyzer.generate_report()


if __name__ == "__main__":
    main()
