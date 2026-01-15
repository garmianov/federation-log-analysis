#!/usr/bin/env python3
"""
Security Center Federation Log Analyzer v3 - Memory efficient version
Uses incremental statistics computation for massive datasets.
Now with TRUE multiprocessing for parallel CPU utilization.
"""

import multiprocessing
import os
import re
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

ERROR_PATTERN = re.compile(r"\((Error|Warning|Fatal)\)", re.IGNORECASE)
EXCEPTION_PATTERN = re.compile(r"Exception", re.IGNORECASE)


def process_file_worker(filepath):
    """
    Worker function to process a single log file.
    Must be at module level for multiprocessing pickle.
    Returns a dictionary with extracted data.
    """
    result = {
        "store_disconnects": defaultdict(int),
        "store_fed_groups": {},
        "store_durations": defaultdict(list),  # Will compute stats later
        "timeline": {},  # Regular dict - entries created manually below
        "error_counts": defaultdict(int),
        "error_samples": [],
        "lines_processed": 0,
        "min_ts": None,
        "max_ts": None,
        "store_last_disconnect": {},
        "seen_hashes": set(),
    }

    current_fed_group = None

    try:
        with open(filepath, encoding="utf-8-sig", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("*"):
                    match = FED_GROUP_PATTERN.search(line)
                    if match:
                        current_fed_group = match.group(1)
                    continue

                # Deduplication
                line_hash = hash(line)
                if line_hash in result["seen_hashes"]:
                    continue
                result["seen_hashes"].add(line_hash)
                result["lines_processed"] += 1

                # Parse timestamp
                if len(line) < 20 or line[4] != "-":
                    continue
                try:
                    timestamp = datetime.strptime(line[:19], "%Y-%m-%dT%H:%M:%S")
                except ValueError:
                    continue

                # Store pattern
                store_match = STORE_PATTERN.search(line)
                if not store_match:
                    continue

                store_id = store_match.group(1).zfill(5)
                line_lower = line.lower()

                # Fed group extraction
                fed_match = FED_GROUP_PATTERN.search(line)
                if fed_match:
                    current_fed_group = fed_match.group(1)
                    result["store_fed_groups"][store_id] = current_fed_group
                elif current_fed_group and store_id not in result["store_fed_groups"]:
                    result["store_fed_groups"][store_id] = current_fed_group

                # Disconnect/reconnect detection
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

                # Error detection
                error_type = None
                error_category = None
                if "(Warning)" in line:
                    error_type = "warning"
                elif "(Fatal)" in line:
                    error_type = "fatal"
                elif "(Error)" in line:
                    error_type = "error"
                if "Exception" in line:
                    error_type = "exception"

                if error_type:
                    if "timeout" in line_lower:
                        error_category = "cat:timeout"
                    elif "connection attempt failed" in line_lower:
                        error_category = "cat:conn_failed"
                    elif "socket" in line_lower:
                        error_category = "cat:socket"
                    elif "tls" in line_lower or "ssl" in line_lower:
                        error_category = "cat:tls_ssl"

                hour_key = timestamp.replace(minute=0, second=0, microsecond=0).isoformat()

                # Time range tracking
                if result["min_ts"] is None or timestamp < result["min_ts"]:
                    result["min_ts"] = timestamp
                if result["max_ts"] is None or timestamp > result["max_ts"]:
                    result["max_ts"] = timestamp

                if is_disconnect:
                    result["store_disconnects"][store_id] += 1
                    result["store_last_disconnect"][store_id] = timestamp

                    # Timeline uses string key for serialization
                    if hour_key not in result["timeline"]:
                        result["timeline"][hour_key] = {
                            "disconnects": 0,
                            "reconnects": 0,
                            "stores": set(),
                        }
                    result["timeline"][hour_key]["disconnects"] += 1
                    result["timeline"][hour_key]["stores"].add(store_id)

                if is_reconnect and not is_disconnect:
                    if hour_key not in result["timeline"]:
                        result["timeline"][hour_key] = {
                            "disconnects": 0,
                            "reconnects": 0,
                            "stores": set(),
                        }
                    result["timeline"][hour_key]["reconnects"] += 1

                    # Calculate duration
                    if store_id in result["store_last_disconnect"]:
                        last_dc = result["store_last_disconnect"][store_id]
                        duration = (timestamp - last_dc).total_seconds()
                        if 0 < duration < 86400 * 7:
                            result["store_durations"][store_id].append(duration)
                        del result["store_last_disconnect"][store_id]

                # Error tracking
                if error_type:
                    result["error_counts"][error_type] += 1
                    if error_category:
                        result["error_counts"][error_category] += 1
                    if len(result["error_samples"]) < 10:  # Keep fewer samples per file
                        result["error_samples"].append(
                            {"ts": timestamp.isoformat(), "store": store_id, "line": line[:200]}
                        )

        # Convert sets to lists for serialization
        for hour_key in result["timeline"]:
            result["timeline"][hour_key]["stores"] = list(result["timeline"][hour_key]["stores"])

        # Clear seen_hashes to reduce memory in return value
        result["seen_hashes"] = set()
        result["store_last_disconnect"] = {}

        return {"success": True, "filepath": filepath, "data": result}

    except Exception as e:
        return {"success": False, "filepath": filepath, "error": str(e)}


def process_zip_worker(zip_path):
    """
    Worker function to process a single ZIP file.
    Must be at module level for multiprocessing pickle.
    Creates its own temp directory for extraction.
    Returns aggregated results from all logs in the zip.
    """
    aggregated = {
        "store_disconnects": defaultdict(int),
        "store_fed_groups": {},
        "store_durations": defaultdict(list),
        "timeline": {},
        "error_counts": defaultdict(int),
        "error_samples": [],
        "lines_processed": 0,
        "min_ts": None,
        "max_ts": None,
        "files_in_zip": 0,
    }

    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            with zipfile.ZipFile(zip_path, "r") as zf:
                log_names = [n for n in zf.namelist() if n.endswith(".log")]

                for name in log_names:
                    extracted = os.path.join(temp_dir, os.path.basename(name))
                    try:
                        with zf.open(name) as src, open(extracted, "wb") as dst:
                            dst.write(src.read())

                        result = process_file_worker(extracted)

                        if result["success"]:
                            data = result["data"]
                            aggregated["files_in_zip"] += 1

                            # Merge store disconnects
                            for store_id, count in data["store_disconnects"].items():
                                aggregated["store_disconnects"][store_id] += count

                            # Merge fed groups
                            aggregated["store_fed_groups"].update(data["store_fed_groups"])

                            # Merge durations
                            for store_id, durations in data["store_durations"].items():
                                aggregated["store_durations"][store_id].extend(durations)

                            # Merge timeline
                            for hour_key, tdata in data["timeline"].items():
                                if hour_key not in aggregated["timeline"]:
                                    aggregated["timeline"][hour_key] = {
                                        "disconnects": 0,
                                        "reconnects": 0,
                                        "stores": [],
                                    }
                                aggregated["timeline"][hour_key]["disconnects"] += tdata[
                                    "disconnects"
                                ]
                                aggregated["timeline"][hour_key]["reconnects"] += tdata[
                                    "reconnects"
                                ]
                                aggregated["timeline"][hour_key]["stores"].extend(tdata["stores"])

                            # Merge errors
                            for err_type, count in data["error_counts"].items():
                                aggregated["error_counts"][err_type] += count

                            if len(aggregated["error_samples"]) < 20:
                                aggregated["error_samples"].extend(
                                    data["error_samples"][: 20 - len(aggregated["error_samples"])]
                                )

                            # Merge time range
                            if data["min_ts"]:
                                if (
                                    aggregated["min_ts"] is None
                                    or data["min_ts"] < aggregated["min_ts"]
                                ):
                                    aggregated["min_ts"] = data["min_ts"]
                            if data["max_ts"]:
                                if (
                                    aggregated["max_ts"] is None
                                    or data["max_ts"] > aggregated["max_ts"]
                                ):
                                    aggregated["max_ts"] = data["max_ts"]

                            aggregated["lines_processed"] += data["lines_processed"]

                        os.remove(extracted)
                    except Exception:
                        # Skip individual file errors within zip
                        pass

        return {"success": True, "filepath": zip_path, "data": aggregated}

    except Exception as e:
        return {"success": False, "filepath": zip_path, "error": str(e)}


class OnlineStats:
    """Welford's online algorithm for mean, variance, min, max."""

    __slots__ = ("n", "mean", "M2", "min_val", "max_val", "values_for_median", "sample_rate")

    def __init__(self):
        self.n = 0
        self.mean = 0.0
        self.M2 = 0.0
        self.min_val = float("inf")
        self.max_val = float("-inf")
        self.values_for_median = []
        self.sample_rate = 100

    def update(self, x):
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        delta2 = x - self.mean
        self.M2 += delta * delta2

        if x < self.min_val:
            self.min_val = x
        if x > self.max_val:
            self.max_val = x

        if self.n % self.sample_rate == 0:
            self.values_for_median.append(x)

    def update_batch(self, values):
        """Update with a batch of values."""
        for x in values:
            self.update(x)

    def get_stats(self):
        if self.n < 1:
            return None
        variance = self.M2 / self.n if self.n > 1 else 0.0
        if self.values_for_median:
            sorted_vals = sorted(self.values_for_median)
            median = sorted_vals[len(sorted_vals) // 2]
        else:
            median = self.mean
        return {
            "count": self.n,
            "mean": self.mean,
            "std": variance**0.5,
            "min": self.min_val,
            "max": self.max_val,
            "median_estimate": median,
        }


class StreamAnalyzer:
    def __init__(self, server_id: str = "Unknown"):
        self.server_id = server_id

        # Per-store aggregated stats
        self.store_disconnect_count = defaultdict(int)
        self.store_fed_groups = {}
        self.store_durations = defaultdict(OnlineStats)

        # Timeline (hourly)
        self.timeline = defaultdict(lambda: {"disconnects": 0, "reconnects": 0, "stores": set()})

        # Error tracking
        self.error_counts = defaultdict(int)
        self.error_samples = []

        # Overall stats
        self.overall_durations = OnlineStats()

        self.files_processed = 0
        self.lines_processed = 0
        self.min_ts = None
        self.max_ts = None

    def merge_result(self, result_data):
        """Merge results from a worker process."""
        data = result_data

        # Merge store disconnects
        for store_id, count in data["store_disconnects"].items():
            self.store_disconnect_count[store_id] += count

        # Merge fed groups (later values override)
        self.store_fed_groups.update(data["store_fed_groups"])

        # Merge durations
        for store_id, durations in data["store_durations"].items():
            self.store_durations[store_id].update_batch(durations)
            for d in durations:
                self.overall_durations.update(d)

        # Merge timeline
        for hour_key_str, tdata in data["timeline"].items():
            hour_key = datetime.fromisoformat(hour_key_str)
            self.timeline[hour_key]["disconnects"] += tdata["disconnects"]
            self.timeline[hour_key]["reconnects"] += tdata["reconnects"]
            self.timeline[hour_key]["stores"].update(tdata["stores"])

        # Merge errors
        for err_type, count in data["error_counts"].items():
            self.error_counts[err_type] += count

        if len(self.error_samples) < 100:
            self.error_samples.extend(data["error_samples"][: 100 - len(self.error_samples)])

        # Merge time range
        if data["min_ts"]:
            if self.min_ts is None or data["min_ts"] < self.min_ts:
                self.min_ts = data["min_ts"]
        if data["max_ts"]:
            if self.max_ts is None or data["max_ts"] > self.max_ts:
                self.max_ts = data["max_ts"]

        self.lines_processed += data["lines_processed"]

    def scan_all(self, log_dirs, max_workers=None):
        """Scan all log directories with TRUE parallel multiprocessing."""
        if max_workers is None:
            max_workers = multiprocessing.cpu_count()

        print("=" * 80, flush=True)
        print(f"SCANNING LOG DIRECTORIES (Multiprocessing: {max_workers} workers)", flush=True)
        print("=" * 80, flush=True)

        for log_dir in log_dirs:
            if not os.path.exists(log_dir):
                print(f"Warning: {log_dir} not found", flush=True)
                continue

            print(f"\nScanning: {os.path.basename(log_dir)}", flush=True)
            files = sorted(os.listdir(log_dir))
            log_files = [os.path.join(log_dir, f) for f in files if f.endswith(".log")]
            zip_files = [os.path.join(log_dir, f) for f in files if f.endswith(".zip")]

            print(f"  {len(log_files)} .log, {len(zip_files)} .zip files", flush=True)
            print(f"  Using {max_workers} CPU cores for parallel processing", flush=True)

            # Process log files in TRUE parallel with multiprocessing
            processed = 0
            errors = 0

            with ProcessPoolExecutor(max_workers=max_workers) as executor:
                # Submit all files
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

            print(f"    Done: {len(log_files)} logs ({errors} errors)", flush=True)

            # Process zip files in PARALLEL (each worker has its own temp dir)
            if zip_files:
                print(f"  Processing {len(zip_files)} zip files in parallel...", flush=True)
                zip_processed = 0
                zip_errors = 0
                files_from_zips = 0

                with ProcessPoolExecutor(max_workers=max_workers) as executor:
                    futures = {executor.submit(process_zip_worker, zp): zp for zp in zip_files}

                    for future in as_completed(futures):
                        zip_processed += 1
                        try:
                            result = future.result()
                            if result["success"]:
                                self.merge_result(result["data"])
                                files_from_zips += result["data"].get("files_in_zip", 0)
                            else:
                                zip_errors += 1
                                if zip_errors <= 3:
                                    print(
                                        f"    Zip error: {os.path.basename(result['filepath'])}: {result['error']}",
                                        file=sys.stderr,
                                        flush=True,
                                    )
                        except Exception as e:
                            zip_errors += 1
                            if zip_errors <= 3:
                                print(f"    Zip worker error: {e}", file=sys.stderr, flush=True)

                        if zip_processed % 50 == 0:
                            print(
                                f"    {zip_processed}/{len(zip_files)} zips... ({files_from_zips} logs extracted)",
                                flush=True,
                            )

                self.files_processed += files_from_zips
                print(
                    f"    Done: {len(zip_files)} zips ({files_from_zips} logs, {zip_errors} errors)",
                    flush=True,
                )

        print(
            f"\nFiles: {self.files_processed}, Unique lines: {self.lines_processed:,}", flush=True
        )
        print(f"Stores: {len(self.store_disconnect_count)}", flush=True)

    def generate_report(self):
        print("\n" + "=" * 80, flush=True)
        print("FEDERATION LOG ANALYSIS REPORT", flush=True)
        print("=" * 80, flush=True)

        if not self.store_disconnect_count:
            print("\nNo events found!", flush=True)
            return

        # Find max store to exclude
        max_store = max(self.store_disconnect_count, key=self.store_disconnect_count.get)
        max_count = self.store_disconnect_count[max_store]
        print(f"\n>>> EXCLUDING: Store {max_store} ({max_count:,} disconnects)", flush=True)

        # Create filtered counts
        filtered = {k: v for k, v in self.store_disconnect_count.items() if k != max_store}

        # ===== SUMMARY =====
        print("\n" + "-" * 80, flush=True)
        print("SUMMARY", flush=True)
        print("-" * 80, flush=True)

        total_dc = sum(filtered.values())
        total_errors = sum(v for k, v in self.error_counts.items() if not k.startswith("cat:"))

        print(f"Stores analyzed: {len(filtered)}", flush=True)
        print(f"Total disconnect events: {total_dc:,}", flush=True)
        print(f"Total errors/warnings: {total_errors:,}", flush=True)
        if self.min_ts and self.max_ts:
            print(
                f"Time range: {self.min_ts.strftime('%Y-%m-%d %H:%M')} to {self.max_ts.strftime('%Y-%m-%d %H:%M')}",
                flush=True,
            )

        overall = self.overall_durations.get_stats()
        if overall:

            def fmt(s):
                if s < 60:
                    return f"{s:.0f}s"
                if s < 3600:
                    return f"{s/60:.1f}m"
                return f"{s/3600:.1f}h"

            print("\nDISCONNECTION DURATION (overall):", flush=True)
            print(f"  Maximum: {fmt(overall['max'])}", flush=True)
            print(f"  Average: {fmt(overall['mean'])}", flush=True)
            print(f"  Median (est): {fmt(overall['median_estimate'])}", flush=True)
            print(f"  Std Dev: {fmt(overall['std'])}", flush=True)
            print(f"  Measurements: {overall['count']:,}", flush=True)

        # ===== TOP STORES =====
        print("\n" + "-" * 80, flush=True)
        print("TOP 20 STORES BY DISCONNECT COUNT", flush=True)
        print("-" * 80, flush=True)

        top20 = sorted(filtered.items(), key=lambda x: x[1], reverse=True)[:20]

        print(f"\n{'Rk':<4}{'Store':<10}{'Disconnects':<14}{'Fed Group':<22}", flush=True)
        print("-" * 50, flush=True)

        for i, (store, cnt) in enumerate(top20, 1):
            fg = self.store_fed_groups.get(store, "Unknown")
            print(f"{i:<4}{store:<10}{cnt:<14,}{fg:<22}", flush=True)

        # ===== TOP BY DURATION =====
        print("\n" + "-" * 80, flush=True)
        print("TOP 10 STORES BY MAX DISCONNECTION TIME", flush=True)
        print("-" * 80, flush=True)

        def fmt(s):
            if s < 60:
                return f"{s:.0f}s"
            if s < 3600:
                return f"{s/60:.1f}m"
            return f"{s/3600:.1f}h"

        store_stats = []
        for store in filtered:
            if store in self.store_durations:
                stats = self.store_durations[store].get_stats()
                if stats and stats["count"] > 0:
                    store_stats.append((store, stats))

        top_by_max = sorted(store_stats, key=lambda x: x[1]["max"], reverse=True)[:10]

        print(
            f"\n{'Store':<10}{'Max':<10}{'Avg':<10}{'Median':<10}{'Count':<8}{'Fed Group':<18}",
            flush=True,
        )
        print("-" * 66, flush=True)

        for store, stats in top_by_max:
            fg = self.store_fed_groups.get(store, "Unknown")[:18]
            print(
                f"{store:<10}{fmt(stats['max']):<10}{fmt(stats['mean']):<10}{fmt(stats['median_estimate']):<10}{stats['count']:<8}{fg:<18}",
                flush=True,
            )

        # ===== FEDERATION GROUPS =====
        print("\n" + "-" * 80, flush=True)
        print("BY FEDERATION GROUP", flush=True)
        print("-" * 80, flush=True)

        fg_stats = defaultdict(lambda: {"stores": set(), "dc": 0})
        for store, cnt in filtered.items():
            fg = self.store_fed_groups.get(store, "Unknown")
            fg_stats[fg]["stores"].add(store)
            fg_stats[fg]["dc"] += cnt

        print(
            f"\n{'Federation Group':<22}{'Stores':<8}{'Disconnects':<15}{'Avg/Store':<10}",
            flush=True,
        )
        print("-" * 55, flush=True)

        for fg, st in sorted(fg_stats.items(), key=lambda x: x[1]["dc"], reverse=True):
            avg = st["dc"] / len(st["stores"]) if st["stores"] else 0
            print(f"{fg:<22}{len(st['stores']):<8}{st['dc']:<15,}{avg:<10,.0f}", flush=True)

        # ===== TIMELINE / OUTAGES =====
        print("\n" + "-" * 80, flush=True)
        print("POTENTIAL OUTAGE PERIODS (High Activity)", flush=True)
        print("-" * 80, flush=True)

        timeline_list = [(h, d["disconnects"], len(d["stores"])) for h, d in self.timeline.items()]
        if timeline_list:
            avg_dc = sum(t[1] for t in timeline_list) / len(timeline_list)

            # Find high activity periods
            high_activity = [
                (h, dc, sc) for h, dc, sc in timeline_list if dc > avg_dc * 2 or dc > 100
            ]
            high_activity.sort(key=lambda x: x[1], reverse=True)

            print(f"\nAverage disconnects/hour: {avg_dc:.1f}", flush=True)
            print("\nTop 15 hours by disconnect count:", flush=True)
            print(f"{'Hour':<22}{'Disconnects':<14}{'Stores':<10}", flush=True)
            print("-" * 46, flush=True)

            for h, dc, sc in high_activity[:15]:
                print(f"{h.strftime('%Y-%m-%d %H:00'):<22}{dc:<14,}{sc:<10}", flush=True)

        # ===== ERRORS =====
        print("\n" + "-" * 80, flush=True)
        print("ERROR ANALYSIS", flush=True)
        print("-" * 80, flush=True)

        print("\nBy type:", flush=True)
        for k, v in sorted(self.error_counts.items(), key=lambda x: x[1], reverse=True):
            if not k.startswith("cat:"):
                print(f"  {k.capitalize()}: {v:,}", flush=True)

        print("\nBy category:", flush=True)
        for k, v in sorted(self.error_counts.items(), key=lambda x: x[1], reverse=True):
            if k.startswith("cat:"):
                print(f"  {k[4:].replace('_', ' ').title()}: {v:,}", flush=True)

        # ===== VISUALS =====
        self.print_visuals(top20, fg_stats, timeline_list, store_stats)

    def print_visuals(self, top_stores, fg_stats, timeline, store_stats):
        print("\n" + "=" * 80, flush=True)
        print("VISUAL CHARTS", flush=True)
        print("=" * 80, flush=True)

        # Top stores bar chart
        print("\n--- TOP 15 STORES BY DISCONNECTS ---\n", flush=True)
        if top_stores:
            max_v = top_stores[0][1]
            for store, cnt in top_stores[:15]:
                fg = self.store_fed_groups.get(store, "?")[:10]
                bar = "█" * int(40 * cnt / max_v)
                print(f"Store {store} ({fg:>10}): {bar} {cnt:,}", flush=True)

        # Timeline
        print("\n--- DAILY DISCONNECT TREND ---\n", flush=True)
        if timeline:
            daily = defaultdict(int)
            for h, dc, _ in timeline:
                daily[h.date()] += dc

            if daily:
                max_d = max(daily.values())
                print(f"Scale: █ = ~{max_d//40 + 1:,} disconnects\n", flush=True)

                for dt in sorted(daily.keys()):
                    cnt = daily[dt]
                    bar_len = int(40 * cnt / max_d) if max_d > 0 else 0
                    print(f"{dt} |{'█' * bar_len:<40}| {cnt:>7,}", flush=True)

        # Federation groups
        print("\n--- DISCONNECTS BY FEDERATION GROUP ---\n", flush=True)
        if fg_stats:
            max_fg = max(s["dc"] for s in fg_stats.values())
            for fg, st in sorted(fg_stats.items(), key=lambda x: x[1]["dc"], reverse=True):
                bar_len = int(35 * st["dc"] / max_fg) if max_fg > 0 else 0
                print(
                    f"{fg:>20}: {'█' * bar_len} {st['dc']:,} ({len(st['stores'])} stores)",
                    flush=True,
                )

        # Duration distribution
        print("\n--- MEDIAN DISCONNECTION TIME DISTRIBUTION ---\n", flush=True)
        if store_stats:
            buckets = {"<1min": 0, "1-5min": 0, "5-15min": 0, "15-60min": 0, "1-4hr": 0, ">4hr": 0}
            for _store, stats in store_stats:
                med = stats["median_estimate"]
                if med < 60:
                    buckets["<1min"] += 1
                elif med < 300:
                    buckets["1-5min"] += 1
                elif med < 900:
                    buckets["5-15min"] += 1
                elif med < 3600:
                    buckets["15-60min"] += 1
                elif med < 14400:
                    buckets["1-4hr"] += 1
                else:
                    buckets[">4hr"] += 1

            max_b = max(buckets.values()) if buckets.values() else 1
            for bkt, cnt in buckets.items():
                bar_len = int(35 * cnt / max_b) if max_b > 0 else 0
                print(f"{bkt:>10}: {'█' * bar_len} {cnt} stores", flush=True)

        print("\n" + "=" * 80, flush=True)
        print("END OF REPORT", flush=True)
        print("=" * 80, flush=True)


class MultiServerAnalyzer:
    """Manages multiple StreamAnalyzers, one per server."""

    def __init__(self):
        self.server_analyzers: dict[str, StreamAnalyzer] = {}
        self.server_pattern = re.compile(r"(MS\d+)")

    def detect_servers(self, path: str) -> dict[str, list[str]]:
        """
        Detect server subdirectories in a path.
        Returns dict of server_id -> list of log directories.
        """
        servers = {}
        path = os.path.expanduser(path)

        if not os.path.exists(path):
            return servers

        # Check if path itself is a server directory
        match = self.server_pattern.search(os.path.basename(path))
        if match:
            server_id = match.group(1)
            servers[server_id] = [path]
            return servers

        # Check for server subdirectories
        for item in os.listdir(path):
            full_path = os.path.join(path, item)
            if os.path.isdir(full_path):
                match = self.server_pattern.search(item)
                if match:
                    server_id = match.group(1)
                    servers[server_id] = [full_path]
                else:
                    # Check if it contains logs (treat as single server "Unknown")
                    try:
                        has_logs = any(f.endswith(".log") for f in os.listdir(full_path))
                        if has_logs:
                            if "Unknown" not in servers:
                                servers["Unknown"] = []
                            servers["Unknown"].append(full_path)
                    except (PermissionError, OSError):
                        pass

        # If no server dirs found, treat the whole path as one server
        if not servers:
            try:
                has_logs = any(f.endswith(".log") for f in os.listdir(path))
                has_zips = any(f.endswith(".zip") for f in os.listdir(path))
                if has_logs or has_zips:
                    servers["Unknown"] = [path]
            except (PermissionError, OSError):
                pass

        return servers

    def analyze(self, paths: list[str]):
        """Analyze all paths, separating by server."""
        # Detect servers across all paths
        all_servers: dict[str, list[str]] = {}

        for path in paths:
            servers = self.detect_servers(path)
            for server_id, dirs in servers.items():
                if server_id not in all_servers:
                    all_servers[server_id] = []
                all_servers[server_id].extend(dirs)

        if not all_servers:
            print("No log files found!", flush=True)
            return

        print(f"Detected {len(all_servers)} server(s): {', '.join(sorted(all_servers.keys()))}")
        print()

        # Create and run analyzer for each server
        for server_id in sorted(all_servers.keys()):
            dirs = all_servers[server_id]
            print(f"\n{'='*80}", flush=True)
            print(f"SERVER: {server_id}", flush=True)
            print(f"{'='*80}", flush=True)

            analyzer = StreamAnalyzer(server_id)
            analyzer.scan_all(dirs)
            self.server_analyzers[server_id] = analyzer

    def generate_reports(self):
        """Generate reports for all servers."""
        for server_id in sorted(self.server_analyzers.keys()):
            analyzer = self.server_analyzers[server_id]
            print(f"\n\n{'#'*80}", flush=True)
            print(f"# REPORT FOR SERVER: {server_id}", flush=True)
            print(f"{'#'*80}", flush=True)
            analyzer.generate_report()

        # Print combined summary if multiple servers
        if len(self.server_analyzers) > 1:
            self.print_combined_summary()

    def print_combined_summary(self):
        """Print a summary across all servers."""
        print(f"\n\n{'='*80}", flush=True)
        print("COMBINED MULTI-SERVER SUMMARY", flush=True)
        print(f"{'='*80}", flush=True)

        print(
            f"\n{'Server':<15}{'Files':<12}{'Lines':<18}{'Stores':<10}{'Disconnects':<15}",
            flush=True,
        )
        print("-" * 70, flush=True)

        total_files = 0
        total_lines = 0
        total_stores = 0
        total_dc = 0

        for server_id in sorted(self.server_analyzers.keys()):
            a = self.server_analyzers[server_id]
            dc = sum(a.store_disconnect_count.values())
            stores = len(a.store_disconnect_count)

            print(
                f"{server_id:<15}{a.files_processed:<12,}{a.lines_processed:<18,}{stores:<10}{dc:<15,}",
                flush=True,
            )

            total_files += a.files_processed
            total_lines += a.lines_processed
            total_stores += stores
            total_dc += dc

        print("-" * 70, flush=True)
        print(
            f"{'TOTAL':<15}{total_files:<12,}{total_lines:<18,}{total_stores:<10}{total_dc:<15,}",
            flush=True,
        )

        # Federation group comparison across servers
        print(f"\n{'='*80}", flush=True)
        print("FEDERATION GROUPS BY SERVER", flush=True)
        print(f"{'='*80}", flush=True)

        # Collect all fed groups
        all_fed_groups = set()
        for a in self.server_analyzers.values():
            all_fed_groups.update(a.store_fed_groups.values())

        if all_fed_groups:
            # Header
            servers = sorted(self.server_analyzers.keys())
            header = f"{'Fed Group':<22}" + "".join(f"{s:<15}" for s in servers)
            print(f"\n{header}", flush=True)
            print("-" * (22 + 15 * len(servers)), flush=True)

            for fg in sorted(all_fed_groups):
                row = f"{fg:<22}"
                for server_id in servers:
                    a = self.server_analyzers[server_id]
                    # Count stores in this fed group
                    count = sum(1 for s, f in a.store_fed_groups.items() if f == fg)
                    dc = sum(
                        a.store_disconnect_count[s]
                        for s, f in a.store_fed_groups.items()
                        if f == fg
                    )
                    row += f"{count}s/{dc:,}dc".ljust(15)
                print(row, flush=True)


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
    print("Security Center Federation Log Analyzer v3", flush=True)
    print("Memory-efficient streaming analysis with MULTIPROCESSING", flush=True)
    print("Now with SERVER-AWARE analysis", flush=True)
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
            print("Usage: python analyze_federation_logs_v3.py <path1> [path2] ...")
            print("\nNo federation log files found in ~/Downloads.")
            print("Please specify directories or ZIP files containing logs.")
            sys.exit(1)
        print(f"Auto-discovered {len(log_dirs)} path(s):")
        for p in log_dirs[:5]:
            print(f"  - {p}")
        if len(log_dirs) > 5:
            print(f"  ... and {len(log_dirs) - 5} more")
        print()

    multi_analyzer = MultiServerAnalyzer()
    multi_analyzer.analyze(log_dirs)
    multi_analyzer.generate_reports()


if __name__ == "__main__":
    main()
