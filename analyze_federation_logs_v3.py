#!/usr/bin/env python3
"""
Security Center Federation Log Analyzer v3 - Memory efficient version
Uses incremental statistics computation for massive datasets.
"""

import os
import re
import sys
import zipfile
import tempfile
from datetime import datetime
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Configuration
LOG_DIRS = [
    "/Users/gancho/Library/CloudStorage/OneDrive-GenetecInc/Documents/Starbucks/Federation reconnects investigations/MS58138Baseline 1/Logs",
    "/Users/gancho/Library/CloudStorage/OneDrive-GenetecInc/Documents/Starbucks/Federation reconnects investigations/MS58138FedLogs/logs1"
]

# Compiled patterns
STORE_PATTERN = re.compile(r'Store[\s_](\d{4,5})(?:\s*\([^)]*\))?')
TIMESTAMP_PATTERN = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})')
FED_GROUP_PATTERN = re.compile(r'(SBUXSCRoleGroup\d+)')

DISCONNECT_INDICATORS = ['logged off', 'Initial sync context is null', 'disconnect', 'offline', 'connection failed', 'connection attempt failed']
RECONNECT_INDICATORS = ['logon', 'sync complete', 'connected successfully', 'Scheduling reconnection']

ERROR_PATTERN = re.compile(r'\((Error|Warning|Fatal)\)', re.IGNORECASE)
EXCEPTION_PATTERN = re.compile(r'Exception', re.IGNORECASE)


class OnlineStats:
    """Welford's online algorithm for mean, variance, min, max.
    Uses __slots__ for memory efficiency when creating many instances."""
    __slots__ = ('n', 'mean', 'M2', 'min_val', 'max_val', 'values_for_median', 'sample_rate')

    def __init__(self):
        self.n = 0
        self.mean = 0.0
        self.M2 = 0.0
        self.min_val = float('inf')
        self.max_val = float('-inf')
        self.values_for_median = []  # Reservoir sampling for median
        self.sample_rate = 100  # Keep every 100th value for median estimation

    def update(self, x):
        """Update statistics with new value using Welford's algorithm."""
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        delta2 = x - self.mean
        self.M2 += delta * delta2

        # Branchless min/max update
        if x < self.min_val:
            self.min_val = x
        if x > self.max_val:
            self.max_val = x

        # Sample for median using modulo (every Nth value)
        if self.n % self.sample_rate == 0:
            self.values_for_median.append(x)

    def get_stats(self):
        """Return computed statistics dictionary."""
        if self.n < 1:
            return None
        variance = self.M2 / self.n if self.n > 1 else 0.0
        # Fast median estimation from sample
        if self.values_for_median:
            sorted_vals = sorted(self.values_for_median)
            median = sorted_vals[len(sorted_vals) // 2]
        else:
            median = self.mean
        return {
            'count': self.n,
            'mean': self.mean,
            'std': variance ** 0.5,
            'min': self.min_val,
            'max': self.max_val,
            'median_estimate': median
        }


class StreamAnalyzer:
    def __init__(self):
        self.seen_hashes = set()

        # Per-store aggregated stats (not storing all events)
        self.store_disconnect_count = defaultdict(int)
        self.store_fed_groups = {}
        self.store_durations = defaultdict(OnlineStats)  # Online stats per store
        self.store_last_disconnect = {}  # Track last disconnect time per store

        # Timeline (hourly)
        self.timeline = defaultdict(lambda: {'disconnects': 0, 'reconnects': 0, 'stores': set()})

        # Error tracking
        self.error_counts = defaultdict(int)
        self.error_samples = []  # Keep a sample of errors (max 100)

        # Overall stats
        self.overall_durations = OnlineStats()

        self.files_processed = 0
        self.lines_processed = 0
        self.min_ts = None
        self.max_ts = None

        # Thread safety
        self._lock = threading.Lock()

    def hash_line(self, line):
        return hash(line.strip())

    def parse_timestamp_fast(self, line):
        if len(line) < 20 or line[4] != '-':
            return None
        try:
            return datetime.strptime(line[:19], '%Y-%m-%dT%H:%M:%S')
        except:
            return None

    def process_line(self, line, current_fed_group):
        """Process a single line with thread-safe updates."""
        line = line.strip()
        if not line or line.startswith('*'):
            match = FED_GROUP_PATTERN.search(line)
            if match:
                return match.group(1)
            return current_fed_group

        # Thread-safe deduplication
        line_hash = self.hash_line(line)
        with self._lock:
            if line_hash in self.seen_hashes:
                return current_fed_group
            self.seen_hashes.add(line_hash)
            self.lines_processed += 1

        timestamp = self.parse_timestamp_fast(line)
        if not timestamp:
            return current_fed_group

        store_match = STORE_PATTERN.search(line)
        if not store_match:
            return current_fed_group

        store_id = store_match.group(1).zfill(5)
        line_lower = line.lower()

        # Fed group extraction
        fed_match = FED_GROUP_PATTERN.search(line)

        # Fast string-based disconnect/reconnect detection
        has_null_sync = 'initial sync context is null' in line_lower
        is_disconnect = (has_null_sync or
                        'logged off' in line_lower or
                        'disconnect' in line_lower or
                        'offline' in line_lower or
                        'connection failed' in line_lower or
                        'connection attempt failed' in line_lower)

        is_reconnect = (not has_null_sync and
                       ('logon' in line_lower or
                        'sync complete' in line_lower or
                        'connected successfully' in line_lower or
                        'scheduling reconnection' in line_lower))

        # Determine error type
        error_type = None
        error_category = None
        if '(Warning)' in line:
            error_type = 'warning'
        elif '(Fatal)' in line:
            error_type = 'fatal'
        elif '(Error)' in line:
            error_type = 'error'
        if 'Exception' in line:
            error_type = 'exception'

        # Error categorization
        if error_type:
            if 'timeout' in line_lower:
                error_category = 'cat:timeout'
            elif 'connection attempt failed' in line_lower:
                error_category = 'cat:conn_failed'
            elif 'socket' in line_lower:
                error_category = 'cat:socket'
            elif 'tls' in line_lower or 'ssl' in line_lower:
                error_category = 'cat:tls_ssl'

        hour_key = timestamp.replace(minute=0, second=0, microsecond=0)

        # Thread-safe updates to all shared state
        with self._lock:
            # Time range tracking
            if self.min_ts is None or timestamp < self.min_ts:
                self.min_ts = timestamp
            if self.max_ts is None or timestamp > self.max_ts:
                self.max_ts = timestamp

            # Fed group mapping
            if fed_match:
                current_fed_group = fed_match.group(1)
                self.store_fed_groups[store_id] = current_fed_group
            elif current_fed_group and store_id not in self.store_fed_groups:
                self.store_fed_groups[store_id] = current_fed_group

            if is_disconnect:
                self.store_disconnect_count[store_id] += 1
                self.store_last_disconnect[store_id] = timestamp
                self.timeline[hour_key]['disconnects'] += 1
                self.timeline[hour_key]['stores'].add(store_id)

            if is_reconnect and not is_disconnect:
                self.timeline[hour_key]['reconnects'] += 1
                # Calculate duration if we have a prior disconnect
                if store_id in self.store_last_disconnect:
                    last_dc = self.store_last_disconnect[store_id]
                    duration = (timestamp - last_dc).total_seconds()
                    if 0 < duration < 86400 * 7:
                        self.store_durations[store_id].update(duration)
                        self.overall_durations.update(duration)
                    del self.store_last_disconnect[store_id]

            # Error tracking
            if error_type:
                self.error_counts[error_type] += 1
                if error_category:
                    self.error_counts[error_category] += 1
                if len(self.error_samples) < 100:
                    self.error_samples.append({'ts': timestamp, 'store': store_id, 'line': line[:200]})

        return current_fed_group

    def process_file(self, filepath):
        """Process a single log file (thread-safe)."""
        current_fed_group = None
        try:
            with open(filepath, 'r', encoding='utf-8-sig', errors='replace') as f:
                for line in f:
                    current_fed_group = self.process_line(line, current_fed_group)
            with self._lock:
                self.files_processed += 1
        except Exception as e:
            print(f"  Error: {os.path.basename(filepath)}: {e}", file=sys.stderr)

    def process_zip(self, zip_path, temp_dir):
        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                for name in zf.namelist():
                    if name.endswith('.log'):
                        extracted = os.path.join(temp_dir, os.path.basename(name))
                        with zf.open(name) as src, open(extracted, 'wb') as dst:
                            dst.write(src.read())
                        self.process_file(extracted)
                        os.remove(extracted)
            self.files_processed += 1
        except Exception as e:
            print(f"  Error zip: {os.path.basename(zip_path)}: {e}", file=sys.stderr)

    def scan_all(self, max_workers=4):
        """Scan all log directories with parallel processing."""
        print("=" * 80, flush=True)
        print("SCANNING LOG DIRECTORIES (Parallel)", flush=True)
        print("=" * 80, flush=True)

        with tempfile.TemporaryDirectory() as temp_dir:
            for log_dir in LOG_DIRS:
                if not os.path.exists(log_dir):
                    print(f"Warning: {log_dir} not found", flush=True)
                    continue

                print(f"\nScanning: {os.path.basename(log_dir)}", flush=True)
                files = sorted(os.listdir(log_dir))
                log_files = [os.path.join(log_dir, f) for f in files if f.endswith('.log')]
                zip_files = [os.path.join(log_dir, f) for f in files if f.endswith('.zip')]

                print(f"  {len(log_files)} .log, {len(zip_files)} .zip files", flush=True)

                # Process log files in parallel
                processed = 0
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = {executor.submit(self.process_file, fp): fp for fp in log_files}
                    for future in as_completed(futures):
                        processed += 1
                        if processed % 500 == 0:
                            print(f"    {processed}/{len(log_files)} logs...", flush=True)
                print(f"    Done: {len(log_files)} logs", flush=True)

                # Process zip files sequentially (temp file handling)
                for i, filepath in enumerate(zip_files):
                    self.process_zip(filepath, temp_dir)
                    if (i + 1) % 20 == 0:
                        print(f"    {i+1}/{len(zip_files)} zips...", flush=True)
                print(f"    Done: {len(zip_files)} zips", flush=True)

        print(f"\nFiles: {self.files_processed}, Unique lines: {self.lines_processed:,}", flush=True)
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
        total_errors = sum(v for k, v in self.error_counts.items() if not k.startswith('cat:'))

        print(f"Stores analyzed: {len(filtered)}", flush=True)
        print(f"Total disconnect events: {total_dc:,}", flush=True)
        print(f"Total errors/warnings: {total_errors:,}", flush=True)
        if self.min_ts and self.max_ts:
            print(f"Time range: {self.min_ts.strftime('%Y-%m-%d %H:%M')} to {self.max_ts.strftime('%Y-%m-%d %H:%M')}", flush=True)

        overall = self.overall_durations.get_stats()
        if overall:
            def fmt(s):
                if s < 60: return f"{s:.0f}s"
                if s < 3600: return f"{s/60:.1f}m"
                return f"{s/3600:.1f}h"

            print(f"\nDISCONNECTION DURATION (overall):", flush=True)
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
            fg = self.store_fed_groups.get(store, 'Unknown')
            print(f"{i:<4}{store:<10}{cnt:<14,}{fg:<22}", flush=True)

        # ===== TOP BY DURATION =====
        print("\n" + "-" * 80, flush=True)
        print("TOP 10 STORES BY MAX DISCONNECTION TIME", flush=True)
        print("-" * 80, flush=True)

        def fmt(s):
            if s < 60: return f"{s:.0f}s"
            if s < 3600: return f"{s/60:.1f}m"
            return f"{s/3600:.1f}h"

        store_stats = []
        for store in filtered:
            if store in self.store_durations:
                stats = self.store_durations[store].get_stats()
                if stats and stats['count'] > 0:
                    store_stats.append((store, stats))

        top_by_max = sorted(store_stats, key=lambda x: x[1]['max'], reverse=True)[:10]

        print(f"\n{'Store':<10}{'Max':<10}{'Avg':<10}{'Median':<10}{'Count':<8}{'Fed Group':<18}", flush=True)
        print("-" * 66, flush=True)

        for store, stats in top_by_max:
            fg = self.store_fed_groups.get(store, 'Unknown')[:18]
            print(f"{store:<10}{fmt(stats['max']):<10}{fmt(stats['mean']):<10}{fmt(stats['median_estimate']):<10}{stats['count']:<8}{fg:<18}", flush=True)

        # ===== FEDERATION GROUPS =====
        print("\n" + "-" * 80, flush=True)
        print("BY FEDERATION GROUP", flush=True)
        print("-" * 80, flush=True)

        fg_stats = defaultdict(lambda: {'stores': set(), 'dc': 0})
        for store, cnt in filtered.items():
            fg = self.store_fed_groups.get(store, 'Unknown')
            fg_stats[fg]['stores'].add(store)
            fg_stats[fg]['dc'] += cnt

        print(f"\n{'Federation Group':<22}{'Stores':<8}{'Disconnects':<15}{'Avg/Store':<10}", flush=True)
        print("-" * 55, flush=True)

        for fg, st in sorted(fg_stats.items(), key=lambda x: x[1]['dc'], reverse=True):
            avg = st['dc'] / len(st['stores']) if st['stores'] else 0
            print(f"{fg:<22}{len(st['stores']):<8}{st['dc']:<15,}{avg:<10,.0f}", flush=True)

        # ===== TIMELINE / OUTAGES =====
        print("\n" + "-" * 80, flush=True)
        print("POTENTIAL OUTAGE PERIODS (High Activity)", flush=True)
        print("-" * 80, flush=True)

        timeline_list = [(h, d['disconnects'], len(d['stores'])) for h, d in self.timeline.items()]
        if timeline_list:
            avg_dc = sum(t[1] for t in timeline_list) / len(timeline_list)

            # Find high activity periods
            high_activity = [(h, dc, sc) for h, dc, sc in timeline_list if dc > avg_dc * 2 or dc > 100]
            high_activity.sort(key=lambda x: x[1], reverse=True)

            print(f"\nAverage disconnects/hour: {avg_dc:.1f}", flush=True)
            print(f"\nTop 15 hours by disconnect count:", flush=True)
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
            if not k.startswith('cat:'):
                print(f"  {k.capitalize()}: {v:,}", flush=True)

        print("\nBy category:", flush=True)
        for k, v in sorted(self.error_counts.items(), key=lambda x: x[1], reverse=True):
            if k.startswith('cat:'):
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
                fg = self.store_fed_groups.get(store, '?')[:10]
                bar = '█' * int(40 * cnt / max_v)
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
            max_fg = max(s['dc'] for s in fg_stats.values())
            for fg, st in sorted(fg_stats.items(), key=lambda x: x[1]['dc'], reverse=True):
                bar_len = int(35 * st['dc'] / max_fg) if max_fg > 0 else 0
                print(f"{fg:>20}: {'█' * bar_len} {st['dc']:,} ({len(st['stores'])} stores)", flush=True)

        # Duration distribution
        print("\n--- MEDIAN DISCONNECTION TIME DISTRIBUTION ---\n", flush=True)
        if store_stats:
            buckets = {'<1min': 0, '1-5min': 0, '5-15min': 0, '15-60min': 0, '1-4hr': 0, '>4hr': 0}
            for store, stats in store_stats:
                med = stats['median_estimate']
                if med < 60: buckets['<1min'] += 1
                elif med < 300: buckets['1-5min'] += 1
                elif med < 900: buckets['5-15min'] += 1
                elif med < 3600: buckets['15-60min'] += 1
                elif med < 14400: buckets['1-4hr'] += 1
                else: buckets['>4hr'] += 1

            max_b = max(buckets.values()) if buckets.values() else 1
            for bkt, cnt in buckets.items():
                bar_len = int(35 * cnt / max_b) if max_b > 0 else 0
                print(f"{bkt:>10}: {'█' * bar_len} {cnt} stores", flush=True)

        print("\n" + "=" * 80, flush=True)
        print("END OF REPORT", flush=True)
        print("=" * 80, flush=True)


def main():
    print("Security Center Federation Log Analyzer v3", flush=True)
    print("Memory-efficient streaming analysis\n", flush=True)

    analyzer = StreamAnalyzer()
    analyzer.scan_all()
    analyzer.generate_report()


if __name__ == "__main__":
    main()
