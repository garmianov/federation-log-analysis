#!/usr/bin/env python3
"""
Security Center Federation Log Analyzer v2 - Optimized for large log sets
Analyzes federation reconnection patterns and outages from Genetec Security Center logs.
"""

import os
import re
import sys
import zipfile
import tempfile
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path
import statistics

# Configuration
LOG_DIRS = [
    "/Users/gancho/Library/CloudStorage/OneDrive-GenetecInc/Documents/Starbucks/Federation reconnects investigations/MS58138Baseline 1/Logs",
    "/Users/gancho/Library/CloudStorage/OneDrive-GenetecInc/Documents/Starbucks/Federation reconnects investigations/MS58138FedLogs/logs1"
]

# Compiled patterns for efficiency
STORE_PATTERN = re.compile(r'Store[\s_](\d{4,5})(?:\s*\([^)]*\))?')
TIMESTAMP_PATTERN = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})')
FED_GROUP_PATTERN = re.compile(r'(SBUXSCRoleGroup\d+)')

# Connection event patterns
DISCONNECT_INDICATORS = ['logged off', 'Initial sync context is null', 'disconnect', 'offline', 'connection failed', 'connection attempt failed']
RECONNECT_INDICATORS = ['logon', 'sync complete', 'connected successfully', 'Scheduling reconnection']

# Error/warning patterns
ERROR_PATTERN = re.compile(r'\((Error|Warning|Fatal)\)', re.IGNORECASE)
EXCEPTION_PATTERN = re.compile(r'Exception', re.IGNORECASE)

class FastLogAnalyzer:
    def __init__(self):
        self.seen_hashes = set()
        self.store_disconnects = defaultdict(list)  # store_id -> [(timestamp, event_type)]
        self.store_fed_groups = {}
        self.timeline = defaultdict(lambda: {'disconnects': 0, 'reconnects': 0, 'stores': set()})
        self.errors_by_type = defaultdict(list)
        self.files_processed = 0
        self.lines_processed = 0

    def hash_line(self, line):
        """Fast hash for deduplication."""
        return hash(line.strip())

    def parse_timestamp_fast(self, line):
        """Fast timestamp extraction."""
        if len(line) < 20 or line[4] != '-':
            return None
        try:
            return datetime.strptime(line[:19], '%Y-%m-%dT%H:%M:%S')
        except:
            return None

    def process_line(self, line, current_fed_group):
        """Process a single log line efficiently."""
        line = line.strip()
        if not line or line.startswith('*'):
            # Check for fed group in header
            match = FED_GROUP_PATTERN.search(line)
            if match:
                return match.group(1)
            return current_fed_group

        # Skip duplicates
        line_hash = self.hash_line(line)
        if line_hash in self.seen_hashes:
            return current_fed_group
        self.seen_hashes.add(line_hash)
        self.lines_processed += 1

        # Parse timestamp
        timestamp = self.parse_timestamp_fast(line)
        if not timestamp:
            return current_fed_group

        # Extract store ID
        store_match = STORE_PATTERN.search(line)
        if not store_match:
            return current_fed_group

        store_id = store_match.group(1).zfill(5)

        # Extract fed group from line if present
        fed_match = FED_GROUP_PATTERN.search(line)
        if fed_match:
            current_fed_group = fed_match.group(1)
            self.store_fed_groups[store_id] = current_fed_group
        elif current_fed_group and store_id not in self.store_fed_groups:
            self.store_fed_groups[store_id] = current_fed_group

        # Check for disconnect/reconnect events
        line_lower = line.lower()

        is_disconnect = any(ind in line_lower for ind in DISCONNECT_INDICATORS)
        is_reconnect = any(ind in line_lower for ind in RECONNECT_INDICATORS) and 'Initial sync context is null' not in line

        if is_disconnect:
            self.store_disconnects[store_id].append((timestamp, 'disconnect', line[:200]))
            hour_key = timestamp.replace(minute=0, second=0, microsecond=0)
            self.timeline[hour_key]['disconnects'] += 1
            self.timeline[hour_key]['stores'].add(store_id)

        if is_reconnect and not is_disconnect:
            self.store_disconnects[store_id].append((timestamp, 'reconnect', line[:200]))
            hour_key = timestamp.replace(minute=0, second=0, microsecond=0)
            self.timeline[hour_key]['reconnects'] += 1

        # Check for errors/warnings
        if ERROR_PATTERN.search(line) or EXCEPTION_PATTERN.search(line):
            error_type = 'error'
            if '(Warning)' in line:
                error_type = 'warning'
            elif '(Fatal)' in line:
                error_type = 'fatal'
            elif 'Exception' in line:
                error_type = 'exception'
            self.errors_by_type[error_type].append({
                'timestamp': timestamp,
                'store': store_id,
                'line': line[:300]
            })

        return current_fed_group

    def process_file(self, filepath):
        """Process a single log file."""
        current_fed_group = None
        try:
            with open(filepath, 'r', encoding='utf-8-sig', errors='replace') as f:
                for line in f:
                    current_fed_group = self.process_line(line, current_fed_group)
            self.files_processed += 1
        except Exception as e:
            print(f"  Error reading {os.path.basename(filepath)}: {e}", file=sys.stderr)

    def process_zip(self, zip_path, temp_dir):
        """Process logs from a zip file."""
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
            print(f"  Error processing zip {os.path.basename(zip_path)}: {e}", file=sys.stderr)

    def scan_all(self):
        """Scan all log directories."""
        print("=" * 80, flush=True)
        print("SCANNING LOG DIRECTORIES", flush=True)
        print("=" * 80, flush=True)

        with tempfile.TemporaryDirectory() as temp_dir:
            for log_dir in LOG_DIRS:
                if not os.path.exists(log_dir):
                    print(f"Warning: {log_dir} not found", flush=True)
                    continue

                print(f"\nScanning: {os.path.basename(log_dir)}", flush=True)

                files = sorted(os.listdir(log_dir))
                log_files = [f for f in files if f.endswith('.log')]
                zip_files = [f for f in files if f.endswith('.zip')]

                print(f"  {len(log_files)} .log files, {len(zip_files)} .zip files", flush=True)

                # Process .log files
                for i, fname in enumerate(log_files):
                    self.process_file(os.path.join(log_dir, fname))
                    if (i + 1) % 500 == 0:
                        print(f"    Processed {i+1}/{len(log_files)} log files...", flush=True)

                print(f"    Completed {len(log_files)} log files", flush=True)

                # Process .zip files
                for i, fname in enumerate(zip_files):
                    self.process_zip(os.path.join(log_dir, fname), temp_dir)
                    if (i + 1) % 20 == 0:
                        print(f"    Processed {i+1}/{len(zip_files)} zip files...", flush=True)

                print(f"    Completed {len(zip_files)} zip files", flush=True)

        print(f"\nTotal files processed: {self.files_processed}", flush=True)
        print(f"Total unique lines: {self.lines_processed}", flush=True)
        print(f"Unique stores found: {len(self.store_disconnects)}", flush=True)

    def calculate_stats(self):
        """Calculate disconnection statistics for each store."""
        store_stats = {}

        for store_id, events in self.store_disconnects.items():
            sorted_events = sorted(events, key=lambda x: x[0])

            disconnect_count = sum(1 for e in sorted_events if e[1] == 'disconnect')
            durations = []
            last_disconnect = None

            for ts, event_type, _ in sorted_events:
                if event_type == 'disconnect':
                    last_disconnect = ts
                elif event_type == 'reconnect' and last_disconnect:
                    duration = (ts - last_disconnect).total_seconds()
                    if 0 < duration < 86400 * 7:  # Valid duration < 7 days
                        durations.append(duration)
                    last_disconnect = None

            store_stats[store_id] = {
                'disconnect_count': disconnect_count,
                'durations': durations,
                'fed_group': self.store_fed_groups.get(store_id, 'Unknown')
            }

        return store_stats

    def generate_report(self):
        """Generate the final report."""
        print("\n" + "=" * 80, flush=True)
        print("FEDERATION LOG ANALYSIS REPORT", flush=True)
        print("=" * 80, flush=True)

        store_stats = self.calculate_stats()

        if not store_stats:
            print("\nNo store events found!", flush=True)
            return

        # Find and exclude store with highest reconnects
        disconnect_counts = {s: stats['disconnect_count'] for s, stats in store_stats.items()}
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
        print(f"Total disconnect events: {total_disconnects}", flush=True)
        print(f"Total errors/warnings: {total_errors}", flush=True)

        # Time range
        all_times = []
        for s, stats in store_stats.items():
            for ts, _, _ in self.store_disconnects.get(s, []):
                all_times.append(ts)
        if all_times:
            print(f"Time range: {min(all_times).strftime('%Y-%m-%d %H:%M')} to {max(all_times).strftime('%Y-%m-%d %H:%M')}", flush=True)

        # ========== TOP STORES ==========
        print("\n" + "-" * 80, flush=True)
        print("TOP 20 STORES BY DISCONNECT COUNT", flush=True)
        print("-" * 80, flush=True)

        sorted_stores = sorted(disconnect_counts.items(), key=lambda x: x[1], reverse=True)[:20]

        print(f"\n{'Rank':<6}{'Store':<12}{'Disconnects':<14}{'Federation Group':<25}", flush=True)
        print("-" * 55, flush=True)

        for rank, (store_id, count) in enumerate(sorted_stores, 1):
            fed_group = store_stats[store_id]['fed_group']
            print(f"{rank:<6}{store_id:<12}{count:<14}{fed_group:<25}", flush=True)

        # ========== DISCONNECTION DURATION STATS ==========
        print("\n" + "-" * 80, flush=True)
        print("DISCONNECTION DURATION STATISTICS", flush=True)
        print("-" * 80, flush=True)

        all_durations = []
        stores_with_durations = {}
        for store_id, stats in store_stats.items():
            if stats['durations']:
                all_durations.extend(stats['durations'])
                stores_with_durations[store_id] = {
                    'max': max(stats['durations']),
                    'avg': statistics.mean(stats['durations']),
                    'median': statistics.median(stats['durations']),
                    'count': len(stats['durations']),
                    'fed_group': stats['fed_group']
                }

        def fmt_dur(sec):
            if sec < 60:
                return f"{sec:.0f}s"
            elif sec < 3600:
                return f"{sec/60:.1f}m"
            else:
                return f"{sec/3600:.1f}h"

        if all_durations:
            print(f"\nOVERALL STATISTICS:", flush=True)
            print(f"  Maximum disconnection: {fmt_dur(max(all_durations))}", flush=True)
            print(f"  Average disconnection: {fmt_dur(statistics.mean(all_durations))}", flush=True)
            print(f"  Median disconnection:  {fmt_dur(statistics.median(all_durations))}", flush=True)
            print(f"  Total measurements:    {len(all_durations)}", flush=True)

            print(f"\nTOP 10 STORES BY MAXIMUM DISCONNECTION TIME:", flush=True)
            print(f"{'Store':<10}{'Max':<12}{'Avg':<12}{'Median':<12}{'Count':<8}{'Fed Group':<20}", flush=True)
            print("-" * 74, flush=True)

            for store_id, stats in sorted(stores_with_durations.items(), key=lambda x: x[1]['max'], reverse=True)[:10]:
                print(f"{store_id:<10}{fmt_dur(stats['max']):<12}{fmt_dur(stats['avg']):<12}{fmt_dur(stats['median']):<12}{stats['count']:<8}{stats['fed_group']:<20}", flush=True)

        # ========== FEDERATION GROUPS ==========
        print("\n" + "-" * 80, flush=True)
        print("RECONNECTS BY FEDERATION GROUP", flush=True)
        print("-" * 80, flush=True)

        fed_stats = defaultdict(lambda: {'stores': set(), 'disconnects': 0})
        for store_id, count in disconnect_counts.items():
            fed_group = store_stats[store_id]['fed_group']
            fed_stats[fed_group]['stores'].add(store_id)
            fed_stats[fed_group]['disconnects'] += count

        print(f"\n{'Federation Group':<25}{'Stores':<10}{'Disconnects':<15}{'Avg/Store':<12}", flush=True)
        print("-" * 62, flush=True)

        for fg, stats in sorted(fed_stats.items(), key=lambda x: x[1]['disconnects'], reverse=True):
            avg = stats['disconnects'] / len(stats['stores']) if stats['stores'] else 0
            print(f"{fg:<25}{len(stats['stores']):<10}{stats['disconnects']:<15}{avg:<12.1f}", flush=True)

        # ========== TIMELINE / OUTAGES ==========
        print("\n" + "-" * 80, flush=True)
        print("HOURLY TIMELINE (HIGH ACTIVITY PERIODS)", flush=True)
        print("-" * 80, flush=True)

        timeline_data = [(k, v['disconnects'], len(v['stores'])) for k, v in self.timeline.items() if k != max_store]

        if timeline_data:
            avg_disc = statistics.mean([t[1] for t in timeline_data])
            std_disc = statistics.stdev([t[1] for t in timeline_data]) if len(timeline_data) > 1 else 0
            threshold = avg_disc + 2 * std_disc

            print(f"\nAverage disconnects/hour: {avg_disc:.1f}", flush=True)
            print(f"High activity threshold:  {threshold:.1f}", flush=True)

            print(f"\nHOURS WITH ELEVATED ACTIVITY (>threshold or >50):", flush=True)
            print(f"{'Hour':<22}{'Disconnects':<14}{'Stores Affected':<18}", flush=True)
            print("-" * 54, flush=True)

            for hour, disc_count, store_count in sorted(timeline_data, key=lambda x: x[1], reverse=True)[:25]:
                if disc_count > threshold or disc_count > 50:
                    print(f"{hour.strftime('%Y-%m-%d %H:00'):<22}{disc_count:<14}{store_count:<18}", flush=True)

        # ========== ERROR ANALYSIS ==========
        print("\n" + "-" * 80, flush=True)
        print("ERROR ANALYSIS", flush=True)
        print("-" * 80, flush=True)

        print(f"\nError counts by type:", flush=True)
        for etype, errors in sorted(self.errors_by_type.items(), key=lambda x: len(x[1]), reverse=True):
            print(f"  {etype.capitalize()}: {len(errors)}", flush=True)

        # Categorize errors
        error_categories = defaultdict(int)
        for etype, errors in self.errors_by_type.items():
            for err in errors:
                line = err['line'].lower()
                if 'timeout' in line or 'timed out' in line:
                    error_categories['Connection Timeout'] += 1
                elif 'connection attempt failed' in line:
                    error_categories['Connection Failed'] += 1
                elif 'socketexception' in line or 'socket' in line:
                    error_categories['Socket Error'] += 1
                elif 'tls' in line or 'ssl' in line:
                    error_categories['TLS/SSL Error'] += 1
                elif 'refused' in line:
                    error_categories['Connection Refused'] += 1

        if error_categories:
            print(f"\nCommon error patterns:", flush=True)
            for cat, count in sorted(error_categories.items(), key=lambda x: x[1], reverse=True):
                print(f"  {cat}: {count}", flush=True)

        # ========== VISUALS ==========
        self.print_visuals(sorted_stores, store_stats, stores_with_durations, fed_stats, timeline_data)

    def print_visuals(self, top_stores, store_stats, duration_stats, fed_stats, timeline_data):
        """Print ASCII visualizations."""
        print("\n" + "=" * 80, flush=True)
        print("VISUAL CHARTS", flush=True)
        print("=" * 80, flush=True)

        # Bar chart: Top stores
        print("\n--- TOP 15 STORES BY DISCONNECTS ---", flush=True)
        if top_stores:
            max_val = top_stores[0][1]
            for store_id, count in top_stores[:15]:
                bar_len = int(45 * count / max_val)
                fed = store_stats[store_id]['fed_group'][:12]
                print(f"Store {store_id} ({fed:>12}): {'█' * bar_len} {count}", flush=True)

        # Timeline heatmap
        print("\n--- DISCONNECT TIMELINE (daily) ---", flush=True)
        if timeline_data:
            daily = defaultdict(int)
            for hour, disc, _ in timeline_data:
                daily[hour.date()] += disc

            max_daily = max(daily.values()) if daily else 1
            print(f"Legend: · <10%, ░ <25%, ▒ <50%, ▓ <75%, █ >=75% of max ({max_daily})", flush=True)

            for date in sorted(daily.keys()):
                count = daily[date]
                pct = count / max_daily
                if pct < 0.1:
                    bar = '·' * 40
                elif pct < 0.25:
                    bar = '░' * int(40 * pct / 0.25)
                elif pct < 0.5:
                    bar = '▒' * int(40 * (pct - 0.25) / 0.25)
                elif pct < 0.75:
                    bar = '▓' * int(40 * (pct - 0.5) / 0.25)
                else:
                    bar = '█' * int(40 * pct)
                print(f"{date} |{bar:<40}| {count:>5}", flush=True)

        # Federation group chart
        print("\n--- DISCONNECTS BY FEDERATION GROUP ---", flush=True)
        if fed_stats:
            max_fed = max(s['disconnects'] for s in fed_stats.values())
            for fg, stats in sorted(fed_stats.items(), key=lambda x: x[1]['disconnects'], reverse=True):
                bar_len = int(35 * stats['disconnects'] / max_fed)
                print(f"{fg:>20}: {'█' * bar_len} {stats['disconnects']} ({len(stats['stores'])} stores)", flush=True)

        # Duration distribution
        print("\n--- MEDIAN DISCONNECTION TIME DISTRIBUTION ---", flush=True)
        if duration_stats:
            buckets = {'<1m': 0, '1-5m': 0, '5-15m': 0, '15-60m': 0, '1-4h': 0, '>4h': 0}
            for store_id, stats in duration_stats.items():
                med = stats['median']
                if med < 60:
                    buckets['<1m'] += 1
                elif med < 300:
                    buckets['1-5m'] += 1
                elif med < 900:
                    buckets['5-15m'] += 1
                elif med < 3600:
                    buckets['15-60m'] += 1
                elif med < 14400:
                    buckets['1-4h'] += 1
                else:
                    buckets['>4h'] += 1

            max_bucket = max(buckets.values()) if buckets.values() else 1
            for bucket, count in buckets.items():
                bar_len = int(35 * count / max_bucket)
                print(f"{bucket:>8}: {'█' * bar_len} {count} stores", flush=True)

        print("\n" + "=" * 80, flush=True)
        print("END OF REPORT", flush=True)
        print("=" * 80, flush=True)


def main():
    print("Security Center Federation Log Analyzer v2", flush=True)
    print("Optimized for large log sets\n", flush=True)

    analyzer = FastLogAnalyzer()
    analyzer.scan_all()
    analyzer.generate_report()


if __name__ == "__main__":
    main()
