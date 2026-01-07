#!/usr/bin/env python3
"""
Security Center Federation Log Analyzer
Analyzes federation reconnection patterns and outages from Genetec Security Center logs.
"""

import os
import re
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

# Search patterns
PATTERNS = {
    'error': re.compile(r'\(Error\)', re.IGNORECASE),
    'warning': re.compile(r'\(Warning\)', re.IGNORECASE),
    'exception': re.compile(r'Exception', re.IGNORECASE),
    'fatal': re.compile(r'\(Fatal\)|fatal', re.IGNORECASE),
    'connection': re.compile(r'connection|disconnect|reconnect|logged off|logon|logoff', re.IGNORECASE),
}

# Store extraction pattern - matches "Store XXXXX" or "Store 0XXXX (vNVR)" etc
STORE_PATTERN = re.compile(r'Store[\s_](\d{4,5})(?:\s*\([^)]*\))?')

# Timestamp pattern for log lines
TIMESTAMP_PATTERN = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[-+]\d{2}:\d{2})')

# Federation group pattern - extract from log header or workflow names
FED_GROUP_PATTERN = re.compile(r'(SBUXSCRoleGroup\d+)')

# Connection status patterns
DISCONNECT_PATTERN = re.compile(r'(logged off|disconnect|offline|connection.*fail|Initial sync context is null)', re.IGNORECASE)
RECONNECT_PATTERN = re.compile(r'(reconnect|logon|online|connected|sync complete|primary sync)', re.IGNORECASE)
SCHEDULING_RECONNECT_PATTERN = re.compile(r'Scheduling reconnection with startDelay\s*=\s*(\d+)', re.IGNORECASE)

class LogAnalyzer:
    def __init__(self):
        self.seen_lines = set()  # For deduplication
        self.events = []  # All parsed events
        self.store_events = defaultdict(list)  # Events by store
        self.store_fed_groups = {}  # Store -> federation group mapping
        self.timeline = defaultdict(list)  # Events by timestamp (hour granularity)
        self.errors_warnings = []  # All errors and warnings

    def get_line_hash(self, line):
        """Generate hash for line deduplication (ignoring whitespace variations)."""
        normalized = ' '.join(line.split())
        return hashlib.md5(normalized.encode()).hexdigest()

    def parse_timestamp(self, line):
        """Extract timestamp from log line."""
        match = TIMESTAMP_PATTERN.match(line)
        if match:
            ts_str = match.group(1)
            # Parse ISO format with timezone
            try:
                # Handle the format: 2025-10-17T23:50:05.946-07:00
                ts_str_normalized = ts_str.replace('-07:00', '-0700').replace('-08:00', '-0800')
                # Try different formats
                for fmt in ['%Y-%m-%dT%H:%M:%S.%f%z', '%Y-%m-%dT%H:%M:%S%z']:
                    try:
                        return datetime.strptime(ts_str_normalized[:26] + ts_str_normalized[-5:], fmt)
                    except:
                        continue
                # Fallback: just parse the datetime part
                return datetime.strptime(ts_str[:19], '%Y-%m-%dT%H:%M:%S')
            except Exception as e:
                pass
        return None

    def extract_store_id(self, line):
        """Extract store ID from log line."""
        match = STORE_PATTERN.search(line)
        if match:
            return match.group(1).zfill(5)  # Normalize to 5 digits
        return None

    def extract_fed_group(self, line):
        """Extract federation group from log line."""
        match = FED_GROUP_PATTERN.search(line)
        if match:
            return match.group(1)
        return None

    def classify_event(self, line):
        """Classify the event type based on patterns."""
        events = []
        for name, pattern in PATTERNS.items():
            if pattern.search(line):
                events.append(name)
        return events

    def is_disconnect_event(self, line):
        """Check if line represents a disconnect event."""
        return bool(DISCONNECT_PATTERN.search(line))

    def is_reconnect_event(self, line):
        """Check if line represents a reconnect event."""
        return bool(RECONNECT_PATTERN.search(line)) and not self.is_disconnect_event(line)

    def process_log_file(self, filepath):
        """Process a single log file."""
        current_fed_group = None

        try:
            with open(filepath, 'r', encoding='utf-8-sig', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    # Skip duplicate lines
                    line_hash = self.get_line_hash(line)
                    if line_hash in self.seen_lines:
                        continue
                    self.seen_lines.add(line_hash)

                    # Extract federation group from header
                    fed_group = self.extract_fed_group(line)
                    if fed_group:
                        current_fed_group = fed_group

                    # Parse timestamp
                    timestamp = self.parse_timestamp(line)
                    if not timestamp:
                        continue

                    # Extract store ID
                    store_id = self.extract_store_id(line)

                    # Classify event
                    event_types = self.classify_event(line)

                    # Determine connection state change
                    is_disconnect = self.is_disconnect_event(line)
                    is_reconnect = self.is_reconnect_event(line)

                    # Build event record
                    if store_id and (is_disconnect or is_reconnect or event_types):
                        event = {
                            'timestamp': timestamp,
                            'store_id': store_id,
                            'fed_group': current_fed_group or fed_group,
                            'event_types': event_types,
                            'is_disconnect': is_disconnect,
                            'is_reconnect': is_reconnect,
                            'line': line[:500],  # Truncate for memory
                            'source': os.path.basename(filepath)
                        }

                        self.events.append(event)
                        self.store_events[store_id].append(event)

                        # Track federation group for store
                        if event['fed_group'] and store_id not in self.store_fed_groups:
                            self.store_fed_groups[store_id] = event['fed_group']

                        # Add to timeline (hour granularity)
                        hour_key = timestamp.replace(minute=0, second=0, microsecond=0)
                        self.timeline[hour_key].append(event)

                    # Collect errors and warnings
                    if 'error' in event_types or 'warning' in event_types or 'exception' in event_types or 'fatal' in event_types:
                        self.errors_warnings.append({
                            'timestamp': timestamp,
                            'store_id': store_id,
                            'types': event_types,
                            'line': line[:500],
                            'source': os.path.basename(filepath)
                        })

        except Exception as e:
            print(f"Error processing {filepath}: {e}")

    def process_zip_file(self, zip_path, temp_dir):
        """Extract and process logs from zip file."""
        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                for name in zf.namelist():
                    if name.endswith('.log'):
                        zf.extract(name, temp_dir)
                        extracted_path = os.path.join(temp_dir, name)
                        self.process_log_file(extracted_path)
                        os.remove(extracted_path)
        except Exception as e:
            print(f"Error processing zip {zip_path}: {e}")

    def scan_directories(self):
        """Scan all configured directories for log files."""
        print("=" * 80)
        print("SCANNING LOG DIRECTORIES")
        print("=" * 80)

        with tempfile.TemporaryDirectory() as temp_dir:
            for log_dir in LOG_DIRS:
                if not os.path.exists(log_dir):
                    print(f"Warning: Directory not found: {log_dir}")
                    continue

                print(f"\nProcessing: {log_dir}")
                files = os.listdir(log_dir)
                log_files = [f for f in files if f.endswith('.log')]
                zip_files = [f for f in files if f.endswith('.zip')]

                print(f"  Found {len(log_files)} .log files, {len(zip_files)} .zip files")

                # Process .log files
                for i, filename in enumerate(log_files):
                    filepath = os.path.join(log_dir, filename)
                    self.process_log_file(filepath)
                    if (i + 1) % 100 == 0:
                        print(f"    Processed {i + 1}/{len(log_files)} log files...")

                # Process .zip files
                for i, filename in enumerate(zip_files):
                    filepath = os.path.join(log_dir, filename)
                    self.process_zip_file(filepath, temp_dir)
                    if (i + 1) % 10 == 0:
                        print(f"    Processed {i + 1}/{len(zip_files)} zip files...")

        print(f"\nTotal unique lines processed: {len(self.seen_lines)}")
        print(f"Total events collected: {len(self.events)}")
        print(f"Unique stores found: {len(self.store_events)}")

    def calculate_disconnection_times(self):
        """Calculate disconnection durations for each store."""
        store_disconnection_times = {}

        for store_id, events in self.store_events.items():
            # Sort events by timestamp
            sorted_events = sorted(events, key=lambda x: x['timestamp'])

            disconnection_times = []
            last_disconnect_time = None

            for event in sorted_events:
                if event['is_disconnect']:
                    last_disconnect_time = event['timestamp']
                elif event['is_reconnect'] and last_disconnect_time:
                    duration = (event['timestamp'] - last_disconnect_time).total_seconds()
                    if duration > 0 and duration < 86400 * 7:  # Ignore unrealistic durations (> 7 days)
                        disconnection_times.append(duration)
                    last_disconnect_time = None

            if disconnection_times:
                store_disconnection_times[store_id] = disconnection_times

        return store_disconnection_times

    def count_reconnects(self):
        """Count reconnects per store."""
        reconnect_counts = {}
        for store_id, events in self.store_events.items():
            # Count disconnect events (each disconnect implies a reconnect needed)
            disconnects = sum(1 for e in events if e['is_disconnect'])
            reconnect_counts[store_id] = disconnects
        return reconnect_counts

    def generate_report(self):
        """Generate the analysis report."""
        print("\n" + "=" * 80)
        print("FEDERATION LOG ANALYSIS REPORT")
        print("=" * 80)

        # Get reconnect counts
        reconnect_counts = self.count_reconnects()

        if not reconnect_counts:
            print("\nNo reconnection events found in the logs.")
            return

        # Find store with highest reconnects to exclude
        max_reconnect_store = max(reconnect_counts, key=reconnect_counts.get)
        max_reconnect_count = reconnect_counts[max_reconnect_store]

        print(f"\n>>> Excluding store with highest reconnects: Store {max_reconnect_store} ({max_reconnect_count} events)")

        # Remove the highest reconnect store
        filtered_reconnects = {k: v for k, v in reconnect_counts.items() if k != max_reconnect_store}

        # Calculate disconnection times (excluding highest reconnect store)
        disconnection_times = self.calculate_disconnection_times()
        if max_reconnect_store in disconnection_times:
            del disconnection_times[max_reconnect_store]

        # =====================
        # SUMMARY SECTION
        # =====================
        print("\n" + "-" * 80)
        print("SUMMARY")
        print("-" * 80)

        total_stores = len(filtered_reconnects)
        total_reconnects = sum(filtered_reconnects.values())

        print(f"Total stores analyzed: {total_stores}")
        print(f"Total reconnection events: {total_reconnects}")
        print(f"Total errors/warnings found: {len(self.errors_warnings)}")

        # Time range
        if self.events:
            timestamps = [e['timestamp'] for e in self.events if e['timestamp']]
            if timestamps:
                min_ts = min(timestamps)
                max_ts = max(timestamps)
                print(f"Time range: {min_ts.strftime('%Y-%m-%d %H:%M')} to {max_ts.strftime('%Y-%m-%d %H:%M')}")

        # =====================
        # TOP STORES SECTION
        # =====================
        print("\n" + "-" * 80)
        print("TOP 20 STORES BY RECONNECTION COUNT (excluding highest)")
        print("-" * 80)

        sorted_stores = sorted(filtered_reconnects.items(), key=lambda x: x[1], reverse=True)[:20]

        print(f"\n{'Rank':<6}{'Store':<12}{'Reconnects':<12}{'Federation Group':<20}")
        print("-" * 50)

        for rank, (store_id, count) in enumerate(sorted_stores, 1):
            fed_group = self.store_fed_groups.get(store_id, 'Unknown')
            print(f"{rank:<6}{store_id:<12}{count:<12}{fed_group:<20}")

        # =====================
        # DISCONNECTION STATISTICS
        # =====================
        print("\n" + "-" * 80)
        print("DISCONNECTION DURATION STATISTICS")
        print("-" * 80)

        all_disconnection_times = []
        store_stats = {}

        for store_id, times in disconnection_times.items():
            if times:
                all_disconnection_times.extend(times)
                store_stats[store_id] = {
                    'max': max(times),
                    'avg': statistics.mean(times),
                    'median': statistics.median(times),
                    'count': len(times)
                }

        if all_disconnection_times:
            overall_max = max(all_disconnection_times)
            overall_avg = statistics.mean(all_disconnection_times)
            overall_median = statistics.median(all_disconnection_times)

            def format_duration(seconds):
                """Format seconds into human-readable duration."""
                if seconds < 60:
                    return f"{seconds:.1f} sec"
                elif seconds < 3600:
                    return f"{seconds/60:.1f} min"
                else:
                    return f"{seconds/3600:.1f} hours"

            print(f"\nOVERALL STATISTICS:")
            print(f"  Maximum disconnection time: {format_duration(overall_max)}")
            print(f"  Average disconnection time: {format_duration(overall_avg)}")
            print(f"  Median disconnection time:  {format_duration(overall_median)}")
            print(f"  Total disconnection events: {len(all_disconnection_times)}")

            # Top stores by max disconnection time
            print(f"\nTOP 10 STORES BY MAXIMUM DISCONNECTION TIME:")
            print(f"{'Store':<12}{'Max Time':<15}{'Avg Time':<15}{'Median':<15}{'Count':<8}{'Fed Group':<20}")
            print("-" * 85)

            sorted_by_max = sorted(store_stats.items(), key=lambda x: x[1]['max'], reverse=True)[:10]
            for store_id, stats in sorted_by_max:
                fed_group = self.store_fed_groups.get(store_id, 'Unknown')
                print(f"{store_id:<12}{format_duration(stats['max']):<15}{format_duration(stats['avg']):<15}{format_duration(stats['median']):<15}{stats['count']:<8}{fed_group:<20}")

        # =====================
        # FEDERATION GROUPS
        # =====================
        print("\n" + "-" * 80)
        print("RECONNECTS BY FEDERATION GROUP")
        print("-" * 80)

        fed_group_stats = defaultdict(lambda: {'stores': set(), 'reconnects': 0})
        for store_id, count in filtered_reconnects.items():
            fed_group = self.store_fed_groups.get(store_id, 'Unknown')
            fed_group_stats[fed_group]['stores'].add(store_id)
            fed_group_stats[fed_group]['reconnects'] += count

        print(f"\n{'Federation Group':<25}{'Stores':<10}{'Total Reconnects':<18}{'Avg per Store':<15}")
        print("-" * 68)

        for fed_group, stats in sorted(fed_group_stats.items(), key=lambda x: x[1]['reconnects'], reverse=True):
            num_stores = len(stats['stores'])
            avg_per_store = stats['reconnects'] / num_stores if num_stores > 0 else 0
            print(f"{fed_group:<25}{num_stores:<10}{stats['reconnects']:<18}{avg_per_store:<15.1f}")

        # =====================
        # TIMELINE / OUTAGES
        # =====================
        print("\n" + "-" * 80)
        print("HOURLY EVENT TIMELINE (potential outage periods)")
        print("-" * 80)

        # Find hours with high activity (potential outages)
        hour_counts = []
        for hour, events in sorted(self.timeline.items()):
            disconnect_count = sum(1 for e in events if e['is_disconnect'] and e['store_id'] != max_reconnect_store)
            hour_counts.append((hour, disconnect_count, len(events)))

        if hour_counts:
            avg_disconnects = statistics.mean([h[1] for h in hour_counts])
            std_disconnects = statistics.stdev([h[1] for h in hour_counts]) if len(hour_counts) > 1 else 0
            threshold = avg_disconnects + 2 * std_disconnects  # 2 standard deviations above mean

            print(f"\nAverage disconnects per hour: {avg_disconnects:.1f}")
            print(f"High activity threshold (2σ): {threshold:.1f}")

            print(f"\nHOURS WITH ELEVATED DISCONNECT ACTIVITY:")
            print(f"{'Timestamp':<25}{'Disconnects':<15}{'Total Events':<15}{'Stores Affected'}")
            print("-" * 80)

            for hour, disconnect_count, total_events in sorted(hour_counts, key=lambda x: x[1], reverse=True)[:20]:
                if disconnect_count > threshold or disconnect_count > 50:
                    affected_stores = set(e['store_id'] for e in self.timeline[hour] if e['is_disconnect'] and e['store_id'] != max_reconnect_store)
                    print(f"{hour.strftime('%Y-%m-%d %H:00'):<25}{disconnect_count:<15}{total_events:<15}{len(affected_stores)}")

        # =====================
        # ERROR ANALYSIS
        # =====================
        print("\n" + "-" * 80)
        print("ERROR AND WARNING ANALYSIS")
        print("-" * 80)

        error_types = defaultdict(int)
        for err in self.errors_warnings:
            for t in err['types']:
                error_types[t] += 1

        print(f"\nEvent type counts:")
        for etype, count in sorted(error_types.items(), key=lambda x: x[1], reverse=True):
            print(f"  {etype.capitalize()}: {count}")

        # Common error patterns
        error_patterns = defaultdict(int)
        for err in self.errors_warnings:
            line = err['line']
            # Extract error message patterns
            if 'connection' in line.lower():
                if 'timeout' in line.lower() or 'timed out' in line.lower():
                    error_patterns['Connection Timeout'] += 1
                elif 'refused' in line.lower():
                    error_patterns['Connection Refused'] += 1
                elif 'failed' in line.lower():
                    error_patterns['Connection Failed'] += 1
                else:
                    error_patterns['Connection Issue (Other)'] += 1
            elif 'exception' in line.lower():
                if 'socket' in line.lower():
                    error_patterns['Socket Exception'] += 1
                elif 'tls' in line.lower() or 'ssl' in line.lower():
                    error_patterns['TLS/SSL Exception'] += 1
                else:
                    error_patterns['Other Exception'] += 1

        if error_patterns:
            print(f"\nCommon error patterns:")
            for pattern, count in sorted(error_patterns.items(), key=lambda x: x[1], reverse=True):
                print(f"  {pattern}: {count}")

        # =====================
        # VISUAL OUTPUT
        # =====================
        self.generate_visuals(filtered_reconnects, sorted_stores, hour_counts, store_stats, fed_group_stats)

    def generate_visuals(self, reconnect_counts, top_stores, hour_counts, store_stats, fed_group_stats):
        """Generate ASCII/Unicode visual charts."""

        print("\n" + "=" * 80)
        print("VISUAL CHARTS")
        print("=" * 80)

        # Bar chart for top stores
        print("\n" + "-" * 80)
        print("TOP 15 STORES BY RECONNECTION COUNT")
        print("-" * 80)

        if top_stores:
            max_count = top_stores[0][1] if top_stores else 1
            for store_id, count in top_stores[:15]:
                bar_length = int(50 * count / max_count)
                bar = "█" * bar_length
                fed_group = self.store_fed_groups.get(store_id, '?')[:10]
                print(f"Store {store_id} ({fed_group:>10}): {bar} {count}")

        # Timeline visualization
        print("\n" + "-" * 80)
        print("DISCONNECT EVENTS OVER TIME (hourly)")
        print("-" * 80)

        if hour_counts:
            # Get max for scaling
            max_disc = max(h[1] for h in hour_counts) if hour_counts else 1

            # Group by date
            daily_events = defaultdict(list)
            for hour, disconnect_count, total_events in hour_counts:
                daily_events[hour.date()].append((hour.hour, disconnect_count))

            print(f"\nLegend: Each █ = ~{max_disc/40:.0f} disconnect events")
            print(f"        Hours shown: 00-23")
            print()

            for date in sorted(daily_events.keys()):
                hours_data = {h: c for h, c in daily_events[date]}

                # Create hour-by-hour display
                hour_bars = []
                for h in range(24):
                    count = hours_data.get(h, 0)
                    if count == 0:
                        hour_bars.append('·')
                    elif count < max_disc * 0.25:
                        hour_bars.append('░')
                    elif count < max_disc * 0.5:
                        hour_bars.append('▒')
                    elif count < max_disc * 0.75:
                        hour_bars.append('▓')
                    else:
                        hour_bars.append('█')

                total_day = sum(hours_data.values())
                print(f"{date} |{''.join(hour_bars)}| {total_day:>5}")

        # Federation group distribution
        print("\n" + "-" * 80)
        print("RECONNECTS BY FEDERATION GROUP")
        print("-" * 80)

        if fed_group_stats:
            max_reconnects = max(s['reconnects'] for s in fed_group_stats.values()) if fed_group_stats else 1

            for fed_group, stats in sorted(fed_group_stats.items(), key=lambda x: x[1]['reconnects'], reverse=True):
                bar_length = int(40 * stats['reconnects'] / max_reconnects)
                bar = "█" * bar_length
                print(f"{fed_group:>20}: {bar} {stats['reconnects']} ({len(stats['stores'])} stores)")

        # Heatmap of disconnections
        if store_stats:
            print("\n" + "-" * 80)
            print("DISCONNECTION DURATION DISTRIBUTION")
            print("-" * 80)

            all_times = []
            for times in [s for s in store_stats.values()]:
                all_times.append(times['median'])

            if all_times:
                # Create buckets
                buckets = {'< 1 min': 0, '1-5 min': 0, '5-15 min': 0, '15-60 min': 0, '1-4 hrs': 0, '> 4 hrs': 0}

                for median_time in all_times:
                    if median_time < 60:
                        buckets['< 1 min'] += 1
                    elif median_time < 300:
                        buckets['1-5 min'] += 1
                    elif median_time < 900:
                        buckets['5-15 min'] += 1
                    elif median_time < 3600:
                        buckets['15-60 min'] += 1
                    elif median_time < 14400:
                        buckets['1-4 hrs'] += 1
                    else:
                        buckets['> 4 hrs'] += 1

                max_bucket = max(buckets.values()) if buckets.values() else 1
                print("\nMedian disconnection time distribution (by store):")
                for bucket, count in buckets.items():
                    bar_length = int(40 * count / max_bucket)
                    bar = "█" * bar_length
                    print(f"  {bucket:>12}: {bar} {count}")

        print("\n" + "=" * 80)
        print("END OF REPORT")
        print("=" * 80)


def main():
    print("Security Center Federation Log Analyzer")
    print("Starting analysis...\n")

    analyzer = LogAnalyzer()
    analyzer.scan_directories()
    analyzer.generate_report()


if __name__ == "__main__":
    main()
