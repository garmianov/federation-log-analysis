#!/usr/bin/env python3
"""
Analyze specific disconnect reasons per store.
Optimized with parallel processing and efficient pattern matching.
"""

import os
import re
from collections import defaultdict
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

LOG_DIR = "/Users/gancho/Library/CloudStorage/OneDrive-GenetecInc/Documents/Starbucks/Federation reconnects investigations/MS58138FedLogs/logs1"

# Patterns to extract store and reason
STORE_PATTERN = re.compile(r'Store[\s_](\d{4,5})(?:\s*\([^)]*\))?')
TIMESTAMP_PATTERN = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})')

# Reason patterns - more specific categories
# Using a combined approach: quick string check first, then regex for complex patterns
REASON_PATTERNS = {
    'connection_timeout': re.compile(r'connection attempt failed.*did not properly respond after a period of time', re.I),
    'host_failed_respond': re.compile(r'connected host has failed to respond', re.I),
    'tls_connection_error': re.compile(r'TlsConnectionException', re.I),
    'socket_exception': re.compile(r'SocketException', re.I),
    'connection_refused': re.compile(r'connection.*refused|actively refused', re.I),
    'network_unreachable': re.compile(r'network.*unreachable|no route to host', re.I),
    'ssl_handshake_failed': re.compile(r'ssl.*handshake|tls.*handshake|handshake.*fail', re.I),
    'certificate_error': re.compile(r'certificate|cert.*error|cert.*invalid', re.I),
    'dns_resolution': re.compile(r'dns|name.*resolution|could not resolve', re.I),
    'proxy_logged_off': re.compile(r'federated proxy.*logged off|Initial sync context is null', re.I),
    'authentication_failed': re.compile(r'authentication.*fail|login.*fail|credential', re.I),
    'service_unavailable': re.compile(r'service.*unavailable|503', re.I),
    'internal_error': re.compile(r'internal.*error|500', re.I),
    'scheduling_reconnect': re.compile(r'Scheduling reconnection with startDelay', re.I),
}

# Quick pre-filter keywords to skip lines that won't match any pattern
QUICK_FILTER_KEYWORDS = (
    'connection', 'respond', 'tls', 'socket', 'refused', 'network', 'ssl',
    'handshake', 'certificate', 'cert', 'dns', 'resolution', 'resolve',
    'proxy', 'logged off', 'sync context', 'authentication', 'login',
    'credential', 'service', '503', '500', 'internal', 'scheduling', 'reconnection'
)

# IP address pattern
IP_PATTERN = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)')

class StoreReasonAnalyzer:
    def __init__(self):
        self.store_reasons = defaultdict(lambda: defaultdict(int))
        self.store_ips = defaultdict(set)
        self.store_ports = defaultdict(set)
        self.store_error_samples = defaultdict(list)
        self.reason_totals = defaultdict(int)
        self.seen_lines = set()
        self._lock = threading.Lock()  # Thread safety for parallel processing

    def process_file(self, filepath):
        try:
            with open(filepath, 'r', encoding='utf-8-sig', errors='replace') as f:
                for line in f:
                    self.process_line(line)
        except Exception as e:
            pass

    def process_line(self, line):
        """Process a single line with optimized pattern matching (thread-safe)."""
        line = line.strip()
        if not line:
            return

        # Skip duplicates (thread-safe)
        line_hash = hash(line)
        with self._lock:
            if line_hash in self.seen_lines:
                return
            self.seen_lines.add(line_hash)

        # Must have a store reference
        store_match = STORE_PATTERN.search(line)
        if not store_match:
            return
        store_id = store_match.group(1).zfill(5)

        # Pre-compute lowercase once for all string checks
        line_lower = line.lower()

        # Quick filter: skip line if it doesn't contain any relevant keywords
        if not any(kw in line_lower for kw in QUICK_FILTER_KEYWORDS):
            return

        # Extract IPs
        ip_matches = IP_PATTERN.findall(line)

        # Check for each reason pattern (only if quick filter passed)
        matched_reasons = []
        for reason, pattern in REASON_PATTERNS.items():
            if pattern.search(line):
                matched_reasons.append(reason)

        # Thread-safe updates
        with self._lock:
            # Update IP tracking
            for ip, port in ip_matches:
                self.store_ips[store_id].add(ip)
                self.store_ports[store_id].add(port)

            # Update reason counts
            for reason in matched_reasons:
                self.store_reasons[store_id][reason] += 1
                self.reason_totals[reason] += 1

                # Keep sample errors (max 5 per store)
                if len(self.store_error_samples[store_id]) < 5:
                    self.store_error_samples[store_id].append({
                        'reason': reason,
                        'line': line[:300]
                    })

    def scan_logs(self, max_workers=4):
        """Scan logs with parallel processing."""
        print("Scanning logs for store-specific disconnect reasons...\n", flush=True)

        files = sorted([os.path.join(LOG_DIR, f) for f in os.listdir(LOG_DIR) if f.endswith('.log')])

        # Process files in parallel
        processed = 0
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.process_file, fp): fp for fp in files}
            for future in as_completed(futures):
                processed += 1
                if processed % 500 == 0:
                    print(f"  {processed}/{len(files)} files...", flush=True)

        print(f"  Done: {len(files)} files\n", flush=True)

    def generate_report(self):
        print("=" * 80, flush=True)
        print("STORE-SPECIFIC DISCONNECT REASON ANALYSIS", flush=True)
        print("=" * 80, flush=True)

        # Overall reason breakdown
        print("\n--- OVERALL DISCONNECT REASONS ---\n", flush=True)
        total = sum(self.reason_totals.values())
        for reason, count in sorted(self.reason_totals.items(), key=lambda x: x[1], reverse=True):
            pct = 100 * count / total if total > 0 else 0
            bar_len = int(40 * count / max(self.reason_totals.values()))
            print(f"{reason:25}: {'█' * bar_len} {count:>8,} ({pct:5.1f}%)", flush=True)

        # Calculate dominant reason per store
        store_dominant = {}
        for store_id, reasons in self.store_reasons.items():
            if reasons:
                dominant = max(reasons.items(), key=lambda x: x[1])
                store_dominant[store_id] = (dominant[0], dominant[1], sum(reasons.values()))

        # Group stores by their primary issue
        print("\n--- STORES GROUPED BY PRIMARY ISSUE ---\n", flush=True)

        reason_stores = defaultdict(list)
        for store_id, (reason, count, total) in store_dominant.items():
            reason_stores[reason].append((store_id, count, total))

        for reason in sorted(reason_stores.keys(), key=lambda r: len(reason_stores[r]), reverse=True):
            stores = reason_stores[reason]
            print(f"\n{reason.upper().replace('_', ' ')} ({len(stores)} stores):", flush=True)
            print("-" * 60, flush=True)

            # Show top 10 stores for this reason
            top_stores = sorted(stores, key=lambda x: x[1], reverse=True)[:10]
            print(f"{'Store':<10}{'This Reason':<15}{'Total Issues':<15}{'IPs':<30}", flush=True)
            for store_id, count, total in top_stores:
                ips = ', '.join(list(self.store_ips.get(store_id, set()))[:3])
                print(f"{store_id:<10}{count:<15,}{total:<15,}{ips:<30}", flush=True)

        # Detailed analysis of top problem stores
        print("\n\n--- DETAILED ANALYSIS: TOP 15 PROBLEM STORES ---\n", flush=True)

        # Rank by total issues
        store_totals = [(s, sum(r.values())) for s, r in self.store_reasons.items()]
        top_stores = sorted(store_totals, key=lambda x: x[1], reverse=True)[:15]

        for store_id, total in top_stores:
            reasons = self.store_reasons[store_id]
            ips = self.store_ips.get(store_id, set())
            ports = self.store_ports.get(store_id, set())

            print(f"\n{'='*60}", flush=True)
            print(f"STORE {store_id} - Total Issues: {total:,}", flush=True)
            print(f"{'='*60}", flush=True)
            print(f"IPs: {', '.join(ips)}", flush=True)
            print(f"Ports: {', '.join(ports)}", flush=True)
            print(f"\nBreakdown by reason:", flush=True)

            for reason, count in sorted(reasons.items(), key=lambda x: x[1], reverse=True):
                pct = 100 * count / total
                print(f"  {reason:30}: {count:>8,} ({pct:5.1f}%)", flush=True)

            # Show diagnosis
            print(f"\nLikely Cause:", flush=True)
            dominant_reason = max(reasons.items(), key=lambda x: x[1])[0]

            if dominant_reason in ['connection_timeout', 'host_failed_respond']:
                print(f"  → Store vNVR is DOWN or UNREACHABLE (network/hardware issue at store)", flush=True)
            elif dominant_reason == 'proxy_logged_off':
                print(f"  → Federation proxy session keeps dropping (may indicate store restarts)", flush=True)
            elif dominant_reason in ['tls_connection_error', 'ssl_handshake_failed']:
                print(f"  → TLS/Certificate issue - possible certificate mismatch or expiry", flush=True)
            elif dominant_reason == 'connection_refused':
                print(f"  → Service not running on store or firewall blocking", flush=True)
            elif dominant_reason == 'scheduling_reconnect':
                print(f"  → Rapid reconnection cycling (underlying issue causing repeated disconnects)", flush=True)
            elif dominant_reason == 'socket_exception':
                print(f"  → Low-level network issue (firewall, NAT, or connectivity)", flush=True)

        print("\n" + "=" * 80, flush=True)
        print("END OF ANALYSIS", flush=True)
        print("=" * 80, flush=True)


def main():
    analyzer = StoreReasonAnalyzer()
    analyzer.scan_logs()
    analyzer.generate_report()


if __name__ == "__main__":
    main()
