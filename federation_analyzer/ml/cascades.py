"""
Cascade failure detection and propagation analysis.
"""

from collections import defaultdict
from typing import Dict, List

import numpy as np


class CascadeDetector:
    """
    Detect cascading failures where one store's failure triggers others.
    """

    def __init__(self, time_window_seconds: int = 60):
        self.time_window = time_window_seconds
        self.cascade_events = []

    def detect_cascades(self, events: List, min_stores: int = 3) -> List[Dict]:
        """
        Detect cascade events where multiple stores fail within time window.
        Optimized with numpy for O(n log n) instead of O(n²) complexity.
        """
        if not events:
            return []

        # Filter events with valid timestamps and sort
        valid_events = [e for e in events if e.timestamp is not None]
        if not valid_events:
            return []

        sorted_events = sorted(valid_events, key=lambda e: e.timestamp)
        n_events = len(sorted_events)

        # Convert timestamps to numpy for fast searchsorted
        timestamps = np.array([e.timestamp.timestamp() for e in sorted_events])
        window_delta = self.time_window

        cascades = []
        i = 0

        while i < n_events:
            # Use searchsorted to find window boundary in O(log n) instead of O(n)
            window_end_ts = timestamps[i] + window_delta
            j = np.searchsorted(timestamps, window_end_ts, side="right")

            # Collect stores and events in window
            stores_in_window = set()
            events_in_window = []
            for k in range(i, j):
                if sorted_events[k].store_id:
                    stores_in_window.add(sorted_events[k].store_id)
                    events_in_window.append(sorted_events[k])

            # Check if this is a cascade
            if len(stores_in_window) >= min_stores:
                # Determine cascade characteristics
                error_types = defaultdict(int)
                machines = set()
                for e in events_in_window:
                    if e.error_category:
                        error_types[e.error_category] += 1
                    if e.machine:
                        machines.add(e.machine)

                cascades.append(
                    {
                        "start_time": sorted_events[i].timestamp,
                        "end_time": events_in_window[-1].timestamp
                        if events_in_window
                        else sorted_events[i].timestamp,
                        "store_count": len(stores_in_window),
                        "stores": list(stores_in_window)[:10],  # Limit for display
                        "event_count": len(events_in_window),
                        "dominant_error": max(error_types.items(), key=lambda x: x[1])[0]
                        if error_types
                        else "unknown",
                        "machines_affected": len(machines),
                        "is_server_wide": len(machines) == 1 and len(stores_in_window) > 10,
                    }
                )

                i = j  # Skip past this cascade
            else:
                i += 1

        self.cascade_events = cascades
        return cascades

    def analyze_propagation(self, cascades: List[Dict]) -> Dict:
        """
        Analyze cascade propagation patterns.
        """
        if not cascades:
            return {}

        # Statistics
        avg_stores = np.mean([c["store_count"] for c in cascades])
        max_stores = max(c["store_count"] for c in cascades)
        server_wide_count = sum(1 for c in cascades if c["is_server_wide"])

        # Error type analysis
        error_counts = defaultdict(int)
        for c in cascades:
            error_counts[c["dominant_error"]] += 1

        return {
            "total_cascades": len(cascades),
            "avg_stores_affected": avg_stores,
            "max_stores_in_cascade": max_stores,
            "server_wide_cascades": server_wide_count,
            "common_error_types": dict(error_counts),
        }
