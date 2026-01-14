"""
Event data classes for federation log analysis.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional


class FederationEvent:
    """Represents a single federation event.

    Attributes:
        timestamp: When the event occurred.
        store_id: 5-digit store identifier.
        fed_group: Federation group name (e.g., SBUXSCRoleGroup1).
        machine: Machine/server name.
        event_type: Type of event.
        error_category: Classified error category.
        severity: Error severity level.
        ip: IP address involved.
        port: Port number involved.
        message: Raw log message (truncated).
        internal_error_subtype: Specific internal error classification.
    """

    __slots__ = (
        "timestamp",
        "store_id",
        "fed_group",
        "machine",
        "event_type",
        "error_category",
        "severity",
        "ip",
        "port",
        "message",
        "internal_error_subtype",
    )

    timestamp: Optional[datetime]
    store_id: Optional[str]
    fed_group: Optional[str]
    machine: Optional[str]
    event_type: Optional[str]
    error_category: Optional[str]
    severity: Optional[str]
    ip: Optional[str]
    port: Optional[str]
    message: Optional[str]
    internal_error_subtype: Optional[str]

    def __init__(self) -> None:
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
        self.internal_error_subtype = None


class OnlineStats:
    """Welford's algorithm for streaming statistics.

    Efficiently computes mean, variance, min, max, and approximate median
    from a stream of values without storing all values in memory.

    Attributes:
        n: Number of values seen.
        mean: Running mean.
        M2: Aggregated squared distance from mean (for variance).
        min_val: Minimum value seen.
        max_val: Maximum value seen.
        samples: Sampled values for median approximation.
    """

    __slots__ = ("n", "mean", "M2", "min_val", "max_val", "samples")

    n: int
    mean: float
    M2: float
    min_val: float
    max_val: float
    samples: List[float]

    def __init__(self) -> None:
        self.n = 0
        self.mean = 0.0
        self.M2 = 0.0
        self.min_val = float("inf")
        self.max_val = float("-inf")
        self.samples = []

    def update(self, x: float) -> None:
        """Update statistics with a new value.

        Args:
            x: The new value to incorporate.
        """
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

    def get_stats(self) -> Optional[Dict[str, Any]]:
        """Get computed statistics.

        Returns:
            Dictionary with count, mean, std, min, max, and median,
            or None if no values have been seen.
        """
        if self.n < 1:
            return None
        std = (self.M2 / self.n) ** 0.5 if self.n > 1 else 0.0
        median = sorted(self.samples)[len(self.samples) // 2] if self.samples else self.mean
        return {
            "count": self.n,
            "mean": self.mean,
            "std": std,
            "min": self.min_val,
            "max": self.max_val,
            "median": median,
        }
