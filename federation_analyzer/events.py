"""
Event data classes for federation log analysis.
"""


class FederationEvent:
    """Represents a single federation event."""
    __slots__ = ('timestamp', 'store_id', 'fed_group', 'machine', 'event_type',
                 'error_category', 'severity', 'ip', 'port', 'message', 'internal_error_subtype')

    def __init__(self):
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
    """Welford's algorithm for streaming statistics."""
    __slots__ = ('n', 'mean', 'M2', 'min_val', 'max_val', 'samples')

    def __init__(self):
        self.n = 0
        self.mean = 0.0
        self.M2 = 0.0
        self.min_val = float('inf')
        self.max_val = float('-inf')
        self.samples = []

    def update(self, x):
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

    def get_stats(self):
        if self.n < 1:
            return None
        std = (self.M2 / self.n) ** 0.5 if self.n > 1 else 0
        median = sorted(self.samples)[len(self.samples)//2] if self.samples else self.mean
        return {'count': self.n, 'mean': self.mean, 'std': std,
                'min': self.min_val, 'max': self.max_val, 'median': median}
