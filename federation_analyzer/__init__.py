"""
Federation Log Analysis Toolkit

A Python package for analyzing Genetec Security Center federation logs
using AI/ML techniques for anomaly detection, prediction, and root cause analysis.
"""

from .analyzer import FederationLogAnalyzer
from .events import FederationEvent, OnlineStats
from .patterns import (
    TIMESTAMP_PATTERN,
    STORE_PATTERN,
    IP_PORT_PATTERN,
    FED_GROUP_PATTERN,
    ERROR_PATTERNS,
    INTERNAL_ERROR_SUBTYPES,
    SEVERITY_PATTERNS,
)
from .ml import (
    AdvancedAnomalyDetector,
    PredictiveAnalytics,
    CausalAnalyzer,
    CascadeDetector,
    Recommendation,
    RecommendationEngine,
)

__all__ = [
    # Main analyzer
    'FederationLogAnalyzer',
    # Event classes
    'FederationEvent',
    'OnlineStats',
    # Patterns
    'TIMESTAMP_PATTERN',
    'STORE_PATTERN',
    'IP_PORT_PATTERN',
    'FED_GROUP_PATTERN',
    'ERROR_PATTERNS',
    'INTERNAL_ERROR_SUBTYPES',
    'SEVERITY_PATTERNS',
    # ML classes
    'AdvancedAnomalyDetector',
    'PredictiveAnalytics',
    'CausalAnalyzer',
    'CascadeDetector',
    'Recommendation',
    'RecommendationEngine',
]

__version__ = '2.0.0'
