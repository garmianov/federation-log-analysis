"""
Federation Log Analysis Toolkit

A Python package for analyzing Genetec Security Center federation logs
using AI/ML techniques for anomaly detection, prediction, and root cause analysis.
"""

from .analyzer import FederationLogAnalyzer
from .events import FederationEvent, OnlineStats
from .exceptions import (
    ConfigurationError,
    DataValidationError,
    FederationAnalysisError,
    InsufficientDataError,
    LogParseError,
    MLModelError,
)
from .ml import (
    AdvancedAnomalyDetector,
    CascadeDetector,
    CausalAnalyzer,
    PredictiveAnalytics,
    Recommendation,
    RecommendationEngine,
)
from .patterns import (
    ERROR_PATTERNS,
    FED_GROUP_PATTERN,
    INTERNAL_ERROR_SUBTYPES,
    IP_PORT_PATTERN,
    SEVERITY_PATTERNS,
    STORE_PATTERN,
    TIMESTAMP_PATTERN,
)

__all__ = [
    # Main analyzer
    "FederationLogAnalyzer",
    # Event classes
    "FederationEvent",
    "OnlineStats",
    # Exceptions
    "FederationAnalysisError",
    "LogParseError",
    "DataValidationError",
    "InsufficientDataError",
    "MLModelError",
    "ConfigurationError",
    # Patterns
    "TIMESTAMP_PATTERN",
    "STORE_PATTERN",
    "IP_PORT_PATTERN",
    "FED_GROUP_PATTERN",
    "ERROR_PATTERNS",
    "INTERNAL_ERROR_SUBTYPES",
    "SEVERITY_PATTERNS",
    # ML classes
    "AdvancedAnomalyDetector",
    "PredictiveAnalytics",
    "CausalAnalyzer",
    "CascadeDetector",
    "Recommendation",
    "RecommendationEngine",
]

__version__ = "2.0.0"
