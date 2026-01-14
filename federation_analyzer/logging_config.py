"""
Logging configuration for federation log analysis.

This module provides a centralized logging configuration that can be used
throughout the federation_analyzer package. By default, it uses a simple
format that mimics print() output for backward compatibility.

Usage:
    from federation_analyzer.logging_config import get_logger

    logger = get_logger(__name__)
    logger.info("Processing file: %s", filename)

To enable structured logging with timestamps:
    from federation_analyzer.logging_config import configure_logging
    import logging

    configure_logging(level=logging.DEBUG, simple_mode=False)
"""

import logging
import sys
from typing import Dict, Optional, TextIO

# Format strings
DEFAULT_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
SIMPLE_FORMAT = "%(message)s"

# Module-level logger cache
_loggers: Dict[str, logging.Logger] = {}
_configured: bool = False


def configure_logging(
    level: int = logging.INFO,
    format_string: Optional[str] = None,
    stream: Optional[TextIO] = None,
    simple_mode: bool = True,
) -> None:
    """
    Configure the root logger for federation analysis.

    Args:
        level: Logging level (default: INFO).
        format_string: Custom format string. If None, uses SIMPLE_FORMAT
            or DEFAULT_FORMAT based on simple_mode.
        stream: Output stream (default: sys.stdout).
        simple_mode: If True, use simple format without timestamps.
            This produces output identical to print() statements.
    """
    global _configured

    if format_string is None:
        format_string = SIMPLE_FORMAT if simple_mode else DEFAULT_FORMAT

    handler = logging.StreamHandler(stream or sys.stdout)
    handler.setFormatter(logging.Formatter(format_string))

    # Configure federation_analyzer namespace
    root_logger = logging.getLogger("federation_analyzer")
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(level)
    root_logger.propagate = False

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for the given module name.

    Args:
        name: Module name (typically __name__).

    Returns:
        Configured logger instance.

    Example:
        logger = get_logger(__name__)
        logger.info("Processing %d events", count)
    """
    global _configured

    # Auto-configure on first use if not already configured
    if not _configured:
        configure_logging()

    if name not in _loggers:
        logger = logging.getLogger(name)
        _loggers[name] = logger

    return _loggers[name]


def set_level(level: int) -> None:
    """
    Set the logging level for all federation_analyzer loggers.

    Args:
        level: Logging level (e.g., logging.DEBUG, logging.INFO).
    """
    root_logger = logging.getLogger("federation_analyzer")
    root_logger.setLevel(level)


def enable_debug() -> None:
    """Enable debug-level logging."""
    set_level(logging.DEBUG)


def enable_quiet() -> None:
    """Set logging to WARNING level (suppress INFO messages)."""
    set_level(logging.WARNING)
