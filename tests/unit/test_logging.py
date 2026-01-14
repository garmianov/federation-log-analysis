"""Tests for logging configuration."""

import logging
from io import StringIO

from federation_analyzer.logging_config import (
    configure_logging,
    enable_debug,
    enable_quiet,
    get_logger,
)


class TestLoggingConfiguration:
    """Test logging setup and configuration."""

    def test_simple_mode_output(self):
        """Test simple mode produces clean output without metadata."""
        stream = StringIO()
        configure_logging(simple_mode=True, stream=stream)
        # Use federation_analyzer namespace so the configured handler applies
        logger = get_logger("federation_analyzer.test.simple")
        logger.info("Test message")
        output = stream.getvalue()
        assert "Test message" in output
        # Simple mode should not include INFO level prefix
        assert "INFO" not in output

    def test_structured_mode_output(self):
        """Test structured mode includes metadata."""
        stream = StringIO()
        configure_logging(simple_mode=False, stream=stream)
        logger = get_logger("federation_analyzer.test.structured")
        logger.info("Test message")
        output = stream.getvalue()
        assert "Test message" in output
        assert "INFO" in output

    def test_get_logger_returns_same_instance(self):
        """Test get_logger returns cached logger instance."""
        logger1 = get_logger("federation_analyzer.test.cache")
        logger2 = get_logger("federation_analyzer.test.cache")
        assert logger1 is logger2

    def test_different_names_different_loggers(self):
        """Test different names return different loggers."""
        logger1 = get_logger("federation_analyzer.test.one")
        logger2 = get_logger("federation_analyzer.test.two")
        assert logger1 is not logger2


class TestLoggingLevels:
    """Test logging level configuration."""

    def test_set_level(self):
        """Test set_level changes logging level."""
        stream = StringIO()
        configure_logging(level=logging.WARNING, stream=stream)
        logger = get_logger("federation_analyzer.test.level")

        logger.info("Should not appear")
        logger.warning("Should appear")

        output = stream.getvalue()
        assert "Should not appear" not in output
        assert "Should appear" in output

    def test_enable_debug(self):
        """Test enable_debug sets DEBUG level."""
        stream = StringIO()
        configure_logging(stream=stream)
        enable_debug()
        logger = get_logger("federation_analyzer.test.debug")
        logger.debug("Debug message")
        output = stream.getvalue()
        assert "Debug message" in output

    def test_enable_quiet(self):
        """Test enable_quiet suppresses INFO messages."""
        stream = StringIO()
        configure_logging(stream=stream)
        enable_quiet()
        logger = get_logger("federation_analyzer.test.quiet")
        logger.info("Info message")
        logger.warning("Warning message")
        output = stream.getvalue()
        assert "Info message" not in output
        assert "Warning message" in output


class TestCustomFormat:
    """Test custom format strings."""

    def test_custom_format_string(self):
        """Test custom format string is used."""
        stream = StringIO()
        configure_logging(format_string="[CUSTOM] %(message)s", stream=stream)
        logger = get_logger("federation_analyzer.test.custom")
        logger.info("Hello")
        output = stream.getvalue()
        assert "[CUSTOM]" in output
        assert "Hello" in output


class TestAutoConfiguration:
    """Test automatic configuration on first use."""

    def test_auto_configure_on_get_logger(self):
        """Test logger auto-configures if not already configured."""
        # This relies on the global state, so just verify it doesn't error
        logger = get_logger("federation_analyzer.test.auto")
        assert logger is not None
