"""Tests for custom exception classes."""

import pytest

from federation_analyzer.exceptions import (
    ConfigurationError,
    DataValidationError,
    FederationAnalysisError,
    InsufficientDataError,
    LogParseError,
    MLModelError,
)


class TestExceptionHierarchy:
    """Test exception inheritance hierarchy."""

    def test_all_exceptions_inherit_from_base(self):
        """All custom exceptions should inherit from FederationAnalysisError."""
        assert issubclass(LogParseError, FederationAnalysisError)
        assert issubclass(DataValidationError, FederationAnalysisError)
        assert issubclass(InsufficientDataError, FederationAnalysisError)
        assert issubclass(MLModelError, FederationAnalysisError)
        assert issubclass(ConfigurationError, FederationAnalysisError)

    def test_base_inherits_from_exception(self):
        """Base exception should inherit from Exception."""
        assert issubclass(FederationAnalysisError, Exception)


class TestLogParseError:
    """Test LogParseError attributes and formatting."""

    def test_basic_message(self):
        """Test basic error message."""
        exc = LogParseError("Parse failed")
        assert str(exc) == "Parse failed"

    def test_with_file_path(self):
        """Test error with file path."""
        exc = LogParseError("Parse failed", file_path="/tmp/test.log")
        assert exc.file_path == "/tmp/test.log"
        assert exc.line_number is None
        assert "file: /tmp/test.log" in str(exc)

    def test_with_line_number(self):
        """Test error with file path and line number."""
        exc = LogParseError("Parse failed", file_path="/tmp/test.log", line_number=42)
        assert exc.file_path == "/tmp/test.log"
        assert exc.line_number == 42
        assert "file: /tmp/test.log" in str(exc)
        assert "line: 42" in str(exc)

    def test_can_be_raised_and_caught(self):
        """Test exception can be raised and caught."""
        with pytest.raises(LogParseError) as exc_info:
            raise LogParseError("Test error", file_path="/test.log", line_number=10)
        assert exc_info.value.file_path == "/test.log"


class TestInsufficientDataError:
    """Test InsufficientDataError attributes and formatting."""

    def test_basic_message(self):
        """Test basic error message."""
        exc = InsufficientDataError("Need more data")
        assert str(exc) == "Need more data"

    def test_with_counts(self):
        """Test error with required and actual counts."""
        exc = InsufficientDataError("Need more data", required=100, actual=10)
        assert exc.required == 100
        assert exc.actual == 10
        assert "required: 100" in str(exc)
        assert "actual: 10" in str(exc)

    def test_partial_counts(self):
        """Test with only required set."""
        exc = InsufficientDataError("Need more data", required=100)
        assert exc.required == 100
        assert exc.actual is None
        # Should not include counts in string since actual is None
        assert str(exc) == "Need more data"


class TestExceptionImports:
    """Test that exceptions are properly exported from package."""

    def test_import_from_package(self):
        """Test exceptions can be imported from main package."""
        from federation_analyzer import (
            FederationAnalysisError,
            LogParseError,
        )

        # Verify they are the same classes
        assert FederationAnalysisError is not None
        assert LogParseError is not None
