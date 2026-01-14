"""
Custom exceptions for federation log analysis.

This module defines a hierarchy of exceptions for handling errors
specific to federation log parsing, analysis, and ML operations.
"""

from typing import Optional


class FederationAnalysisError(Exception):
    """Base exception for all federation analysis errors."""

    pass


class LogParseError(FederationAnalysisError):
    """Raised when a log file cannot be parsed.

    Attributes:
        file_path: Path to the file that failed to parse.
        line_number: Line number where parsing failed (if applicable).
    """

    def __init__(
        self,
        message: str,
        file_path: Optional[str] = None,
        line_number: Optional[int] = None,
    ) -> None:
        self.file_path = file_path
        self.line_number = line_number
        super().__init__(message)

    def __str__(self) -> str:
        base = super().__str__()
        if self.file_path and self.line_number:
            return f"{base} (file: {self.file_path}, line: {self.line_number})"
        elif self.file_path:
            return f"{base} (file: {self.file_path})"
        return base


class DataValidationError(FederationAnalysisError):
    """Raised when input data fails validation."""

    pass


class InsufficientDataError(FederationAnalysisError):
    """Raised when there is insufficient data for analysis.

    Attributes:
        required: Minimum number of data points required.
        actual: Actual number of data points provided.
    """

    def __init__(
        self,
        message: str,
        required: Optional[int] = None,
        actual: Optional[int] = None,
    ) -> None:
        self.required = required
        self.actual = actual
        super().__init__(message)

    def __str__(self) -> str:
        base = super().__str__()
        if self.required is not None and self.actual is not None:
            return f"{base} (required: {self.required}, actual: {self.actual})"
        return base


class MLModelError(FederationAnalysisError):
    """Raised when ML model operations fail."""

    pass


class ConfigurationError(FederationAnalysisError):
    """Raised for configuration-related errors."""

    pass
