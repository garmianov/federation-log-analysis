"""
Pytest configuration and shared fixtures for federation log analysis tests.
"""

import pytest
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# =============================================================================
# SAMPLE LOG DATA FIXTURES
# =============================================================================

@pytest.fixture
def sample_log_lines():
    """Sample federation log lines for testing."""
    return [
        "2024-01-04T21:06:38.339-08:00 Federation (Info) Store 51389 (vNVR) connected successfully",
        "2024-01-04T21:07:15.123-08:00 Federation (Error) Store 05139 connection attempt failed: timed out",
        "2024-01-04T21:08:22.456-08:00 Federation (Warning) Store_12345 TlsConnectionException: error completing the handshake",
        "2024-01-04T21:09:30.789-08:00 SBUXSCRoleGroup42 (Error) Store 99999 SocketException occurred",
        "2024-01-04T21:10:45.012-08:00 Federation (Error) Store 00123 logged off from federated proxy",
        "2024-01-04T21:11:00.000-08:00 Federation (Info) Scheduling reconnection with startDelay=30",
        "Invalid line without timestamp",
        "2024-01-04T21:12:00.000-08:00 No store ID in this line but has timestamp",
    ]


@pytest.fixture
def sample_timestamps():
    """Sample timestamps in various formats for testing."""
    return {
        'valid': [
            "2024-01-04T21:06:38.339-08:00",
            "2024-12-31T23:59:59.999+00:00",
            "2025-06-15T00:00:00.000-05:00",
        ],
        'invalid': [
            "not a timestamp",
            "2024-13-01T00:00:00",  # invalid month
            "01-04-2024T21:06:38",  # wrong format
            "",
        ]
    }


@pytest.fixture
def sample_store_ids():
    """Sample store ID patterns for testing."""
    return {
        'valid': [
            ("Store 51389 (vNVR)", "51389"),
            ("Store_12345", "12345"),
            ("Store 05139", "05139"),
            ("Store 0123", "00123"),  # Should normalize to 5 digits
            ("Store 99999 connected", "99999"),
        ],
        'invalid': [
            "No store here",
            "Store ABC",
            "Store 123",  # Too short (3 digits)
            "Store 1234567",  # Too long (7 digits)
        ]
    }


@pytest.fixture
def sample_error_lines():
    """Sample error lines for classification testing."""
    return {
        'tls_handshake_error': "2024-01-04T21:06:38.339-08:00 (Error) TlsConnectionException: error completing the handshake",
        'connection_timeout': "2024-01-04T21:06:38.339-08:00 (Error) connection attempt failed: did not properly respond after a period of time",
        'connection_refused': "2024-01-04T21:06:38.339-08:00 (Error) target machine actively refused the connection",
        'socket_exception': "2024-01-04T21:06:38.339-08:00 (Error) SocketException: connection reset",
        'proxy_disconnect': "2024-01-04T21:06:38.339-08:00 (Warning) Store 51389 logged off from federated proxy",
    }


# =============================================================================
# ANALYZER FIXTURES
# =============================================================================

@pytest.fixture
def federation_analyzer():
    """Create a FederationLogAnalyzer instance for testing."""
    from analyze_federation_ai import FederationLogAnalyzer
    return FederationLogAnalyzer()


# =============================================================================
# TEMPORARY FILE FIXTURES
# =============================================================================

@pytest.fixture
def temp_log_file(tmp_path, sample_log_lines):
    """Create a temporary log file for testing."""
    log_file = tmp_path / "test_federation.log"
    log_file.write_text("\n".join(sample_log_lines))
    return log_file


@pytest.fixture
def temp_log_directory(tmp_path, sample_log_lines):
    """Create a temporary directory with multiple log files."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    # Create multiple log files
    for i in range(3):
        log_file = log_dir / f"SBUXSCRoleGroup{i}.log"
        log_file.write_text("\n".join(sample_log_lines))

    return log_dir
