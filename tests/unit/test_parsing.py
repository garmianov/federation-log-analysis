"""
Unit tests for log parsing functionality.

Tests the core parsing logic including:
- Timestamp extraction
- Store ID extraction
- Federation group extraction
- Error classification
"""

import pytest
import re
from datetime import datetime


class TestTimestampParsing:
    """Tests for timestamp extraction from log lines."""

    def test_valid_timestamp_extraction(self, federation_analyzer, sample_log_lines):
        """Test extraction of valid timestamps."""
        # First line has a valid timestamp
        line = sample_log_lines[0]
        ts = federation_analyzer.parse_timestamp(line)

        assert ts is not None
        assert isinstance(ts, datetime)
        assert ts.year == 2024
        assert ts.month == 1
        assert ts.day == 4
        assert ts.hour == 21
        assert ts.minute == 6
        assert ts.second == 38

    def test_invalid_timestamp_returns_none(self, federation_analyzer):
        """Test that invalid timestamps return None."""
        invalid_lines = [
            "No timestamp here",
            "2024-13-01T00:00:00 invalid month",
            "",
            "   ",
        ]
        for line in invalid_lines:
            assert federation_analyzer.parse_timestamp(line) is None

    def test_timestamp_at_line_start(self, federation_analyzer):
        """Test that timestamp must be at the start of line."""
        line = "Some prefix 2024-01-04T21:06:38.339-08:00 message"
        # Depending on implementation, this may or may not parse
        # The current implementation requires timestamp at start
        ts = federation_analyzer.parse_timestamp(line)
        assert ts is None


class TestStoreIdExtraction:
    """Tests for store ID extraction using STORE_PATTERN regex."""

    def test_store_id_with_space(self):
        """Test 'Store 51389' format."""
        from analyze_federation_ai import STORE_PATTERN
        match = STORE_PATTERN.search("Store 51389 connected")
        assert match is not None
        assert match.group(1) == "51389"

    def test_store_id_with_underscore(self):
        """Test 'Store_12345' format."""
        from analyze_federation_ai import STORE_PATTERN
        match = STORE_PATTERN.search("Store_12345 connected")
        assert match is not None
        assert match.group(1) == "12345"

    def test_store_id_with_vnvr_suffix(self):
        """Test 'Store 51389 (vNVR)' format."""
        from analyze_federation_ai import STORE_PATTERN
        match = STORE_PATTERN.search("Store 51389 (vNVR) connected")
        assert match is not None
        assert match.group(1) == "51389"

    def test_store_id_4_digits(self):
        """Test 4-digit store IDs are captured."""
        from analyze_federation_ai import STORE_PATTERN
        match = STORE_PATTERN.search("Store 0123 connected")
        assert match is not None
        assert match.group(1) == "0123"

    def test_no_store_id_returns_none(self):
        """Test that lines without store ID return None."""
        from analyze_federation_ai import STORE_PATTERN
        assert STORE_PATTERN.search("No store here") is None
        assert STORE_PATTERN.search("Store ABC invalid") is None


class TestFederationGroupExtraction:
    """Tests for federation group extraction."""

    def test_fed_group_extraction(self):
        """Test extraction of SBUXSCRoleGroup pattern."""
        from analyze_federation_ai import FED_GROUP_PATTERN
        match = FED_GROUP_PATTERN.search("SBUXSCRoleGroup42 (Info) message")
        assert match is not None
        assert match.group(1) == "SBUXSCRoleGroup42"

    def test_fed_group_various_numbers(self):
        """Test federation groups with various numbers."""
        from analyze_federation_ai import FED_GROUP_PATTERN
        test_cases = ["SBUXSCRoleGroup1", "SBUXSCRoleGroup99", "SBUXSCRoleGroup123"]
        for group in test_cases:
            match = FED_GROUP_PATTERN.search(group)
            assert match is not None
            assert match.group(1) == group

    def test_no_fed_group_returns_none(self):
        """Test that lines without federation group return None."""
        from analyze_federation_ai import FED_GROUP_PATTERN
        assert FED_GROUP_PATTERN.search("Federation (Info) message") is None


class TestErrorClassification:
    """Tests for error category classification.

    Note: classify_error returns a tuple (category, severity).
    """

    def test_tls_error_classification(self, federation_analyzer):
        """Test TLS handshake error detection."""
        line = "TlsConnectionException: error completing the handshake"
        category, severity = federation_analyzer.classify_error(line)
        assert category == "tls_handshake_error"

    def test_timeout_classification(self, federation_analyzer):
        """Test connection timeout detection."""
        line = "connection attempt failed: did not properly respond after a period of time"
        category, severity = federation_analyzer.classify_error(line)
        assert category == "connection_timeout"

    def test_socket_exception_classification(self, federation_analyzer):
        """Test socket exception detection."""
        line = "SocketException occurred"
        category, severity = federation_analyzer.classify_error(line)
        assert category == "socket_exception"

    def test_proxy_disconnect_classification(self, federation_analyzer):
        """Test proxy disconnect detection."""
        line = "Store 51389 logged off from federated proxy"
        category, severity = federation_analyzer.classify_error(line)
        assert category == "proxy_disconnect"

    def test_no_error_returns_none(self, federation_analyzer):
        """Test that normal lines return None for error category."""
        line = "Store 51389 connected successfully"
        category, severity = federation_analyzer.classify_error(line)
        assert category is None


class TestPatternConstants:
    """Tests for regex pattern constants."""

    def test_timestamp_pattern(self):
        """Test TIMESTAMP_PATTERN regex."""
        from analyze_federation_ai import TIMESTAMP_PATTERN

        valid = "2024-01-04T21:06:38.339-08:00 rest of line"
        match = TIMESTAMP_PATTERN.match(valid)
        assert match is not None
        assert match.group(1) == "2024-01-04T21:06:38"

    def test_store_pattern(self):
        """Test STORE_PATTERN regex."""
        from analyze_federation_ai import STORE_PATTERN

        test_cases = [
            ("Store 51389", "51389"),
            ("Store_12345", "12345"),
            ("Store 51389 (vNVR)", "51389"),
            ("Store 0123 connected", "0123"),
        ]
        for text, expected in test_cases:
            match = STORE_PATTERN.search(text)
            assert match is not None, f"Failed to match: {text}"
            assert match.group(1) == expected

    def test_ip_port_pattern(self):
        """Test IP_PORT_PATTERN regex."""
        from analyze_federation_ai import IP_PORT_PATTERN

        text = "Connected to 192.168.1.100:5500"
        match = IP_PORT_PATTERN.search(text)
        assert match is not None
        assert match.group(1) == "192.168.1.100"
        assert match.group(2) == "5500"

    def test_fed_group_pattern(self):
        """Test FED_GROUP_PATTERN regex."""
        from analyze_federation_ai import FED_GROUP_PATTERN

        test_cases = [
            "SBUXSCRoleGroup1",
            "SBUXSCRoleGroup42",
            "SBUXSCRoleGroup999",
        ]
        for group in test_cases:
            match = FED_GROUP_PATTERN.search(group)
            assert match is not None
            assert match.group(1) == group
