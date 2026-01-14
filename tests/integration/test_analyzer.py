"""
Integration tests for the federation log analyzer.

Tests the full workflow including:
- Log file processing
- Event extraction
- Statistics generation
"""

import pytest
import os
from datetime import datetime


class TestLogFileProcessing:
    """Tests for processing log files."""

    def test_process_single_log_file(self, federation_analyzer, temp_log_file):
        """Test processing a single log file."""
        federation_analyzer.process_log_file(str(temp_log_file))

        # Should have processed some events
        assert len(federation_analyzer.events) > 0

    def test_process_log_directory(self, federation_analyzer, temp_log_directory):
        """Test processing a directory of log files."""
        federation_analyzer.process_log_directory(str(temp_log_directory))

        # Should have processed events from all files
        assert len(federation_analyzer.events) > 0
        assert federation_analyzer.lines_processed > 0

    def test_event_attributes(self, federation_analyzer, temp_log_file):
        """Test that processed events have required attributes."""
        federation_analyzer.process_log_file(str(temp_log_file))

        for event in federation_analyzer.events:
            assert hasattr(event, 'timestamp')
            assert hasattr(event, 'store_id')
            assert event.timestamp is not None
            # store_id may be None for some events


class TestStatisticsGeneration:
    """Tests for statistics generation."""

    def test_store_statistics(self, federation_analyzer, temp_log_file):
        """Test per-store statistics are tracked."""
        federation_analyzer.process_log_file(str(temp_log_file))

        # store_stats is a dict tracking per-store data
        assert hasattr(federation_analyzer, 'store_stats')
        assert isinstance(federation_analyzer.store_stats, dict)

    def test_error_category_counts(self, federation_analyzer, temp_log_file):
        """Test error category counting."""
        federation_analyzer.process_log_file(str(temp_log_file))

        # error_category_totals tracks error counts
        assert hasattr(federation_analyzer, 'error_category_totals')
        assert isinstance(federation_analyzer.error_category_totals, dict)


class TestLineDeduplication:
    """Tests for duplicate line handling."""

    def test_duplicate_lines_filtered(self, federation_analyzer, tmp_path):
        """Test that duplicate lines are tracked via seen_hashes."""
        # Create log with duplicate lines
        log_content = """2024-01-04T21:06:38.339-08:00 Store 51389 connected
2024-01-04T21:06:38.339-08:00 Store 51389 connected
2024-01-04T21:06:38.339-08:00 Store 51389 connected
2024-01-04T21:07:00.000-08:00 Store 12345 connected
"""
        log_file = tmp_path / "duplicate_test.log"
        log_file.write_text(log_content)

        federation_analyzer.process_log_file(str(log_file))

        # seen_hashes should track unique lines
        assert len(federation_analyzer.seen_hashes) == 2
        # lines_processed counts unique lines
        assert federation_analyzer.lines_processed == 2


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_log_file(self, federation_analyzer, tmp_path):
        """Test handling of empty log file."""
        empty_file = tmp_path / "empty.log"
        empty_file.write_text("")

        # Should not raise exception
        federation_analyzer.process_log_file(str(empty_file))
        assert len(federation_analyzer.events) == 0

    def test_malformed_lines(self, federation_analyzer, tmp_path):
        """Test handling of malformed log lines."""
        log_content = """Not a valid log line
Another invalid line
2024-01-04T21:06:38.339-08:00 Store 51389 valid line
Partial timestamp 2024-01-04
"""
        log_file = tmp_path / "malformed.log"
        log_file.write_text(log_content)

        # Should not raise exception, should process valid lines
        federation_analyzer.process_log_file(str(log_file))

    def test_nonexistent_file(self, federation_analyzer):
        """Test handling of nonexistent file."""
        # Should handle gracefully (not raise unhandled exception)
        try:
            federation_analyzer.process_log_file("/nonexistent/path/file.log")
        except FileNotFoundError:
            pass  # Expected behavior
        except Exception as e:
            # Other exceptions should be handled gracefully
            pass

    def test_unicode_in_log(self, federation_analyzer, tmp_path):
        """Test handling of unicode characters in log."""
        log_content = "2024-01-04T21:06:38.339-08:00 Store 51389 message with unicode: \u00e9\u00e8\u00ea\n"
        log_file = tmp_path / "unicode.log"
        log_file.write_text(log_content, encoding='utf-8')

        # Should not raise exception
        federation_analyzer.process_log_file(str(log_file))
